// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Review counterexample 1: declaring a dependency directory writable must not spend the
// project's scan budget there and drop a previously found secret (ADR 0043 D10).
func TestWriteDeclarationCannotStarveProjectSecretScan(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.project, ".env")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(f.project, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(f.root, "ordinary")
	f.file(seed, "fixture", 0600)
	for i := range envScanMaxEntries {
		if err := os.Link(seed, filepath.Join(target, strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(f.project, "secrets", ".env")
	f.file(secret, "FIXTURE=protected", 0600)
	for _, writes := range []string{`"./"`, `"./", "./target/"`} {
		rt, ds := f.compile(loadCoverageContract(t, f, "version: 0\nname: scan\ncommand: [python]\nfs:\n  write: ["+writes+"]\n"), WithTiers(backend.TierLandlock))
		found := false
		for _, r := range rt.FS {
			found = found || r.Kind == FSDenyRead && r.Resolved == secret
		}
		if !found || !rt.ReadsHeldAt(backend.TierLandlock) {
			t.Errorf("write [%s]: existing secret lost or reads became direct: found=%v held=%v\n%s", writes, found, rt.ReadsHeldAt(backend.TierLandlock), render(ds))
		}
	}
}

// Review counterexamples 2 and 3 rely on extending the path-based built-in floor. A write
// declaration must add neither that coverage nor a promise about moving future declared names.
// The ordinary contract/cwd roots and held glob checks remain exactly as before the extension.
func TestWriteDeclarationsDoNotExtendNameScopes(t *testing.T) {
	for _, tc := range []struct {
		name, dir, deny string
	}{
		{"ancestor-and-exchange", "a/target", ""},
		{"declared-held-pattern", "private/target", "  deny_read: [\"./private/*/token.key\"]\n  reads: held\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if err := os.MkdirAll(filepath.Join(f.project, tc.dir), 0755); err != nil {
				t.Fatal(err)
			}
			compile := func(extra string) *RuleTable {
				rt, _ := f.compile(loadCoverageContract(t, f, "version: 0\nname: scopes\ncommand: [python]\nfs:\n  write: [\"./\""+extra+"]\n"+tc.deny))
				return rt
			}
			before, after := compile(""), compile(", "+strconv.Quote("./"+tc.dir+"/"))
			if !reflect.DeepEqual(before.NameDeny, after.NameDeny) || !reflect.DeepEqual(before.Reads.Names, after.Reads.Names) {
				t.Errorf("declaring %s introduced extra name coverage:\nbefore %+v\nafter %+v", tc.dir, before.Reads.Names, after.Reads.Names)
			}
			if tc.deny != "" && (len(after.Reads.Patterns) == 0 || !reflect.DeepEqual(before.Reads.Patterns, after.Reads.Patterns)) {
				t.Fatal("declared held-read patterns changed with a write declaration")
			}
		})
	}
}

// Keep the contract outside the writable project, as R10 requires.
func loadCoverageContract(t *testing.T, f *fixture, yaml string) *Contract {
	t.Helper()
	dir := filepath.Join(f.root, "policy")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.yaml")
	f.file(path, yaml, 0600)
	c, ds, err := Load(path, f.profiles())
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	return c
}
