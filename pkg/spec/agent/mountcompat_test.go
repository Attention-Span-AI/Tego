// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestBuiltinDenyReadMountCompatibility measures layout compatibility using the real built-in expansion.
// These are modeled mount layouts, not captures or claims about every installation of a distribution.
func TestBuiltinDenyReadMountCompatibility(t *testing.T) {
	var cases []struct {
		Name, Home, Project, HomeTarget, Assumption string
		Want                                        map[string][]string
	}
	data, err := os.ReadFile("testdata/mountcompat/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 6 {
		t.Fatalf("got %d host layouts, want six", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			f := newFixture(t)
			at := func(p string) string { return filepath.Join(f.root, p) }
			f.home, f.project = at(tc.Home), at(tc.Project)
			if tc.HomeTarget != "" {
				if err := os.MkdirAll(at(tc.HomeTarget), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(f.home), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(at(tc.HomeTarget), f.home); err != nil {
					t.Fatal(err)
				}
			}
			// Hold the credential inventory constant so this measures the mount topology's effect.
			for _, p := range []string{f.project, filepath.Join(f.home, ".ssh"), filepath.Join(f.home, ".aws"),
				filepath.Join(f.home, ".config/gh"), filepath.Join(f.home, ".mozilla/firefox"),
				filepath.Join(f.home, "snap/firefox/common/.mozilla")} {
				if err := os.MkdirAll(p, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f.file(filepath.Join(f.home, ".netrc"), "fixture", 0o600)
			f.file(filepath.Join(f.project, ".env"), "FIXTURE=1", 0o600)
			// A run creates its record directory before Compile, so retain the mandatory own-record refusal too.
			f.ledger = filepath.Join(f.home, ".tego", "runs")
			f.machine.LedgerRoot.Value = f.ledger
			if err := os.MkdirAll(f.ledger, 0o700); err != nil {
				t.Fatal(err)
			}
			ownRecords, err := filepath.EvalSymlinks(filepath.Dir(f.ledger))
			if err != nil {
				t.Fatal(err)
			}
			rt, _ := f.compile(f.load("version: 0\nname: mount-compatibility\ncommand: [static-tool]\n"), WithMountInfo(""))
			data, err := os.ReadFile(filepath.Join("testdata/mountcompat", tc.Name+".mountinfo"))
			if err != nil {
				t.Fatal(err)
			}
			mt, err := ParseMountTableStrict([]byte(strings.ReplaceAll(string(data), "{{ROOT}}", f.root)))
			if err != nil {
				t.Fatal(err)
			}
			got := map[string][]string{}
			builtins := 0
			ownRecordsDenied := false
			for _, r := range rt.FS {
				if r.Kind != FSDenyRead || !r.BuiltIn {
					continue
				}
				builtins++
				ownRecordsDenied = ownRecordsDenied || r.Canonical() == ownRecords
				aliases, ok := mt.TreeAliases(r.Canonical())
				if !ok {
					t.Fatalf("mount table cannot place %s", r.Canonical())
				}
				parts, ok := mt.DetachedParts(r.Canonical())
				if !ok || len(parts) != 0 {
					t.Fatalf("fixture has an unmodeled detached part for %s: %v, held %v", r.Canonical(), parts, ok)
				}
				if len(aliases) == 0 {
					continue
				}
				for i := range aliases {
					aliases[i] = strings.TrimPrefix(aliases[i], f.root)
				}
				slices.Sort(aliases)
				got[strings.TrimPrefix(r.Canonical(), f.root)] = aliases
			}
			if builtins != 8 || !ownRecordsDenied {
				t.Fatalf("compiled %d built-in entries, own records denied=%v; want six home entries, project .env and own records", builtins, ownRecordsDenied)
			}
			if !maps.EqualFunc(got, tc.Want, slices.Equal) {
				t.Errorf("aliases = %v, want %v", got, tc.Want)
			}
			t.Logf("%s: %d built-in entries, %d with other names; listener startup refused=%v; assumptions: %s", tc.Name, builtins, len(got), len(got) != 0, tc.Assumption)
			for _, p := range slices.Sorted(maps.Keys(got)) {
				t.Logf("  %s: %s", p, strings.Join(got[p], ", "))
			}
		})
	}
}
