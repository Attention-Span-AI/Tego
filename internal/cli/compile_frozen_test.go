// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileNamesTheDirectoriesADenyReadFreezes (GAPS A12): compile prints one note naming the directories a run's
// Landlock ruleset will list once at launch for its deny_read entries, the target's ancestors up to /, and says that a
// name made directly in one of them during a run cannot be read until it ends, at tier landlock and at a root tier,
// which composes the same ruleset. A table that lists no directory prints no such note.
func TestCompileNamesTheDirectoriesADenyReadFreezes(t *testing.T) {
	for _, tc := range []struct {
		name, tier string
	}{
		{"landlock", "landlock"},
		{"cgroup", "cgroup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "secret"), 0o755); err != nil {
				t.Fatal(err)
			}
			contract := "version: 0\nname: frozen\ncommand: [\"true\"]\ntier: " + tc.tier + "\nfs:\n  write: [\"./work/\"]\n  deny_read: [\"./secret/\"]\n"
			if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Chdir(dir)
			code, out, errs := run(t, "compile", "agent.yaml")
			if code != identity.ExitOK {
				t.Fatalf("exit %d\nstderr %s", code, errs)
			}
			var notes []string
			for l := range strings.Lines(out) {
				if strings.HasPrefix(l, "note      deny_read lists ") {
					notes = append(notes, strings.TrimSuffix(l, "\n"))
				}
			}
			if len(notes) != 1 {
				t.Fatalf("%d frozen notes, want one\n%s", len(notes), out)
			}
			for _, d := range []string{"/", filepath.Dir(dir), dir} {
				if !strings.Contains(notes[0], " "+d+",") && !strings.Contains(notes[0], " "+d+" ") {
					t.Errorf("the note does not name %s: %q", d, notes[0])
				}
			}
			if !strings.Contains(notes[0], "during a run cannot be read until it ends") {
				t.Errorf("the note does not say what freezing means: %q", notes[0])
			}
		})
	}
}

// TestCompileSaysNothingFrozenWhenNothingIsListed: a table with no enforced deny_read lists no directory, so compile
// prints no note.
func TestCompileSaysNothingFrozenWhenNothingIsListed(t *testing.T) {
	var b strings.Builder
	if err := printFrozen(&b, &agent.RuleTable{FS: []agent.FSRule{{Kind: agent.FSDenyRead, Path: "/w/secret", Unenforced: true}}}); err != nil || b.Len() != 0 {
		t.Errorf("printFrozen = %q, %v; want nothing", b.String(), err)
	}
}
