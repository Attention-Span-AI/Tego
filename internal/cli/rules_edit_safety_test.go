// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestRulesEditFileSafety(t *testing.T) {
	for _, attack := range []string{"publication-link", "rejected-link", "destination-link", "concurrent-edit", "rejected-error"} {
		t.Run(attack, func(t *testing.T) {
			w := newRegistryWorld(t)
			path := filepath.Join(w.project, "agent.yaml")
			victim := filepath.Join(t.TempDir(), "outside")
			good := "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\n"
			if err := os.WriteFile(path, []byte(good), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(victim, []byte(good), 0600); err != nil {
				t.Fatal(err)
			}
			edited := "printf '\\n# edited\\n' >> \"$1\"\n"
			switch attack {
			case "publication-link":
				if err := os.Symlink(victim, path+".tego-edit"); err != nil {
					t.Fatal(err)
				}
			case "rejected-link":
				if err := os.Symlink(victim, path+".rejected"); err != nil {
					t.Fatal(err)
				}
				edited = "printf '\\ninvalid: [\\n' >> \"$1\"\n"
			case "destination-link":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			case "concurrent-edit":
				t.Setenv("RULES_DEST", path)
				edited += "printf '# someone else\\n' >> \"$RULES_DEST\"\n"
			case "rejected-error":
				if err := os.Mkdir(path+".rejected", 0700); err != nil {
					t.Fatal(err)
				}
				edited = "printf '\\ninvalid: [\\n' >> \"$1\"\n"
			}
			editor := filepath.Join(t.TempDir(), "editor")
			if err := os.WriteFile(editor, []byte("#!/bin/sh\n"+edited), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("VISUAL", editor)
			code, out, errs := run(t, "rules", "edit", path)
			if b, err := os.ReadFile(victim); err != nil || string(b) != good {
				t.Fatalf("outside changed: %q %v", b, err)
			}
			if attack == "publication-link" {
				if code != identity.ExitOK {
					t.Fatalf("safe publication failed: %d %s %s", code, out, errs)
				}
			} else if code == identity.ExitOK || (attack == "rejected-error" && strings.Contains(out, "your edit is in")) {
				t.Fatalf("unsafe edit accepted: %d %s %s", code, out, errs)
			}
			if attack == "concurrent-edit" {
				b, _ := os.ReadFile(path)
				if string(b) != good+"# someone else\n" {
					t.Fatalf("concurrent change lost: %s", b)
				}
			}
		})
	}
}

func TestRulesEditReportsSubstitutedPublication(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "link"}[link], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "agent.yaml")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(dir, "victim")
			if err := os.WriteFile(victim, []byte("victim"), 0600); err != nil {
				t.Fatal(err)
			}
			err := atomicRulesWrite(path, []byte("checked"), 0600, func() error {
				names, e := filepath.Glob(filepath.Join(dir, ".tego-edit-*"))
				if e != nil {
					return e
				}
				if len(names) != 1 {
					t.Fatalf("temporary files: %v", names)
				}
				if e = os.Remove(names[0]); e != nil {
					return e
				}
				if link {
					return os.Symlink(victim, names[0])
				}
				return os.WriteFile(names[0], []byte("substituted"), 0600)
			})
			if err == nil || !strings.Contains(err.Error(), "changed underneath") {
				t.Fatalf("substituted temporary inode not reported: %v", err)
			}
			b, e := os.ReadFile(victim)
			if e != nil || string(b) != "victim" {
				t.Fatalf("victim: %q %v", b, e)
			}
		})
	}
}
