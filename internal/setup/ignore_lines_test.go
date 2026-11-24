// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every folder the contract makes under .tego/ is covered by a .gitignore line, and the lines are each named once with
// none that another line already covers: what a page tells a person to add and what init adds are the same short list.
func TestEveryGeneratedStateFolderIsIgnoredOnce(t *testing.T) {
	cases := map[string]struct {
		o     Options
		files []string
	}{
		"folders a person adds and the temp folder": {Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src/", "notes/"}, Command: "true", Name: "a"}, nil},
		"an agent's own folder":                     {Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src/"}, Agent: "claude-code", Name: "a"}, nil},
		"a read-only project, the agent's own":      {Options{Presets: []string{"no-secrets"}, Agent: "claude-code", Name: "a", ReadOnlyProject: true}, nil},
		"a read-only project, a custom command":     {Options{Presets: []string{"no-secrets"}, Command: "true", Name: "a", ReadOnlyProject: true}, nil},
		"a Go project":                              {Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src/"}, Command: "true", Name: "a"}, []string{"go.mod", "package.json"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			tc.o.Dir = dir
			r, err := Compose(tc.o)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range r.MakeDirs {
				rel, err := filepath.Rel(dir, d)
				if err != nil || !strings.HasPrefix(rel, ".tego"+string(filepath.Separator)) {
					continue // a folder the person added is theirs to keep or ignore
				}
				rel = filepath.ToSlash(rel) + "/"
				if !slices.ContainsFunc(r.Ignore, func(l string) bool { return strings.HasPrefix(rel, l) }) {
					t.Errorf("%s is made and no .gitignore line covers it: %q", rel, r.Ignore)
				}
			}
			for i, l := range r.Ignore {
				for j, o := range r.Ignore {
					if i != j && strings.HasPrefix(l, o) {
						t.Errorf("%q is named beside %q, which already covers it (or twice): %q", l, o, r.Ignore)
					}
				}
			}
		})
	}
}
