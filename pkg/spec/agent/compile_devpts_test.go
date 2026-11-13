// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// The terminal Landlock layer excludes /dev/pts, but recursively grants the
// ordinary directories beside /dev. A devpts mount elsewhere must therefore
// never be admitted by a write grant, including a bind of a slave alone.
func TestCompileRefusesDevptsAliases(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	alias := filepath.Join(work, "pts")
	if err := os.MkdirAll(filepath.Join(alias, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, root, entry string
	}{
		{"mount", "/", alias},
		{"ancestor", "/", work},
		{"descendant", "/", filepath.Join(alias, "child")},
		{"slave-bind", "/7", alias},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mi := fakeMountInfo(f, "5 1 0:24 "+tc.root+" "+alias+" rw - devpts devpts rw")
			wantRefused(t, f, f.load(writeSection(tc.entry)), "the devpts filesystem mounted at "+alias, mi)
			wantRefused(t, f, f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  ask: [\""+tc.entry+"\"]\n"),
				"the devpts filesystem mounted at "+alias, mi)
		})
	}
}
