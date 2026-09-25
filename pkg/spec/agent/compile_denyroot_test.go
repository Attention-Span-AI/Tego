// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDenyReadRootIsACompileError is enforce-landlock.md E5: `deny_read: ["/"]` has no parent to enumerate, and
// compile must reject it rather than leave the run to fail at Prepare. It is judged on the resolved path, so a
// symlink to / is refused too.
func TestDenyReadRootIsACompileError(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.project, "to-root")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"/", "/tmp/..", link} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  deny_read: [\"" + entry + "\"]\n")
		_, ds, err := Compile(c, f.machine, f.opts()...)
		if err == nil || !hasCode(ds, CodeSchema) {
			t.Errorf("deny_read %q compiled: %v\n%s", entry, err, render(ds))
		}
	}
}
