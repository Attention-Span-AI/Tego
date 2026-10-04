// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestDenyReadEqualWriteContradictionAnyOrder is R15's contradiction: a deny_read entry that resolves to the same
// path as a write entry is refused whatever order the write entries are listed in. The check returned at the first
// write entry enclosing the target, so a broader write entry listed before the equal one compiled the table
// silently, and tier 3 and tier 2 decided the read differently.
func TestDenyReadEqualWriteContradictionAnyOrder(t *testing.T) {
	for _, writes := range []string{`["./out", "./out/s"]`, `["./out/s", "./out"]`} {
		t.Run(writes, func(t *testing.T) {
			f := newFixture(t)
			f.file(filepath.Join(f.project, "out", "s"), "secret", 0o600)
			c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: " + writes + "\n  deny_read: [\"./out/s\"]\n")
			_, ds, err := Compile(c, f.machine, f.opts()...)
			if err == nil || !hasCode(ds, CodeContradiction) {
				t.Fatalf("write %s with deny_read ./out/s: err = %v, want a contradiction\n%s", writes, err, render(ds))
			}
			if !errors.Is(err, ErrContractOverlap) {
				t.Errorf("err = %v, want ErrContractOverlap", err)
			}
		})
	}
}
