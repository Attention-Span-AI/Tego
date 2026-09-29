// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBTFProbeFollowsASymlink is limits-check-doctor-cli.md E24's BTF half: D2 opens the path, and open(2)
// follows a link, so a vmlinux that is a symlink to the real file is BTF present and reports the target's
// size, as the kernel's own loader would see it, where an lstat would have seen a 20-byte link. A link to
// nothing is the absence D2 reports, with the tier-2/3 consequence in its detail and a fix.
func TestBTFProbeFollowsASymlink(t *testing.T) {
	dir := t.TempDir()
	real := writeFakeBTF(t, fakeKernelTypes()...)
	st, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "vmlinux")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	setBTFPath(t, link)
	r := probeBTFWith(needs())
	if want := fmt.Sprintf("(%d bytes)", st.Size()); !r.OK || r.Fix != "" || !strings.Contains(r.Detail, want) {
		t.Errorf("through a symlink: %+v, want OK with the target's %s", r, want)
	}

	if err := os.Remove(real); err != nil {
		t.Fatal(err)
	}
	r = probeBTFWith(needs())
	if r.OK || r.Fix == "" || !strings.Contains(r.Detail, "no tier-2/3 program loads") {
		t.Errorf("a dangling symlink: %+v, want not OK, a fix, and the tier consequence", r)
	}
}
