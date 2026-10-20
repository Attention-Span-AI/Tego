// SPDX-License-Identifier: Apache-2.0

package perf

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestTrueImageExitsZero: the exec check's image is a valid static executable of this machine that exits 0 at once.
func TestTrueImageExitsZero(t *testing.T) {
	img, err := TrueImage(runtime.GOARCH)
	if err != nil {
		t.Skipf("no image for this machine: %v", err)
	}
	path := filepath.Join(t.TempDir(), "true")
	if err := os.WriteFile(path, img, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(path).CombinedOutput(); err != nil {
		t.Fatalf("exec the image: %v %q", err, out)
	}
	if _, err := TrueImage("mips"); err == nil {
		t.Error("an image for an architecture with none was made")
	}
}
