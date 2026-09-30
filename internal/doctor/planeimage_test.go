// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPlaneImageIsMadeOnceAndClosed: every mode's get returns the one image, made on the first get; a failed make is
// not kept, and close releases the descriptor.
func TestPlaneImageIsMadeOnceAndClosed(t *testing.T) {
	made := 0
	fail := true
	makePlaneImage = func() (int, error) {
		made++
		if fail {
			return -1, unix.EMFILE
		}
		return unix.Dup(0)
	}
	defer func() { makePlaneImage = planeExecImage }()
	img := &planeImage{fd: -1}
	if _, err := img.get(); !errors.Is(err, unix.EMFILE) {
		t.Fatalf("a failed make: %v", err)
	}
	fail = false
	a, err := img.get()
	if err != nil {
		t.Fatal(err)
	}
	b, err := img.get()
	if err != nil || b != a {
		t.Fatalf("second get: %d, %v; want %d", b, err, a)
	}
	if made != 2 {
		t.Errorf("made %d images for one failure and two gets, want 2", made)
	}
	img.close()
	if _, err := unix.FcntlInt(uintptr(a), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Errorf("descriptor %d is open after close: %v", a, err)
	}
	img.close()
}
