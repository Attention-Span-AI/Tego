// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"os"
	"testing"
)

func TestIsTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(int(r.Fd())) {
		t.Fatal("a pipe reports as a terminal")
	}
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	defer ptmx.Close()
	if !IsTerminal(int(ptmx.Fd())) {
		t.Fatal("a pty master does not report as a terminal")
	}
	if IsTerminal(-1) {
		t.Fatal("fd -1 reports as a terminal")
	}
}
