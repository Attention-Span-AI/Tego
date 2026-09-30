// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// openPipes counts this process's open pipe descriptors.
func openPipes(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && strings.HasPrefix(link, "pipe:") {
			n++
		}
	}
	return n
}

// A failed stdout pipe (EMFILE under the fd pressure the probe marks Faulted) leaves no pipe open: nothing is
// started, so nothing else would close the child's stdin pipe before a GC finalizer.
func TestStartPlaneChildPipeFailureLeaksNothing(t *testing.T) {
	saved := planeStdoutPipe
	t.Cleanup(func() { planeStdoutPipe = saved })
	planeStdoutPipe = func() (*os.File, *os.File, error) { return nil, nil, syscall.EMFILE }

	before := openPipes(t)
	_, err := startPlaneChildAs(&planeCgroup{fd: -1, path: t.TempDir()}, planeChildRole, t.TempDir(), -1)
	if !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("startPlaneChildAs = %v, want EMFILE", err)
	}
	if after := openPipes(t); after != before {
		t.Fatalf("open pipes %d before, %d after a failed start", before, after)
	}
}
