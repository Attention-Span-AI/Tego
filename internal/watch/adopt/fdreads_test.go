// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestFDsBoundsItsReadsAcrossCopiedTables: every thread of a process that called unshare(CLONE_FILES) holds a table
// of its own, a copy of the leader's, and FDs read each in full, so many such threads cost many full tables before the
// adoption recorded. FDs reads at most FS.maxReads descriptors of one
// process across its tables (maxFDReads in NewFS); past it the listing is truncated (the process is counted unread),
// and below it every copy is still read.
//
// The test lowers the bound to a few tables of n descriptors, and each descriptor is a link whose target is a short
// pipe name: a fast symlink with no data block, so the fake tables cost a few inodes rather than one 4 KiB block per
// link (the full-size tables took 130 MB per run).
func TestFDsBoundsItsReadsAcrossCopiedTables(t *testing.T) {
	const n, bound = 16, 4 * 16
	listing := func(t *testing.T, copies int) ([]FD, error) {
		t.Helper()
		root := t.TempDir()
		dirs := []string{filepath.Join(root, "42", "fd")}
		for c := range copies {
			dirs = append(dirs, filepath.Join(root, "42", "task", strconv.Itoa(100+c), "fd"))
		}
		for _, d := range dirs {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			for i := range n {
				if err := os.Symlink("pipe:["+strconv.Itoa(i)+"]", filepath.Join(d, strconv.Itoa(i))); err != nil {
					t.Fatal(err)
				}
			}
		}
		fs := NewFS(root)
		fs.internal = func() map[devID]bool { return nil }
		fs.mounts = nil
		fs.sameFiles = func(pid, tid int) (bool, error) { return false, nil }
		if fs.maxReads != maxFDReads {
			t.Fatalf("NewFS bounds the reads at %d, want maxFDReads (%d)", fs.maxReads, maxFDReads)
		}
		fs.maxReads = bound
		return fs.FDs(42)
	}
	below := bound/n - 1 // tables the bound reads whole: the leader's and its copies
	t.Run("copies the bound reads", func(t *testing.T) {
		if fds, err := listing(t, below-1); len(fds) != n || err != nil {
			t.Errorf("FDs = %d descriptors, %v; want the %d of the leader's table and no error", len(fds), err, n)
		}
	})
	t.Run("more copies than the bound reads", func(t *testing.T) {
		fds, err := listing(t, 2*below)
		if !errors.Is(err, ErrTruncated) || !strings.Contains(err.Error(), "more than "+strconv.Itoa(bound)+" descriptors in all") {
			t.Fatalf("FDs = %d descriptors, %v; want ErrTruncated naming the bound across tables", len(fds), err)
		}
		if len(fds) != n {
			t.Errorf("FDs listed %d, want the %d it read before the bound", len(fds), n)
		}
	})
}
