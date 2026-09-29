// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestBuildLockProtocolAsSpecified pins the build-lock protocol runtime-launch.md R15 and R16 state: every
// launcher takes the lock shared at once (no exclusive creator, no downgrade), a departing launcher's
// non-blocking exclusive probe decides last out, a launcher told it is not last holds nothing, and the lock
// file is never unlinked, so every later launcher of the build locks the same inode (ADR 0034 (3)).
//
// Also pins runtime-launch.md I6: the LOCK_SH count is the number of live launchers; a launcher told it is not last holds nothing.
func TestBuildLockProtocolAsSpecified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bpf-hash.lock")

	// probe opens its own description of the lock file and asks for how without blocking; flock contends
	// per open file description, so it stands in for another launcher.
	probe := func(how int) error {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		return unix.Flock(int(f.Fd()), how|unix.LOCK_NB)
	}
	inode := func() uint64 {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("the lock file is gone: %v", err)
		}
		return fi.Sys().(*syscall.Stat_t).Ino
	}

	first, err := acquireBuildLock(dir, "hash")
	if err != nil {
		t.Fatal(err)
	}
	// The first launcher holds the lock shared, not exclusive: another shared hold is granted at once.
	if err := probe(unix.LOCK_SH); err != nil {
		t.Fatalf("a shared probe beside the first launcher: %v; R15 says it holds LOCK_SH, never LOCK_EX", err)
	}
	ino := inode()
	second, err := acquireBuildLock(dir, "hash")
	if err != nil {
		t.Fatalf("a second launcher joining: %v", err)
	}
	if err := probe(unix.LOCK_EX); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("an exclusive probe while two launchers hold the lock = %v, want EWOULDBLOCK", err)
	}

	// The first to leave is not last and afterwards holds nothing, so the second is last.
	if last, err := first.lastOut(); err != nil || last {
		t.Fatalf("first departure lastOut = %v, %v; want false", last, err)
	}
	if last, err := second.lastOut(); err != nil || !last {
		t.Fatalf("second departure lastOut = %v, %v; want true (the first holds nothing)", last, err)
	}
	// The last out keeps the lock exclusive until Close: a launcher arriving now waits rather than adopting
	// pins that are being removed.
	if err := probe(unix.LOCK_SH); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("a shared probe while the last out removes the pins = %v, want EWOULDBLOCK", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	// No unlink. The file stays, and the next launcher locks the same inode.
	if got := inode(); got != ino {
		t.Fatalf("lock file inode changed from %d to %d: it was unlinked and recreated", ino, got)
	}
	next, err := acquireBuildLock(dir, "hash")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(next.f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if st.Ino != ino {
		t.Fatalf("the next launcher locked inode %d, want the same file %d", st.Ino, ino)
	}
}
