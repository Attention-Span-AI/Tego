// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFDsListsTwoFilesUnderOneNumberAndName: two descriptor tables of one process can hold two different files under
// one number and one name: here the leader's table holds x, opened and unlinked, and a thread's own table (unshare
// CLONE_FILES) holds, under the same number, a hard link of key made at x, opened and unlinked too, so both links read
// "<dir>/x (deleted)" with the same flags. The count asks the rules by the inode as well as the name, so a merge by
// number, name and flags alone dropped the keyed file, counted neither held nor unread. FDs lists both.
func TestFDsListsTwoFilesUnderOneNumberAndName(t *testing.T) {
	dir := t.TempDir()
	x, key := filepath.Join(dir, "x"), filepath.Join(dir, "key")
	for _, p := range []string{x, key} {
		if err := os.WriteFile(p, []byte(filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var xSt, keySt unix.Stat_t
	if err := unix.Stat(x, &xSt); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(key, &keySt); err != nil {
		t.Fatal(err)
	}
	n, err := unix.Open(x, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(n) //nolint:errcheck // the test's own descriptor
	if err := os.Remove(x); err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan error), make(chan struct{})
	defer close(done)
	var thread func()
	thread = func() {
		runtime.LockOSThread() // never unlocked: the runtime ends the thread, and its table, with the goroutine
		if unix.Gettid() == unix.Getpid() {
			// The leader: unsharing here would give the leader the new table. Hold it, so the next goroutine runs on
			// another thread.
			go thread()
			<-done
			return
		}
		ready <- func() error {
			if err := unix.Unshare(unix.CLONE_FILES); err != nil {
				return err
			}
			if err := os.Link(key, x); err != nil {
				return err
			}
			fd, err := unix.Open(x, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			if err := unix.Dup3(fd, n, unix.O_CLOEXEC); err != nil {
				return err
			}
			_ = unix.Close(fd)
			return os.Remove(x)
		}()
		<-done
	}
	go thread()
	if err := <-ready; err != nil {
		t.Skipf("a thread's own table holding a hard link under the leader's number: %v", err)
	}
	fds, err := NewFS("").FDs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	var inodes []uint64
	for _, fd := range fds {
		if fd.Num == n {
			if fd.Target != x+" (deleted)" {
				t.Errorf("fd %d names %q, want %q", n, fd.Target, x+" (deleted)")
			}
			inodes = append(inodes, fd.ID.Ino)
		}
	}
	slices.Sort(inodes)
	want := []uint64{xSt.Ino, keySt.Ino}
	slices.Sort(want)
	if !slices.Equal(inodes, want) {
		t.Errorf("fd %d is listed on inodes %v, want both tables' files %v (x %d, key %d)", n, inodes, want, xSt.Ino,
			keySt.Ino)
	}
}

// TestFDsNeverMergesTwoRings: io_uring instances share one name, and on an older kernel one inode, so no listing
// tells one ring from another: a ring in a thread's own table under the leader's ring's number is listed too, and its
// table of registered files is not lost to the leader's ring, which has none.
func TestFDsNeverMergesTwoRings(t *testing.T) {
	root := t.TempDir()
	for tid, files := range map[string]string{"": "0", "44": "1"} {
		base := filepath.Join(root, "42")
		if tid != "" {
			base = filepath.Join(root, "42", "task", tid)
		}
		for _, d := range []string{"fd", "fdinfo"} {
			if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(RingTarget, filepath.Join(base, "fd", "7")); err != nil {
			t.Fatal(err)
		}
		info := "pos:\t0\nflags:\t02000002\nUserFiles:\t" + files + "\n"
		if err := os.WriteFile(filepath.Join(base, "fdinfo", "7"), []byte(info), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := NewFS(root)
	fs.sameFiles = func(pid, tid int) (bool, error) { return false, nil }
	fs.anon = nil
	fds, err := fs.FDs(42)
	if err != nil {
		t.Fatal(err)
	}
	rings, registered := 0, 0
	for _, fd := range fds {
		if fd.Num == 7 && fd.Ring {
			rings++
			if fd.RegisteredFiles {
				registered++
			}
		}
	}
	if rings != 2 || registered != 1 {
		t.Errorf("fd 7: %d rings listed, %d with registered files; want 2 and 1: %+v", rings, registered, fds)
	}
}
