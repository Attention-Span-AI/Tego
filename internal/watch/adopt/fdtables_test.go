// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFDsSaysADescriptorItCannotName: a descriptor whose /proc link cannot be read for a reason other than its closing
// (a name longer than PATH_MAX gives ENAMETOOLONG; here a link that is no link, EINVAL), or whose fdinfo cannot be
// read, is listed as Unread, never left out: what it holds, and how it was opened, is not known, so its process is
// counted unread rather than taken as holding only the rest.
func TestFDsSaysADescriptorItCannotName(t *testing.T) {
	root := t.TempDir()
	fdDir := filepath.Join(root, "42", "fd")
	infoDir := filepath.Join(root, "42", "fdinfo")
	for _, d := range []string{fdDir, infoDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	held := filepath.Join(t.TempDir(), "held")
	if err := os.WriteFile(held, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"3", "5"} {
		if err := os.Symlink(held, filepath.Join(fdDir, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(fdDir, "4"), nil, 0o600); err != nil { // readlink: EINVAL
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(infoDir, "3"), []byte("pos:\t0\nflags:\t02\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(infoDir, "5"), 0o755); err != nil { // read: EISDIR
		t.Fatal(err)
	}
	fds, err := NewFS(root).FDs(42)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]FD{}
	for _, fd := range fds {
		got[fd.Num] = fd
	}
	if fd, ok := got[3]; !ok || fd.Unread || fd.Target != held || fd.Flags != 0o2 {
		t.Errorf("a descriptor /proc names: %+v (listed %v), want %s, flags 02, not Unread", fd, ok, held)
	}
	if fd, ok := got[4]; !ok || !fd.Unread {
		t.Errorf("a descriptor whose link cannot be read: %+v (listed %v), want it listed Unread", fd, ok)
	}
	if fd, ok := got[5]; !ok || !fd.Unread {
		t.Errorf("a descriptor whose fdinfo cannot be read: %+v (listed %v), want it listed Unread", fd, ok)
	}
}

// TestFDsSaysADescriptorWhoseNameIsTooLong: on the kernel, a file open at a path longer than PATH_MAX has a
// /proc/<pid>/fd link readlink refuses (ENAMETOOLONG); FDs lists it as Unread.
func TestFDsSaysADescriptorWhoseNameIsTooLong(t *testing.T) {
	dir, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir) //nolint:errcheck // the test's own descriptor
	comp := strings.Repeat("d", 200)
	for range 25 { // 25 * 201 bytes: past PATH_MAX (4096)
		if err := unix.Mkdirat(dir, comp, 0o700); err != nil {
			t.Fatal(err)
		}
		next, err := unix.Openat(dir, comp, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(dir)
		dir = next
	}
	fd, err := unix.Openat(dir, "held", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // the test's own descriptor
	if _, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); !errors.Is(err, unix.ENAMETOOLONG) {
		t.Skipf("readlink of a descriptor past PATH_MAX: %v, want ENAMETOOLONG (this kernel names it)", err)
	}
	fds, err := NewFS("").FDs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(fds, func(f FD) bool { return f.Num == fd })
	if i < 0 || !fds[i].Unread {
		t.Fatalf("a descriptor open at a path past PATH_MAX: listed %v (%+v), want it listed Unread", i >= 0, fds)
	}
}

// TestFDsReadsEveryTasksTable: a thread can hold a descriptor table of its own (unshare CLONE_FILES), listed only
// under /proc/<pid>/task/<tid>/fd, while /proc/<pid>/fd is the leader's.
// FDs lists, besides the leader's, each task's table the kernel does not say is the leader's (kcmp KCMP_FILES; one it
// cannot compare is read too), each descriptor once; a task directory that cannot be listed is an error, with what
// was read.
func TestFDsReadsEveryTasksTable(t *testing.T) {
	root := t.TempDir()
	held := t.TempDir()
	link := func(dir, n, target string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	// Each file exists, so each descriptor has an identity (FD.ID): only a file with one is merged with its copy.
	file := func(name string) string {
		p := filepath.Join(held, name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link(filepath.Join(root, "42", "fd"), "3", file("leader"))
	task := func(tid string) string { return filepath.Join(root, "42", "task", tid, "fd") }
	link(task("42"), "3", file("leader"))
	link(task("43"), "3", file("leader"))
	link(task("43"), "4", file("shared-table-only"))  // listed under a task that shares the leader's table: never read
	link(task("44"), "3", file("leader"))             // the same descriptor in a copy of the table: listed once
	link(task("44"), "5", file("own-table"))          // a table of its own
	link(task("45"), "6", file("uncomparable-table")) // kcmp could not say: read
	fs := NewFS(root)
	asked := map[int]bool{}
	fs.sameFiles = func(pid, tid int) (bool, error) {
		asked[tid] = true
		switch tid {
		case 43:
			return true, nil
		case 44:
			return false, nil
		}
		return false, unix.ENOSYS
	}
	fds, err := fs.FDs(42)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, fd := range fds {
		got = append(got, strconv.Itoa(fd.Num)+" "+filepath.Base(fd.Target))
	}
	slices.Sort(got)
	if want := []string{"3 leader", "5 own-table", "6 uncomparable-table"}; !slices.Equal(got, want) {
		t.Errorf("FDs over the tasks' tables = %q, want %q", got, want)
	}
	if asked[42] {
		t.Error("the leader's own task was compared with itself")
	}
	if err := os.Chmod(filepath.Join(root, "42", "task"), 0o000); err == nil && os.Geteuid() != 0 {
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "42", "task"), 0o755) })
		fds, err := fs.FDs(42)
		if err == nil || errors.Is(err, ErrGone) || len(fds) != 1 {
			t.Errorf("an unlistable task directory: %d descriptors, %v; want the leader's and an error", len(fds), err)
		}
	}
	// A /proc with no task directory (the process ended since its fd listing) has no other tables.
	if err := os.Chmod(filepath.Join(root, "42", "task"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "42", "task")); err != nil {
		t.Fatal(err)
	}
	if fds, err := fs.FDs(42); err != nil || len(fds) != 1 {
		t.Errorf("no task directory: %d descriptors, %v; want the leader's alone", len(fds), err)
	}
}

// TestFDsReadsAThreadsOwnTableOnTheKernel: a thread of this process unshares its descriptor table and opens a file
// in it alone; FDs of this process lists that descriptor, which /proc/<pid>/fd does not.
func TestFDsReadsAThreadsOwnTableOnTheKernel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "thread-only")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	type opened struct {
		fd, tid int
		err     error
	}
	ready, done := make(chan opened), make(chan struct{})
	defer close(done)
	var thread func()
	thread = func() {
		// The thread keeps its own table until it exits: it is never unlocked, so the runtime ends it with the goroutine.
		runtime.LockOSThread()
		if unix.Gettid() == unix.Getpid() {
			// The leader: unsharing here would give the leader the new table. Hold it, so the next goroutine runs on
			// another thread.
			go thread()
			<-done
			return
		}
		if err := unix.Unshare(unix.CLONE_FILES); err != nil {
			ready <- opened{err: err}
			return
		}
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		ready <- opened{fd: fd, tid: unix.Gettid(), err: err}
		<-done
	}
	go thread()
	o := <-ready
	if o.err != nil {
		t.Skipf("unshare(CLONE_FILES) in a thread: %v", o.err)
	}
	if target, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(o.fd)); target == p {
		t.Fatalf("fd %d of the thread's own table is the leader's too", o.fd)
	}
	fds, err := NewFS("").FDs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(fds, func(fd FD) bool { return fd.Num == o.fd && fd.Target == p }) {
		t.Errorf("fd %d (%s), held in thread %d's own table, is not listed", o.fd, p, o.tid)
	}
}

// TestFDsCapsTheMergedListing: the cap counts the descriptors listed, after a copied table's entries are merged with
// the leader's. Counting what a table read before the merge made a thread that copied a table of 3000 descriptors
// (unshare(CLONE_FILES)) a truncated listing, so the process was counted unread although every descriptor was read,
// and the error said 4096 were. Two tables whose descriptors differ are
// still capped.
func TestFDsCapsTheMergedListing(t *testing.T) {
	n := maxFDs * 3 / 4
	held := t.TempDir()
	for i := range n {
		if err := os.WriteFile(filepath.Join(held, strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	listing := func(t *testing.T, offset int) ([]FD, error) {
		t.Helper()
		root := t.TempDir()
		for _, d := range []string{filepath.Join(root, "42", "fd"), filepath.Join(root, "42", "task", "44", "fd")} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for i := range n {
			target := filepath.Join(held, strconv.Itoa(i))
			if err := os.Symlink(target, filepath.Join(root, "42", "fd", strconv.Itoa(i))); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, "42", "task", "44", "fd", strconv.Itoa(i+offset))); err != nil {
				t.Fatal(err)
			}
		}
		fs := NewFS(root)
		fs.internal = func() map[devID]bool { return nil }
		fs.mounts = nil
		fs.sameFiles = func(pid, tid int) (bool, error) { return false, nil }
		return fs.FDs(42)
	}
	t.Run("a copied table", func(t *testing.T) {
		if fds, err := listing(t, 0); len(fds) != n || err != nil {
			t.Errorf("FDs = %d descriptors, %v; want the %d of the leader's table, each once, and no error", len(fds), err, n)
		}
	})
	t.Run("two tables past the cap", func(t *testing.T) {
		fds, err := listing(t, n)
		if len(fds) != maxFDs || !errors.Is(err, ErrTruncated) || !strings.Contains(err.Error(), strconv.Itoa(maxFDs)+" read") {
			t.Errorf("FDs = %d descriptors, %v; want %d and ErrTruncated saying so", len(fds), err, maxFDs)
		}
	})
}
