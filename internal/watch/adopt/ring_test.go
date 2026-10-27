// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestRingRegisteredFilesIsTheFdinfosTable: an io_uring descriptor holds registered files when its fdinfo's UserFiles
// line counts a table, of any size (a sparse one is filled by later updates); one with no such line after the reads
// FDs makes (the kernel prints the ring's state only when it takes the ring's lock at once, and no kernel before 5.9
// prints it) may: fail-closed.
func TestRingRegisteredFilesIsTheFdinfosTable(t *testing.T) {
	const head = "pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t2077\nSqMask:\t0x0\n"
	none := []byte("pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t2077\n") // the lock was busy
	for _, c := range []struct {
		name   string
		reads  [][]byte
		err    error
		want   bool
		nreads int
	}{
		{"no table", [][]byte{[]byte(head + "UserFiles:\t0\nUserBufs:\t0\n")}, nil, false, 1},
		{"a file registered", [][]byte{[]byte(head + "UserFiles:\t1\n    0: /home/u/.netrc\nUserBufs:\t0\n")}, nil, true, 1},
		{"a sparse table", [][]byte{[]byte(head + "UserFiles:\t8\nUserBufs:\t0\n")}, nil, true, 1},
		{"busy, then read", [][]byte{none, []byte(head + "UserFiles:\t0\n")}, nil, false, 2},
		{"never read", [][]byte{none, none, none}, nil, true, ringReadTries},
		{"an unreadable fdinfo", [][]byte{nil, nil, nil}, errors.New("EACCES"), true, ringReadTries},
		{"a line it cannot read", [][]byte{[]byte("UserFiles:\tx\n"), []byte("UserFiles:\tx\n"), []byte("UserFiles:\tx\n")}, nil, true, ringReadTries},
	} {
		reads := 1
		got := ringRegisteredFiles(c.reads[0], c.err, func() ([]byte, error) {
			b := c.reads[reads]
			reads++
			return b, c.err
		})
		if got != c.want || reads != c.nreads {
			t.Errorf("%s: registered files %v after %d reads, want %v after %d", c.name, got, reads, c.want, c.nreads)
		}
	}
}

// TestMapsNamesEachRingItMaps: an io_uring instance's mapping is one Mapping per instance, with the device and inode
// its smaps line gives, so the count can tell a ring the process still holds a descriptor of from one it does not.
func TestMapsNamesEachRingItMaps(t *testing.T) {
	smaps := "7f0000000000-7f0000001000 rw-s 00000000 00:0f 2077                       anon_inode:[io_uring]\n" +
		"VmFlags: rd wr sh mr mw me ms\n" +
		"7f0000001000-7f0000002000 rw-s 10000000 00:0f 2077                       anon_inode:[io_uring]\n" +
		"VmFlags: rd wr sh mr mw me ms\n" +
		"7f0000002000-7f0000003000 rw-s 00000000 00:0f 2078                       anon_inode:[io_uring]\n" +
		"VmFlags: rd wr sh mr mw me ms\n" +
		"7f0000003000-7f0000004000 r--p 00000000 08:01 12                         /usr/lib/libc.so.6\n" +
		"VmFlags: rd mr mw me\n"
	got, truncated := parseMappings([]byte(smaps), nil, nil)
	if truncated {
		t.Fatal("truncated")
	}
	var rings []FileID
	for _, m := range got {
		if m.Ring {
			if m.Path != RingTarget || len(m.IDs) != 1 || m.SharedWritable || m.NoPath {
				t.Errorf("a ring's mapping %+v, want Path %s and one ID", m, RingTarget)
			}
			rings = append(rings, m.IDs...)
		}
	}
	dev := unix.Mkdev(0, 0xf)
	if want := []FileID{{Dev: dev, Ino: 2077}, {Dev: dev, Ino: 2078}}; !slices.Equal(rings, want) {
		t.Errorf("rings %v, want %v (one per instance)", rings, want)
	}
	if !slices.ContainsFunc(got, func(m Mapping) bool { return m.Path == "/usr/lib/libc.so.6" && !m.Ring }) {
		t.Errorf("the library is not listed beside the rings: %+v", got)
	}
}

// TestMapsCarryTheMappedFilesInodes: each mapped file carries the device and inode its map_files entry gives (here the
// name function's), each once, so the count can find a keyed inode under a name no rule names; a mapping whose entry
// could not be read gives none.
func TestMapsCarryTheMappedFilesInodes(t *testing.T) {
	smaps := "7f0000000000-7f0000001000 r--s 00000000 08:01 9   /home/u/work/n\n" +
		"7f0000001000-7f0000002000 r--s 00001000 08:01 9   /home/u/work/n\n" +
		"7f0000002000-7f0000003000 r--s 00000000 08:01 12  /home/u/other\n"
	ids := map[string]FileID{"7f0000000000-7f0000001000": {Dev: 8<<8 | 1, Ino: 9}, "7f0000001000-7f0000002000": {Dev: 8<<8 | 1, Ino: 9}}
	got, _ := parseMappings([]byte(smaps), nil, func(rng, path string, deleted bool) naming {
		id, ok := ids[rng]
		if !ok {
			return naming{unnamed: true}
		}
		return naming{id: id, idKnown: true}
	})
	want := map[string][]FileID{"/home/u/work/n": {{Dev: 8<<8 | 1, Ino: 9}}, "/home/u/other": nil}
	for _, m := range got {
		if w, ok := want[m.Path]; !ok || !slices.Equal(m.IDs, w) {
			t.Errorf("%s: IDs %v, want %v", m.Path, m.IDs, w)
		}
	}
	if len(got) != 2 {
		t.Errorf("mappings %+v, want two files", got)
	}
}

// TestRingOnTheRealKernel: on this kernel, FDs marks an io_uring descriptor a Ring, with RegisteredFiles once a file is
// registered with it (and the file closed, so no descriptor of it is left), and Maps names the ring's mapping with the
// descriptor's own device and inode.
func TestRingOnTheRealKernel(t *testing.T) {
	var params [120]byte // struct io_uring_params
	ring, _, e := syscall.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	if e != 0 {
		t.Skipf("io_uring_setup: %v (io_uring is disabled here: kernel.io_uring_disabled, or a seccomp filter)", e)
	}
	t.Cleanup(func() { _ = unix.Close(int(ring)) })
	m, err := unix.Mmap(int(ring), 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		t.Fatalf("mmap the ring: %v", err)
	}
	t.Cleanup(func() { _ = unix.Munmap(m) })
	fs := NewFS("")
	ringFD := func() FD {
		t.Helper()
		fds, err := fs.FDs(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(fds, func(fd FD) bool { return fd.Num == int(ring) })
		if i < 0 {
			t.Fatalf("descriptor %d is not listed", ring)
		}
		return fds[i]
	}
	// The descriptor's ID is the ring's inode, unless the kernel puts every ring on the shared anonymous inode (5.15
	// does), where it has none (TestRingIdentityOnTheRealKernel); the mapping names the inode either way.
	own := fdID(t, int(ring))
	want := own
	if anon, ok := sharedAnonInode(); !ok || anon == own {
		want = FileID{}
	}
	fd := ringFD()
	if !fd.Ring || fd.RegisteredFiles || fd.ID != want || fd.Target != RingTarget {
		t.Fatalf("a ring with no file registered: %+v, want Ring, no RegisteredFiles, ID %v", fd, want)
	}
	ms, _ := fs.Maps(os.Getpid())
	if !slices.ContainsFunc(ms, func(m Mapping) bool { return m.Ring && slices.Equal(m.IDs, []FileID{own}) }) {
		t.Errorf("the ring's mapping is not listed with the ring's inode %v", own)
	}
	file, err := os.Open(filepath.Join(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	files := []int32{int32(file.Fd())}
	if _, _, e := syscall.Syscall6(unix.SYS_IO_URING_REGISTER, ring, 2 /* IORING_REGISTER_FILES */, uintptr(unsafe.Pointer(&files[0])), 1, 0, 0); e != 0 {
		t.Fatalf("IORING_REGISTER_FILES: %v", e)
	}
	_ = file.Close()
	if fd := ringFD(); !fd.RegisteredFiles {
		t.Errorf("a ring holding a registered file: %+v, want RegisteredFiles", fd)
	}
}

// TestFDsCarryTheHeldFilesInode: FDs gives each held file its device and inode, as a stat of the file gives them, so
// the count can find a keyed inode under a name no rule names (a hard link).
func TestFDsCarryTheHeldFilesInode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	fds, err := NewFS("").FDs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(fds, func(fd FD) bool { return fd.Num == int(f.Fd()) })
	if i < 0 {
		t.Fatal("the file's descriptor is not listed")
	}
	if want := (FileID{Dev: uint64(st.Dev), Ino: st.Ino}); fds[i].ID != want { //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
		t.Errorf("descriptor of %s: ID %v, want %v", p, fds[i].ID, want)
	}
}

// ringSetup makes an io_uring instance in the test's own process, or skips where io_uring is disabled.
func ringSetup(t *testing.T) int {
	t.Helper()
	var params [120]byte // struct io_uring_params
	ring, _, e := syscall.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	if e != 0 {
		t.Skipf("io_uring_setup: %v (io_uring is disabled here: kernel.io_uring_disabled, or a seccomp filter)", e)
	}
	t.Cleanup(func() { _ = unix.Close(int(ring)) })
	return int(ring)
}

// fdID is the device and inode a stat of descriptor fd gives, as FDs writes them.
func fdID(t *testing.T, fd int) FileID {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	dev := uint64(st.Dev) //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
	return FileID{Dev: unix.Mkdev(unix.Major(dev), unix.Minor(dev)), Ino: st.Ino}
}

// TestARingOnTheSharedAnonInodeHasNoIdentity: a kernel whose io_uring makes its instances with no inode of their own
// gives every ring the inode an eventfd has (fs/anon_inodes.c), so a ring's device and inode cannot tell a ring the
// process holds a descriptor of from another it only maps; FDs then gives the ring no ID, and the count takes a mapped
// ring as one it holds no descriptor of (unread), never as the one it does. Here the kernel's shared inode is stood in
// for by the ring's own; a probe that could not learn it leaves every ring with no ID too, and one that learnt
// another inode keeps it.
func TestARingOnTheSharedAnonInodeHasNoIdentity(t *testing.T) {
	ring := ringSetup(t)
	own := fdID(t, ring)
	for _, c := range []struct {
		name string
		anon func() (FileID, bool)
		want FileID
	}{
		{"the ring's inode is the shared one", func() (FileID, bool) { return own, true }, FileID{}},
		{"the shared inode is unknown", func() (FileID, bool) { return FileID{}, false }, FileID{}},
		{"no probe", nil, FileID{}},
		{"the ring has its own inode", func() (FileID, bool) { return FileID{Dev: own.Dev, Ino: own.Ino + 1}, true }, own},
	} {
		fs := NewFS("")
		fs.anon = c.anon
		fds, err := fs.FDs(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(fds, func(fd FD) bool { return fd.Num == ring })
		if i < 0 {
			t.Fatalf("descriptor %d is not listed", ring)
		}
		if !fds[i].Ring || fds[i].ID != c.want {
			t.Errorf("%s: %+v, want a Ring with ID %v", c.name, fds[i], c.want)
		}
	}
}

// TestRingIdentityOnTheRealKernel: on this kernel, two io_uring instances get distinct IDs exactly when each has an
// inode of its own (not the eventfd's shared one); where they share it, FDs gives neither an ID. The test logs which
// the kernel does.
func TestRingIdentityOnTheRealKernel(t *testing.T) {
	a, b := ringSetup(t), ringSetup(t)
	ev, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(ev) })
	ida, idb, ide := fdID(t, a), fdID(t, b), fdID(t, ev)
	shared := ida == ide
	t.Logf("rings %v and %v, an eventfd %v: the rings are on the shared anonymous inode: %v", ida, idb, ide, shared)
	if shared != (idb == ide) || shared != (ida == idb) {
		t.Fatalf("two rings, one on the shared inode and one not: %v %v (eventfd %v)", ida, idb, ide)
	}
	fds, err := NewFS("").FDs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		fd int
		id FileID
	}{{a, ida}, {b, idb}} {
		i := slices.IndexFunc(fds, func(fd FD) bool { return fd.Num == c.fd })
		if i < 0 {
			t.Fatalf("descriptor %d is not listed", c.fd)
		}
		want := c.id
		if shared {
			want = FileID{}
		}
		if !fds[i].Ring || fds[i].ID != want {
			t.Errorf("ring %d: %+v, want a Ring with ID %v", c.fd, fds[i], want)
		}
	}
}
