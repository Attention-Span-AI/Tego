// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestMapsOnTheRealKernel: this process's own smaps, with a shared writable mapping of a file whose name has spaces,
// a shared mapping that is read-only now of a file opened for writing (mprotect could make it writable with no open
// the plane decides), a shared read-only mapping of a file opened read-only (it cannot be), and a private mapping of
// a deleted file.
func TestMapsOnTheRealKernel(t *testing.T) {
	dir := t.TempDir()
	paths := map[string]string{}
	for _, n := range []string{"a b  c.db", "maywrite", "readonly", "gone"} {
		paths[n] = filepath.Join(dir, n)
		if err := os.WriteFile(paths[n], make([]byte, 4096), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mapFile := func(name string, flag, prot, kind int) {
		f, err := os.OpenFile(paths[name], flag, 0)
		if err != nil {
			t.Fatal(err)
		}
		m, err := syscall.Mmap(int(f.Fd()), 0, 4096, prot, kind)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = syscall.Munmap(m) })
		_ = f.Close() // the mapping outlives its descriptor
	}
	mapFile("a b  c.db", os.O_RDWR, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	mapFile("maywrite", os.O_RDWR, syscall.PROT_READ, syscall.MAP_SHARED)
	mapFile("readonly", os.O_RDONLY, syscall.PROT_READ, syscall.MAP_SHARED)
	mapFile("gone", os.O_RDONLY, syscall.PROT_READ, syscall.MAP_PRIVATE)
	_ = os.Remove(paths["gone"])
	ms, err := NewFS("").Maps(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*Mapping{}
	for i := range ms {
		got[ms[i].Path] = &ms[i]
	}
	for name, want := range map[string]bool{"a b  c.db": true, "maywrite": true, "readonly": false, "gone": false} {
		m := got[paths[name]]
		if m == nil {
			t.Errorf("%s: not listed among %d mappings", name, len(ms))
			continue
		}
		if m.SharedWritable != want {
			t.Errorf("%s: SharedWritable %v, want %v", name, m.SharedWritable, want)
		}
	}
}

// TestFDsSaysATruncatedListing: a process holding more descriptors than FDs reads gets the first maxFDs and an error
// that says the rest went unread, never a list that passes for whole.
func TestFDsSaysATruncatedListing(t *testing.T) {
	root := t.TempDir()
	fdDir := filepath.Join(root, "42", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range maxFDs + 1 {
		if err := os.Symlink("/home/u/f"+strconv.Itoa(i), filepath.Join(fdDir, strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	fds, err := NewFS(root).FDs(42)
	if len(fds) != maxFDs || !errors.Is(err, ErrTruncated) {
		t.Fatalf("FDs = %d descriptors, %v; want %d and ErrTruncated", len(fds), err, maxFDs)
	}
	if err := os.Remove(filepath.Join(fdDir, "0")); err != nil {
		t.Fatal(err)
	}
	if fds, err := NewFS(root).FDs(42); len(fds) != maxFDs || err != nil {
		t.Fatalf("at the cap: %d descriptors, %v", len(fds), err)
	}
}

// TestNoPathIsTheKernelsInternalDevices: a mapping or a descriptor is on no path exactly when its device is one of
// the kernel-internal superblocks' devices tego probed, whatever /proc calls it and whichever mount shows it: the AIO
// ring, hugetlb and shared anonymous memory and a System V segment are, a file a process named /SYSVfake is not, nor
// is a file of a filesystem no mount table shows (a detached mount, a chroot's view, a btrfs subvolume's device). A
// file mapped both ways is a path. With no internal devices known, nothing is taken for no path (fail closed).
func TestNoPathIsTheKernelsInternalDevices(t *testing.T) {
	internal := map[devID]bool{{0, 1}: true, {0, 15}: true, {0, 16}: true}
	maps := "7f00-7f10 rw-s 00000000 00:0f 17903792 /[aio] (deleted)\n" +
		"7f10-7f20 rw-s 00000000 00:10 4 /anon_hugepage (deleted)\n" +
		"7f20-7f30 rw-s 00000000 00:01 7 /dev/zero (deleted)\n" +
		"7f30-7f40 rw-s 00000000 00:01 8 /SYSV00000001 (deleted)\n" +
		"7f40-7f50 rw-s 00000000 08:01 9 /SYSVfake\n" +
		"7f50-7f60 rw-s 00000000 00:17 10 /dev/shm/x\n" +
		"7f60-7f70 rw-s 00000000 00:21 11 /home/u/db\n" +
		"7f70-7f80 r--s 00000000 00:01 12 /both\n" +
		"7f80-7f90 r--s 00000000 08:01 12 /both\n" +
		"7f90-7fa0 rw-s 00000000 zz:01 13 /baddev\n"
	// The device field is hexadecimal: 00:0f is 0:15, 00:10 0:16. 00:21 is a btrfs subvolume's device, which no
	// mountinfo line shows, and is a path all the same.
	got, _ := parseMappings([]byte(maps), internal, nil)
	want := map[string]bool{"/[aio]": true, "/anon_hugepage": true, "/dev/zero": true, "/SYSV00000001": true,
		"/SYSVfake": false, "/dev/shm/x": false, "/home/u/db": false, "/both": false, "/baddev": false}
	for _, m := range got {
		w, ok := want[m.Path]
		if !ok {
			t.Errorf("unexpected mapping %+v", m)
			continue
		}
		if m.NoPath != w {
			t.Errorf("%s: NoPath %v, want %v", m.Path, m.NoPath, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d mappings, want %d: %+v", len(got), len(want), got)
	}
	unknown, _ := parseMappings([]byte(maps), nil, nil)
	for _, m := range unknown {
		if m.NoPath {
			t.Errorf("%s with no internal devices known: NoPath", m.Path)
		}
	}

	// Descriptors, over a fake /proc whose fd links name real files: NoPath follows the device a stat through the
	// link reads, never the name nor a mount table.
	dir := t.TempDir()
	held := filepath.Join(dir, "held.db")
	if err := os.WriteFile(held, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(held, &st); err != nil {
		t.Fatal(err)
	}
	heldDev := devOf(uint64(st.Dev)) //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
	root := t.TempDir()
	fdDir := filepath.Join(root, "42", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, target := range map[string]string{"3": held, "4": filepath.Join(dir, "closed-since"), "5": "socket:[77]"} {
		if err := os.Symlink(target, filepath.Join(fdDir, n)); err != nil {
			t.Fatal(err)
		}
	}
	read := func(internal map[devID]bool) map[int]FD {
		t.Helper()
		fs := NewFS(root)
		fs.internal = func() map[devID]bool { return internal }
		fds, err := fs.FDs(42)
		if err != nil {
			t.Fatal(err)
		}
		out := map[int]FD{}
		for _, fd := range fds {
			out[fd.Num] = fd
		}
		return out
	}
	for _, c := range []struct {
		name     string
		internal map[devID]bool
		want3    bool
	}{
		{"its device is internal", map[devID]bool{heldDev: true}, true},
		{"its device is not", map[devID]bool{{heldDev.major, heldDev.minor + 1}: true}, false},
		{"no internal devices known", nil, false},
	} {
		fds := read(c.internal)
		if fds[3].NoPath != c.want3 {
			t.Errorf("%s: %s NoPath %v, want %v", c.name, held, fds[3].NoPath, c.want3)
		}
		if fds[4].NoPath || fds[5].NoPath {
			t.Errorf("%s: a descriptor that cannot be stat'ed, or a socket, is NoPath: %+v %+v", c.name, fds[4], fds[5])
		}
	}
	if (&FS{root: root}).internalDevs() != nil {
		t.Error("an FS with no probe has internal devices")
	}

	// The probe's helpers: each huge page size's MFD_HUGE_* flag, and the device of a mapping found by its address.
	hp := t.TempDir()
	for _, n := range []string{"hugepages-2048kB", "hugepages-1048576kB", "hugepages-3000kB", "other"} {
		if err := os.Mkdir(filepath.Join(hp, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := hugePageFlags(hp), []int{0, unix.MFD_HUGE_1GB, unix.MFD_HUGE_2MB}; !slices.Equal(got, want) {
		t.Errorf("hugePageFlags = %#x, want %#x", got, want)
	}
	if got := hugePageFlags(filepath.Join(hp, "none")); !slices.Equal(got, []int{0}) {
		t.Errorf("hugePageFlags with no sysfs = %v, want the default size only", got)
	}
	if got := devsMappedAt([]byte(maps), []uint64{0x7f00, 0x7f20, 0x7f90, 0x1234}); !slices.Equal(got, []devID{{0, 15}, {0, 1}}) {
		t.Errorf("devsMappedAt = %v", got)
	}
}

// TestNoPathOnTheRealKernel: this process's own descriptors and mappings. A memfd, a hugetlb memfd, shared anonymous
// memory (which the kernel backs with a /dev/zero file on its internal shmem mount) and the AIO ring are on the
// kernel-internal superblocks the probe found; a regular file, mapped and held, is on a path, and so is a file of a
// tmpfs mounted by name (/dev/shm), a superblock of the same filesystem type as the internal shmem one.
func TestNoPathOnTheRealKernel(t *testing.T) {
	file := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(file, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(file, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	fileMap, err := syscall.Mmap(int(f.Fd()), 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(fileMap) })
	mfd, err := unix.MemfdCreate("tego-nopath", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(mfd) })
	if err := unix.Ftruncate(mfd, 4096); err != nil {
		t.Fatal(err)
	}
	memMap, err := syscall.Mmap(mfd, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(memMap) })
	anonMap, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(anonMap) })
	var aioCtx uintptr
	aio := true
	if _, _, e := syscall.Syscall(unix.SYS_IO_SETUP, 8, uintptr(unsafe.Pointer(&aioCtx)), 0); e != 0 {
		t.Logf("io_setup: %v; the AIO ring is not checked", e)
		aio = false
	} else {
		t.Cleanup(func() { _, _, _ = syscall.Syscall(unix.SYS_IO_DESTROY, aioCtx, 0, 0) })
	}
	huge, err := unix.MemfdCreate("tego-nopath-huge", unix.MFD_CLOEXEC|unix.MFD_HUGETLB)
	if err != nil {
		t.Logf("memfd_create(MFD_HUGETLB): %v; the hugetlb descriptor is not checked", err)
		huge = -1
	} else {
		t.Cleanup(func() { _ = unix.Close(huge) })
	}
	shm := -1
	if sf, err := os.CreateTemp("/dev/shm", "tego-nopath-"); err == nil {
		t.Cleanup(func() { _ = sf.Close(); _ = os.Remove(sf.Name()) })
		shm = int(sf.Fd())
	} else {
		t.Logf("/dev/shm: %v; a tmpfs mounted by name is not checked", err)
	}
	if len(internalDevices()) == 0 {
		t.Fatal("the probe found no kernel-internal superblock on this kernel")
	}
	fs := NewFS("")
	ms, err := fs.Maps(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	maps := map[string]Mapping{}
	for _, m := range ms {
		maps[m.Path] = m
	}
	want := map[string]bool{file: false, "/memfd:tego-nopath": true, "/dev/zero": true}
	if aio {
		want["/[aio]"] = true
	}
	for p, w := range want {
		m, ok := maps[p]
		if !ok {
			t.Errorf("%s: not among this process's %d mapped files", p, len(ms))
			continue
		}
		if m.NoPath != w {
			t.Errorf("%s: NoPath %v, want %v", p, m.NoPath, w)
		}
	}
	fds, err := fs.FDs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]FD{}
	for _, fd := range fds {
		seen[fd.Num] = fd
	}
	if fd := seen[int(f.Fd())]; fd.Target != file || fd.NoPath {
		t.Errorf("the regular file's descriptor: %+v, want %s on a path", fd, file)
	}
	if fd := seen[mfd]; !strings.HasPrefix(fd.Target, "/memfd:tego-nopath") || !fd.NoPath {
		t.Errorf("the memfd's descriptor: %+v, want no path", fd)
	}
	if fd := seen[huge]; huge >= 0 && (!strings.HasPrefix(fd.Target, "/memfd:tego-nopath-huge") || !fd.NoPath) {
		t.Errorf("the hugetlb memfd's descriptor: %+v, want no path", fd)
	}
	if fd := seen[shm]; shm >= 0 && (!strings.HasPrefix(fd.Target, "/dev/shm/tego-nopath-") || fd.NoPath) {
		t.Errorf("the /dev/shm file's descriptor: %+v, want a path", fd)
	}
}
