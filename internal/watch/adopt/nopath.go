// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// What "no path" is (FD.NoPath, Mapping.NoPath). The decision plane passes an object as no fs decision when its
// superblock is SB_NOUSER, its inode is S_PRIVATE, or its dentry is a pseudo one (its own parent) on an MNT_INTERNAL
// mount (bpf/decide.bpf.c tego_no_path), and only then: a file of a real filesystem reached through a detached mount,
// a lazily unmounted one or from a chroot is decided like any other. The files of the first kind an agent maps or
// holds by a name with a leading slash live on a few superblocks the kernel mounts for itself (kern_mount), which no
// mount of any namespace shows and none can clone (may_copy_tree refuses a mount whose namespace is the internal
// one): the shmem mount behind memfds, System V segments, shared anonymous memory and most GPU drivers' objects, the
// AIO ring's, and hugetlbfs' one per huge page size. A device number names one superblock machine-wide, so tego
// learns those devices in its own process (internalDevices), by making one object of each kind and reading its
// device, and a held file is NoPath exactly when its device is one of them. Every other file, whatever /proc calls it
// and whichever mount it was reached through, is a path: counted by its name and its aliases, or, when its name is no
// path of it in tego's namespace (held through a detached or lazily unmounted mount, names.go), counted unread. A
// pseudo file of an internal superblock tego did not probe (a dma-buf, secretmem, a driver's own shmem mount) is on a
// mount no line of tego's mountinfo shows, so it is counted unread too: of the files /proc lists, the count can be
// high, never low.
//
// Rejected: a name list (/memfd:, /SYSV), which missed the AIO ring and hugetlb memory and took a file named /SYSVx on
// a mounted filesystem for none; and reading the holder's /proc/<pid>/mountinfo, which shows only the mounts under
// the holder's root and none that is detached, so a file held from a chroot, through a lazily unmounted mount or a
// detached bind (and on btrfs, whose st_dev is a subvolume's device that no mountinfo line shows) was dropped from
// the count though the plane decides it.

// devID is a device number as its major and minor: a stat's st_dev, an smaps line's dev field.
type devID struct{ major, minor uint32 }

func devOf(dev uint64) devID { return devID{unix.Major(dev), unix.Minor(dev)} }

// internalDevices is the set of the kernel-internal superblocks' devices this kernel showed tego (probeInternalDevices),
// probed once per process.
var internalDevices = sync.OnceValue(probeInternalDevices)

// probeInternalDevices makes, in tego's own process, one object of each kernel-internal kind an agent can hold or map
// and reads its device: a memfd (the shmem mount), a memfd of each huge page size (hugetlbfs' internal mounts, which
// MAP_HUGETLB memory and SHM_HUGETLB segments use too), shared anonymous memory (the shmem mount's /dev/zero file)
// and the AIO ring (the aio mount). An object the kernel refuses to make (no hugetlb, an exhausted aio-max-nr) adds no
// device, so its kind is counted as a path: fail-closed. Each object is released before it returns.
func probeInternalDevices() map[devID]bool {
	out := map[devID]bool{}
	add := func(fd *sys.FD, err error) {
		if err != nil {
			return
		}
		defer func() { _ = fd.Close() }() // the probe's own memfd
		var st unix.Stat_t
		if fd.Fstat(&st) == nil {
			out[devOf(uint64(st.Dev))] = true //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
		}
	}
	add(sys.Own(unix.MemfdCreate("tego-nopath-probe", unix.MFD_CLOEXEC)))
	for _, huge := range hugePageFlags("/sys/kernel/mm/hugepages") {
		add(sys.Own(unix.MemfdCreate("tego-nopath-probe", unix.MFD_CLOEXEC|unix.MFD_HUGETLB|huge)))
	}
	var at []uint64
	if b, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED|unix.MAP_ANONYMOUS); err == nil {
		at = append(at, uint64(uintptr(unsafe.Pointer(&b[0]))))
		defer unix.Munmap(b) //nolint:errcheck // the probe's own page
	}
	var aio uintptr // io_setup's context is the address of the ring it maps
	if _, _, e := unix.Syscall(unix.SYS_IO_SETUP, 1, uintptr(unsafe.Pointer(&aio)), 0); e == 0 {
		at = append(at, uint64(aio))
		defer unix.Syscall(unix.SYS_IO_DESTROY, aio, 0, 0) //nolint:errcheck // the probe's own ring
	}
	if len(at) > 0 {
		if b, err := os.ReadFile("/proc/self/maps"); err == nil {
			for _, d := range devsMappedAt(b, at) {
				out[d] = true
			}
		}
	}
	return out
}

// hugePageFlags is memfd_create's MFD_HUGE_* flag of each huge page size the kernel lists under dir
// (hugepages-<n>kB), and 0, the default size, first.
func hugePageFlags(dir string) []int {
	out := []int{0}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		kb, ok := strings.CutPrefix(e.Name(), "hugepages-")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(kb, "kB"), 10, 64)
		if err != nil || n == 0 || n&(n-1) != 0 {
			continue
		}
		shift := 10 // kB
		for ; n > 1; n >>= 1 {
			shift++
		}
		if shift <= unix.MFD_HUGE_MASK {
			out = append(out, shift<<unix.MFD_HUGE_SHIFT)
		}
	}
	return out
}

// devsMappedAt is the device of each /proc/<pid>/maps line whose mapping starts at one of the addresses.
func devsMappedAt(maps []byte, at []uint64) []devID {
	var out []devID
	for _, line := range strings.Split(string(maps), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		start, _, ok := strings.Cut(f[0], "-")
		if !ok {
			continue
		}
		a, err := strconv.ParseUint(start, 16, 64)
		if err != nil {
			continue
		}
		for _, want := range at {
			if a == want {
				if d, ok := parseDev(f[3], 16); ok {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// parseDev reads major:minor in base (16 in maps and smaps).
func parseDev(s string, base int) (devID, bool) {
	maj, minor, ok := strings.Cut(s, ":")
	if !ok {
		return devID{}, false
	}
	a, err1 := strconv.ParseUint(maj, base, 32)
	b, err2 := strconv.ParseUint(minor, base, 32)
	if err1 != nil || err2 != nil {
		return devID{}, false
	}
	return devID{uint32(a), uint32(b)}, true
}

// markFDs sets NoPath on each file descriptor of fds whose device, a statx through dir/<n> (/proc/<pid>/fd), is one
// of internal's, and Unnamed and Aliases on each other file from its mount (namer.name; a nil namer names each as
// itself). A descriptor that cannot be stat'ed (closed since the listing) is left a path, and unnamed when nm is set:
// what it held is not known. Each file's, and each io_uring instance's, device and inode go in its ID.
func markFDs(dir string, fds []FD, internal map[devID]bool, nm *namer) {
	for i := range fds {
		if !fds[i].File() && !fds[i].Ring {
			continue
		}
		id, err := statHeld(filepath.Join(dir, strconv.Itoa(fds[i].Num)))
		if err != nil {
			fds[i].Unnamed = nm != nil && fds[i].File()
			continue
		}
		fds[i].ID = id.file()
		if !fds[i].File() {
			continue
		}
		if internal[devOf(id.dev)] {
			fds[i].NoPath = true
			continue
		}
		path, deleted := strings.CutSuffix(fds[i].Target, " (deleted)")
		v := nm.name(path, deleted, id)
		fds[i].Unnamed, fds[i].Aliases = v.unnamed, v.aliases
	}
}

// sharedAnonInode is the inode the kernel gives every anonymous file made with no inode of its own (fs/anon_inodes.c
// anon_inode_getfile: an eventfd, an epoll instance, and on a kernel whose io_uring does not ask for its own inode,
// every io_uring instance), learnt once per process from an eventfd tego makes; ok false when none could be made.
var sharedAnonInode = sync.OnceValues(func() (FileID, bool) {
	fd, err := sys.Own(unix.Eventfd(0, unix.EFD_CLOEXEC))
	if err != nil {
		return FileID{}, false
	}
	defer func() { _ = fd.Close() }() // the probe's own eventfd
	var st unix.Stat_t
	if fd.Fstat(&st) != nil {
		return FileID{}, false
	}
	dev := uint64(st.Dev) //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
	return FileID{Dev: unix.Mkdev(unix.Major(dev), unix.Minor(dev)), Ino: st.Ino}, true
})
