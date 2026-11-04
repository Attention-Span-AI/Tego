// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// R11a compares UNIX_DIAG_VFS's device, which is the socket file's superblock device (d_sb->s_dev), with the file a
// name resolves to. stat(2)'s st_dev is that device on most filesystems and is not on btrfs, where it is the
// subvolume's own anonymous device, the top-level subvolume's included. mountinfo's third field is the superblock's
// device of each mount (show_mountinfo prints sb->s_dev), so the file's mount id (STATX_MNT_ID) names it: owns asks
// for it only when st_dev and the binding's device differ.

// mountDevs is this process's mount table as a map from a mount's id to its superblock's device, read from
// /proc/self/mountinfo. The file stays open: the kernel flags POLLPRI on it when the namespace's mount table changes,
// and the table is read again then, and on a miss, so an id a later mount reuses is never answered from a table read
// before it.
var mountDevs struct {
	mu   sync.Mutex
	fd   int
	devs map[uint64]uint64
}

// errMountUnknown is MountDev's answer for a mount id this process's mountinfo does not list.
var errMountUnknown = errors.New("supervisor: no mount with that id in this process's mountinfo")

// MountDev is the superblock device of the mount with id mnt in this process's mount namespace (R11a).
func (sysKernel) MountDev(mnt uint64) (uint64, error) {
	mountDevs.mu.Lock()
	defer mountDevs.mu.Unlock()
	fresh := false
	if mountDevs.devs == nil {
		fd, err := unix.Open("/proc/self/mountinfo", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return 0, fmt.Errorf("mountinfo: %w", err)
		}
		devs, err := readMountDevs(fd)
		if err != nil {
			_ = unix.Close(fd)
			return 0, err
		}
		mountDevs.fd, mountDevs.devs, fresh = fd, devs, true
	} else if mountTableChanged(mountDevs.fd) {
		if err := rereadMountDevs(); err != nil {
			return 0, err
		}
		fresh = true
	}
	if dev, ok := mountDevs.devs[mnt]; ok {
		return dev, nil
	}
	if !fresh {
		if err := rereadMountDevs(); err != nil {
			return 0, err
		}
		if dev, ok := mountDevs.devs[mnt]; ok {
			return dev, nil
		}
	}
	return 0, errMountUnknown
}

// rereadMountDevs reads the kept mountinfo again; the caller holds mountDevs.mu.
func rereadMountDevs() error {
	devs, err := readMountDevs(mountDevs.fd)
	if err != nil {
		return err
	}
	mountDevs.devs = devs
	return nil
}

// mountTableChanged reports whether the kernel flagged the kept mountinfo since it was last polled (a mount or an
// unmount in this namespace). A poll that fails reads as a change, so the table is read again.
func mountTableChanged(fd int) bool {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI}}
	n, err := unix.Poll(fds, 0)
	return err != nil || (n > 0 && fds[0].Revents&(unix.POLLPRI|unix.POLLERR) != 0)
}

// readMountDevs reads mountinfo from its start on fd.
func readMountDevs(fd int) (map[uint64]uint64, error) {
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, fmt.Errorf("mountinfo: seek: %w", err)
	}
	var data []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := unix.Read(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("mountinfo: read: %w", err)
		}
		if n == 0 {
			break
		}
		data = append(data, buf[:n]...)
	}
	return parseMountDevs(data), nil
}

// parseMountDevs maps each mountinfo line's mount id (field 1) to its "major:minor" (field 3). A line it cannot
// read is skipped: its mount is then unknown, and R11a refuses what lies on it.
func parseMountDevs(data []byte) map[uint64]uint64 {
	devs := map[uint64]uint64{}
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		f := bytes.Fields(line)
		if len(f) < 3 {
			continue
		}
		id, err := strconv.ParseUint(string(f[0]), 10, 64)
		if err != nil {
			continue
		}
		majS, minS, ok := bytes.Cut(f[2], []byte{':'})
		if !ok {
			continue
		}
		maj, err1 := strconv.ParseUint(string(majS), 10, 32)
		minor, err2 := strconv.ParseUint(string(minS), 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		devs[id] = unix.Mkdev(uint32(maj), uint32(minor))
	}
	return devs
}

// UnixFile is the socket file p names in this process's view, symlinks followed, as R11a matches it (unixFile): the
// kernel half's tests compare it with what sock_diag reports. A decision never stats a name in this view; it asks
// what the task's own lookup reaches (UnixTarget).
func (sysKernel) UnixFile(p string) (unixFile, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, p, 0, unixFileMask, &st); err != nil {
		return unixFile{}, err
	}
	return unixFileOf(&st), nil
}

// unixFileMask is what R11a asks statx about a socket file: its inode, the mount it was reached on, and its birth
// time, which decides where st_dev is not the superblock's (owns).
const unixFileMask = unix.STATX_NLINK | unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_BTIME

// unixFileOf is a statx answer as R11a matches it; mnt stays 0 when the kernel reported no mount id, and born when it
// reported no birth time.
func unixFileOf(st *unix.Statx_t) unixFile {
	f := unixFile{dev: unix.Mkdev(st.Dev_major, st.Dev_minor), ino: st.Ino}
	if st.Mask&unix.STATX_MNT_ID != 0 {
		f.mnt = st.Mnt_id
	}
	if st.Mask&unix.STATX_BTIME != 0 {
		f.born = st.Btime.Sec*int64(time.Second) + int64(st.Btime.Nsec)
	}
	return f
}
