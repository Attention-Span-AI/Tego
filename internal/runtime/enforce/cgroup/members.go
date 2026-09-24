// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// fileidKernfs is FILEID_KERNFS (include/linux/exportfs.h): the file handle type kernfs, and so cgroupfs,
// gives a node, whose eight bytes are the node's 64-bit id. For a cgroup that id is its cgroup id, the value
// PIDFD_INFO_CGROUPID reports and the inode number cgroupIDOfPath reads.
const fileidKernfs = 0xfe

// membersCap bounds the cgroup ids runMembers remembers. Each id is one cgroup some opener was in, so a host
// meets it only with that many cgroups, and the whole cache starts over rather than grow past it.
const membersCap = 4096

// runMembers answers the listener's membership question — is this opener in the run's cgroup subtree? — by
// cgroup id, where the kernel can say which cgroup a process is in without text (§6 E34). The listener asks it
// for every event the policy would refuse, and for a host exec of a binary the contract did not name that is
// every such exec on the marked mount (§6 E34), so the answer is on a host-wide hot path. /proc/<pid>/cgroup
// answers it with an open, a read of kernel-formatted text, a parse and a path compare; PIDFD_GET_INFO's
// PIDFD_INFO_CGROUPID answers with the id itself, read under RCU. That ioctl is upstream from 6.13 and
// backported to some older kernels (RHEL 9's 5.14 answers it), so it is found by asking, never by version.
//
// An id's answer is kept: a cgroup never moves in the hierarchy (cgroup v2 has no rename, and cgroup v1's
// keeps the parent), and a cgroup's id names it alone for the whole boot, so whether one id lies in the run's
// subtree cannot change while the run lasts. The first event from a cgroup other than the run's own names it
// through the cgroup filesystem (open_by_handle_at with its id, then the path of that descriptor); every later
// event from it costs the pidfd and the ioctl. Whatever this cannot answer is left to /proc/<pid>/cgroup, the
// path the listener always had: a kernel without the ioctl, an opener that is gone (ESRCH, which the kernel
// also reports for a process outside this pid namespace's hierarchy), a cgroup removed before it was named,
// or no CAP_DAC_READ_SEARCH for the handle.
type runMembers struct {
	mount   string // the cgroup2 mount the run's path is relative to
	runPath string
	runID   uint64
	// mountFD is a descriptor of the cgroup2 mount's root directory, which open_by_handle_at resolves handles
	// under; -1 when it could not be opened, and then only the run's own id is answered here. It is opened
	// for reading, not O_PATH: the kernel looks the anchor up with fdget, which does not return an O_PATH
	// file, and answers EBADF for one. fdMu orders close after the reads using it: a decision answered at
	// E16's deadline keeps running, and can still be naming a cgroup when the listener closes.
	fdMu    sync.RWMutex
	mountFD int

	// idOf and pathOf are the two kernel reads. They are fields so the caching and the fallbacks are tested
	// without a pidfd ioctl, which not every kernel has, or a file handle, which needs CAP_DAC_READ_SEARCH.
	idOf   func(pid int) (uint64, error)
	pathOf func(id uint64) (string, error)

	// unsupported latches a kernel with no PIDFD_GET_INFO cgroup id, so it is asked once and not once per
	// event: every membership read there would otherwise pay a pidfd, a failed ioctl and a close before /proc.
	unsupported atomic.Bool

	mu    sync.Mutex
	known map[uint64]bool
}

// newRunMembers prepares the id path for a run. It never fails: a mount it cannot open leaves the handle
// lookup to /proc/<pid>/cgroup, which still answers.
func newRunMembers(run Run) *runMembers {
	m := &runMembers{
		mount: run.mount(), runPath: run.CgroupPath, runID: run.CgroupID, mountFD: -1,
		known: map[uint64]bool{},
	}
	if fd, err := unix.Open(m.mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		m.mountFD = fd
	}
	m.idOf = cgroupIDOfPID
	m.pathOf = m.pathOfCgroupID
	return m
}

// close releases the mount descriptor. It is idempotent.
func (m *runMembers) close() {
	if m == nil {
		return
	}
	m.fdMu.Lock()
	defer m.fdMu.Unlock()
	if m.mountFD < 0 {
		return
	}
	_ = unix.Close(m.mountFD)
	m.mountFD = -1
}

// lookup answers whether pid is in the run's subtree. ok is false when this path has no answer, and the
// caller then asks /proc/<pid>/cgroup, which also tells an exited opener apart (ErrProcGone, §6 E10).
func (m *runMembers) lookup(pid int) (member, ok bool) {
	if m == nil || m.unsupported.Load() {
		return false, false
	}
	id, err := m.idOf(pid)
	if err != nil {
		if errors.Is(err, errNoPidfdInfo) {
			m.unsupported.Store(true)
		}
		return false, false
	}
	if id == m.runID && id != 0 {
		return true, true
	}
	m.mu.Lock()
	in, seen := m.known[id]
	m.mu.Unlock()
	if seen {
		return in, true
	}
	if m.pathOf == nil {
		return false, false
	}
	rel, err := m.pathOf(id)
	if err != nil {
		return false, false
	}
	in = inSubtree(m.runPath, rel)
	m.mu.Lock()
	if len(m.known) >= membersCap {
		clear(m.known)
	}
	m.known[id] = in
	m.mu.Unlock()
	return in, true
}

// errNoPidfdInfo is a kernel without PIDFD_GET_INFO or without its cgroup id: one that refuses the ioctl
// (pidfdInfoErr), or one built without cgroups, which answers it without PIDFD_INFO_CGROUPID in the mask.
var errNoPidfdInfo = errors.New("cgroup: this kernel has no PIDFD_GET_INFO cgroup id")

// cgroupIDOfPID reads the id of the cgroup v2 cgroup an opening thread is in through a pidfd (PIDFD_GET_INFO,
// PIDFD_INFO_CGROUPID). A kernel without the ioctl is reported as errNoPidfdInfo so the caller stops asking;
// any other failure, an exited process's ESRCH included, is returned as it is.
func cgroupIDOfPID(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, unix.ESRCH
	}
	fd, err := sys.PidfdOpenThread(pid)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	info := unix.PidfdInfo{Mask: unix.PIDFD_INFO_CGROUPID}
	if err := unix.IoctlPidfdInfo(fd, &info); err != nil {
		return 0, pidfdInfoErr(err)
	}
	if info.Mask&unix.PIDFD_INFO_CGROUPID == 0 {
		return 0, errNoPidfdInfo
	}
	return info.Cgroupid, nil
}

// pidfdInfoErr says which failures of PIDFD_GET_INFO mean the kernel has no such ioctl, so that the caller
// stops asking (§6 E34). Two errnos do. A pidfd with no ioctl handler at all (below 6.11) is ENOTTY. From 6.11
// to 6.12 a pidfd has a handler, for the namespace ioctls alone, and it refuses any of them called with a
// non-zero argument with EINVAL before it looks at the command, so PIDFD_GET_INFO, whose argument is the
// struct's address, is EINVAL there; Debian 13's and AL2023's 6.12 answer so. On a kernel that has the ioctl,
// EINVAL means a NULL or undersized struct, which unix.IoctlPidfdInfo never passes, so reading it as "no
// ioctl" there misreads nothing. Were it ever wrong, the cost is the /proc path, which answers every event.
func pidfdInfoErr(err error) error {
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("%w (%w)", errNoPidfdInfo, err)
	}
	return err
}

// pathOfCgroupID names a cgroup by its id: the path of the cgroup directory the kernfs handle opens, relative
// to the cgroup2 mount, in the form /proc/<pid>/cgroup gives. A cgroup removed since its id was read is ESTALE.
func (m *runMembers) pathOfCgroupID(id uint64) (string, error) {
	var raw [8]byte
	binary.NativeEndian.PutUint64(raw[:], id)
	m.fdMu.RLock()
	if m.mountFD < 0 {
		m.fdMu.RUnlock()
		return "", unix.EBADF
	}
	fd, err := unix.OpenByHandleAt(m.mountFD, unix.NewFileHandle(fileidKernfs, raw[:]),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	m.fdMu.RUnlock()
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	full, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return "", err
	}
	// A cgroup removed after the open is named with this suffix, as /proc/<pid>/cgroup names it
	// (parseCgroupFile); its ancestry, which is all the answer depends on, is unchanged.
	full = strings.TrimSuffix(full, " (deleted)")
	mount := strings.TrimSuffix(filepath.Clean(m.mount), "/")
	if full == mount {
		return "/", nil
	}
	rel, ok := strings.CutPrefix(full, mount+"/")
	if !ok {
		// The cgroup is not under the mount the run's path is relative to (another cgroup namespace's view,
		// or a mount that moved): no path here can be compared with the run's.
		return "", unix.EXDEV
	}
	return "/" + rel, nil
}
