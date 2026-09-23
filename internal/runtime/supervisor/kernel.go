// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// kernel is every syscall the loop makes, behind one seam so the dispatch, the readers and the decisions
// are unit-tested against a fake target without a kernel (docs/p0/supervisor.md §10). The production
// implementation is sysKernel; it holds the listener fd and nothing else.
type kernel interface {
	// Wait blocks until the listener has a notification pending, wake becomes readable, or timeoutMS
	// elapses, and reports which of those happened.
	Wait(wake, timeoutMS int) (waitState, error)
	// Recv takes one pending notification (SECCOMP_IOCTL_NOTIF_RECV).
	Recv(n *sys.SeccompNotif) error
	// Send answers one notification exactly once (SECCOMP_IOCTL_NOTIF_SEND).
	Send(r *sys.SeccompNotifResp) error
	// IDValid reports whether the notification id is still pending (SECCOMP_IOCTL_NOTIF_ID_VALID); a dead
	// target is false, nil.
	IDValid(id uint64) (bool, error)
	// CloseListener closes the notify fd; further Recv calls fail.
	CloseListener() error
	// SetSyncWakeUp asks for SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP on the listener (Linux 6.6); an older
	// kernel refuses it and nothing else changes.
	SetSyncWakeUp() error

	// ReadMem reads len(buf) bytes of the target's memory at addr (process_vm_readv). A short read is the
	// byte count, not an error.
	ReadMem(pid int, addr uint64, buf []byte) (int, error)
	// ReadMemV reads the target's memory segments into buf back to back in one process_vm_readv (ADR 0048 (3),
	// batched argv reads), at most len(segs) <= 1024 segments. The count is the bytes read; a fault ends the
	// transfer at the segment it hit, so the segments before it are whole.
	ReadMemV(pid int, segs []memSeg, buf []byte) (int, error)
	// Readlink resolves one magic symlink under /proc (cwd, fd/<n>, root); single hop, never recursive.
	Readlink(name string) (string, error)
	// PlaceLink reads one name of a unix path being placed (resolveUnixDeclared: a declared entry or scope when the
	// loop is built, or the name of a connect whose socket or directory is not there yet, at most
	// agent.ResolveUnixPlace's bound of names per placement): agent.ReadPlaceLink, the directories before the name
	// walked without following any symlink, ELOOP when one of them is a symlink.
	PlaceLink(name string) (string, error)
	// Unlinked stats what one such link names and reports whether it has no links left (st_nlink == 0): the
	// one test that tells a " (deleted)" readlink of an unlinked file from a live file of that name.
	Unlinked(name string) (bool, error)
	// ProcStat reads /proc/<pid>/stat and returns the parent pid and the start time in clock ticks.
	ProcStat(pid int) (ppid int, startTicks uint64, err error)
	// Tgid reads the thread group id of a task from /proc/<pid>/status: the pid an exec id carries when
	// the notifying thread is not the group leader.
	Tgid(pid int) (int, error)
	// InGroup reports whether task tid is a thread of thread group tgid right now (/proc/<tgid>/task/<tid>
	// exists): one lookup with no read, which revalidates a cached Tgid answer against tid's reuse.
	InGroup(tgid, tid int) bool
	// ProcCgroup reads the unified-hierarchy cgroup path of a task from /proc/<pid>/cgroup, and ProcPgrp
	// its process group from /proc/<pid>/stat; ProcessGroups maps every process group on the host to its
	// processes, from one scan of /proc. They decide a signal's target below Landlock ABI 6 (signal.go). A
	// task that is gone is ESRCH.
	ProcCgroup(pid int) (string, error)
	ProcPgrp(pid int) (int, error)
	ProcessGroups() (map[int][]int, error)

	// OpenPidFD takes a pidfd for the task that trapped: thread-scoped (PIDFD_THREAD) where the kernel has
	// the flag, and otherwise the plain form, which only a thread-group leader's tid gets; any other tid
	// is refused.
	OpenPidFD(tid int) (int, error)
	// OpenPidFDProcess takes a process-scoped pidfd, the fallback for a kernel with no PIDFD_THREAD.
	OpenPidFDProcess(pid int) (int, error)
	// SignalPidFD sends sig through a pidfd (pidfd_send_signal, no flags): to the thread a PIDFD_THREAD
	// pidfd names, and to the process otherwise. A task that has exited is ESRCH.
	SignalPidFD(pidfd int, sig unix.Signal) error
	// SameFiles reports whether tasks a and b share one file-descriptor table (kcmp(2) KCMP_FILES): whether
	// a descriptor number read out of one names the same file in the other.
	SameFiles(a, b int) (bool, error)
	// GetFD duplicates the target's fd into this process (pidfd_getfd): the same open file description,
	// so O_NONBLOCK and the socket's connection state are shared.
	GetFD(pidfd, fd int) (int, error)
	// SockType reads SO_TYPE of an fd (SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_RAW).
	SockType(fd int) (int, error)
	// SockDomain reads SO_DOMAIN of an fd (AF_INET, AF_INET6, AF_UNIX, ...): whether a socket can reach an
	// IP destination whatever address a syscall on it names, which the models[] guard needs (decideGuarded).
	SockDomain(fd int) (int, error)
	// SockProtocol reads SO_PROTOCOL of an fd (IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_SCTP, ...): what the kernel
	// recorder names a connect by (protoOf).
	SockProtocol(fd int) (int, error)
	// SourceRouted reports whether an IP socket of the given domain carries a source route: IP_OPTIONS with
	// LSRR or SSRR, or (AF_INET6) a sticky IPV6_RTHDR. A relay on it would send the first hop to an address the
	// decision never scored (ADR 0041 D6).
	SourceRouted(fd, domain int) (bool, error)
	// UDPCorked reports whether a UDP socket has UDP_CORK set: every datagram sent on it joins one pending frame,
	// whose destination is the first datagram's, until the cork is cleared (frameFree).
	UDPCorked(fd int) (bool, error)
	// Connected reports whether the socket already has a peer (getpeername): a connected stream socket's
	// send carries no destination the kernel will honour, whatever the caller put in msg_name.
	Connected(fd int) bool
	// ConnectRaw connects fd to the sockaddr bytes exactly as the target passed them.
	ConnectRaw(fd int, sa []byte) error
	// TaskOf reads what a relayed unix connect needs to be made as the task tid (unixrelay.go): its
	// credentials and O_PATH descriptors of its root and cwd, which the caller closes (closeTask).
	TaskOf(tid int) (taskView, error)
	// ConnectUnixAs makes a relayed unix connect on fd as task would make it, asking admit about the
	// socket a pathname resolves to before connecting to it (unixrelay.go).
	ConnectUnixAs(fd int, task taskView, sa []byte, sunPath string, admit func(resolved string, file unixFile) bool) (unixOutcome, error)
	// SendUnixAs sends the datagram p with flags on fd as task would send it to the unix name sa carries: ConnectUnixAs's
	// walk and admit, then a send to the inode admitted in place of a connect, its byte count the call's (unixrelay.go).
	SendUnixAs(fd int, task taskView, sa []byte, sunPath string, p []byte, flags int, admit func(resolved string, file unixFile) bool) (unixOutcome, int, error)
	// SendToRawAs is SendToRaw on a thread holding task's credentials (sys.RunAs): a relayed send whose permission
	// checks the kernel makes against the sender, a route query of the unix-only state (relayRouteQuery).
	SendToRawAs(fd int, task taskView, p []byte, flags int, sa []byte) (int, error)
	// SocketID reads a socket descriptor's identity, its sockfs inode and SO_COOKIE (R11a, unixorigin.go).
	SocketID(fd int) (sockID, error)
	// UnixBound asks the kernel's socket diagnostics which file the unix socket id is bound to now (R11a), in one exact
	// lookup: errSocketGone when no socket has that identity any more.
	UnixBound(id sockID) (unixBinding, error)
	// UnixAbstractName asks the kernel's socket diagnostics which abstract name the unix socket id is bound to now
	// (UNIX_DIAG_NAME, without its leading NUL), in one exact lookup: "" for a socket bound to a file or to nothing,
	// errSocketGone when no socket has that identity any more (ADR 0070, runSockets.holdsAbstract).
	UnixAbstractName(id sockID) (string, error)
	// UnixTarget resolves a unix name as the task would — from its root or cwd, magic links refused — and says what
	// it reaches: where it lies in this process's view and its identity there, the socket file a datagram names or
	// the directory an unrecorded bind creates its socket in (unixname.go, R11, R11a).
	UnixTarget(q unixQuery) (unixPlace, error)
	// UnixDump lists the unix sockets of this network namespace bound to a file a connect or a datagram can reach,
	// reading at most limit of the namespace's sockets (R11a, unixorigin.go): what alone asks where a binding is
	// shared by files of several subvolumes. need says whether connected sockets are listed and whether only a dump
	// the kernel made in one pass of its socket table will do (errUnixDumpSplit).
	UnixDump(limit int, need dumpNeed) ([]unixDumpEntry, error)
	// MountDev is the superblock device of the mount with that id in this process's mountinfo (R11a): the device
	// UNIX_DIAG_VFS reports, which st_dev is not on btrfs.
	MountDev(mnt uint64) (uint64, error)
	// EvalSymlinks resolves every symlink in a declared exec entry's path, once, when the loop is built
	// (resolveDeclared).
	EvalSymlinks(p string) (string, error)
	// ExecImage resolves what an execve or execveat names to the file the kernel would load, walked the way
	// the task's own lookup walks it, and describes that file (execimage.go, R16b).
	ExecImage(q pathQuery) (execImage, error)
	// FSTarget resolves the path an fs syscall names to where it lands, walked the way the task's own lookup
	// walks it, with the name its line gives a ".." spelling, from the same walk (execimage.go, R15b).
	FSTarget(q pathQuery) (fsLanding, error)
	// ScanDir reads a directory reached with no symlink on the way and names the symlinks in it: the walk
	// cache's answer for the paths in it (walkcache.go).
	ScanDir(dir string) (dirScan, error)
	// FinalIsLink says whether a path's final component is a symlink, for a path in a big scanned directory.
	FinalIsLink(p string) (bool, error)
	// FinalIsDir says whether a path's final component, not followed, is a directory: what REFER's no-gain rule
	// compares for a rename's moved object (decide.ReferRefuses). A missing name is not one.
	FinalIsDir(p string) (bool, error)
	// StatID is a declared exec entry's identity, symlinks followed, taken once when the loop first sees
	// the entry (resolveExecEntries).
	StatID(p string) (fileID, error)
	// LstatID is a path's identity with its final component not followed (fstatat AT_SYMLINK_NOFOLLOW): what the
	// no-gain rule compares with the inodes the Landlock builder granted EXECUTE to (execGrants), at a rename's or a
	// link's ends and their directories.
	LstatID(p string) (fileID, error)
	// SendToRaw sends p on fd to the sockaddr bytes exactly as the target passed them.
	SendToRaw(fd int, p []byte, flags int, sa []byte) (int, error)
	// CloseFD closes a duplicate this loop owns.
	CloseFD(fd int) error
}

// sysKernel is the production kernel: the notify fd plus plain syscalls. It owns no other state, so two
// Loops on two fds never interact (E15). ln owns the listener (supervisor.New moved it in); each call on it
// borrows the number for that call alone (ADR 0023), so a close under the loop is an error the call reports,
// never a call on a number that was closed and reused. The zero value, which the methods that make plain
// syscalls are called on, owns none.
type sysKernel struct{ ln *sys.FD }

// waitState is the outcome of one Wait: what woke the poll.
type waitState int

// Wait outcomes.
const (
	waitTimeout waitState = iota // nothing happened before the timeout
	waitReady                    // a notification is pending on the listener
	waitWake                     // the loop's own wake fd fired: shut down
	waitHup                      // the listener hung up: no task carries the filter any more
	waitInvalid                  // the listener fd is not open (POLLNVAL): closed under the loop
)

// Wait polls the listener and the wake fd. EINTR restarts the wait, which is why the loop's cancellation
// travels on the wake fd and not on a signal: SECCOMP_IOCTL_NOTIF_RECV restarts on EINTR too.
func (k sysKernel) Wait(wake, timeoutMS int) (state waitState, err error) {
	err = k.ln.Borrow(func(fd int) error {
		var err error
		state, err = pollListener(fd, wake, timeoutMS)
		return err
	})
	if errors.Is(err, sys.ErrClosed) {
		// The listener's owner is closed: something in this process closed it under the loop, which is the
		// failure POLLNVAL reports for a number closed behind its owner's back.
		return waitInvalid, nil
	}
	return state, err
}

// pollListener is Wait's poll of the listener fd and the wake fd. Its error names no descriptor number, so
// the listener's number is lent to it for the call alone (ADR 0023).
func pollListener(fd, wake, timeoutMS int) (waitState, error) {
	fds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},
		{Fd: int32(wake), Events: unix.POLLIN},
	}
	for {
		n, err := unix.Poll(fds, timeoutMS)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return waitTimeout, fmt.Errorf("poll(listener): %w", err)
		}
		if n == 0 {
			return waitTimeout, nil
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			return waitReady, nil
		}
		if fds[1].Revents&unix.POLLIN != 0 {
			return waitWake, nil
		}
		// POLLNVAL is not a hangup: the fd is not open, so something in this process closed the listener
		// under the loop (Run closes it only after every worker has left), and the run's tasks, still
		// carrying the filter, now fail every notified syscall ENOSYS. That is a failure Run reports.
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return waitInvalid, nil
		}
		// POLLHUP on the listener means the last task carrying the filter is gone: the run is over and every
		// notified syscall would now fail ENOSYS on its own (ARCHITECTURE §6).
		if fds[0].Revents&unix.POLLHUP != 0 {
			return waitHup, nil
		}
		// POLLERR alone is no hangup. seccomp_notify_poll answers EPOLLERR, and nothing else, when its
		// mutex_lock_interruptible on notify_lock fails for a signal pending on this thread (kernel/seccomp.c,
		// since 5.0): the Go runtime signals its threads all the time, and the lock is contended by every RECV,
		// SEND, ADDFD and notifying task. Read as a hangup it ended each worker it reached as if the run were
		// over, the loop closed the listener under a live agent, and the agent's every notified syscall failed
		// ENOSYS with no line and no error (2026-10-16). It is a wait that took nothing: the worker polls again.
		return waitTimeout, nil
	}
}

// Recv takes one notification.
func (k sysKernel) Recv(n *sys.SeccompNotif) error {
	return k.ln.Borrow(func(fd int) error { return sys.SeccompNotifRecv(fd, n) })
}

// Send answers one notification.
func (k sysKernel) Send(r *sys.SeccompNotifResp) error {
	return k.ln.Borrow(func(fd int) error { return sys.SeccompNotifSend(fd, r) })
}

// IDValid brackets a read of the target.
func (k sysKernel) IDValid(id uint64) (valid bool, err error) {
	err = k.ln.Borrow(func(fd int) error {
		var err error
		valid, err = sys.SeccompNotifIDValid(fd, id)
		return err
	})
	return valid, err
}

// CloseListener closes the notify fd. Run calls it once every worker has left, so no call borrows it; the
// listener is strict (launch.Child.WaitNotifyFD), so a borrow still out would be ErrLeased here, reported,
// rather than a close deferred past Run's return.
func (k sysKernel) CloseListener() error {
	if err := k.ln.Close(); err != nil {
		return fmt.Errorf("close(listener): %w", err)
	}
	return nil
}

// SetSyncWakeUp sets the listener's sync wake-up flag.
func (k sysKernel) SetSyncWakeUp() error {
	return k.ln.Borrow(func(fd int) error { return sys.SeccompNotifSetFlags(fd, sys.SeccompUserNotifFdSyncWakeUp) })
}

// ReadMem reads the target's memory with process_vm_readv, falling back to a bounded pread of
// /proc/<pid>/mem when the call is not available at all (ENOSYS). It does not fall back on EPERM: that is
// the same ptrace_may_access check both paths make, so the second attempt would fail identically (E18).
func (k sysKernel) ReadMem(pid int, addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	local := []unix.Iovec{{Base: &buf[0], Len: uint64(len(buf))}}
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(buf)}}
	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err == nil {
		return n, nil
	}
	if n > 0 {
		return n, nil // a short read is truncation of what was there (E19)
	}
	if err != unix.ENOSYS {
		return 0, fmt.Errorf("process_vm_readv(pid=%d, addr=%#x, len=%d): %w", pid, addr, len(buf), err)
	}
	return k.readProcMem(pid, addr, buf)
}

// memSeg is one segment of the target's memory a batched read covers.
type memSeg struct {
	addr uint64
	n    int
}

// ReadMemV is one process_vm_readv over several remote segments into one local buffer. Where the syscall is missing
// (ENOSYS) it reads segment by segment with ReadMem, stopping at the first short one.
func (k sysKernel) ReadMemV(pid int, segs []memSeg, buf []byte) (int, error) {
	if len(segs) == 0 || len(buf) == 0 {
		return 0, nil
	}
	remote := make([]unix.RemoteIovec, len(segs))
	total := 0
	for i, s := range segs {
		remote[i] = unix.RemoteIovec{Base: uintptr(s.addr), Len: s.n}
		total += s.n
	}
	if total > len(buf) {
		return 0, fmt.Errorf("process_vm_readv: %d bytes into a buffer of %d", total, len(buf))
	}
	local := []unix.Iovec{{Base: &buf[0], Len: uint64(total)}}
	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err == nil || n > 0 {
		return n, nil
	}
	if err != unix.ENOSYS {
		return 0, fmt.Errorf("process_vm_readv(pid=%d, %d segments): %w", pid, len(segs), err)
	}
	off := 0
	for _, s := range segs {
		got, err := k.ReadMem(pid, s.addr, buf[off:off+s.n])
		off += got
		if err != nil || got < s.n {
			break
		}
	}
	return off, nil
}

// readProcMem is the /proc/<pid>/mem fallback; the fd is closed before the call returns (E28).
func (k sysKernel) readProcMem(pid int, addr uint64, buf []byte) (int, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mem")
	if err != nil {
		return 0, fmt.Errorf("open /proc/%d/mem: %w", pid, err)
	}
	defer f.Close() //nolint:errcheck // read-only fd
	n, err := f.ReadAt(buf, int64(addr))
	if n > 0 {
		return n, nil
	}
	if err != nil {
		return 0, fmt.Errorf("pread /proc/%d/mem at %#x: %w", pid, addr, err)
	}
	return 0, nil
}

// Readlink reads one /proc magic link.
func (k sysKernel) Readlink(name string) (string, error) {
	dst, err := os.Readlink(name)
	if err != nil {
		return "", fmt.Errorf("readlink %s: %w", name, err)
	}
	return dst, nil
}

// PlaceLink reads one name of a unix path being placed, through no symlink before it (agent.ReadPlaceLink).
func (k sysKernel) PlaceLink(name string) (string, error) {
	return agent.ReadPlaceLink(name)
}

// Unlinked stats a /proc magic link's file, following it, and reports whether its link count is zero.
func (k sysKernel) Unlinked(name string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Stat(name, &st); err != nil {
		return false, fmt.Errorf("stat %s: %w", name, err)
	}
	return st.Nlink == 0, nil
}

// ProcStat reads /proc/<pid>/stat for the parent pid (field 4) and the start time (field 22).
func (k sysKernel) ProcStat(pid int) (int, uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, fmt.Errorf("read /proc/%d/stat: %w", pid, err)
	}
	return parseProcStat(string(b))
}

// parseProcStat is ProcStat's pure half: it takes the file's contents and returns ppid and starttime. It
// goes through proc.ParseStat, the one fuzzed parser of the line, so the start an exec id is built from is
// read exactly as every other package reads it (execIDOf); a malformed line is errProcStat wrapping
// proc.ErrStat.
func parseProcStat(s string) (int, uint64, error) {
	st, err := proc.ParseStat([]byte(s))
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", errProcStat, err)
	}
	return st.PPID, st.StartTicks, nil
}

// Tgid reads the Tgid: line of /proc/<pid>/status.
func (k sysKernel) Tgid(pid int) (int, error) {
	procReads.Add(1)
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}
	return parseTgid(string(b))
}

// InGroup reports whether /proc/<tgid>/task/<tid> exists.
func (k sysKernel) InGroup(tgid, tid int) bool {
	return unix.Faccessat(unix.AT_FDCWD, "/proc/"+strconv.Itoa(tgid)+"/task/"+strconv.Itoa(tid), unix.F_OK, 0) == nil
}

// ProcCgroup reads the unified-hierarchy path of /proc/<pid>/cgroup; a task that is gone is ESRCH.
func (k sysKernel) ProcCgroup(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", unix.ESRCH
		}
		return "", fmt.Errorf("read /proc/%d/cgroup: %w", pid, err)
	}
	return proc.ParseCgroup(b), nil
}

// ProcPgrp reads the process group of pid from /proc/<pid>/stat; a task that is gone is ESRCH.
func (k sysKernel) ProcPgrp(pid int) (int, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, unix.ESRCH
		}
		return 0, fmt.Errorf("read /proc/%d/stat: %w", pid, err)
	}
	st, err := proc.ParseStat(b)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", errProcStat, err)
	}
	return st.Pgrp, nil
}

// ProcessGroups maps every process group to its processes by reading every /proc/<pid>/stat: there is no
// kernel interface that enumerates a group. The scan grows with the host, not the run, which is why
// signalInside shares one across calls (groupCache).
func (k sysKernel) ProcessGroups() (map[int][]int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return groupsOf(pids, k.ProcPgrp)
}

// groupsOf is ProcessGroups' pure half: it groups pids by what pgrp reads for each. A process that exited
// during the scan (ESRCH) is skipped; any other failure (EMFILE, ENOMEM, EACCES, a stat it cannot parse)
// fails the whole scan, naming the pid. A process the scan could not read may be an outside member of the
// group being decided, and a snapshot without it would continue a group signal that reaches it (R33).
func groupsOf(pids []int, pgrp func(int) (int, error)) (map[int][]int, error) {
	groups := make(map[int][]int)
	for _, pid := range pids {
		g, err := pgrp(pid)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("process group of pid %d: %w", pid, err)
		}
		groups[g] = append(groups[g], pid)
	}
	return groups, nil
}

// parseTgid is Tgid's pure half.
func parseTgid(s string) (int, error) {
	for _, line := range strings.Split(s, "\n") {
		rest, ok := strings.CutPrefix(line, "Tgid:")
		if !ok {
			continue
		}
		tgid, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, fmt.Errorf("%w: tgid %q: %w", errProcStat, rest, err)
		}
		return tgid, nil
	}
	return 0, fmt.Errorf("%w: no Tgid line", errProcStat)
}

// OpenPidFD takes a pidfd for the trapping task through sys.PidfdOpenThread: thread-scoped on Linux 6.9
// and later; below that PidfdOpenThread retries the plain form itself, which serves a thread-group leader
// and refuses any other tid (openTargetPidFD's fallback covers that). pidfd_getfd works through either
// scope because threads share a descriptor table.
func (k sysKernel) OpenPidFD(tid int) (int, error) { return sys.PidfdOpenThread(tid) }

// OpenPidFDProcess takes a process-scoped pidfd, which is all a kernel below 6.9 can give.
func (k sysKernel) OpenPidFDProcess(pid int) (int, error) { return sys.PidfdOpenProcess(pid) }

// SignalPidFD raises sig on the task pidfd names (relayed sends' SIGPIPE, raisePipe).
func (k sysKernel) SignalPidFD(pidfd int, sig unix.Signal) error {
	return unix.PidfdSendSignal(pidfd, sig, nil, 0)
}

// kcmpFiles is KCMP_FILES (include/uapi/linux/kcmp.h), which golang.org/x/sys/unix does not define.
const kcmpFiles = 2

// SameFiles asks kcmp(2) whether a and b share a file-descriptor table: 0 is the same table, and 1, 2 or 3
// order two different ones. It needs PTRACE_MODE_READ on both, which pidfd_getfd's own ATTACH check implies.
func (k sysKernel) SameFiles(a, b int) (bool, error) {
	r, _, e := unix.Syscall6(unix.SYS_KCMP, uintptr(a), uintptr(b), kcmpFiles, 0, 0, 0)
	if e != 0 {
		return false, fmt.Errorf("kcmp(%d, %d, KCMP_FILES): %w", a, b, e)
	}
	return r == 0, nil
}

// GetFD duplicates the target's fd.
func (k sysKernel) GetFD(pidfd, fd int) (int, error) { return sys.PidfdGetfd(pidfd, fd) }

// SockType reads SO_TYPE.
func (k sysKernel) SockType(fd int) (int, error) {
	t, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return 0, fmt.Errorf("getsockopt(fd=%d, SO_TYPE): %w", fd, err)
	}
	return t, nil
}

// SockProtocol reads SO_PROTOCOL.
func (k sysKernel) SockProtocol(fd int) (int, error) {
	p, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil {
		return 0, fmt.Errorf("getsockopt(fd=%d, SO_PROTOCOL): %w", fd, err)
	}
	return p, nil
}

// SockDomain reads SO_DOMAIN.
func (k sysKernel) SockDomain(fd int) (int, error) {
	d, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return 0, fmt.Errorf("getsockopt(fd=%d, SO_DOMAIN): %w", fd, err)
	}
	return d, nil
}

// SourceRouted reads IP_OPTIONS (both IP domains: an AF_INET6 socket's v4-mapped traffic uses them too) and,
// for any domain but AF_INET, IPV6_RTHDR. ENOPROTOOPT is an option the socket does not have; any other
// failure is returned, and the caller refuses.
func (k sysKernel) SourceRouted(fd, domain int) (bool, error) {
	buf := make([]byte, 2048) // an IPv6 routing header is at most (255+1)*8 bytes; IPv4 options 40
	opts, err := getsockoptBytes(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, buf)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return false, fmt.Errorf("getsockopt(fd=%d, IP_OPTIONS): %w", fd, err)
	}
	if ipv4SourceRoute(opts) {
		return true, nil
	}
	if domain == unix.AF_INET {
		return false, nil
	}
	rthdr, err := getsockoptBytes(fd, unix.IPPROTO_IPV6, unix.IPV6_RTHDR, buf)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return false, fmt.Errorf("getsockopt(fd=%d, IPV6_RTHDR): %w", fd, err)
	}
	return len(rthdr) != 0, nil
}

// UDPCorked reads UDP_CORK (level SOL_UDP, which udpv6_setsockopt shares). Any failure is returned, and the caller
// refuses.
func (k sysKernel) UDPCorked(fd int) (bool, error) {
	v, err := unix.GetsockoptInt(fd, unix.SOL_UDP, unix.UDP_CORK)
	if err != nil {
		return false, fmt.Errorf("getsockopt(fd=%d, UDP_CORK): %w", fd, err)
	}
	return v != 0, nil
}

// getsockoptBytes is getsockopt(2) into buf, returning the bytes the kernel wrote.
func getsockoptBytes(fd, level, opt int, buf []byte) ([]byte, error) {
	n := uint32(len(buf))
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
	if e != 0 {
		return nil, e
	}
	return buf[:min(int(n), len(buf))], nil
}

// ipv4SourceRoute reports whether an IP options block (RFC 791) carries a loose or strict source route. A block
// it cannot walk to its end is taken as carrying one: the side that refuses.
func ipv4SourceRoute(opts []byte) bool {
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0: // IPOPT_END
			return false
		case 1: // IPOPT_NOOP
			i++
			continue
		case 0x83, 0x89: // IPOPT_LSRR, IPOPT_SSRR
			return true
		}
		if i+1 >= len(opts) || opts[i+1] < 2 {
			return true
		}
		i += int(opts[i+1])
	}
	return false
}

// Connected reports whether the socket has a peer. Any error — ENOTCONN above all — means it does not.
func (k sysKernel) Connected(fd int) bool {
	_, err := unix.Getpeername(fd)
	return err == nil
}

// ConnectRaw connects with the bytes the target passed, never a re-serialized address: what the run asked
// for is what the kernel sees (I3).
func (k sysKernel) ConnectRaw(fd int, sa []byte) error { return connectRaw(fd, sa) }

// EvalSymlinks is filepath.EvalSymlinks.
func (k sysKernel) EvalSymlinks(p string) (string, error) { return filepath.EvalSymlinks(p) }

// connectRaw is connect(2) with the sockaddr bytes as given, returning the bare errno.
func connectRaw(fd int, sa []byte) error {
	if len(sa) == 0 {
		return unix.EINVAL
	}
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa[0])), uintptr(len(sa)))
	if errno != 0 {
		return errno
	}
	return nil
}

// SendToRaw sends p to the sockaddr bytes the target passed.
func (k sysKernel) SendToRaw(fd int, p []byte, flags int, sa []byte) (int, error) {
	var buf unsafe.Pointer
	if len(p) > 0 {
		buf = unsafe.Pointer(&p[0])
	}
	var addr unsafe.Pointer
	if len(sa) > 0 {
		addr = unsafe.Pointer(&sa[0])
	}
	n, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(buf), uintptr(len(p)),
		uintptr(flags), uintptr(addr), uintptr(len(sa)))
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// CloseFD closes a duplicate.
func (k sysKernel) CloseFD(fd int) error {
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close(fd=%d): %w", fd, err)
	}
	return nil
}
