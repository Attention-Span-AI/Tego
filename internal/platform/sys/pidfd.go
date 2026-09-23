// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sigchldInfo is the SIGCHLD view of siginfo_t on 64-bit Linux: the union starts at byte 16 with
// si_pid, si_uid, si_status. unix.Siginfo keeps the union opaque, so waitid results are read through this.
type sigchldInfo struct {
	Signo  int32
	Errno  int32
	Code   int32
	_      int32
	Pid    int32
	UID    uint32
	Status int32
}

// The calls below that take a pidfd use its number only in the system call: their errors name the call and
// the errno, never the number (ADR 0023, 2026-10-19 note), so an owner lends it straight in, as in
// pidfd.Borrow(func(n int) error { return PidfdSendSignal(n, sig) }), and fdcheck follows it there.

// PidfdThread is PIDFD_THREAD (Linux 6.9): the pidfd names the exact task rather than its thread group,
// which is the only way to open one for a thread that is not its group's leader. The flag is O_EXCL, whose
// numeric value is architecture-dependent (0x80 on amd64/arm64, 0x400 on mips), so it is taken from the
// kernel's own per-architecture table instead of being spelled out here.
const PidfdThread = unix.PIDFD_THREAD

// PidfdSignalThreadGroup is PIDFD_SIGNAL_THREAD_GROUP (include/uapi/linux/pidfd.h, Linux 6.9): it makes
// pidfd_send_signal direct the signal at the whole thread group even when the pidfd names one thread.
const PidfdSignalThreadGroup = 0x2

// ErrThreadScopedPidfd rejects a PIDFD_THREAD descriptor where a process-scoped one is required. A
// thread-scoped pidfd answers a different question — it becomes readable when that one task becomes a
// zombie, not when the thread group empties (pidfd_open(2)) — so a caller asking "has the process exited"
// through one would be told yes the moment any single thread died.
var ErrThreadScopedPidfd = errors.New("sys: pidfd was opened with PIDFD_THREAD; this call needs a process-scoped pidfd (PidfdOpenProcess)")

// PidfdOpenProcess returns a process-scoped pidfd for pid (pidfd_open(2), Linux 5.3). The fd is O_CLOEXEC.
//
// pid must be a thread-group leader: without PIDFD_THREAD the kernel tests pid_has_task(pid, PIDTYPE_TGID)
// and refuses a non-leader tid, with EINVAL on older kernels and ENOENT on newer ones (measured on 6.17).
// This is the form every caller that will signal, poll or reap the target wants, because the resulting fd
// carries process semantics: signals reach the thread group and readability means the whole group has
// exited.
func PidfdOpenProcess(pid int) (int, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, fmt.Errorf("pidfd_open(%d): %w", pid, err)
	}
	return fd, nil
}

// PidfdOpenThread returns a pidfd that names the single task tid (PIDFD_THREAD, Linux 6.9). The fd is
// O_CLOEXEC.
//
// This is what a seccomp notification needs: its Pid field is task_pid_vnr(current), a tid, and the plain
// form refuses every notification a secondary thread raised. Below 6.9 the flag does not exist, so this
// falls back to the plain form, which succeeds only when tid is its thread group's leader. The supervisor
// still passes the trapping tid on every kernel and handles a refused non-leader tid itself, by opening
// the tgid with PidfdOpenProcess instead (internal/runtime/supervisor/net.go openTargetPidFD).
//
// The returned fd is thread-scoped: use it for pidfd_getfd, not for signalling, polling or reaping, which
// PidfdSendSignal, PollPidfd and WaitPidfd document.
func PidfdOpenThread(tid int) (int, error) {
	fd, err := unix.PidfdOpen(tid, PidfdThread)
	if err == nil {
		return fd, nil
	}
	// EINVAL is a kernel that does not know the flag; ESRCH and ENOENT are a task that is already gone,
	// and retrying the plain form for those is harmless and keeps one error path.
	fd, ferr := unix.PidfdOpen(tid, 0)
	if ferr != nil {
		return -1, fmt.Errorf("pidfd_open(%d): %w", tid, ferr)
	}
	return fd, nil
}

// PidfdGetfd duplicates targetfd of the process behind pidfd into the caller's table (pidfd_getfd(2),
// Linux 5.6). The new fd is O_CLOEXEC. The target must be dumpable and ptrace-attachable by the caller
// (PTRACE_MODE_ATTACH_REALCREDS); a non-dumpable target yields EPERM. Either scope of pidfd works: threads
// share a descriptor table, so the leader's pidfd reaches a worker's fd.
func PidfdGetfd(pidfd, targetfd int) (int, error) {
	fd, err := unix.PidfdGetfd(pidfd, targetfd, 0)
	if err != nil {
		return -1, fmt.Errorf("pidfd_getfd(fd=%d): %w", targetfd, err)
	}
	return fd, nil
}

// PidfdSignalVerified sends sig to pid through a process-scoped pidfd opened before verify runs. verify checks that pid
// still names the process the caller means (its /proc start time, say): the pidfd names the process pid named when it
// was opened, so a pid reused after the open fails verify and is never signalled, and the signal reaches the verified
// process or none.
func PidfdSignalVerified(pid int, sig syscall.Signal, verify func() error) error {
	fd, err := PidfdOpenProcess(pid)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := verify(); err != nil {
		return err
	}
	return PidfdSendSignal(fd, sig)
}

// PidfdOpenProcessFD is PidfdOpenProcess born an owner (ADR 0023 C2). The int form stays until its last caller
// has moved (C19).
func PidfdOpenProcessFD(pid int) (*FD, error) { return Own(PidfdOpenProcess(pid)) }

// PidfdOpenThreadFD is PidfdOpenThread born an owner.
func PidfdOpenThreadFD(tid int) (*FD, error) { return Own(PidfdOpenThread(tid)) }

// PeerPidfdFD is the pidfd of a connected unix socket's peer (SO_PEERPIDFD, Linux 6.5), born an owner: the process
// that connected, or made the socket pair, as the kernel recorded it then, so no process that reused its pid since
// can stand in for it. It is process-scoped and close-on-exec by the kernel (pidfd_prepare with no flags). Below 6.5
// the error is ENOPROTOOPT. The socket's number is used inside conn's Control alone.
func PeerPidfdFD(conn syscall.RawConn) (*FD, error) {
	var p *FD
	var err error
	if cerr := conn.Control(func(fd uintptr) {
		p, err = Own(unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD))
	}); cerr != nil {
		return nil, cerr
	}
	return p, err
}

// PollPidfdFD is PollPidfd on an owned pidfd, borrowed for the wait.
func PollPidfdFD(pidfd *FD, timeoutMS int) (exited bool, err error) {
	err = pidfd.Borrow(func(n int) error {
		var perr error
		exited, perr = PollPidfd(n, timeoutMS)
		return perr
	})
	return exited, err
}

// PidfdGetfdFD is PidfdGetfd born an owner. pidfd is borrowed for the call. The seccomp listener taken from the
// child stage this way is made strict by its caller: sys.Strict(sys.PidfdGetfdFD(pidfd, n)) (ADR 0023 T1.4).
func PidfdGetfdFD(pidfd, targetfd int) (*FD, error) { return Own(PidfdGetfd(pidfd, targetfd)) }

// PidfdSendSignal sends sig to the thread group behind pidfd (pidfd_send_signal(2), Linux 5.1). It targets
// the exact task the fd refers to, so it is safe across pid reuse (R22), and the signal is process-directed
// whichever way that fd was opened.
//
// The scope is a property of the descriptor, not of the signal: with flags 0 the kernel infers PIDTYPE_PID
// for a pidfd opened with PIDFD_THREAD and PIDTYPE_TGID otherwise (Linux 6.9 onwards). A thread-directed
// signal is the classic tgkill trap — SIGTERM aimed at a task that blocks it sits in that task's private
// queue forever instead of being taken by a sibling that does not block it. Neither caller hands this a
// thread-scoped fd today: runtime.StopTarget holds a PidfdOpenProcess fd and launch.Child the clone3
// CLONE_PIDFD one, and on both flags 0 already means the thread group. PIDFD_SIGNAL_THREAD_GROUP is
// therefore defence in depth, not a fix for either: it keeps the scope the callers mean (R22's stop reaches
// the launcher) a property of this wrapper, so a thread-scoped fd routed here later could not turn `tego
// stop` into a signal the launcher never sees.
func PidfdSendSignal(pidfd int, sig syscall.Signal) error {
	err := unix.PidfdSendSignal(pidfd, unix.Signal(sig), nil, PidfdSignalThreadGroup)
	if errors.Is(err, unix.EINVAL) {
		// Below 6.9 pidfd_send_signal rejects every non-zero flag, and PIDFD_THREAD does not exist there
		// either, so flags 0 is already thread-group scope on exactly the kernels that refuse the flag.
		err = unix.PidfdSendSignal(pidfd, unix.Signal(sig), nil, 0)
	}
	if err != nil {
		return fmt.Errorf("pidfd_send_signal(%s): %w", sig, err)
	}
	return nil
}

// PidfdSendSignalFD is PidfdSendSignal through the owner pidfd, borrowed for the call (ADR 0023 A6), so a Close
// racing it keeps the number until the signal is sent; a closed or nil owner signals nothing and is ErrClosed.
func PidfdSendSignalFD(pidfd *FD, sig syscall.Signal) error {
	return pidfd.Borrow(func(n int) error { return PidfdSendSignal(n, sig) })
}

// WaitPidfd reaps the exited process behind pidfd (waitid(P_PIDFD, ..., WEXITED), Linux 5.4) and returns its
// wait status in the classic wait4 encoding so syscall.WaitStatus methods apply. With nohang it returns
// (0, false, nil) when the process has not exited yet; without it the call blocks. Only a parent may reap.
// pidfd must be process-scoped (ErrThreadScopedPidfd otherwise): a thread's exit is not the process's.
func WaitPidfd(pidfd int, nohang bool) (ws syscall.WaitStatus, reaped bool, err error) {
	if err := requireProcessScope(pidfd); err != nil {
		return 0, false, err
	}
	opts := unix.WEXITED
	if nohang {
		opts |= unix.WNOHANG
	}
	var info unix.Siginfo
	for {
		err = unix.Waitid(unix.P_PIDFD, pidfd, &info, opts, nil)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return 0, false, fmt.Errorf("waitid(P_PIDFD): %w", err)
	}
	cld := (*sigchldInfo)(unsafe.Pointer(&info))
	if cld.Pid == 0 { // WNOHANG and still running: the kernel zeroes si_pid.
		return 0, false, nil
	}
	return siginfoWaitStatus(cld.Code, cld.Status), true, nil
}

// WaitPidfdStopped takes the job-control stop of the process behind pidfd that no wait has reported yet
// (waitid(P_PIDFD, ..., WSTOPPED|WNOHANG), which consumes the report) and returns the signal that stopped it, or
// 0 when it is running or its stop was already taken. It never reaps: WEXITED is not asked for, so a process
// that exited (a zombie, or reaped) is ECHILD. pidfd must be process-scoped (ErrThreadScopedPidfd otherwise).
func WaitPidfdStopped(pidfd int) (syscall.Signal, error) {
	if err := requireProcessScope(pidfd); err != nil {
		return 0, err
	}
	const cldStopped = 5
	var info unix.Siginfo
	var err error
	for {
		err = unix.Waitid(unix.P_PIDFD, pidfd, &info, unix.WSTOPPED|unix.WNOHANG, nil)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return 0, fmt.Errorf("waitid(P_PIDFD, WSTOPPED): %w", err)
	}
	cld := (*sigchldInfo)(unsafe.Pointer(&info))
	if cld.Pid == 0 || cld.Code != cldStopped {
		return 0, nil
	}
	return syscall.Signal(cld.Status), nil
}

// siginfoWaitStatus converts CLD_* codes of a SIGCHLD siginfo into the wait4 status word:
// exited -> status<<8, killed/dumped -> signal (| 0x80 for a core dump).
func siginfoWaitStatus(code, status int32) syscall.WaitStatus {
	const (
		cldExited = 1
		cldDumped = 3
	)
	switch code {
	case cldExited:
		return syscall.WaitStatus(uint32(status)&0xff) << 8
	case cldDumped:
		return syscall.WaitStatus(uint32(status)&0x7f) | 0x80
	default: // CLD_KILLED and anything else the kernel reports for WEXITED
		return syscall.WaitStatus(uint32(status) & 0x7f)
	}
}

// PollPidfd waits until the process behind pidfd exits (the fd becomes readable, Linux 5.3) or timeoutMS
// elapses; a negative timeout blocks. It reports whether the process has exited. EINTR restarts the wait
// with the same timeout. pidfd must be process-scoped (ErrThreadScopedPidfd otherwise): with PIDFD_THREAD
// the fd is readable as soon as that one task becomes a zombie, which would be read here as "exited" while
// the rest of the thread group still runs.
func PollPidfd(pidfd int, timeoutMS int) (exited bool, err error) {
	if err := requireProcessScope(pidfd); err != nil {
		return false, err
	}
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, timeoutMS)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("poll(pidfd): %w", err)
		}
		return n > 0, nil
	}
}

// requireProcessScope rejects a pidfd whose exit semantics are a single thread's. PIDFD_THREAD is kept in
// the file's f_flags — the kernel itself reads it back there (pidfd_poll tests file->f_flags &
// PIDFD_THREAD) — so F_GETFL is an exact answer, not a heuristic. A pidfd from clone3(CLONE_PIDFD), which
// the launcher uses, never carries it.
func requireProcessScope(pidfd int) error {
	fl, err := unix.FcntlInt(uintptr(pidfd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("fcntl(F_GETFL, pidfd): %w", err)
	}
	if fl&PidfdThread != 0 {
		return ErrThreadScopedPidfd
	}
	return nil
}

// ErrNoPidfd is a start that made its child but left no pidfd to own: clone3 stored none through
// SysProcAttr.PidFD (a kernel below the 5.4 floor), or the number it stored could not be owned. The child
// exists, so the caller kills and reaps it through what the start gave it (os/exec's Process).
var ErrNoPidfd = errors.New("sys: the start left no pidfd from clone3(CLONE_PIDFD)")

// StartWithPidfd runs start, one process start through attr, with clone3's CLONE_PIDFD asked for through
// attr.PidFD, and returns the pidfd the clone stored, owned (ADR 0023 A10 F4: this is the one site that adopts
// it, so no caller handles the bare number clone3 writes). On return attr.PidFD is nil, so attr keeps no
// pointer a later start could write a second number through. A start that fails is its error, with any pidfd
// the clone stored before the start undid its child already closed; a start that succeeds without a pidfd to
// own is ErrNoPidfd. A nil attr is an error and start is not run.
func StartWithPidfd(attr *syscall.SysProcAttr, start func() error) (*FD, error) {
	if attr == nil {
		return nil, errors.New("sys: StartWithPidfd: nil SysProcAttr")
	}
	n := -1
	attr.PidFD = &n
	err := start()
	attr.PidFD = nil
	if n < 0 {
		if err == nil {
			err = ErrNoPidfd
		}
		return nil, err
	}
	f, aerr := Adopt(n, "clone3 CLONE_PIDFD")
	switch {
	case err != nil:
		if aerr == nil {
			_ = f.Close() // the start undid its child after clone3; the pidfd it returned is still ours
		}
		return nil, err
	case aerr != nil:
		return nil, fmt.Errorf("%w: %w", ErrNoPidfd, aerr)
	}
	return f, nil
}
