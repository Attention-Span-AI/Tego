// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// SeccompData mirrors the kernel's struct seccomp_data: the syscall a notification is about.
type SeccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// SeccompNotif mirrors struct seccomp_notif (SECCOMP_IOCTL_NOTIF_RECV, Linux 5.0): one pending
// user-notification. The buffer must be zeroed before RECV; the kernel rejects a dirty one with EINVAL.
// Pid is the thread id (tid) of the calling task in the listener's pid namespace, not its process id.
type SeccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  SeccompData
}

// SeccompNotifResp mirrors struct seccomp_notif_resp (SECCOMP_IOCTL_NOTIF_SEND): the answer to one
// notification. Flags SECCOMP_USER_NOTIF_FLAG_CONTINUE (Linux 5.5) lets the syscall run unchanged.
type SeccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// SeccompNotifSizes mirrors struct seccomp_notif_sizes (seccomp SECCOMP_GET_NOTIF_SIZES): the byte sizes
// the running kernel uses for the three structs above, so a layout mismatch is detected at startup.
type SeccompNotifSizes struct {
	Notif     uint16
	NotifResp uint16
	Data      uint16
}

// ErrSeccompNotifLayout reports that the running kernel's notification structs are not the ones this build
// decodes. Callers match it to fail a run at startup rather than let a listener be created that no RECV can
// read: the struct size is encoded in the ioctl number, so a mismatch makes SECCOMP_IOCTL_NOTIF_RECV fall
// through seccomp_notify_ioctl's default case with EINVAL on the very first notification.
var ErrSeccompNotifLayout = errors.New("sys: kernel seccomp notification layout differs from this build")

// getNotifSizes is the SECCOMP_GET_NOTIF_SIZES syscall as a variable so a test can present a kernel whose
// layout disagrees with this build; nothing but a test ever replaces it.
var getNotifSizes = SeccompGetNotifSizes

// SeccompGetNotifSizes asks the kernel for its notification struct sizes (seccomp(SECCOMP_GET_NOTIF_SIZES),
// Linux 5.0). It needs no privilege and installs nothing.
func SeccompGetNotifSizes() (SeccompNotifSizes, error) {
	var s SeccompNotifSizes
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&s)))
	if errno != 0 {
		return SeccompNotifSizes{}, fmt.Errorf("seccomp(SECCOMP_GET_NOTIF_SIZES): %w", errno)
	}
	return s, nil
}

// CheckSeccompNotifLayout verifies that the kernel's struct sizes match the Go types in this package,
// so a notification is never decoded through a mismatched layout.
func CheckSeccompNotifLayout() error {
	s, err := getNotifSizes()
	if err != nil {
		return err
	}
	want := SeccompNotifSizes{
		Notif:     uint16(unsafe.Sizeof(SeccompNotif{})),
		NotifResp: uint16(unsafe.Sizeof(SeccompNotifResp{})),
		Data:      uint16(unsafe.Sizeof(SeccompData{})),
	}
	if s != want {
		return fmt.Errorf("%w: kernel sizes %+v, this build %+v", ErrSeccompNotifLayout, s, want)
	}
	return nil
}

// SeccompSetFilterNewListener installs prog as a seccomp filter on the calling thread with
// SECCOMP_FILTER_FLAG_NEW_LISTENER (seccomp(SECCOMP_SET_MODE_FILTER), Linux 5.0), plus
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV where the kernel has it (5.19), and returns the
// user-notification listener fd (O_CLOEXEC). No TSYNC: the flag pair is EINVAL, and the single locked
// child-stage thread execs right after. Requires no_new_privs or CAP_SYS_ADMIN (else EACCES); a thread whose
// filter chain already has a listener gets EBUSY. The filter survives execve.
func SeccompSetFilterNewListener(prog []bpf.RawInstruction) (int, error) {
	// seccomp_unotify(2) requires the supervisor to size its buffers from SECCOMP_GET_NOTIF_SIZES rather
	// than from its own build. Checking it here, where the listener is born, is the only place that covers
	// every listener by construction: a mismatch otherwise surfaces as EINVAL on the first NOTIF_RECV,
	// after the agent is already running, and a receive loop that reads EINVAL as "listener closed" ends
	// the run reporting success with an empty ledger. The check costs one syscall, needs no privilege and
	// installs nothing.
	if err := CheckSeccompNotifLayout(); err != nil {
		return -1, err
	}
	if len(prog) == 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER): empty program: %w", unix.EINVAL)
	}
	if len(prog) > unix.BPF_MAXINSNS {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER): %d instructions exceed BPF_MAXINSNS: %w", len(prog), unix.EINVAL)
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	// WAIT_KILLABLE_RECV (Linux 5.19) closes docs/p0/supervisor.md E35's double side effect: once the
	// supervisor has received a notification, the target ignores non-fatal signals until the answer
	// arrives, so a signal can no longer withdraw a connect or send the supervisor has already performed
	// and have the kernel restart it. A kernel that predates the flag — the 5.14 floor, RHEL 9 — answers
	// EINVAL for the unknown bit, and the listener is then installed exactly as before. EINVAL is also a
	// malformed program's answer, which the second attempt returns unchanged. The flag had a race of its
	// own until 2025 (cce436aa, "seccomp: Fix a race with WAIT_KILLABLE_RECV if the tracer replies too
	// fast"); on a kernel without that fix the residual window stays where it was without the flag.
	//
	// The flag has a cost, taken on purpose. From the RECV until the answer the target's non-fatal signals
	// wait, and for a relayed connect that is the relay's whole duration, which has no deadline
	// (docs/p0/supervisor.md E35 and §4: up to the ~127 s SYN retry schedule against a blackholed route).
	// A SIGINT or SIGTERM the agent handles, an alarm() timeout and SIGSTOP all wait for it. A fatal
	// signal still ends it — SIGKILL, and any signal whose default action terminates and that has no
	// handler — and that is what tego stop escalates to after stop_grace.
	fd, errno := seccompSetFilter(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER|unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, &fprog)
	if errno == unix.EINVAL {
		fd, errno = seccompSetFilter(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog)
	}
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER, NEW_LISTENER, %d insns): %w", len(prog), errno)
	}
	return fd, nil
}

// SeccompNewListenerFD is SeccompSetFilterNewListener born a strict owner: a listener is strict wherever it
// lives (ADR 0023 A1), so its Close never waits on a lease and never silently defers.
func SeccompNewListenerFD(prog []bpf.RawInstruction) (*FD, error) {
	return Strict(Own(SeccompSetFilterNewListener(prog)))
}

// seccompSetFilter is the one seccomp(SECCOMP_SET_MODE_FILTER) call, behind a variable so the flag
// fallback above is unit-tested without installing a filter on the test's thread.
var seccompSetFilter = func(flags uintptr, fprog *unix.SockFprog) (int, unix.Errno) {
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(fprog)))
	return int(fd), errno
}

// SeccompNotifRecv blocks until one notification arrives on the listener fd and fills n
// (ioctl SECCOMP_IOCTL_NOTIF_RECV). n is zeroed first as the kernel requires. EINTR restarts the wait;
// ENOENT means the target died before the notification was read.
func SeccompNotifRecv(fd int, n *SeccompNotif) error {
	for {
		*n = SeccompNotif{}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_RECV, uintptr(unsafe.Pointer(n)))
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_RECV): %w", errno)
		}
		return nil
	}
}

// notifIoctl is the one ioctl SeccompNotifSend and SeccompNotifIDValid make. notifIoctlFake, which only a test
// sets, answers in its place, so their EINTR retry is unit-tested without a listener. The fake is never given
// the descriptor number: the number goes to the system call alone, so an owner may lend it in (ADR 0023).
func notifIoctl(fd int, req uint, arg unsafe.Pointer) unix.Errno {
	if notifIoctlFake != nil {
		return notifIoctlFake(req, arg)
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	return errno
}

var notifIoctlFake func(req uint, arg unsafe.Pointer) unix.Errno

// notifIoctlRetry is notifIoctl with EINTR retried. seccomp_notify_send and seccomp_notify_id_valid take the
// filter's notify_lock with mutex_lock_interruptible and return -EINTR, not -ERESTARTSYS, when a signal is
// pending on the calling thread (the Go runtime's SIGURG preemption is enough), so the kernel never restarts
// them. Nothing was done when that happens, so the call is made again; returned to the caller, it read as a
// dead target, and a notification nobody answered kept its task trapped until the listener closed.
func notifIoctlRetry(fd int, req uint, arg unsafe.Pointer) unix.Errno {
	for {
		if errno := notifIoctl(fd, req, arg); errno != unix.EINTR {
			return errno
		}
	}
}

// SeccompNotifSend answers one notification (ioctl SECCOMP_IOCTL_NOTIF_SEND). ENOENT means the target
// was killed or the id was already answered. EINTR is retried (notifIoctlRetry).
func SeccompNotifSend(fd int, r *SeccompNotifResp) error {
	if errno := notifIoctlRetry(fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(r)); errno != 0 {
		return fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_SEND, id=%d): %w", r.ID, errno)
	}
	return nil
}

// SeccompNotifIDValid reports whether notification id is still pending (ioctl SECCOMP_IOCTL_NOTIF_ID_VALID):
// the bracket a supervisor uses around reads of the target's memory. A dead target yields false, nil. EINTR
// is retried (notifIoctlRetry).
func SeccompNotifIDValid(fd int, id uint64) (bool, error) {
	switch errno := notifIoctlRetry(fd, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&id)); errno {
	case 0:
		return true, nil
	case unix.ENOENT:
		return false, nil
	default:
		return false, fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID, id=%d): %w", id, errno)
	}
}

// SeccompUserNotifFdSyncWakeUp is SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP (Linux 6.6): the notified task hands
// the CPU straight to the supervisor instead of going through a full wake-up, which took one round trip
// from ~12 us to ~3 us when it was measured upstream (commit 48a1084ade02, Andrei Vagin).
const SeccompUserNotifFdSyncWakeUp = unix.SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP

// SeccompNotifSetFlags sets the listener's flags (ioctl SECCOMP_IOCTL_NOTIF_SET_FLAGS, Linux 6.6). A caller
// that wants the sync wake-up must probe rather than assume — the runtime's rule for every mechanism above
// the tested 6.1 floor — and the probe cannot read the errno alone: a kernel below 6.6 does not know this
// ioctl number and answers from seccomp_notify_ioctl's default case with EINVAL, the same errno a 6.6 kernel
// gives for an unknown flag (measured on 6.17; ENOTTY means the fd was not a listener at all). Nothing here
// decides whether to ask for the flag; that is the supervisor's call.
//
// Unlike every other notification ioctl in this file, the flags go in the ioctl argument *by value*:
// seccomp_notify_ioctl passes `arg` straight to seccomp_notify_set_flags, which compares it against the
// known-flag mask, even though the SECCOMP_IOW(4, __u64) declaration reads like a pointer. Handing it a
// pointer returns EINVAL, because the address has bits outside that mask — verified on 6.17 against both
// forms, with SECCOMP_IOCTL_NOTIF_ID_VALID (a genuine pointer) as the control.
func SeccompNotifSetFlags(fd int, flags uint64) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_SET_FLAGS, uintptr(flags))
	if errno != 0 {
		return fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_SET_FLAGS, flags=%#x): %w", flags, errno)
	}
	return nil
}

// ErrNotifReplyLost is what SeccompNotifAddfdSend wraps when the kernel holds the notification as answered but
// installed no descriptor for it: the notified syscall has returned, or will return, a value nobody sent (0,
// which reads as descriptor 0), or has been restarted under a new id. The caller must not answer the
// notification again, and must not say what the notified task saw: it does not know.
var ErrNotifReplyLost = errors.New("the kernel took the notification as answered without installing the descriptor")

// seccompNotifAddfd mirrors struct seccomp_notif_addfd (SECCOMP_IOCTL_NOTIF_ADDFD, Linux 5.9).
type seccompNotifAddfd struct {
	ID                              uint64
	Flags, SrcFD, NewFD, NewFDFlags uint32
}

// addfdIoctl is the SECCOMP_IOCTL_NOTIF_ADDFD ioctl SeccompNotifAddfdSend makes. addfdIoctlFake, which only a
// test sets, answers in its place, so that a test can make a signal reach the calling thread inside it, the
// moment the kernel race below needs and that is otherwise a few microseconds wide. Like notifIoctlFake it is
// never given the descriptor number.
func addfdIoctl(fd int, arg unsafe.Pointer) (int, unix.Errno) {
	if addfdIoctlFake != nil {
		return addfdIoctlFake(arg)
	}
	n, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ADDFD, uintptr(arg))
	return int(n), errno
}

var addfdIoctlFake func(arg unsafe.Pointer) (int, unix.Errno)

// allSignals is every signal: rt_sigprocmask leaves SIGKILL and SIGSTOP unblocked whatever the set says.
var allSignals = unix.Sigset_t{Val: [len(unix.Sigset_t{}.Val)]uint64{^uint64(0)}}

// SeccompNotifAddfdSend injects a duplicate of src into the task that raised notification id and completes the
// notified syscall with the new descriptor as its result, in one ioctl (SECCOMP_IOCTL_NOTIF_ADDFD with
// SECCOMP_ADDFD_FLAG_SEND, Linux 5.14); cloexec gives the new descriptor O_CLOEXEC.
//
// The ioctl runs with every signal blocked on its thread, because the kernel mishandles one that arrives while the
// ioctl waits for the notified task to take the descriptor (kernel/seccomp.c, seccomp_notify_addfd, through 6.17 at
// least): it has already marked the notification answered and woken the task, takes the queued descriptor back,
// and returns -ERESTARTSYS. The task wakes to an answered notification with no descriptor and its syscall returns
// 0, a reply nobody sent; the Go runtime's handlers carry SA_RESTART, so the ioctl is made again, meets a
// notification it already answered and fails with EINPROGRESS, or ENOENT once the task has gone on. An agent's
// approved open came back as descriptor 0 that way, which its write then met as EBADF (custom-agent POC, one in
// about 2,800 approvals; the Go runtime signals its threads for preemption and profiling, and a busy run's
// SIGCHLD can land on any thread). Blocked, a signal stays pending until the ioctl is done and is delivered then.
// SIGKILL, SIGSTOP, a cgroup freeze and a ptrace interrupt still reach the thread; the first ends the process,
// and the others are rare enough that what they leave is reported, not prevented: EINPROGRESS here wraps
// ErrNotifReplyLost. EINTR, which the ioctl returns only before it has queued anything (mutex_lock_interruptible
// on notify_lock), is retried.
func SeccompNotifAddfdSend(fd int, id uint64, src int, cloexec bool) (int, error) {
	a := seccompNotifAddfd{ID: id, Flags: unix.SECCOMP_ADDFD_FLAG_SEND, SrcFD: uint32(src)}
	if cloexec {
		a.NewFDFlags = unix.O_CLOEXEC
	}
	n, errno := addfdNoSignals(fd, unsafe.Pointer(&a))
	switch {
	case errno == unix.EINPROGRESS:
		return -1, fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_ADDFD, id=%d): %w: %w", id, ErrNotifReplyLost, errno)
	case errno != 0:
		return -1, fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_ADDFD, id=%d): %w", id, errno)
	}
	return n, nil
}

// addfdNoSignals makes the ADDFD ioctl on a locked thread with every signal blocked, and gives the thread its mask
// back before it is unlocked, so no other goroutine ever runs with it. A mask that cannot be set is not worked
// around: the ioctl is not made, and the caller refuses the open as it would any delivery that failed.
func addfdNoSignals(fd int, arg unsafe.Pointer) (int, unix.Errno) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var old unix.Sigset_t
	if err := unix.PthreadSigmask(unix.SIG_SETMASK, &allSignals, &old); err != nil {
		var errno unix.Errno
		if !errors.As(err, &errno) {
			errno = unix.EINVAL
		}
		return -1, errno
	}
	defer func() { _ = unix.PthreadSigmask(unix.SIG_SETMASK, &old, nil) }()
	for {
		n, errno := addfdIoctl(fd, arg)
		if errno != unix.EINTR {
			return n, errno
		}
	}
}
