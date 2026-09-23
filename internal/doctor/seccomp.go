// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// seccompSelfTestTimeout bounds D5. The probe is a round trip between two goroutines through the
// kernel; anything slower than this is a kernel that is not going to answer, and the probe must
// report that rather than hang `tego doctor`.
const seccompSelfTestTimeout = 5 * time.Second

// probeSyscall is the syscall D5's throwaway filter notifies on. memfd_create is chosen because the
// Go runtime never issues it, so the only notification the listener can receive is the probe's own;
// the syscall itself never executes, because ADDFD with SEND answers the notification instead.
const probeSyscall = unix.SYS_MEMFD_CREATE

// seccompAddfd mirrors struct seccomp_notif_addfd (Linux 5.9; SECCOMP_ADDFD_FLAG_SEND is 5.14).
// It belongs beside the other notification structs in internal/platform/sys; it lives here until
// that package's owner adds it, because this is the only caller (noted in the ticket).
type seccompAddfd struct {
	ID         uint64
	Flags      uint32
	SrcFD      uint32
	NewFD      uint32
	NewFDFlags uint32
}

// addfdSendSince is the release SECCOMP_ADDFD_FLAG_SEND arrived in: the newest mechanism D5's round
// trip uses, so a kernel at or above it that is built with CONFIG_SECCOMP_FILTER has every piece the
// round trip asks for (NEW_LISTENER is 5.0, ADDFD 5.9). Without CONFIG_SECCOMP_FILTER the release
// promises nothing: seccomp(SECCOMP_SET_MODE_FILTER) is then the kernel's EINVAL stub on any release
// (kernel/seccomp.c; seccomp(2), "not supported by this kernel version or configuration").
// Mechanisms, D1's table, carries the same row from this value.
var addfdSendSince = Version{5, 14, 0}

// ErrSeccompSelfTest is a D5 self-test that did not complete its round trip.
var ErrSeccompSelfTest = errors.New("doctor: seccomp ADDFD/SEND self-test failed")

// errInterrupted is what an attempt's error wraps beside the errno when the kernel took the probe's notification
// back, which is what a signal that reaches a thread of the round trip makes it do, and so says nothing of whether
// the kernel has ADDFD|SEND (seccompRoundTrip).
var errInterrupted = errors.New("the notification was withdrawn, as when a signal interrupts the probe")

// seccompRoundTripAttempts bounds how often D5 makes a round trip again after an interruption. A signal is a chance
// event and independent from one attempt to the next, so a few attempts make an interruption that fails D5 vanishingly
// rare, while one on every attempt is no longer chance and is reported, not retried for ever.
const seccompRoundTripAttempts = 5

// The three calls of an attempt that a signal can disturb are variables, so that a test can make it happen at a moment
// that is otherwise a few microseconds wide (between RECV and ADDFD), or answer with what the kernel then answers.
// Nothing but a test replaces them.
var (
	// installFilter installs the probe's filter on the calling thread and returns its listener.
	installFilter = sys.SeccompSetFilterNewListener
	// notifRecv receives the one notification the probe's thread raised.
	notifRecv = sys.SeccompNotifRecv
	// notifAddfd is the ADDFD ioctl: 0 once the descriptor is in the notified task, else the kernel's errno.
	notifAddfd = seccompNotifAddfd
)

// probeSeccomp is D5: install a real filter with SECCOMP_FILTER_FLAG_NEW_LISTENER on a throwaway
// locked thread, trigger the notified syscall from it, and answer from the prober with
// SECCOMP_IOCTL_NOTIF_ADDFD carrying SECCOMP_ADDFD_FLAG_SEND. EINVAL from the round trip means a
// kernel below 5.14, where `ask` cannot complete a syscall race-free, on a release D1 reads as below
// it; at or above it, the kernel's seccomp configuration or a defect in this probe (R27 D5).
//
// The filter is installed on an OS thread that is locked and never unlocked, and never the main
// thread (onThrowawayThread), so the Go runtime ends the thread when the probing goroutine returns:
// no other goroutine can ever be scheduled onto a thread that still carries the probe's filter, and
// seccompRoundTrip returns only once that thread has ended, or fails D5 when it has not ended within
// seccompSelfTestTimeout, so after a D5 that passed no thread of this process carries the filter or the
// no_new_privs set for it (limits-check-doctor-cli.md §4 ForRun: no kernel object is left behind).
//
// D5's question has two halves: the round trip above, and Yama's ptrace_scope, which decides
// whether the supervisor that filter feeds may read the agent at all. seccompVerdictOn folds them into
// the one Result R27 prints. The two halves are also returned separately — the PtraceState and the
// round trip's own error, nil when it worked — because the tier derivation (derive.go) needs to
// know which half failed, and the Result's prose cannot say that without being parsed.
//
// The verdict reads D1's release, which decides whose failure an EINVAL is. It parses uname again
// rather than taking D1's answer as an argument: the release cannot change between the two probes,
// and the signature the probe runner calls stays the one it has.
func probeSeccomp() (Result, PtraceState, error) {
	pt := probePtrace(yamaScopePath)
	_, _, kernel := probeKernelVersion()
	fd, _, err := seccompRoundTrip()
	return seccompVerdictOn(fd, err, pt, kernel), pt, err
}

// seccompVerdictOn is D5's Result from its two halves: fd and err are what seccompRoundTrip returned, pt is
// what probePtrace found. It is pure so that every branch can be driven without a kernel that fails in the way
// the branch describes. A filter this kernel will not install is the more fundamental answer and is reported
// alone, without Yama's sentence; a working round trip that the supervisor could never use is still a failure,
// because what D5 is really asking is whether the supervisor can do its job.
//
// The release decides only the remedy for a round trip that failed on its own: below
// 5.14 the kernel lacks what the round trip uses and a newer one is the fix, while at or above it a
// newer kernel would change nothing and the fix must name what can. A round trip that was interrupted on every
// attempt (errInterrupted) is neither: the kernel was never asked whether it has ADDFD|SEND, whatever its release.
func seccompVerdictOn(fd int, err error, pt PtraceState, kernel Version) Result {
	known := kernel != Version{}
	old := known && !kernel.AtLeast(addfdSendSince)
	fix := fmt.Sprintf("boot a kernel >= %s (SECCOMP_ADDFD_FLAG_SEND)", addfdSendSince)
	switch {
	case err == nil && pt.Blocked != "":
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("NEW_LISTENER + ADDFD(SEND) round trip on syscall %d returned fd %d, but %s",
				probeSyscall, fd, pt.Blocked),
			Fix: pt.Fix}
	case err == nil:
		return Result{ID: CheckSeccomp, OK: true,
			Detail: fmt.Sprintf("NEW_LISTENER + ADDFD(SEND) round trip on syscall %d returned fd %d; %s",
				probeSyscall, fd, pt.Detail)}
	case errors.Is(err, unix.EINVAL) && old:
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("%v (race-free ask unavailable: %s is below %s)", err, kernel, addfdSendSince), Fix: fix}
	case errors.Is(err, unix.EINVAL) && known:
		// Not a missing feature: this release has every piece of the round trip. What is left is a
		// kernel built without CONFIG_SECCOMP_FILTER, whose seccomp(SET_MODE_FILTER) is an EINVAL stub
		// on every release, or a malformed flag or struct in this probe, and no kernel upgrade fixes
		// either.
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("%v (%s has SECCOMP_ADDFD_FLAG_SEND, so this is a kernel built without "+
				"CONFIG_SECCOMP_FILTER, or a defect in this probe)", err, kernel),
			Fix: seccompConfigFix}
	case errors.Is(err, unix.EINVAL):
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("%v (a kernel below %s, or one built without CONFIG_SECCOMP_FILTER; D1 could "+
				"not read the release to say which)", err, addfdSendSince),
			Fix: fmt.Sprintf("boot a kernel >= %s built with CONFIG_SECCOMP_FILTER=y", addfdSendSince)}
	case errors.Is(err, unix.EACCES):
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("%v (a filter needs no_new_privs or CAP_SYS_ADMIN)", err),
			Fix:    "run without a seccomp filter that already blocks seccomp(2), or grant CAP_SYS_ADMIN"}
	case errors.Is(err, unix.ENOSYS):
		// seccomp(2) is a cond_syscall: a kernel built without CONFIG_SECCOMP answers ENOSYS on every
		// release, and so does an outer filter that answers seccomp(2) with ENOSYS. Both are
		// configuration, not a defect and not a missing release, so neither the bug report below nor
		// a kernel upgrade is the remedy.
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("%v (seccomp(2) is not implemented here: a kernel built without CONFIG_SECCOMP, "+
				"or an outer seccomp filter answering seccomp(2) with ENOSYS)", err),
			Fix: seccompNoSyscallFix}
	case errors.Is(err, unix.EBUSY):
		// seccomp(2), EBUSY: "While installing a new filter, the SECCOMP_FILTER_FLAG_NEW_LISTENER flag
		// was specified, but a previous filter had already been installed with that flag". This
		// process already runs under someone's seccomp supervisor (a tego run, a container
		// runtime), and the kernel allows one listener per filter chain. The kernel is not the
		// problem, so the default "boot a newer kernel" would send the operator the wrong way, and
		// since this answer reaches Report.Fix it has to name the real lever.
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("%v (a seccomp listener is already installed on this process's filter chain)", err),
			Fix:    "run tego outside any seccomp user-notification supervisor (the kernel allows one listener per filter chain)"}
	case errors.Is(err, errInterrupted):
		// seccompRoundTrip repeats an interrupted attempt, so this is the last of its attempts. The errno (ENOENT,
		// EINPROGRESS, ESRCH, EINTR) is how the kernel takes a notification back from a task a signal reached, not a
		// missing feature, so a newer kernel is no remedy on any release. D5 cannot say more than that, so it asks
		// for another run and, if that fails the same way, for a report.
		return Result{ID: CheckSeccomp,
			Detail: fmt.Sprintf("%v, on each of %d attempts", err, seccompRoundTripAttempts),
			Fix:    seccompRerunFix}
	case known && !old:
		// A timeout or an errno the arms above do not know, on a kernel that has every piece: a newer
		// kernel is no remedy for it either.
		return Result{ID: CheckSeccomp, Detail: err.Error(), Fix: seccompRerunFix}
	default:
		return Result{ID: CheckSeccomp, Detail: err.Error(), Fix: fix}
	}
}

// seccompRerunFix is D5's remedy for a failure that names neither a missing release nor a configuration.
const seccompRerunFix = "re-run tego doctor; if D5 fails the same way again on this kernel, report it as a tego bug"

// seccompNoSyscallFix is D5's remedy for ENOSYS from seccomp(2), on any release.
const seccompNoSyscallFix = "boot a kernel built with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y; if this " +
	"kernel has them, run tego outside the sandbox whose seccomp filter answers seccomp(2) with ENOSYS"

// seccompConfigFix is D5's remedy for an EINVAL on a release that has SECCOMP_ADDFD_FLAG_SEND.
const seccompConfigFix = "boot a kernel built with CONFIG_SECCOMP_FILTER=y; if this kernel has it, " +
	"report the EINVAL as a tego bug"

// seccompRoundTrip performs the self-test and returns the fd the notified syscall came back with,
// and thread, the id of the thread the probe's filter went on. It returns only once that thread has
// ended; one that has not ended within seccompSelfTestTimeout fails the probe, since a filtered
// thread would then outlive D5.
//
// A round trip that a signal interrupted is made again, up to seccompRoundTripAttempts times, each on a new
// thread with its own filter and listener, so a retry shares nothing with the attempt it follows. The kernel takes
// a notification back from a task a signal reaches and restarts that task's syscall under a new id
// (seccomp_unotify(2)), and a signal that reaches the prober inside its ADDFD ioctl restarts the ioctl, which then
// meets a notification its first try already marked answered (and the notified thread returns 0, a reply nobody
// sent). Either way a sound round trip ends in ENOENT at RECV or ADDFD, or in EINPROGRESS, ESRCH or EINTR at ADDFD,
// and nothing in it says the kernel lacks anything: SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (5.19) shuts the notified
// thread's window from RECV on, but not its wait before RECV and not the prober's ioctl, and a kernel without it
// leaves all three open. D5 failed once in a guest boot on EINPROGRESS, and a failed round trip leaves doctor and
// run with no tier. A failure that is none of these is the kernel's answer and ends the round trip at once: an
// EINVAL from a release below 5.14 must still name the kernel floor.
func seccompRoundTrip() (fd, thread int, err error) {
	for attempt := 1; ; attempt++ {
		fd, thread, err = seccompRoundTripOnce()
		if !errors.Is(err, errInterrupted) || attempt == seccompRoundTripAttempts {
			return fd, thread, err
		}
	}
}

// seccompRoundTripOnce is one attempt of seccompRoundTrip. Its error wraps errInterrupted when the kernel took the
// probe's notification back; an interruption never outranks a filtered thread that has not ended, which fails the
// attempt as it always has, so no attempt is repeated beside a thread still carrying the filter.
func seccompRoundTripOnce() (fd, thread int, err error) {
	prog, err := notifyOneSyscall(probeSyscall)
	if err != nil {
		return -1, 0, err
	}
	type started struct {
		fd, tid int
		err     error
	}
	listenerCh := make(chan started, 1)
	resultCh := make(chan started, 1)
	// Read here, and not by the thread below, which runs on its own and may outlive a failed attempt: a test that
	// restores the variable when the attempt has returned would race with a read there.
	install := installFilter

	go onThrowawayThread(func() {
		tid := unix.Gettid()
		if err := sys.SetNoNewPrivs(); err != nil {
			listenerCh <- started{-1, tid, fmt.Errorf("%w: %w", ErrSeccompSelfTest, err)}
			return
		}
		fd, err := install(prog)
		listenerCh <- started{fd, tid, err}
		if err != nil {
			return
		}
		// From here on this thread is filtered; the call below notifies and blocks.
		ret, _, errno := unix.Syscall(probeSyscall, 0, 0, 0)
		if errno != 0 {
			resultCh <- started{-1, tid, fmt.Errorf("%w: the notified syscall returned %w", ErrSeccompSelfTest, errno)}
			return
		}
		resultCh <- started{int(ret), tid, nil}
	})

	l := <-listenerCh
	thread = l.tid
	// Deferred before the closes below, so it runs after them: closing the listener answers a notification
	// still pending with ENOSYS (seccomp_notify_detach), so the filtered syscall returns and its goroutine,
	// and with it the thread, ends however this returns. That includes a notification the thread raised again
	// after a signal took the first back.
	defer func() {
		if werr := awaitThreadEnd(thread, seccompSelfTestTimeout); werr != nil && (err == nil || errors.Is(err, errInterrupted)) {
			fd, err = -1, werr
		}
	}()
	if l.err != nil {
		return -1, thread, fmt.Errorf("%w: %w", ErrSeccompSelfTest, l.err)
	}
	listener := l.fd
	defer func() { _ = unix.Close(listener) }()

	donor, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, thread, fmt.Errorf("%w: open /dev/null: %w", ErrSeccompSelfTest, err)
	}
	defer func() { _ = unix.Close(donor) }()

	if err := waitReadable(listener, seccompSelfTestTimeout); err != nil {
		return -1, thread, err
	}
	id, err := answerWithAddfd(listener, donor)
	if err != nil {
		if id != 0 {
			// The filtered thread is still blocked in the kernel; answering releases it.
			_ = sys.SeccompNotifSend(listener, &sys.SeccompNotifResp{ID: id, Error: int32(unix.ENOSYS)})
		}
		return -1, thread, err
	}
	select {
	case r := <-resultCh:
		if r.err != nil {
			return -1, thread, r.err
		}
		_ = unix.Close(r.fd)
		return r.fd, thread, nil
	case <-time.After(seccompSelfTestTimeout):
		return -1, thread, fmt.Errorf("%w: no answer within %s", ErrSeccompSelfTest, seccompSelfTestTimeout)
	}
}

// onThrowawayThread runs fn on an OS thread locked to fn's goroutine for good. It is started with go and
// does nothing after fn, so the goroutine exits still locked, and Go ends the thread rather than hand it
// to another goroutine (runtime.LockOSThread): what fn did to the thread, D5's filter and no_new_privs,
// ends with it.
//
// The main thread is the one Go does not end. When a goroutine exits locked to it, the runtime parks it
// for good instead, fn's changes and all, and the main thread is the thread group leader, whose
// Seccomp and NoNewPrivs lines /proc/self/status reports as the process's (launch's clone diagnostic
// reads that Seccomp line). Landing there, it hands fn to a goroutine of its own, which cannot be
// scheduled on the main thread while this one holds it locked, waits for it, and gives the main thread
// back unchanged, as sys.RunAs does for the thread it switches (internal/platform/sys/threadcreds.go).
// Found in a test binary, where the first D5 ran on the main thread and left /proc/self/status reading
// "Seccomp: 2" for the rest of the process.
func onThrowawayThread(fn func()) {
	runtime.LockOSThread()
	if unix.Gettid() == unix.Getpid() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			onThrowawayThread(fn)
		}()
		<-done
		runtime.UnlockOSThread()
		return
	}
	fn()
}

// awaitThreadEnd returns once thread tid of this process has ended, or an error when it has not within
// timeout. tgkill(2) with signal 0 finds a thread until the kernel has released it and answers ESRCH
// after, when it is no longer among the process's tasks; it needs no /proc, which a sandbox may not mount.
func awaitThreadEnd(tid int, timeout time.Duration) error {
	pid := unix.Getpid()
	deadline := time.Now().Add(timeout)
	for pause := 20 * time.Microsecond; ; pause = min(2*pause, 5*time.Millisecond) {
		err := unix.Tgkill(pid, tid, 0)
		switch {
		case errors.Is(err, unix.ESRCH):
			return nil
		case err != nil:
			// %v, not %w: seccompVerdictOn reads a wrapped errno as seccomp(2)'s answer, which this is not.
			return fmt.Errorf("%w: tgkill(2) the probe's thread %d: %v", ErrSeccompSelfTest, tid, err)
		case time.Now().After(deadline):
			return fmt.Errorf("%w: the probe's filtered thread %d had not ended after %s", ErrSeccompSelfTest, tid, timeout)
		}
		time.Sleep(pause)
	}
}

// waitReadable blocks until the listener has a notification to hand over, or the timeout expires.
// Without it a kernel that accepted the filter but never delivers would leave the ioctl below
// blocked forever, and `tego doctor` would hang instead of reporting. Only POLLIN is a notification:
// seccomp_notify_poll answers EPOLLERR alone when its interruptible lock loses to a signal pending on
// this thread (kernel/seccomp.c, since 5.0; the supervisor's rule, internal/runtime/supervisor/kernel.go),
// and that wait took nothing, so it is asked again until the deadline. POLLHUP is the filtered thread gone
// without a notification, POLLNVAL a listener no longer open: both fail the self-test.
func waitReadable(fd int, timeout time.Duration) error {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("%w: no notification within %s", ErrSeccompSelfTest, timeout)
		}
		n, err := unix.Poll(pfd, int(remaining/time.Millisecond)+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: poll the listener: %w", ErrSeccompSelfTest, err)
		}
		if n == 0 {
			continue
		}
		switch r := pfd[0].Revents; {
		case r&unix.POLLIN != 0:
			return nil
		case r&unix.POLLNVAL != 0:
			return fmt.Errorf("%w: the listener is not open", ErrSeccompSelfTest)
		case r&unix.POLLHUP != 0:
			return fmt.Errorf("%w: the probe's filtered thread left without a notification", ErrSeccompSelfTest)
		}
		// POLLERR alone: a signal interrupted the poll's lock. A pause keeps a repeat from spinning a CPU.
		time.Sleep(time.Millisecond)
	}
}

// answerWithAddfd receives the one pending notification and answers it by installing donor in the
// notified thread, with SECCOMP_ADDFD_FLAG_SEND so the syscall's return value is the new fd. It
// returns the notification id even on failure, so the caller can release the blocked thread.
//
// An error wraps errInterrupted when the kernel's answer is one it gives for a notification it has taken back
// (seccompRoundTrip says which and why). Which of them an interruption leaves depends on where in the round trip it
// fell and on whether the notified thread or the prober took it, so they are one class:
//   - ENOENT from RECV: the notification was withdrawn after the poll that saw it, and none is left to receive.
//   - ENOENT from ADDFD: the id is gone, because the notified thread left its wait without WAIT_KILLABLE_RECV, or
//     because the prober's ioctl restarted after the notified thread had finished with the notification.
//   - EINPROGRESS: the ioctl restarted and found the notification answered by its own first try.
//   - ESRCH: the notified thread was interrupted as the request was queued, which a kernel without cce436aa
//     (WAIT_KILLABLE_RECV's race fix, 2025) can still allow after RECV.
//   - EINTR: a signal was pending when the ioctl took the notification lock, before it did anything.
func answerWithAddfd(listener, donor int) (uint64, error) {
	var n sys.SeccompNotif
	if err := notifRecv(listener, &n); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return 0, fmt.Errorf("%w: %w (%w)", ErrSeccompSelfTest, err, errInterrupted)
		}
		return 0, fmt.Errorf("%w: %w", ErrSeccompSelfTest, err)
	}
	if n.Data.Nr != int32(probeSyscall) {
		return n.ID, fmt.Errorf("%w: notified about syscall %d, expected %d", ErrSeccompSelfTest, n.Data.Nr, probeSyscall)
	}
	addfd := seccompAddfd{
		ID:         n.ID,
		Flags:      unix.SECCOMP_ADDFD_FLAG_SEND,
		SrcFD:      uint32(donor),
		NewFDFlags: unix.O_CLOEXEC,
	}
	switch errno := notifAddfd(listener, &addfd); errno {
	case 0:
		return n.ID, nil
	case unix.ENOENT, unix.EINPROGRESS, unix.ESRCH, unix.EINTR:
		return n.ID, fmt.Errorf("%w: ioctl(SECCOMP_IOCTL_NOTIF_ADDFD, SEND): %w (%w)", ErrSeccompSelfTest, errno, errInterrupted)
	default:
		return n.ID, fmt.Errorf("%w: ioctl(SECCOMP_IOCTL_NOTIF_ADDFD, SEND): %w", ErrSeccompSelfTest, errno)
	}
}

// seccompNotifAddfd is ioctl SECCOMP_IOCTL_NOTIF_ADDFD: 0 once the descriptor is installed in the notified task
// (with SEND, as the notified syscall's return value), else the errno.
func seccompNotifAddfd(listener int, a *seccompAddfd) unix.Errno {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), uintptr(unix.SECCOMP_IOCTL_NOTIF_ADDFD),
		uintptr(unsafe.Pointer(a)))
	return errno
}

// notifyOneSyscall assembles the throwaway filter: guard the architecture, notify exactly one
// syscall number, allow everything else. The architecture guard is the same first instruction every
// production filter starts with (docs/p0/enforce-landlock.md R13): a filter without it would decide
// on a syscall number from a different ABI.
func notifyOneSyscall(nr uintptr) ([]bpf.RawInstruction, error) {
	const (
		offArch = 4 // offsetof(struct seccomp_data, arch)
		offNr   = 0 // offsetof(struct seccomp_data, nr)
	)
	arch, err := auditArch()
	if err != nil {
		return nil, err
	}
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArch, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: arch, SkipTrue: 3},
		bpf.LoadAbsolute{Off: offNr, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(nr), SkipTrue: 1},
		bpf.RetConstant{Val: retUserNotif},
		bpf.RetConstant{Val: retAllow},
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("%w: assemble the probe filter: %w", ErrSeccompSelfTest, err)
	}
	return raw, nil
}

// The two filter return values this probe uses (linux/seccomp.h).
const (
	retAllow     = 0x7fff0000 // SECCOMP_RET_ALLOW
	retUserNotif = 0x7fc00000 // SECCOMP_RET_USER_NOTIF
)

// auditArch is the AUDIT_ARCH_* value of the architecture this binary runs on, the value a seccomp
// filter must compare struct seccomp_data's arch field against before it trusts a syscall number.
// An architecture with no entry here cannot be probed, and says so rather than installing a filter
// that would decide on a number from the wrong ABI.
func auditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return uint32(unix.AUDIT_ARCH_X86_64), nil
	case "arm64":
		return uint32(unix.AUDIT_ARCH_AARCH64), nil
	default:
		return 0, fmt.Errorf("%w: no seccomp architecture guard for GOARCH %s", ErrSeccompSelfTest, runtime.GOARCH)
	}
}
