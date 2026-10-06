// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// R27 D5: a signal that reaches a thread of the round trip makes the kernel take the notification back, and the
// round trip is made again on a fresh thread (seccompRoundTrip). These tests drive that against the real kernel,
// where the window can be held open (a signal between RECV and ADDFD, an ADDFD that finds its notification
// answered) or hit with signals as fast as they can be sent (the prober inside its ADDFD, the notified thread
// before its RECV), and answer in the kernel's place where it cannot be (every errno one interruption can leave).

// replaceSeam sets *p to v until the test ends.
func replaceSeam[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// installWithoutWaitKillableRecv is sys.SeccompSetFilterNewListener without SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV:
// the listener a kernel below 5.19 gives, where the notified task still takes a signal after RECV, takes its
// notification back and restarts the syscall. A kernel with the flag shuts that window, so the window is held open
// here to test what D5 does when a signal falls in it.
func installWithoutWaitKillableRecv(prog []bpf.RawInstruction) (int, error) {
	if err := sys.CheckSeccompNotifLayout(); err != nil {
		return -1, err
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER, NEW_LISTENER): %w", errno)
	}
	return int(fd), nil
}

// interruptNotifiedThread sends the thread that raised n a signal and reports whether the kernel took n back for
// it within wait: SECCOMP_IOCTL_NOTIF_ID_VALID turns false once the thread has left its wait for the answer, which
// it does, restarting its syscall under a new id, only when the signal finds it in an interruptible wait. SIGURG
// is the Go runtime's own preemption signal, which its handler takes with SA_RESTART and otherwise ignores, so
// the test process is disturbed no further than that one thread's syscall.
func interruptNotifiedThread(t *testing.T, listener int, n *sys.SeccompNotif, wait time.Duration) bool {
	t.Helper()
	if err := unix.Tgkill(unix.Getpid(), int(n.Pid), unix.SIGURG); err != nil {
		t.Fatalf("tgkill the notified thread %d: %v", n.Pid, err)
	}
	for deadline := time.Now().Add(wait); ; time.Sleep(100 * time.Microsecond) {
		valid, err := sys.SeccompNotifIDValid(listener, n.ID)
		if err != nil {
			t.Fatalf("SECCOMP_IOCTL_NOTIF_ID_VALID: %v", err)
		}
		if !valid {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// signalStorm is a goroutine that sends SIGURG, as fast as it can, to the thread it is aimed at, and none while it is
// aimed at no thread. It spins, so that a thread is signalled the moment it is aimed at: a sender started for the
// occasion is not yet running when a window of microseconds has gone by, and a window that nothing was sent in tests
// nothing. A thread is interrupted whenever a signal finds it asleep in a syscall that a signal can interrupt.
type signalStorm struct {
	target     atomic.Int64
	quit, done chan struct{}
}

// newSignalStorm starts the sender, aimed at nothing, until the test ends. The sender has to be running on a CPU of its
// own while the thread it signals sleeps in a syscall: on one CPU the notified thread answers as soon as the prober
// sleeps and the window is shut before the sender is next scheduled (measured, with the process pinned to one CPU),
// and with one Go processor the sender runs only after the syscall. So the test needs two CPUs, and gives the
// runtime a second processor when GOMAXPROCS is lower.
func newSignalStorm(t *testing.T) *signalStorm {
	if runtime.NumCPU() < 2 {
		t.Skip("a signal storm needs a second CPU for its sender")
	}
	if prev := runtime.GOMAXPROCS(0); prev < 2 {
		runtime.GOMAXPROCS(2)
		t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
	}
	s := &signalStorm{quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		pid := unix.Getpid()
		for {
			select {
			case <-s.quit:
				return
			default:
			}
			if tid := int(s.target.Load()); tid != 0 {
				_ = unix.Tgkill(pid, tid, unix.SIGURG)
			} else {
				runtime.Gosched()
			}
		}
	}()
	t.Cleanup(func() {
		close(s.quit)
		<-s.done
	})
	return s
}

// aim points the storm at thread tid, or at nothing for 0.
func (s *signalStorm) aim(tid int) { s.target.Store(int64(tid)) }

// stormTrips bounds the round trips a signal-storm test makes while it waits for the storm to land in its window. It
// lands in about one trip of eight at the prober's ADDFD and two of five at the notified thread's RECV (measured on
// 6.17, four CPUs), so the bound is never what ends a pass, even on a machine a hundred times less lucky; a test that
// reaches it has interrupted nothing and says so.
const stormTrips = 5000

// TestSeccompRoundTripSurvivesASignalBetweenRecvAndAddfd interrupts the notified thread between RECV and ADDFD and
// wants D5 to pass. Without WAIT_KILLABLE_RECV the signal takes the notification back, so the ADDFD that follows
// asks for an id the kernel no longer has (ENOENT) while the thread raises a new one: the first attempt cannot
// complete and the second must. With the flag, which the filter D5 installs asks for where the kernel has it, the
// thread keeps waiting and the first attempt is undisturbed (5.19 and newer), or it is retried (older kernels).
func TestSeccompRoundTripSurvivesASignalBetweenRecvAndAddfd(t *testing.T) {
	roundTripOrSkip(t)
	for _, tc := range []struct {
		name      string
		install   func([]bpf.RawInstruction) (int, error)
		withdraws bool // the filter leaves the thread's wait after RECV interruptible, on every kernel
	}{
		{"the filter D5 installs", sys.SeccompSetFilterNewListener, false},
		{"a filter without WAIT_KILLABLE_RECV", installWithoutWaitKillableRecv, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replaceSeam(t, &installFilter, tc.install)
			var recvs int
			var withdrawn bool
			replaceSeam(t, &notifRecv, func(listener int, n *sys.SeccompNotif) error {
				if err := sys.SeccompNotifRecv(listener, n); err != nil {
					return err
				}
				if recvs++; recvs == 1 {
					// A kernel that withdraws does it at once; one that does not is given a moment to show it.
					wait := 100 * time.Millisecond
					if tc.withdraws {
						wait = seccompSelfTestTimeout
					}
					withdrawn = interruptNotifiedThread(t, listener, n, wait)
				}
				return nil
			})
			fd, _, err := seccompRoundTrip()
			if err != nil {
				t.Fatalf("D5 failed after the notified thread was interrupted between RECV and ADDFD (the kernel took the notification back: %v): %v",
					withdrawn, err)
			}
			if tc.withdraws && (!withdrawn || recvs != 2) {
				t.Errorf("the notification was taken back: %v, and the round trip was made %d times, want true and 2", withdrawn, recvs)
			}
			t.Logf("round trip returned fd %d after %d attempt(s); the kernel took the notification back: %v", fd, recvs, withdrawn)
		})
	}
}

// TestSeccompRoundTripSurvivesAnAddfdThatFindsItsNotificationAnswered is the failure D5 showed in a guest boot,
// ADDFD answering EINPROGRESS. A signal that reaches the prober inside its ADDFD ioctl restarts the ioctl, and the
// kernel had marked the notification answered before it waited, so the restart finds a notification that has been
// replied to (EINPROGRESS) or has already left the list (ENOENT), while the notified thread returns 0 from a reply
// nobody sent. A reply of 0 sent here leaves the same state, and the ioctl after it is the restart's.
func TestSeccompRoundTripSurvivesAnAddfdThatFindsItsNotificationAnswered(t *testing.T) {
	roundTripOrSkip(t)
	var addfds int
	replaceSeam(t, &notifAddfd, func(listener int, a *seccompAddfd) unix.Errno {
		if addfds++; addfds > 1 {
			return seccompNotifAddfd(listener, a)
		}
		if err := sys.SeccompNotifSend(listener, &sys.SeccompNotifResp{ID: a.ID}); err != nil {
			t.Fatalf("answering the notification the way an interrupted ADDFD leaves it: %v", err)
		}
		errno := seccompNotifAddfd(listener, a)
		if errno != unix.ENOENT && errno != unix.EINPROGRESS {
			t.Errorf("ADDFD for a notification already answered: %v, want ENOENT or EINPROGRESS", errno)
		}
		return errno
	})
	if _, _, err := seccompRoundTrip(); err != nil {
		t.Fatalf("D5 failed when ADDFD found its notification answered: %v", err)
	}
	if addfds != 2 {
		t.Errorf("%d ADDFD ioctls, want 2: the first found the notification answered and the second belonged to a new round trip", addfds)
	}
}

// TestSeccompRoundTripSurvivesSignalsAtTheProbersAddfd sends the prober's own thread signals for as long as its first
// ADDFD runs, so the kernel restarts the ioctl as it does when a signal lands in it, and wants D5 to pass. Only the
// first ADDFD of a round trip is under the storm, so the attempt after an interruption is undisturbed. It goes on
// until one round trip has had its ADDFD interrupted, which is the point, and fails if none has: a test whose
// signals never land shows nothing.
func TestSeccompRoundTripSurvivesSignalsAtTheProbersAddfd(t *testing.T) {
	roundTripOrSkip(t)
	runtime.LockOSThread() // the thread signalled is this goroutine's
	defer runtime.UnlockOSThread()
	prober := unix.Gettid()
	storm := newSignalStorm(t)
	var addfds int
	var first unix.Errno
	replaceSeam(t, &notifAddfd, func(listener int, a *seccompAddfd) unix.Errno {
		if addfds++; addfds > 1 {
			return seccompNotifAddfd(listener, a)
		}
		storm.aim(prober)
		first = seccompNotifAddfd(listener, a)
		storm.aim(0)
		return first
	})
	for trip := 1; trip <= stormTrips; trip++ {
		addfds, first = 0, 0
		if _, _, err := seccompRoundTrip(); err != nil {
			t.Fatalf("round trip %d failed (its first ADDFD answered %v): %v", trip, first, err)
		}
		if first != 0 {
			t.Logf("round trip %d: the first ADDFD was interrupted (%v) and D5 passed on attempt %d", trip, first, addfds)
			return
		}
	}
	t.Fatalf("none of %d round trips had its ADDFD interrupted: the signals never landed, so this test interrupted nothing", stormTrips)
}

// TestSeccompRoundTripSurvivesSignalsAtTheNotifiedThread sends the notified thread signals from the moment its filter
// is installed until its notification has been received, so the kernel withdraws and re-raises the notification
// as it does when a signal lands in the wait before RECV, and wants D5 to pass. Only the first attempt is under the
// storm. It goes on until one round trip has had its RECV find nothing to receive (ENOENT), and fails if none has.
func TestSeccompRoundTripSurvivesSignalsAtTheNotifiedThread(t *testing.T) {
	roundTripOrSkip(t)
	storm := newSignalStorm(t)
	var attempts int
	var firstRecv error
	replaceSeam(t, &installFilter, func(prog []bpf.RawInstruction) (int, error) {
		fd, err := sys.SeccompSetFilterNewListener(prog)
		if attempts++; attempts == 1 && err == nil {
			storm.aim(unix.Gettid())
		}
		return fd, err
	})
	replaceSeam(t, &notifRecv, func(listener int, n *sys.SeccompNotif) error {
		err := sys.SeccompNotifRecv(listener, n)
		if attempts == 1 {
			firstRecv = err
			storm.aim(0)
		}
		return err
	})
	for trip := 1; trip <= stormTrips; trip++ {
		attempts, firstRecv = 0, nil
		_, _, err := seccompRoundTrip()
		storm.aim(0) // an attempt that failed before its RECV
		if err != nil {
			t.Fatalf("round trip %d failed (its first RECV answered %v): %v", trip, firstRecv, err)
		}
		if firstRecv != nil {
			t.Logf("round trip %d: the first RECV found no notification (%v) and D5 passed on attempt %d", trip, firstRecv, attempts)
			return
		}
	}
	t.Fatalf("none of %d round trips had its RECV interrupted: the signals never landed, so this test interrupted nothing", stormTrips)
}

// firstCalls counts the calls of a seam, which the prober makes one at a time, and answers the first n of them in the
// kernel's place.
type firstCalls struct{ n, calls int }

// instead counts one call and reports whether it is one to answer in the kernel's place.
func (f *firstCalls) instead() bool {
	f.calls++
	return f.calls <= f.n
}

// TestSeccompRoundTripRepeatsAnInterruptedAttempt: each answer the kernel gives for a notification it took back is
// repeated, once and then as often as the bound allows in a row.
func TestSeccompRoundTripRepeatsAnInterruptedAttempt(t *testing.T) {
	roundTripOrSkip(t)
	recvENOENT := func(t *testing.T, f *firstCalls) {
		replaceSeam(t, &notifRecv, func(listener int, n *sys.SeccompNotif) error {
			if f.instead() {
				return fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_RECV, fd=%d): %w", listener, unix.ENOENT)
			}
			return sys.SeccompNotifRecv(listener, n)
		})
	}
	addfdErrno := func(errno unix.Errno) func(*testing.T, *firstCalls) {
		return func(t *testing.T, f *firstCalls) {
			replaceSeam(t, &notifAddfd, func(listener int, a *seccompAddfd) unix.Errno {
				if f.instead() {
					return errno
				}
				return seccompNotifAddfd(listener, a)
			})
		}
	}
	for _, tc := range []struct {
		name   string
		inject func(*testing.T, *firstCalls)
	}{
		{"RECV finds no notification (ENOENT)", recvENOENT},
		{"ADDFD: the id is gone (ENOENT)", addfdErrno(unix.ENOENT)},
		{"ADDFD: the notification is answered (EINPROGRESS)", addfdErrno(unix.EINPROGRESS)},
		{"ADDFD: the task left its wait (ESRCH)", addfdErrno(unix.ESRCH)},
		{"ADDFD: the ioctl was interrupted (EINTR)", addfdErrno(unix.EINTR)},
	} {
		for _, interruptions := range []int{1, seccompRoundTripAttempts - 1} {
			t.Run(fmt.Sprintf("%s, %d in a row", tc.name, interruptions), func(t *testing.T) {
				f := &firstCalls{n: interruptions}
				tc.inject(t, f)
				if _, _, err := seccompRoundTrip(); err != nil {
					t.Fatalf("D5 failed after %d interruptions, which its %d attempts allow: %v", interruptions, seccompRoundTripAttempts, err)
				}
				if f.calls != interruptions+1 {
					t.Errorf("the seam was called %d times, want %d: %d interrupted attempts and the one that completed",
						f.calls, interruptions+1, interruptions)
				}
			})
		}
	}
}

// TestSeccompRoundTripAttemptsAreBounded: an interruption on every attempt fails D5 after exactly the bound, with
// the errno the kernel gave, and every attempt's thread has ended by then.
func TestSeccompRoundTripAttemptsAreBounded(t *testing.T) {
	roundTripOrSkip(t)
	var mu sync.Mutex
	var threads []int
	replaceSeam(t, &installFilter, func(prog []bpf.RawInstruction) (int, error) {
		mu.Lock()
		threads = append(threads, unix.Gettid())
		mu.Unlock()
		return sys.SeccompSetFilterNewListener(prog)
	})
	f := &firstCalls{n: 1 << 30}
	replaceSeam(t, &notifAddfd, func(int, *seccompAddfd) unix.Errno {
		f.instead()
		return unix.EINPROGRESS
	})
	_, thread, err := seccompRoundTrip()
	if err == nil {
		t.Fatal("D5 passed although every attempt was interrupted")
	}
	if f.calls != seccompRoundTripAttempts {
		t.Errorf("%d attempts, want %d", f.calls, seccompRoundTripAttempts)
	}
	for _, want := range []error{ErrSeccompSelfTest, errInterrupted, unix.EINPROGRESS} {
		if !errors.Is(err, want) {
			t.Errorf("error %v does not wrap %v", err, want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(threads) != seccompRoundTripAttempts {
		t.Fatalf("%d filtered threads, want one for each of the %d attempts", len(threads), seccompRoundTripAttempts)
	}
	if thread != threads[len(threads)-1] {
		t.Errorf("returned thread %d, want the last attempt's, %d", thread, threads[len(threads)-1])
	}
	for _, tid := range threads {
		if err := unix.Tgkill(unix.Getpid(), tid, 0); !errors.Is(err, unix.ESRCH) {
			t.Errorf("an attempt's thread %d is still a thread of this process (tgkill: %v)", tid, err)
		}
	}
}

// TestSeccompRoundTripDoesNotRepeatTheKernelsAnswer: an errno that is not the kernel taking a notification back is
// the answer to the question D5 asks, and a retry would only hide it, EINVAL above all: a release below 5.14 has
// no SECCOMP_ADDFD_FLAG_SEND and answers EINVAL, which must still reach doctor as the kernel floor.
func TestSeccompRoundTripDoesNotRepeatTheKernelsAnswer(t *testing.T) {
	roundTripOrSkip(t)
	fine := PtraceState{Scope: yamaRelational, Detail: "yama ptrace_scope=1"}
	for _, errno := range []unix.Errno{unix.EINVAL, unix.EACCES, unix.ENOSYS, unix.EBUSY, unix.EBADF, unix.EFAULT, unix.ENOTTY} {
		t.Run(errno.Error(), func(t *testing.T) {
			f := &firstCalls{n: 1 << 30}
			replaceSeam(t, &notifAddfd, func(int, *seccompAddfd) unix.Errno {
				f.instead()
				return errno
			})
			_, _, err := seccompRoundTrip()
			if !errors.Is(err, errno) || errors.Is(err, errInterrupted) || !errors.Is(err, ErrSeccompSelfTest) {
				t.Fatalf("error %v, want the kernel's %v as D5's own, and not an interruption", err, errno)
			}
			if f.calls != 1 {
				t.Errorf("%d attempts, want 1", f.calls)
			}
		})
	}

	// The real kernel's EINVAL for a flag it does not have, which is what a release between 5.9 and 5.13 answers for
	// SECCOMP_ADDFD_FLAG_SEND: the remedy stays the kernel floor below 5.14, and does not on a release that has it.
	// An interruption before it does not hide it: the attempt after the interruption meets the same EINVAL.
	for _, tc := range []struct {
		name          string
		interruptions int // injected ENOENTs before the kernel is asked
	}{
		{"the kernel's own EINVAL", 0},
		{"an interruption before it", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &firstCalls{n: tc.interruptions}
			replaceSeam(t, &notifAddfd, func(listener int, a *seccompAddfd) unix.Errno {
				if f.instead() {
					return unix.ENOENT
				}
				a.Flags |= 1 << 8
				return seccompNotifAddfd(listener, a)
			})
			_, _, err := seccompRoundTrip()
			if !errors.Is(err, unix.EINVAL) || errors.Is(err, errInterrupted) {
				t.Fatalf("an ADDFD flag the kernel does not know: %v, want its EINVAL", err)
			}
			if want := tc.interruptions + 1; f.calls != want {
				t.Errorf("%d attempts, want %d: the kernel's EINVAL was repeated", f.calls, want)
			}
			if r := seccompVerdictOn(-1, err, fine, Version{5, 10, 0}); r.OK || r.Fix != "boot a kernel >= 5.14.0 (SECCOMP_ADDFD_FLAG_SEND)" {
				t.Errorf("below 5.14 the remedy is %q (%+v), want the kernel floor", r.Fix, r)
			}
			if r := seccompVerdictOn(-1, err, fine, Version{6, 17, 0}); r.OK || r.Fix != seccompConfigFix {
				t.Errorf("at 6.17 the remedy is %q (%+v), want %q", r.Fix, r, seccompConfigFix)
			}
		})
	}
}

// TestSeccompInterruptedOnEveryAttemptIsNotAKernelGap: the failure D5 reports after its last attempt was interrupted
// carries the kernel's errno and the number of attempts, and its remedy is to re-run, on every release: the kernel
// was never shown to lack anything, so neither the kernel floor nor a configuration is the fix, and no release
// excuses it (seccompSkipReason).
func TestSeccompInterruptedOnEveryAttemptIsNotAKernelGap(t *testing.T) {
	fine := PtraceState{Scope: yamaRelational, Detail: "yama ptrace_scope=1"}
	for _, errno := range []unix.Errno{unix.ENOENT, unix.EINPROGRESS, unix.ESRCH, unix.EINTR} {
		err := fmt.Errorf("%w: ioctl(SECCOMP_IOCTL_NOTIF_ADDFD, SEND): %w (%w)", ErrSeccompSelfTest, errno, errInterrupted)
		for _, kernel := range []Version{{5, 10, 0}, addfdSendSince, {6, 17, 0}, {}} {
			t.Run(fmt.Sprintf("%v, kernel %s", errno, kernel), func(t *testing.T) {
				r := seccompVerdictOn(-1, err, fine, kernel)
				if r.OK || r.ID != CheckSeccomp {
					t.Fatalf("an interrupted round trip = %+v", r)
				}
				if r.Fix != seccompRerunFix {
					t.Errorf("fix %q, want %q", r.Fix, seccompRerunFix)
				}
				for _, want := range []string{errno.Error(), fmt.Sprintf("%d attempts", seccompRoundTripAttempts)} {
					if !strings.Contains(r.Detail, want) {
						t.Errorf("detail %q does not say %q", r.Detail, want)
					}
				}
				if why := seccompSkipReason(err, fine, kernel); why != "" {
					t.Errorf("seccompSkipReason excuses an interrupted round trip: %q", why)
				}
			})
		}
	}
}
