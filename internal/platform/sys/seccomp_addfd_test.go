// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// threadSigmask is the calling thread's signal mask (rt_sigprocmask with no new set).
func threadSigmask(t *testing.T) uint64 {
	t.Helper()
	var cur unix.Sigset_t
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, nil, &cur); err != nil {
		t.Fatal(err)
	}
	return cur.Val[0]
}

// sigurgPending reports whether SIGURG is pending on the calling thread (rt_sigpending).
func sigurgPending() bool {
	var set unix.Sigset_t
	if _, _, errno := unix.RawSyscall(unix.SYS_RT_SIGPENDING, uintptr(unsafe.Pointer(&set)), 8, 0); errno != 0 {
		return false
	}
	return set.Val[0]&(1<<(uint(unix.SIGURG)-1)) != 0
}

// TestAddfdSendBlocksSignalsInsideTheIoctl reproduces the custom-agent POC's spurious EBADF through the ioctl seam,
// deterministically: the stand-in for the kernel sends the calling thread a signal from inside the ioctl, the moment
// the kernel race needs, and answers as the kernel then does. A signal that is delivered at once (not blocked)
// interrupts the wait, the kernel has the notification answered with no descriptor, and the restarted ioctl meets
// EINPROGRESS: the agent's syscall returned 0. A signal that stays pending was blocked, and the ioctl completes.
// The thread's mask is the same after the call as before it.
func TestAddfdSendBlocksSignalsInsideTheIoctl(t *testing.T) {
	real := addfdIoctlFake
	t.Cleanup(func() { addfdIoctlFake = real })
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before := threadSigmask(t)
	var lost int
	addfdIoctlFake = func(arg unsafe.Pointer) (int, unix.Errno) {
		a := (*seccompNotifAddfd)(arg)
		if a.Flags != unix.SECCOMP_ADDFD_FLAG_SEND || a.SrcFD != 5 || a.ID != 7 || a.NewFDFlags != unix.O_CLOEXEC {
			t.Errorf("addfd argument %+v", *a)
		}
		_ = unix.Tgkill(unix.Getpid(), unix.Gettid(), unix.SIGURG)
		if !sigurgPending() {
			lost++
			return -1, unix.EINPROGRESS
		}
		return 42, 0
	}
	for i := 0; i < 100; i++ {
		n, err := SeccompNotifAddfdSend(3, 7, 5, true)
		if err != nil || n != 42 {
			t.Fatalf("try %d: (%d, %v); want (42, nil): a signal reached the thread inside the ioctl", i, n, err)
		}
	}
	if lost != 0 {
		t.Fatalf("%d signals were delivered inside the ioctl", lost)
	}
	if after := threadSigmask(t); after != before {
		t.Fatalf("signal mask %#x after the call, %#x before", after, before)
	}
}

// TestAddfdSendErrors: EINTR (nothing was queued) is made again; EINPROGRESS says the reply was lost; any other
// errno is returned after one call.
func TestAddfdSendErrors(t *testing.T) {
	real := addfdIoctlFake
	t.Cleanup(func() { addfdIoctlFake = real })
	script := func(answers ...unix.Errno) *int {
		calls := 0
		addfdIoctlFake = func(unsafe.Pointer) (int, unix.Errno) {
			e := answers[calls]
			calls++
			if e == 0 {
				return 9, 0
			}
			return -1, e
		}
		return &calls
	}
	calls := script(unix.EINTR, unix.EINTR, 0)
	if n, err := SeccompNotifAddfdSend(3, 7, 5, false); n != 9 || err != nil || *calls != 3 {
		t.Errorf("EINTR twice: (%d, %v) after %d calls; want (9, nil) after 3", n, err, *calls)
	}
	calls = script(unix.EINPROGRESS)
	if _, err := SeccompNotifAddfdSend(3, 7, 5, false); !errors.Is(err, ErrNotifReplyLost) || !errors.Is(err, unix.EINPROGRESS) || *calls != 1 {
		t.Errorf("EINPROGRESS: %v after %d calls; want ErrNotifReplyLost", err, *calls)
	}
	calls = script(unix.ENOENT)
	if _, err := SeccompNotifAddfdSend(3, 7, 5, false); !errors.Is(err, unix.ENOENT) || errors.Is(err, ErrNotifReplyLost) || *calls != 1 {
		t.Errorf("ENOENT: %v after %d calls; want ENOENT alone", err, *calls)
	}
}

// auditArchForTest is AUDIT_ARCH_* of this binary's architecture.
func auditArchForTest(t *testing.T) uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return 0xc000003e
	case "arm64":
		return 0xc00000b7
	}
	t.Skipf("no AUDIT_ARCH for %s", runtime.GOARCH)
	return 0
}

// TestAddfdSendUnderASignalStorm is the stress form of the reproduction above, against the real kernel: a thread
// raises notification after notification (memfd_create, answered with ADDFD|SEND of /dev/null) while another
// goroutine signals the answering thread as fast as it can. Every notified syscall must come back with a
// descriptor the answer installed, never 0, and every answer must succeed. Before the ioctl blocked signals, about half
// the rounds came back 0 on a 6.17 kernel (1,509 of 3,000), each answer failing with ENOENT. No privilege is needed: the filter goes on a throwaway
// thread under no_new_privs.
func TestAddfdSendUnderASignalStorm(t *testing.T) {
	rounds := 400
	if testing.Short() {
		rounds = 100
	}
	arch := auditArchForTest(t)
	prog, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 4, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: arch, SkipTrue: 3},
		bpf.LoadAbsolute{Off: 0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(unix.SYS_MEMFD_CREATE), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF},
		bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW},
	})
	if err != nil {
		t.Fatal(err)
	}
	donor, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(donor) }()

	listenerCh := make(chan int, 1)
	var bad []uintptr
	targetDone := make(chan struct{})
	go offMainThreadForGood(func() {
		defer close(targetDone)
		if err := SetNoNewPrivs(); err != nil {
			t.Error(err)
			listenerCh <- -1
			return
		}
		fd, err := SeccompSetFilterNewListener(prog)
		if err != nil {
			t.Error(err)
			listenerCh <- -1
			return
		}
		listenerCh <- fd
		for i := 0; i < rounds; i++ {
			ret, _, errno := unix.Syscall(unix.SYS_MEMFD_CREATE, 0, 0, 0)
			if errno != 0 || ret <= 2 {
				bad = append(bad, ret) // 0 is not closed: it is this process's stdin
				continue
			}
			_ = unix.Close(int(ret))
		}
	})
	listener := <-listenerCh
	if listener < 0 {
		<-targetDone
		return
	}
	defer func() { _ = unix.Close(listener) }()

	var tid atomic.Int64
	stop := make(chan struct{})
	var flood sync.WaitGroup
	flood.Add(1)
	go func() {
		defer flood.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if id := tid.Load(); id != 0 {
				_ = unix.Tgkill(unix.Getpid(), int(id), unix.SIGURG)
			} else {
				runtime.Gosched()
			}
		}
	}()

	var answerErrs []error
	runtime.LockOSThread()
	tid.Store(int64(unix.Gettid()))
	for done := false; !done; {
		select {
		case <-targetDone:
			done = true
			continue
		default:
		}
		pfd := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
		if k, err := unix.Poll(pfd, 50); err != nil || k == 0 {
			continue
		}
		var n SeccompNotif
		if err := SeccompNotifRecv(listener, &n); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				answerErrs = append(answerErrs, err)
			}
			continue
		}
		if _, err := SeccompNotifAddfdSend(listener, n.ID, donor, true); err != nil {
			answerErrs = append(answerErrs, err)
			if !errors.Is(err, ErrNotifReplyLost) && !errors.Is(err, unix.ENOENT) {
				// Not answered: release the target rather than leave it waiting.
				_ = SeccompNotifSend(listener, &SeccompNotifResp{ID: n.ID, Error: -int32(unix.ENOSYS)})
			}
		}
	}
	tid.Store(0)
	runtime.UnlockOSThread()
	close(stop)
	flood.Wait()
	if len(bad) != 0 || len(answerErrs) != 0 {
		first := error(nil)
		if len(answerErrs) > 0 {
			first = answerErrs[0]
		}
		t.Fatalf("%d of %d notified syscalls returned no installed descriptor (%v), %d answers failed (first: %v)",
			len(bad), rounds, bad[:min(len(bad), 8)], len(answerErrs), first)
	}
}

// offMainThreadForGood runs fn on an OS thread locked to its goroutine for good, never the main thread: the goroutine
// exits locked, so Go ends the thread and whatever fn did to it (a seccomp filter, no_new_privs) with it. On the main
// thread, which Go parks rather than ends, it hands fn to a goroutine of its own and gives the main thread back.
func offMainThreadForGood(fn func()) {
	runtime.LockOSThread()
	if unix.Gettid() == unix.Getpid() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			offMainThreadForGood(fn)
		}()
		<-done
		runtime.UnlockOSThread()
		return
	}
	fn()
}

// BenchmarkAddfdSendSignalMask is what blocking signals adds to one delivery: a locked thread and two
// rt_sigprocmask calls around an ioctl that here does nothing. An approved open is a person's decision, so this is
// paid once per approval, never on the notification path of an ordinary syscall.
func BenchmarkAddfdSendSignalMask(b *testing.B) {
	real := addfdIoctlFake
	b.Cleanup(func() { addfdIoctlFake = real })
	addfdIoctlFake = func(unsafe.Pointer) (int, unix.Errno) { return 9, 0 }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := SeccompNotifAddfdSend(3, 7, 5, true); err != nil {
			b.Fatal(err)
		}
	}
}
