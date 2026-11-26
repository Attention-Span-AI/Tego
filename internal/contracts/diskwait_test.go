// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A thread in uninterruptible sleep (state D, what a wait for the disk is), made with no disk, no load tool and no
// privilege, for the tests that must run a real helper through a disk wait.
//
// A thread that vforks is asleep in the kernel until its child execs or exits, and the kernel waits killably, which /proc
// shows as D. The child is held before its exec by a seccomp filter that has the supervisor (this code) be asked about
// every execve: the filter is installed on one locked thread, which the child inherits, and nobody answers until the
// time asked for has passed or the context ends, when the child's execve is refused and the vfork returns. The thread
// ends with its goroutine, so the filter never reaches another.
//
// It cannot be made everywhere: the kernel allows one seccomp listener on a chain of filters, so inside `tego run`
// (which installs one), under LXD or Incus syscall interception or sysbox, the call is refused with EBUSY; before
// Linux 5.0 it is ENOSYS or EINVAL; a strict profile or gVisor refuses it (EPERM, EACCES). Every test that needs the
// state calls requireDiskWait, which tries once per test binary and skips, saying why, where it cannot be made.

// seccompNotifyListener installs the filter on this thread and returns its listener; a test replaces it with an error.
var seccompNotifyListener = func(fprog *unix.SockFprog) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, 1 /* SECCOMP_SET_MODE_FILTER */, 8 /* SECCOMP_FILTER_FLAG_NEW_LISTENER */, uintptr(unsafe.Pointer(fprog)))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// diskWaitSkipReason says why err means the state cannot be made here, "" when err is something else (a real failure).
func diskWaitSkipReason(err error) string {
	switch {
	case errors.Is(err, unix.EBUSY):
		return "a seccomp listener is already installed on this process's filter chain (EBUSY: inside tego run, LXD or Incus syscall interception, sysbox)"
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return "this kernel has no seccomp user notification listener (ENOSYS or EINVAL: before Linux 5.0)"
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return "a strict seccomp or security profile (or gVisor) refuses the seccomp call (EPERM or EACCES)"
	}
	return ""
}

// stayInUninterruptibleSleep puts one thread of this process in state D for d, or until ctx ends. It returns the error
// of making the listener (diskWaitSkipReason reads it), or nil when the wait was held and ended.
func stayInUninterruptibleSleep(ctx context.Context, d time.Duration) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread, with its filter, ends with this goroutine
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			done <- err
			return
		}
		// BPF: load the syscall number; execve is a user notification, everything else is allowed.
		const (
			retAllow = 0x7fff0000
			retNotif = 0x7fc00000
		)
		prog := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_EXECVE, Jt: 0, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: retNotif},
			{Code: unix.BPF_RET | unix.BPF_K, K: retAllow},
		}
		fd, err := seccompNotifyListener(&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]})
		if err != nil {
			done <- err
			return
		}
		stop, answerEnded := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(answerEnded)
			answerExec(ctx, fd, d, stop)
		}()
		// The vfork is a raw system call: the Go runtime counts the thread as running, so a stop-the-world (a garbage collection
		// started by any allocation) would wait for the fork to return, and the answer that ends it is made by a goroutine
		// the stopped world cannot run. No collection starts while the hold lasts.
		defer debug.SetGCPercent(debug.SetGCPercent(-1))
		// The child dies with this thread (Pdeathsig fires when the thread that made it ends, which a vfork form allows:
		// it is set in the child before its exec, which the filter does not touch), so a held child cannot outlive the
		// process whose thread is holding it.
		_, _ = syscall.ForkExec("/bin/true", []string{"true"}, &syscall.ProcAttr{Sys: &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}})
		close(stop)
		<-answerEnded
		_ = unix.Close(fd) // every path closes our listener; the child's own copy ends with the child
		done <- nil
	}()
	return <-done
}

// answerExec refuses the held child's execve (EPERM) when d has passed or ctx ends, and gives up when stop is closed (the
// fork returned by itself). It polls for the notification before it asks for it, so it never sits in a call that
// nothing will end.
func answerExec(ctx context.Context, fd int, d time.Duration, stop <-chan struct{}) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	case <-stop:
		return
	}
	for {
		select {
		case <-stop:
			return
		default:
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, _ := unix.Poll(fds, 100); n > 0 {
			break
		}
	}
	var req [80]byte // seccomp_notif: id, pid, flags, seccomp_data
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0xc0502100, uintptr(unsafe.Pointer(&req[0]))); e != 0 {
		return
	}
	var resp [24]byte // seccomp_notif_resp: id, val, error, flags
	copy(resp[:8], req[:8])
	*(*int32)(unsafe.Pointer(&resp[16])) = -int32(unix.EPERM)
	unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0xc0182101, uintptr(unsafe.Pointer(&resp[0])))
}

// probeDiskWait tries the state once and says why it cannot be made: "" when it can. An error that is not one of the
// known refusals is returned as itself, a real failure.
func probeDiskWait() (skip string, fail error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() { ended <- stayInUninterruptibleSleep(ctx, 5*time.Second) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-ended:
			if r := diskWaitSkipReason(err); r != "" {
				return r, nil
			}
			if err != nil {
				return "", err
			}
			return "the held vfork ended by itself before it was seen in state D", nil
		default:
		}
		if threads, err := procScheduler(os.Getpid(), 0); err == nil && anyUninterruptible(threads) {
			cancel()
			select {
			case <-ended:
			case <-time.After(10 * time.Second):
				killDescendantsHeld()
			}
			return "", nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		killDescendantsHeld()
	}
	return "the vfork parent did not show state D within 3 s", nil
}

var diskWaitProbe struct {
	sync.Once
	skip string
	fail error
}

// requireDiskWait skips the test, with the reason, where the state cannot be made, fails it where the attempt failed for
// another reason, and otherwise registers the check that no held process of the test outlives it.
func requireDiskWait(t *testing.T) {
	t.Helper()
	diskWaitProbe.Do(func() { diskWaitProbe.skip, diskWaitProbe.fail = probeDiskWait() })
	if diskWaitProbe.fail != nil {
		t.Fatalf("the uninterruptible wait could not be made, and not for a reason that means it cannot be here: %v", diskWaitProbe.fail)
	}
	if diskWaitProbe.skip != "" {
		t.Skip("cannot hold a thread in uninterruptible sleep here: " + diskWaitProbe.skip)
	}
	t.Cleanup(func() { noHeldDescendants(t) })
}

// heldDescendants are the processes below this one that sit in the seccomp wait of a held vfork child (the in-process
// holds; a real helper's children are looked for by the helper's pid, reapHelper).
func heldDescendants() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	parent := map[int]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if st, err := readParsedStat(pid); err == nil {
			parent[pid] = st
		}
	}
	// depth is how far below this process pid is: 0 when it is not below it.
	depth := func(pid int) int {
		for d := 1; d <= 64; d++ {
			pid = parent[pid]
			if pid == os.Getpid() {
				return d
			}
			if pid <= 1 {
				return 0
			}
		}
		return 0
	}
	var held []int
	for pid := range parent {
		d := depth(pid)
		if d == 0 {
			continue
		}
		if w, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/wchan"); err == nil && strings.Contains(string(w), "seccomp_do_user") {
			held = append(held, pid)
		}
	}
	return held
}

// readParsedStat is the parent pid of pid.
func readParsedStat(pid int) (int, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	fields := strings.Fields(s[i+1:])
	if i < 0 || len(fields) < 2 {
		return 0, fmt.Errorf("malformed stat of %d", pid)
	}
	return strconv.Atoi(fields[1])
}

// killDescendantsHeld ends every held child of this process by its exact pid.
func killDescendantsHeld() {
	for _, pid := range heldDescendants() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// noHeldDescendants waits, bounded, for the held children of this test binary to be gone, ends any that stay by their exact
// pid, and fails the test that left them.
func noHeldDescendants(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(heldDescendants()) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	left := heldDescendants()
	killDescendantsHeld()
	t.Errorf("held children %v were still in the seccomp wait 10 s after the test; ended by pid", left)
}

// Each refusal that means the state cannot be made here is a skip with its reason; anything else is a failure. The
// probe maps an injected error the same way.
func TestDiskWaitRefusalsAreSkips(t *testing.T) {
	for name, errno := range map[string]error{
		"a listener already installed": unix.EBUSY, "a kernel before 5.0 (ENOSYS)": unix.ENOSYS, "a kernel before 5.0 (EINVAL)": unix.EINVAL,
		"a strict profile (EPERM)": unix.EPERM, "a strict profile (EACCES)": unix.EACCES,
	} {
		t.Run(name, func(t *testing.T) {
			if diskWaitSkipReason(errno) == "" || diskWaitSkipReason(fmt.Errorf("wrapped: %w", errno)) == "" {
				t.Fatalf("%v is not a skip", errno)
			}
			before := seccompNotifyListener
			seccompNotifyListener = func(*unix.SockFprog) (int, error) { return -1, errno }
			t.Cleanup(func() { seccompNotifyListener = before })
			skip, fail := probeDiskWait()
			if skip == "" || fail != nil {
				t.Fatalf("the probe under %v: skip %q, failure %v", errno, skip, fail)
			}
		})
	}
	if diskWaitSkipReason(unix.EFAULT) != "" || diskWaitSkipReason(errors.New("other")) != "" {
		t.Fatal("an error that does not mean the state cannot be made was taken for a skip")
	}
	before := seccompNotifyListener
	seccompNotifyListener = func(*unix.SockFprog) (int, error) { return -1, unix.EFAULT }
	t.Cleanup(func() { seccompNotifyListener = before })
	if skip, fail := probeDiskWait(); skip != "" || fail == nil {
		t.Fatalf("an unexpected error was not a failure: skip %q, failure %v", skip, fail)
	}
}

// The wait is what it says: a thread of the process is in state D while it is held, and it ends when asked to.
func TestUninterruptibleSleepIsStateD(t *testing.T) {
	requireDiskWait(t)
	ctx, cancel := context.WithCancel(context.Background())
	ended, over := make(chan error, 1), make(chan struct{})
	go func() { ended <- stayInUninterruptibleSleep(ctx, time.Hour); close(over) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-over:
		case <-time.After(10 * time.Second):
			killDescendantsHeld()
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if threads, err := procScheduler(os.Getpid(), 0); err == nil && anyUninterruptible(threads) {
			cancel()
			select {
			case err := <-ended:
				if err != nil {
					t.Fatal(err)
				}
				return
			case <-time.After(10 * time.Second):
				t.Fatal("the wait did not end when asked to")
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no thread of this process was in state D while the wait was held")
}

// A held child that nobody answers is ended by its pid and leaves nothing in the wait: the cleanup works when the answer
// never comes.
func TestHeldChildIsEndedByItsPidAndNothingIsLeft(t *testing.T) {
	requireDiskWait(t)
	ended := make(chan error, 1)
	go func() { ended <- stayInUninterruptibleSleep(context.Background(), time.Hour) }()
	deadline := time.Now().Add(10 * time.Second)
	for len(heldDescendants()) == 0 {
		if time.Now().After(deadline) {
			killDescendantsHeld()
			t.Fatal("no held child appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	killDescendantsHeld()
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the vfork did not return after its child was ended")
	}
	for range 200 {
		if len(heldDescendants()) == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("held children %v are left after being ended", heldDescendants())
}

// A helper that is killed while it holds a child leaves no child in the wait: the child is made to die with the thread that
// made it (Pdeathsig), so no orphan can sit in the seccomp wait after its holder is gone.
func TestKilledHelperLeavesNoHeldChild(t *testing.T) {
	requireDiskWait(t)
	useRealScheduler(t)
	useClass(t, true)
	ctx, cancel := WithBudget(context.Background())
	defer cancel()
	ctx, closeSession := WithHelperSession(ctx)
	defer closeSession()
	ctx = WithLocations(ctx, "/data/contracts")
	pidfile := filepath.Join(t.TempDir(), "helper.pid")
	t.Cleanup(func() { reapHelper(t, pidfile) })
	exchanged := make(chan error, 1)
	go func() { _, err := HelperExchange(ctx, "test-disk-wait", []byte("1h "+pidfile)); exchanged <- err }()
	var helper, child int
	deadline := time.Now().Add(15 * time.Second)
	for child == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the helper never held a child")
		}
		if helper = helperPidOf(pidfile); helper != 0 {
			if kids := childrenOf(helper); len(kids) > 0 {
				child = kids[0]
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(helper, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(25 * time.Millisecond) {
		if _, err := readParsedStat(child); err != nil {
			break
		}
	}
	if st, err := readParsedStat(child); err == nil {
		_ = syscall.Kill(child, syscall.SIGKILL)
		t.Fatalf("the held child %d (parent %d) outlived the helper that was killed", child, st)
	}
	select {
	case <-exchanged:
	case <-time.After(30 * time.Second):
		t.Fatal("the exchange did not end after its helper was killed")
	}
}
