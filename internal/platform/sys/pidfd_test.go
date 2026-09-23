// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPidfdGetfdSelf(t *testing.T) {
	pidfd, err := PidfdOpenProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	f, err := os.CreateTemp(t.TempDir(), "getfd")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dup, err := PidfdGetfd(pidfd, int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dup)
	var a, b unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(dup, &b); err != nil {
		t.Fatal(err)
	}
	if a.Ino != b.Ino || a.Dev != b.Dev {
		t.Fatalf("pidfd_getfd duplicate refers to a different file: %+v vs %+v", a, b)
	}
	flags, err := unix.FcntlInt(uintptr(dup), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("pidfd_getfd result is not O_CLOEXEC")
	}
}

func TestPidfdOpenBadPid(t *testing.T) {
	_, err := PidfdOpenProcess(-5)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("pidfd_open(-5) = %v, want EINVAL", err)
	}
}

func TestPidfdSignalAndWait(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	var pidfd int
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if pidfd < 0 {
		t.Fatal("kernel gave no pidfd via clone3")
	}
	defer unix.Close(pidfd)
	if exited, err := PollPidfd(pidfd, 0); err != nil || exited {
		t.Fatalf("PollPidfd on a running child: exited=%v err=%v", exited, err)
	}
	if _, reaped, err := WaitPidfd(pidfd, true); err != nil || reaped {
		t.Fatalf("WaitPidfd(nohang) on a running child: reaped=%v err=%v", reaped, err)
	}
	if err := PidfdSendSignal(pidfd, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if exited, err := PollPidfd(pidfd, 5000); err != nil || !exited {
		t.Fatalf("PollPidfd after SIGKILL: exited=%v err=%v", exited, err)
	}
	ws, reaped, err := WaitPidfd(pidfd, false)
	if err != nil || !reaped {
		t.Fatalf("WaitPidfd: reaped=%v err=%v", reaped, err)
	}
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("wait status %#x: want killed by SIGKILL", uint32(ws))
	}
	// The child is already reaped: cmd.Wait must not be used, and a second reap is ECHILD.
	if _, _, err := WaitPidfd(pidfd, false); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("second reap = %v, want ECHILD", err)
	}
	if err := PidfdSendSignal(pidfd, syscall.SIGTERM); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("signal to a reaped pidfd = %v, want ESRCH", err)
	}
}

// WaitPidfdStopped reports a stop once and by its signal, and never reaps: a running child is 0, a stopped one its
// stop signal, the same stop asked again 0, and an exited child ECHILD while it is still the parent's to reap.
func TestWaitPidfdStopped(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	var pidfd int
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	if sig, err := WaitPidfdStopped(pidfd); err != nil || sig != 0 {
		t.Fatalf("a running child: %v %v, want 0 nil", sig, err)
	}
	if err := PidfdSendSignal(pidfd, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	var sig syscall.Signal
	for end := time.Now().Add(5 * time.Second); sig == 0 && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		var err error
		if sig, err = WaitPidfdStopped(pidfd); err != nil {
			t.Fatal(err)
		}
	}
	if sig != syscall.SIGSTOP {
		t.Fatalf("the stopped child reported %v, want SIGSTOP", sig)
	}
	if again, err := WaitPidfdStopped(pidfd); err != nil || again != 0 {
		t.Fatalf("the same stop taken twice: %v %v", again, err)
	}
	if err := PidfdSendSignal(pidfd, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if exited, err := PollPidfd(pidfd, 5000); err != nil || !exited {
		t.Fatalf("PollPidfd after SIGKILL: exited=%v err=%v", exited, err)
	}
	if _, err := WaitPidfdStopped(pidfd); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("an exited child = %v, want ECHILD", err)
	}
	if _, reaped, err := WaitPidfd(pidfd, false); err != nil || !reaped {
		t.Fatalf("the zombie was not left to reap: reaped=%v err=%v", reaped, err)
	}
}

func TestSiginfoWaitStatus(t *testing.T) {
	tests := []struct {
		name         string
		code, status int32
		exited       bool
		exit         int
		signaled     bool
		sig          syscall.Signal
		dumped       bool
	}{
		{"exit 0", 1, 0, true, 0, false, 0, false},
		{"exit 127", 1, 127, true, 127, false, 0, false},
		{"killed 9", 2, 9, false, 0, true, syscall.SIGKILL, false},
		{"dumped 11", 3, 11, false, 0, true, syscall.SIGSEGV, true},
		{"unknown code", 9, 15, false, 0, true, syscall.SIGTERM, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ws := siginfoWaitStatus(tc.code, tc.status)
			if ws.Exited() != tc.exited || (tc.exited && ws.ExitStatus() != tc.exit) {
				t.Fatalf("exited=%v status=%d, want %v/%d", ws.Exited(), ws.ExitStatus(), tc.exited, tc.exit)
			}
			if ws.Signaled() != tc.signaled || (tc.signaled && ws.Signal() != tc.sig) {
				t.Fatalf("signaled=%v sig=%v, want %v/%v", ws.Signaled(), ws.Signal(), tc.signaled, tc.sig)
			}
			if ws.CoreDump() != tc.dumped {
				t.Fatalf("coredump=%v, want %v", ws.CoreDump(), tc.dumped)
			}
		})
	}
}

// sigscopeEnv re-runs this test binary as the helper process of
// TestPidfdSendSignalTargetsTheThreadGroup.
const sigscopeEnv = "TEGO_SYS_SIGSCOPE_HELPER"

const (
	helperReady        = "sigscope-ready" // followed by the tid whose SIGTERM is blocked
	exitHelperSetup    = 9                // the helper could not arrange the discriminator; the test proves nothing
	exitHelperNoSignal = 3                // SIGTERM never reached a thread that could take it
)

// requirePidfdThread skips t on a kernel without PIDFD_THREAD (below Linux 6.9, which the support matrix
// still covers down to RHEL 9's 5.14). There every pidfd is process-scoped, so a test that measures the
// difference between the two scopes has nothing to measure. It asks the kernel directly rather than reading
// PidfdOpenThread's result, so the wrapper under test takes no part in the skip: once this returns, a
// PidfdOpenThread failure or a process-scoped fd from it is the wrapper's fault and must fail the test.
func requirePidfdThread(t *testing.T) {
	t.Helper()
	fd, err := unix.PidfdOpen(os.Getpid(), PidfdThread)
	if errors.Is(err, unix.EINVAL) { // pidfd_open's answer to a flag it does not know
		t.Skipf("kernel has no PIDFD_THREAD (pidfd_open: %v): every pidfd is process-scoped", err)
	}
	if err != nil {
		t.Fatalf("pidfd_open(self, PIDFD_THREAD): %v", err)
	}
	unix.Close(fd)
}

// TestPidfdSignalBlockedThreadHelper is the target process of TestPidfdSendSignalTargetsTheThreadGroup,
// not a test on its own. It blocks SIGTERM on one locked thread and leaves it unblocked on the Go
// runtime's other threads, which is what makes the two delivery scopes tell apart: a thread-directed
// signal aimed at that task sits in its private queue while it is blocked, a thread-group signal is taken
// by any sibling that does not block it (kernel/signal.c complete_signal).
//
// The blocked thread is never the thread-group leader, and its tid goes out on stdout. Which thread a
// tRunner goroutine lands on is the Go scheduler's choice; fixing it here keeps the parent on one path on
// every run instead of two, and puts it on the path that needs PIDFD_THREAD to open at all — the one a
// seccomp notification from a worker thread takes in the supervisor.
func TestPidfdSignalBlockedThreadHelper(t *testing.T) {
	if os.Getenv(sigscopeEnv) == "" {
		t.Skip("helper process for TestPidfdSendSignalTargetsTheThreadGroup")
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	runtime.LockOSThread() // while this goroutine holds its thread, no other goroutine runs there
	var tid int
	if unix.Gettid() != unix.Getpid() {
		tid = blockSigtermHere()
	} else {
		// This goroutine now owns the leader, so the one started here cannot be scheduled onto it.
		held := make(chan int)
		go func() {
			runtime.LockOSThread() // never unlocked: the thread must keep its mask until the helper exits
			held <- blockSigtermHere()
			select {}
		}()
		tid = <-held
	}
	fmt.Println(helperReady, tid) // os.Stdout is unbuffered: the parent sees this immediately
	select {
	case <-c:
		os.Exit(0)
	case <-time.After(10 * time.Second):
		os.Exit(exitHelperNoSignal)
	}
}

// blockSigtermHere blocks SIGTERM on the calling thread, which must be locked and must not be the leader,
// and returns its tid; it exits the helper with exitHelperSetup when either cannot be arranged.
func blockSigtermHere() int {
	tid := unix.Gettid()
	if tid == unix.Getpid() {
		os.Exit(exitHelperSetup)
	}
	var set unix.Sigset_t
	set.Val[0] = 1 << (uint(syscall.SIGTERM) - 1)
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &set, nil); err != nil {
		os.Exit(exitHelperSetup)
	}
	if !sigtermBlocked(tid) {
		os.Exit(exitHelperSetup)
	}
	return tid
}

// sigtermBlocked reads tid's own SigBlk mask back from /proc, because a Go runtime that quietly unblocked
// SIGTERM again would make the helper's answer meaningless rather than wrong.
func sigtermBlocked(tid int) bool {
	b, err := os.ReadFile("/proc/self/task/" + strconv.Itoa(tid) + "/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "SigBlk:")
		if !ok {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return false
		}
		return mask&(1<<(uint(syscall.SIGTERM)-1)) != 0
	}
	return false
}

// TestPidfdSendSignalTargetsTheThreadGroup pins PidfdSendSignal's own guarantee: the signal is
// process-directed whatever scope the pidfd it is handed carries. From Linux 6.9 a pidfd opened with
// PIDFD_THREAD makes flags-0 pidfd_send_signal thread-directed (PIDTYPE_PID), so without
// PIDFD_SIGNAL_THREAD_GROUP a SIGTERM through such an fd would sit unseen in the queue of a thread that
// blocks it. `tego stop` (runtime.StopTarget.Signal, R22) does not depend on this today — its fd comes
// from PidfdOpenProcess, on which both flag values mean the thread group — so this guards the wrapper's
// contract against a thread-scoped fd routed to it later, not a live path.
//
// The fd must therefore be the thread-scoped one: on a process-scoped fd both flag values mean
// PIDTYPE_TGID, so the assertion below would hold whether or not PidfdSendSignal names the scope and
// the wrapper's own guarantee would go untested. PIDFD_SIGNAL_THREAD_GROUP is what makes the two agree
// again, and that is what this measures.
func TestPidfdSendSignalTargetsTheThreadGroup(t *testing.T) {
	// Probed before the helper exists: below 6.9 PidfdOpenThread falls back to plain pidfd_open, which
	// refuses the helper's non-leader tid, and that refusal would read as a broken wrapper on exactly the
	// kernels where there is nothing to discriminate.
	requirePidfdThread(t)

	cmd := exec.Command(os.Args[0], "-test.run=^TestPidfdSignalBlockedThreadHelper$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), sigscopeEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	tid := 0
	scan := bufio.NewScanner(stdout)
	for scan.Scan() {
		rest, ok := strings.CutPrefix(scan.Text(), helperReady+" ")
		if !ok {
			continue
		}
		if tid, err = strconv.Atoi(rest); err != nil {
			t.Fatalf("helper ready line %q: %v", scan.Text(), err)
		}
		break // the helper writes nothing more until it exits; another Scan would block on that
	}
	if tid == 0 {
		// Every setup failure in blockSigtermHere exits before the ready line, so this is the only place
		// its code can be read; skipping there and failing here is what keeps a machine that cannot
		// hold the mask from being reported as a broken wrapper.
		waited = true
		err := cmd.Wait()
		if helperExitCode(err) == exitHelperSetup {
			t.Skip("helper could not keep SIGTERM blocked on a thread other than its leader")
		}
		t.Fatalf("helper never reported ready: %v (scan err %v)", err, scan.Err())
	}

	// tid is the task that blocks SIGTERM, which is what the two scopes disagree about. The kernel was
	// probed for PIDFD_THREAD above, so a failure or a process-scoped fd here is PidfdOpenThread's own.
	fd, err := PidfdOpenThread(tid)
	if err != nil {
		t.Fatalf("PidfdOpenThread(%d) on a kernel with PIDFD_THREAD: %v", tid, err)
	}
	defer unix.Close(fd)
	if err := requireProcessScope(fd); err == nil {
		t.Fatalf("PidfdOpenThread(%d) returned a process-scoped fd on a kernel with PIDFD_THREAD", tid)
	}
	if err := PidfdSendSignal(fd, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		waited = true
		if err != nil {
			if helperExitCode(err) == exitHelperNoSignal {
				t.Fatal("SIGTERM was delivered to the blocked thread alone (thread-scoped " +
					"pidfd_send_signal), so no sibling thread ever took it")
			}
			t.Fatalf("helper exited %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("helper still running 8s after SIGTERM: the signal was thread-directed at the task that " +
			"blocks it, instead of at the thread group")
	}
}

// helperExitCode is the helper's os.Exit status behind a cmd.Wait error, or -1 for anything else.
func helperExitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// TestPidfdOpenThreadAcceptsATgid pins the part of PidfdOpenThread's contract that holds on every supported
// kernel: handed a thread-group leader's pid, which is the case that succeeds below 6.9 when the trapping
// task is its group's leader (a non-leader tid falls back to PidfdOpenProcess(tgid) in openTargetPidFD),
// it returns a pidfd that pidfd_getfd can use, the one job the supervisor opens it for. From 6.9 the
// PIDFD_THREAD call answers; on 5.14–6.8 only the retry without the flag does, and
// TestKernelWithoutPidfdThread runs this test under an emulation of those kernels so the retry is
// exercised on a 6.9+ machine too.
func TestPidfdOpenThreadAcceptsATgid(t *testing.T) {
	fd, err := PidfdOpenThread(os.Getpid())
	if err != nil {
		t.Fatalf("PidfdOpenThread(tgid %d): %v", os.Getpid(), err)
	}
	defer unix.Close(fd)
	f, err := os.CreateTemp(t.TempDir(), "getfd")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dup, err := PidfdGetfd(fd, int(f.Fd()))
	if err != nil {
		t.Fatalf("pidfd_getfd through PidfdOpenThread's fd: %v", err)
	}
	defer unix.Close(dup)
	var a, b unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(dup, &b); err != nil {
		t.Fatal(err)
	}
	if a.Ino != b.Ino || a.Dev != b.Dev {
		t.Fatalf("pidfd_getfd duplicate refers to a different file: %+v vs %+v", a, b)
	}
}

// TestPidfdOpenScopes checks that the two openers really differ in scope, since every other guarantee in
// this file rests on PIDFD_THREAD being present or absent in the descriptor.
func TestPidfdOpenScopes(t *testing.T) {
	proc, err := PidfdOpenProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(proc)
	if err := requireProcessScope(proc); err != nil {
		t.Fatalf("PidfdOpenProcess gave a thread-scoped fd: %v", err)
	}
	requirePidfdThread(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, err := PidfdOpenThread(unix.Gettid())
	if err != nil {
		t.Fatalf("PidfdOpenThread on a kernel with PIDFD_THREAD: %v", err)
	}
	defer unix.Close(thread)
	if err := requireProcessScope(thread); !errors.Is(err, ErrThreadScopedPidfd) {
		t.Fatalf("requireProcessScope on a PidfdOpenThread fd = %v, want ErrThreadScopedPidfd", err)
	}
}

// TestPollAndWaitRejectThreadScopedPidfd keeps the exit-reporting wrappers away from a descriptor that
// reports one thread's exit: with PIDFD_THREAD the fd is readable once that task is a zombie even though
// the thread group still runs (pidfd_open(2)), so a silent "the process exited" is the failure to avoid.
func TestPollAndWaitRejectThreadScopedPidfd(t *testing.T) {
	requirePidfdThread(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, err := PidfdOpenThread(unix.Gettid())
	if err != nil {
		t.Fatalf("PidfdOpenThread on a kernel with PIDFD_THREAD: %v", err)
	}
	defer unix.Close(fd)
	if err := requireProcessScope(fd); err == nil {
		t.Fatal("PidfdOpenThread returned a process-scoped fd on a kernel with PIDFD_THREAD")
	}
	if _, err := PollPidfd(fd, 0); !errors.Is(err, ErrThreadScopedPidfd) {
		t.Fatalf("PollPidfd on a thread-scoped pidfd = %v, want ErrThreadScopedPidfd", err)
	}
	if _, _, err := WaitPidfd(fd, true); !errors.Is(err, ErrThreadScopedPidfd) {
		t.Fatalf("WaitPidfd on a thread-scoped pidfd = %v, want ErrThreadScopedPidfd", err)
	}
}
