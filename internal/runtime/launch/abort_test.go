// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestAbortBoundsTheReapOfAStuckChild is R13 for the child that does not die on SIGKILL. The kernel only
// delivers a pending SIGKILL when a task leaves uninterruptible sleep, so a child stuck in D state on the
// startup-failure path used to hang abort in Wait's poll loop for as long as the sleep lasted: the launcher
// never reported the failure it was aborting for. No unprivileged test can put a process in D state, so the
// stand-in is a live child that abortKill waits on without signalling, which is exactly what the reap sees.
//
// Also pins runtime-launch.md R13: a child that outlives the bound is ErrChildNotReaped.
func TestAbortBoundsTheReapOfAStuckChild(t *testing.T) {
	testutil.NoFDLeak(t) // abort closes the pidfd and the pipes it was given (ADR 0023 C6)
	requireExecutable(t, "/bin/sleep")
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	child, err := startOnKeptThread(cmd)
	if err != nil {
		t.Fatal(err)
	}
	pid := child.PID
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		_, _ = syscall.Wait4(pid, nil, 0, nil) // startOnKeptThread released cmd.Process
	})

	prevKill, prevBound := abortKill, abortReapTimeout
	t.Cleanup(func() { abortKill, abortReapTimeout = prevKill, prevBound })
	abortKill = func(c *Child, ctx context.Context) error {
		_, err := c.Wait(ctx) // the SIGKILL that never takes effect
		return err
	}
	abortReapTimeout = 200 * time.Millisecond

	cause := errors.New("handshake failed")
	done := make(chan error, 1)
	go func() { done <- child.abort(cause) }()
	select {
	case err := <-done:
		if !errors.Is(err, cause) {
			t.Errorf("abort = %v, want the cause of the abort kept", err)
		}
		if !errors.Is(err, ErrChildNotReaped) {
			t.Errorf("abort = %v, want ErrChildNotReaped naming the child still running", err)
		}
	case <-time.After(10 * time.Second):
		// Release the reap so the goroutine can finish before the test binary tears down.
		_ = syscall.Kill(pid, syscall.SIGKILL)
		<-done
		t.Fatal("abort never returned while its child outlived SIGKILL: the reap is unbounded (R13)")
	}
	if pidfdOpen(child) {
		t.Error("abort left the pidfd open")
	}
}

// TestAbortReapsADeadChildQuietly is the ordinary abort: the child dies on SIGKILL, the reap finishes well
// inside the bound, and the error is the cause alone.
//
// Also pins runtime-launch.md R13: a failed Start kills and reaps its child.
func TestAbortReapsADeadChildQuietly(t *testing.T) {
	testutil.NoFDLeak(t) // abort closes the pidfd and the pipes it was given (ADR 0023 C6)
	requireExecutable(t, "/bin/sleep")
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	child, err := startOnKeptThread(cmd)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("handshake failed")
	err = child.abort(cause)
	if !errors.Is(err, cause) || errors.Is(err, ErrChildNotReaped) {
		t.Fatalf("abort = %v, want the cause alone", err)
	}
	if err := syscall.Kill(child.PID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("kill(%d, 0) = %v, want ESRCH: abort must reap the child it killed", child.PID, err)
	}
}

// TestKillAfterAbortIsANoOp is the unwind that follows a failed startup: abort has killed, reaped and closed
// the child, and the runner's unwind still calls Kill. It must not report EBADF for the closed pidfd, which
// logged a spurious warning on every failed child start.
func TestKillAfterAbortIsANoOp(t *testing.T) {
	testutil.NoFDLeak(t) // abort closes the pidfd and the pipes it was given (ADR 0023 C6)
	requireExecutable(t, "/bin/sleep")
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	child, err := startOnKeptThread(cmd)
	if err != nil {
		t.Fatal(err)
	}
	_ = child.abort(errors.New("handshake failed"))
	if err := child.Kill(context.Background()); err != nil {
		t.Fatalf("Kill after abort = %v, want nil", err)
	}
}

// openFDs counts this process's open descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// TestStartLeavesNoDuplicatePidfd: os/exec dups the pidfd clone3 returned for its own os.Process, and only
// Wait, Release or a GC cleanup closes that copy. A Child that was started, killed and closed must leave the
// fd table as it found it, or a long-lived launcher (tegod) holds one pidfd per run until the next GC. GC is
// off for the test so a cleanup cannot hide the leak.
func TestStartLeavesNoDuplicatePidfd(t *testing.T) {
	requireExecutable(t, "/bin/sleep")
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	run := func() {
		cmd := exec.Command("/bin/sleep", "60")
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		child, err := startOnKeptThread(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := child.Kill(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := child.Close(); err != nil {
			t.Fatal(err)
		}
	}
	run() // the first start opens the runtime's one-time fds (pidfd probe, netpoller)
	before := openFDs(t)
	for range 3 {
		run()
	}
	if after := openFDs(t); after != before {
		t.Fatalf("open fds %d -> %d after three Start/Kill/Close: a pidfd outlives its Child", before, after)
	}
}

// TestAbortNamesHowADeadChildEnded: a stage that dies before the handoff by a signal (an outer seccomp
// profile's SIGSYS, the OOM killer's SIGKILL) prints nothing, so its wait status is the only record of the
// cause. abort reaps it anyway; for ErrChildDied the status must reach the error instead of being dropped.
func TestAbortNamesHowADeadChildEnded(t *testing.T) {
	testutil.NoFDLeak(t) // abort closes the pidfd and the pipes it was given (ADR 0023 C6)
	requireExecutable(t, "/bin/sh")
	for _, tc := range []struct {
		script, want string
	}{
		{"exit 7", "exit status 7"},
		{"kill -TERM $$", "signal 15 (terminated)"}, // not SIGSYS: its core dump makes the test slow
	} {
		t.Run(tc.script, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", tc.script)
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			child, err := startOnKeptThread(cmd)
			if err != nil {
				t.Fatal(err)
			}
			// Let it end on its own, as the stage had when readControl saw EOF.
			pollExit(t, child, 10_000)
			err = child.abort(fmt.Errorf("%w: %w", ErrChildDied, io.EOF))
			if !errors.Is(err, ErrChildDied) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("abort = %v, want ErrChildDied naming %q", err, tc.want)
			}
		})
	}
}

// TestWaitNotifyFDNamesAStageThatDiedBeforeGetfd: the stage wrote its fd message and then died (an OOM kill,
// a runtime crash under a low pids.max) before the parent's pidfd_getfd. The kernel answers EBADF while the
// stage is an unreaped zombie and ESRCH once it is reaped; both are a death before the handoff, so the error
// must be ErrChildDied carrying the wait status, like every other such death (runtime-launch.md case 3).
func TestWaitNotifyFDNamesAStageThatDiedBeforeGetfd(t *testing.T) {
	testutil.NoFDLeak(t) // abort closes the pidfd and the pipes it was given (ADR 0023 C6)
	requireExecutable(t, "/bin/sh")
	for _, reap := range []bool{false, true} {
		t.Run(fmt.Sprintf("reaped=%v", reap), func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", "exit 7")
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			child, err := startOnKeptThread(cmd)
			if err != nil {
				t.Fatal(err)
			}
			pollExit(t, child, 10_000)
			if reap {
				if _, err := child.Wait(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if _, err := w.Write(encodeFD(3)); err != nil {
				t.Fatal(err)
			}
			child.ControlR = r
			fd, err := child.WaitNotifyFD(context.Background())
			if fd != nil || !errors.Is(err, ErrChildDied) || !strings.Contains(err.Error(), "exit status 7") {
				t.Fatalf("WaitNotifyFD = %v, %v; want ErrChildDied naming exit status 7", fd, err)
			}
		})
	}
}
