// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exit codes of the interrupt helper: the launcher's view of how many interrupts the person made.
const (
	scopeOneInterrupt  = 37
	scopeTwoInterrupts = 38
	scopeNoChannel     = 84
	scopeChannelSilent = 85
)

// scopeInterrupt is the launcher half of the A51 tests. It takes its signals through scopeNotify, the seam the
// run's own signal rules read, so it counts what a run would count: one entry per interrupt the person made.
func scopeInterrupt(ctx context.Context) int {
	sigs, stop, ready := scopeNotify(ctx)
	defer stop()
	own := make(chan os.Signal, 16)
	signal.Notify(own, syscall.SIGINT)
	defer signal.Stop(own)
	if ready == nil {
		return scopeNoChannel
	}
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		return scopeChannelSilent
	}
	dir := os.Getenv("SCOPE_EXPECT_CWD")
	if err := scopeWriteMarker(filepath.Join(dir, "child"), []byte(strconv.Itoa(os.Getpid()))); err != nil {
		return 87
	}
	interrupt := func(wait <-chan time.Time) bool {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGINT {
					return true
				}
			case <-wait:
				return false
			}
		}
	}
	if !interrupt(time.After(10 * time.Second)) {
		return 89
	}
	// os/signal keeps one pending notification per signal until its receiving goroutine has run, so a second signal
	// that arrives before that is the first one again (the counts are a lower bound, ADR 0142, amendment of
	// 2026-11-25), and a person's second keystroke is never that close to the first. The first interrupt may be acted
	// on from the outer process's report before this process's own copy of it has been taken; the helper therefore
	// waits for its own copy (a second subscription sees every arrival) before it says the first is settled.
	if os.Getenv("SCOPE_FIRST_REACHES_LAUNCHER") == "1" {
		select {
		case <-own:
		case <-time.After(5 * time.Second):
			return 88
		}
	}
	if err := scopeWriteMarker(filepath.Join(dir, "first"), []byte("1")); err != nil {
		return 87
	}
	// A duplicate is a forbidden event, a deliberate repeat is a required one. Either has a bounded observation
	// window, as the launcher's double-interrupt policy has, rather than counting only what is queued now.
	wait := 150 * time.Millisecond
	if d, err := time.ParseDuration(os.Getenv("SCOPE_INTERRUPT_WAIT")); err == nil {
		wait = d
	}
	// The window of observation starts when the test has made its last send, not when the first was settled: a test
	// stalled on a loaded machine between two sends would otherwise find the launcher already gone.
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if _, err := os.Stat(filepath.Join(dir, "sent")); err == nil {
			break
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	if interrupt(timer.C) {
		// A real launcher has a stop to carry out before it ends, and its signal handling lasts as long. This one
		// has none: it stays subscribed a moment longer, so a group send whose second copy the sender has not yet
		// delivered (it was preempted between two deliveries) finds a handler and not the default action.
		time.Sleep(100 * time.Millisecond)
		return scopeTwoInterrupts
	}
	return scopeOneInterrupt
}

// One person's interrupt is one interrupt for the launcher whichever way it was sent, and a deliberate repeat is two.
// The pair agrees by counts (launch.Arbiter): the number of interrupts is the larger of what each process received
// itself. A second signal is therefore the one a process receives itself a second time. Two signals sent separately
// to two DIFFERENT processes of the pair (the launcher alone, the outer process alone) cannot be told from one signal
// to the group, since each process has then received one, so they are one: the cases below that send to both, in
// either order, want one interrupt. The red case on the earlier forwarding, which only the outer process did, is the background
// group: the outer process forwarded the group's INT to a launcher that had already got it.
func TestScopeInterruptReachesTheLauncherOnce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		term  bool
		sends []string // "group": the whole job, "outer": the outer process, "launcher": the launcher alone
		want  int
	}{
		{"parent alone without terminal", false, []string{"outer"}, scopeOneInterrupt},
		{"launcher alone", false, []string{"launcher"}, scopeOneInterrupt},
		{"foreground group with piped stdin", true, []string{"group"}, scopeOneInterrupt},
		{"background group with piped stdin", false, []string{"group"}, scopeOneInterrupt},
		{"a deliberate repeat to the group", false, []string{"group", "group"}, scopeTwoInterrupts},
		{"the launcher, then the outer process: one signal to each process is one interrupt", false, []string{"launcher", "outer"}, scopeOneInterrupt},
		{"the outer process, then the launcher: one signal to each process is one interrupt", false, []string{"outer", "launcher"}, scopeOneInterrupt},
		{"the launcher twice", false, []string{"launcher", "launcher"}, scopeTwoInterrupts},
		{"the outer process twice", false, []string{"outer", "outer"}, scopeTwoInterrupts},
		{"the launcher, the outer process, the launcher: the launcher received two", false, []string{"launcher", "outer", "launcher"}, scopeTwoInterrupts},
		{"the outer process, then the group", false, []string{"outer", "group"}, scopeTwoInterrupts},
		{"the group, then the launcher alone", false, []string{"group", "launcher"}, scopeTwoInterrupts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0])
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=proxy-interrupt", "SCOPE_EXPECT_CWD="+cmd.Dir,
				"SCOPE_INTERRUPT_WAIT=3s")
			cmd.Stdin = strings.NewReader("task")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if tc.term {
				_, slave := scopePTY(t)
				cmd.Stdout, cmd.Stderr = slave, slave
				cmd.SysProcAttr.Setctty = true
				cmd.SysProcAttr.Ctty = 1
			}
			if tc.want == scopeOneInterrupt {
				cmd.Env = append(cmd.Env, "SCOPE_INTERRUPT_WAIT=300ms")
			}
			if tc.sends[0] != "outer" {
				cmd.Env = append(cmd.Env, "SCOPE_FIRST_REACHES_LAUNCHER=1")
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var waitErr error
			go func() { waitErr = cmd.Wait(); close(done) }()
			t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
			child, err := strconv.Atoi(string(scopeWaitFile(t, filepath.Join(cmd.Dir, "child"))))
			if err != nil {
				t.Fatal(err)
			}
			target := map[string]int{"group": -cmd.Process.Pid, "outer": cmd.Process.Pid, "launcher": child}
			for i, send := range tc.sends {
				if i > 0 {
					scopeWaitFile(t, filepath.Join(cmd.Dir, "first")) // the first one is settled before the next is sent
					// and delivered to both processes: a signal sent to a process that still has one pending is the
					// same pending signal (the kernel keeps one), which a person's second keystroke never meets.
					scopeWaitNoInterruptPending(t, cmd.Process.Pid, child)
				}
				if err := syscall.Kill(target[send], syscall.SIGINT); err != nil {
					t.Fatal(err)
				}
			}
			if err := scopeWriteMarker(filepath.Join(cmd.Dir, "sent"), []byte("1")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				if ee, ok := waitErr.(*exec.ExitError); !ok || ee.ExitCode() != tc.want {
					t.Fatalf("sends %v: %v, want exit %d", tc.sends, waitErr, tc.want)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("the launcher never settled")
			}
		})
	}
}

// scopeWaitNoInterruptPending waits until none of the processes has an INT waiting to be taken by one of its threads,
// by the pending sets in /proc/<pid>/status (the process's shared set) and in each of its tasks' status files.
func scopeWaitNoInterruptPending(t *testing.T, pids ...int) {
	t.Helper()
	const intBit = 1 << (int(syscall.SIGINT) - 1)
	pending := func(path string) bool {
		b, err := os.ReadFile(path)
		if err != nil {
			return false // the task or the process is gone: nothing is pending there
		}
		for _, line := range strings.Split(string(b), "\n") {
			for _, key := range []string{"SigPnd:", "ShdPnd:"} {
				if v, ok := strings.CutPrefix(line, key); ok {
					if n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64); err == nil && n&intBit != 0 {
						return true
					}
				}
			}
		}
		return false
	}
	for end := time.Now().Add(4 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		any := false
		for _, pid := range pids {
			root := "/proc/" + strconv.Itoa(pid)
			if pending(root + "/status") {
				any = true
			}
			tasks, _ := filepath.Glob(root + "/task/*/status")
			for _, f := range tasks {
				if pending(f) {
					any = true
				}
			}
		}
		if !any {
			return
		}
	}
	t.Fatalf("an interrupt stayed pending in %v", pids)
}
