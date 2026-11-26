// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"golang.org/x/sys/unix"
)

// scopeControlCommand uses only test helpers, never a product run or a user manager.
func scopeControlCommand(ctx context.Context, mode string) (int, bool) {
	if mode == "interrupt" {
		return scopeInterrupt(ctx), true
	}
	if mode == "parentdeath" {
		return scopeWaitForParentDeath(), true
	}
	if mode == "stop-nested" {
		return scopeNestedLauncher(), true
	}
	dir := os.Getenv("SCOPE_EXPECT_CWD")
	if mode == "stop" || mode == "stop-group" {
		if mode == "stop-group" {
			if err := unix.Setpgid(0, 0); err != nil {
				return 93, true
			}
			signal.Ignore(syscall.SIGTTOU)
			if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, unix.Getpgrp()); err != nil {
				return 92, true
			}
		}
		modes, err := unix.IoctlGetTermios(0, unix.TCGETS)
		if err != nil {
			return 91, true
		}
		modes.Lflag &^= unix.ICANON | unix.ECHO
		if err := unix.IoctlSetTermios(0, unix.TCSETS, modes); err != nil {
			return 90, true
		}
		_ = scopeWriteMarker(filepath.Join(dir, "child"), []byte(strconv.Itoa(os.Getpid())))
		// A process-directed stop can be pending on another Go thread while this
		// goroutine reaches os.Exit(37). Stop the calling thread so this syscall
		// cannot return until the test's explicit fg has continued the helper.
		runtime.LockOSThread()
		stopErr := unix.Tgkill(os.Getpid(), unix.Gettid(), unix.SIGSTOP)
		runtime.UnlockOSThread()
		if stopErr != nil {
			return 88, true
		}
		// fg continues the shared group at once. The child can run before its parent restores modes, so wait for
		// that observable restoration instead of assuming an ordering between resumed processes.
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			front, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
			now, e := unix.IoctlGetTermios(0, unix.TCGETS)
			if err == nil && e == nil && front == unix.Getpgrp() && now.Lflag&unix.ICANON == 0 {
				return 37, true
			}
		}
		return 89, true
	}
	return 0, false
}

func scopePTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func scopeWaitFile(t *testing.T, path string) []byte {
	t.Helper()
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if b, err := os.ReadFile(path); err == nil {
			return b
		}
	}
	t.Fatalf("no helper acknowledgement at %s", path)
	return nil
}

func scopeWaitStopped(t *testing.T, pid int) {
	t.Helper()
	for end := time.Now().Add(4 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err == nil && strings.HasPrefix(string(b[strings.LastIndexByte(string(b), ')')+1:]), " T ") {
			return
		}
	}
	t.Fatalf("pid %d did not stop with its child", pid)
}

// The launcher stops itself after putting the terminal raw. The proxy must follow that stop and, when only
// the proxy is continued, resume the launcher and restore its modes and foreground group (including a separate group).
func TestScopeProcessFollowsAStoppedLauncher(t *testing.T) {
	for _, mode := range []string{"stop", "stop-group"} {
		t.Run(mode, func(t *testing.T) {
			_, slave := scopePTY(t)
			saved, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			cmd := exec.Command("/bin/bash", "--norc", "--noprofile", "-c", `set -m
"$1"
while [ ! -e "$2/continue" ]; do sleep 0.01; done
fg
exit "$?"`, "bash", os.Args[0], dir)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=proxy-"+mode, "SCOPE_EXPECT_CWD="+dir)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			child := 0
			t.Cleanup(func() {
				if child > 0 {
					_ = syscall.Kill(child, syscall.SIGKILL)
				}
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				_ = cmd.Wait()
			})
			child, _ = strconv.Atoi(string(scopeWaitFile(t, filepath.Join(cmd.Dir, "child"))))
			scopeWaitStopped(t, child)
			proxy, _ := strconv.Atoi(string(scopeWaitFile(t, filepath.Join(dir, "proxy"))))
			t.Cleanup(func() { _ = syscall.Kill(-proxy, syscall.SIGKILL) })
			scopeWaitStopped(t, proxy)
			now, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || *now != *saved {
				t.Fatalf("stopped proxy left raw terminal: %v %v", now, err)
			}
			// bash performs the foreground transfer before continuing its direct child, as fg does at a prompt.
			if err := os.WriteFile(filepath.Join(dir, "continue"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 37 {
					t.Fatalf("resume: %v", err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("proxy did not resume/reap launcher")
			}
		})
	}
}

func TestScopeCancelHasNoFallbackAdvice(t *testing.T) {
	scopeStands(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { return 0, context.Canceled }
	ctx = context.WithValue(ctx, scopeKey{}, scopeInvocation{argv: []string{"tego", "run", "missing"}})
	var out bytes.Buffer
	code, done := enterUserScope(ctx, &out)
	if !done || code != 130 || out.Len() != 0 {
		t.Fatalf("cancel: code %d done %v advice %q", code, done, out.String())
	}
}

// Stdin stays a pipe in both cases. The controlling terminal, not that stream, decides whether INT/QUIT already
// reached the launcher. TERM and other forwarded signals retain the existing policy.
func TestScopeSignalsUseTheControllingTerminal(t *testing.T) {
	old := scopeForeground
	defer func() { scopeForeground = old }()
	for _, front := range []bool{false, true} {
		scopeForeground = func() bool { return front }
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGQUIT} {
			if got := shouldForwardScope(sig); got == front {
				t.Errorf("foreground %v signal %v forwarded %v", front, sig, got)
			}
		}
		if !shouldForwardScope(syscall.SIGTERM) {
			t.Error("TERM not forwarded")
		}
	}
}

// SIGURG and SIGCHLD have default-ignore actions: no child can die from those defaults. Real subprocesses test
// their fallback statuses instead; terminating defaults are covered by the real child status test above.
func TestScopeReraiseIgnoredDefaultsReturnsStatus(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGURG, syscall.SIGCHLD} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0])
			cmd.Env = append(os.Environ(), fmt.Sprintf("TEGO_SCOPE_TEST_HELPER=reraise-%d", sig))
			err := cmd.Run()
			ee, ok := err.(*exec.ExitError)
			if !ok || ee.ExitCode() != 128+int(sig) {
				t.Fatalf("signal %v: %v", sig, err)
			}
		})
	}
}

func scopeReraiseHelper(mode string) {
	n, _ := strconv.Atoi(strings.TrimPrefix(mode, "reraise-"))
	os.Exit(launch.Reraise(syscall.Signal(n)))
}
