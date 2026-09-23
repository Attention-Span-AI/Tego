// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// bigEnvSpec is a spec whose serialized wire form is far larger than any pipe buffer (the Linux default is
// 64 KiB). ARG_MAX-sized Command/Env is a supported input, not abuse: cases 18 and 27 say this package
// "passes whatever final []string it receives unchanged", and maxSpecBytes allows 8 MiB.
func bigEnvSpec(t *testing.T, cmd []string) ChildSpec {
	t.Helper()
	s := validSpec()
	s.Command = cmd
	const entries, size = 2048, 1024 // ~2 MiB, the ARG_MAX figure case 18 names
	s.Env = make([]string, 0, entries)
	for i := range entries {
		s.Env = append(s.Env, fmt.Sprintf("TEGO_BIG_%04d=%s", i, strings.Repeat("a", size)))
	}
	return s
}

// startAsync runs Start on its own goroutine so a Start that never returns fails the test instead of
// hanging the whole package run.
func startAsync(t *testing.T, ctx context.Context, l *Launcher, s ChildSpec) (*Child, error) {
	t.Helper()
	type result struct {
		child *Child
		err   error
	}
	done := make(chan result, 1)
	go func() {
		c, err := l.Start(ctx, s, nil)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		return r.child, r.err
	case <-time.After(20 * time.Second):
		t.Fatal("Start never returned: the spec write is blocked on a pipe with no reader but a live read end " +
			"held by the parent (R6: a dead peer must yield EOF/EPIPE, never a hang)")
		return nil, nil
	}
}

func requireExecutable(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not available on this box: %v", path, err)
	}
}

// TestStartLargeSpecReportsDeadChild is R6's "a dead peer yields EOF, never a hang" for the one write Start
// makes. A spec larger than the pipe buffer cannot be absorbed by the buffer, so the write can only finish
// when the child reads it or dies. The child here exits without ever reading, which must surface as
// ErrChildDied (case 3) -- and does so only because Start no longer keeps pipe B's own read end open while
// writing: while the parent is itself a reader the kernel raises no EPIPE and the write parks forever.
func TestStartLargeSpecReportsDeadChild(t *testing.T) {
	requireExecutable(t, "/bin/true")
	l := &Launcher{Exe: "/bin/true", Args: []string{}}
	child, err := startAsync(t, context.Background(), l, bigEnvSpec(t, []string{"/bin/true"}))
	if child != nil {
		t.Errorf("Start returned a Child on the failure path: %+v", child)
		_ = child.Close()
	}
	if !errors.Is(err, ErrChildDied) {
		t.Fatalf("Start err = %v, want it to wrap ErrChildDied", err)
	}
}

// TestStartLargeSpecWriteHonoursContext covers the child that is stopped rather than dead: it holds pipe B's
// read end open and never reads, so no EPIPE can ever arrive. Only ctx can end that write, and Start's
// contract is that the caller's ctx governs the handshake.
func TestStartLargeSpecWriteHonoursContext(t *testing.T) {
	requireExecutable(t, "/bin/sleep")
	l := &Launcher{Exe: "/bin/sleep", Args: []string{"60"}}
	ctx, cancel := context.WithCancel(context.Background())
	// The write blocks as soon as the pipe buffer fills; cancelling after it is parked is what the deadline
	// must break. A cancel this early would also be caught by Start's entry check, so it is deliberately late.
	time.AfterFunc(300*time.Millisecond, cancel)
	defer cancel()
	child, err := startAsync(t, ctx, l, bigEnvSpec(t, []string{"/bin/sleep", "60"}))
	if child != nil {
		t.Errorf("Start returned a Child on the failure path: %+v", child)
		_ = child.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start err = %v, want context.Canceled", err)
	}
}

// TestCloneHintSeparatesFilteredClone3FromOldKernel is moby#42680 as a diagnosis, not a message: the same
// EPERM means "a container runtime's seccomp profile refused clone3" when this process is itself filtered
// (Seccomp: 2) and something else entirely when it is not (Seccomp: 0). Case 20 previously attributed both
// to kernel age, which is the one explanation that cannot be true when /proc says a filter is in force.
//
// Also pins runtime-launch.md E20: only the causes it can prove are named.
func TestCloneHintSeparatesFilteredClone3FromOldKernel(t *testing.T) {
	// os/exec hands Start a *os.PathError, not a bare Errno; the hint must survive that wrapping.
	forkExec := func(e syscall.Errno) error {
		return &os.PathError{Op: "fork/exec", Path: "/proc/self/exe", Err: e}
	}
	tests := []struct {
		name          string
		err           error
		mode          int
		intoCgroup    bool
		want, notWant string
	}{
		{"EPERM under a filter is the Docker profile", forkExec(syscall.EPERM), 2, true, "Seccomp: 2", "kernel itself has no"},
		{"ENOSYS under a filter is the post-42680 profile", forkExec(syscall.ENOSYS), 2, true, "clone3 is being filtered", "kernel itself has no"},
		{"ENOSYS with no filter is a real old kernel", forkExec(syscall.ENOSYS), 0, true, "kernel itself has no", "moby"},
		{"EPERM with no filter is not a filtered clone3", forkExec(syscall.EPERM), 0, true, "EACCES", "container runtime"},
		{"unreadable /proc names both causes", forkExec(syscall.EPERM), seccompModeUnknown, true, "could not be read", ""},
		// a nil cgroup (tests, observe tier without a manager): os/exec picks clone3 only for UseCgroupFD,
		// so blaming a clone3-blocking profile here would name a syscall that was never made.
		{"no cgroup fd means the syscall was clone(2)", forkExec(syscall.EPERM), 2, false, "clone(2) is being filtered", "clone3 is being"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cloneHint(tc.err, tc.mode, tc.intoCgroup)
			if !strings.Contains(got, tc.want) {
				t.Errorf("cloneHint(%v, mode=%d) = %q, want it to contain %q", tc.err, tc.mode, got, tc.want)
			}
			if tc.notWant != "" && strings.Contains(got, tc.notWant) {
				t.Errorf("cloneHint(%v, mode=%d) = %q, must not contain %q", tc.err, tc.mode, got, tc.notWant)
			}
		})
	}
	// Errnos that say nothing about a filter keep the bare message: EAGAIN is RLIMIT_NPROC, ENOSPC is case 2.
	for _, e := range []syscall.Errno{syscall.EAGAIN, syscall.ENOSPC, syscall.EINVAL} {
		if got := cloneHint(forkExec(e), 2, true); got != "" {
			t.Errorf("cloneHint(%v) = %q, want no hint: only EPERM/ENOSYS implicate a syscall filter", e, got)
		}
	}
}

// TestCloneFailureKeepsErrCloneAndErrno pins the wrapping the callers depend on: runtime.Run tests errors.Is
// against ErrClone for its exit-125 path (§7) and the operator needs the errno itself in the one stderr line.
//
// Also pins runtime-launch.md E20: a refused clone3 is ErrClone with the errno.
func TestCloneFailureKeepsErrCloneAndErrno(t *testing.T) {
	err := cloneFailure(&os.PathError{Op: "fork/exec", Path: "/proc/self/exe", Err: syscall.EPERM}, true)
	if !errors.Is(err, ErrClone) {
		t.Errorf("cloneFailure err = %v, want it to wrap ErrClone", err)
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("cloneFailure err = %v, want it to wrap EPERM", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "seccomp") {
		t.Errorf("cloneFailure err = %q, want it to name seccomp as the thing to check", err)
	}
}

// TestParseSeccompModeIgnoresSeccompFilters guards the one parsing trap: Seccomp_filters (5.9+) sits right
// under Seccomp in /proc/<pid>/status and is a filter count, not a mode — reading it as the mode would
// report "no filter" on a filtered process with zero attached filters, the exact case the hint turns on.
func TestParseSeccompModeIgnoresSeccompFilters(t *testing.T) {
	const status = "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t0\nSpeculation_Store_Bypass:\tvulnerable\n"
	if got := parseSeccompMode(status); got != 2 {
		t.Errorf("parseSeccompMode = %d, want 2 (SECCOMP_MODE_FILTER)", got)
	}
	if got := parseSeccompMode("Name:\tsh\nNoNewPrivs:\t0\n"); got != seccompModeUnknown {
		t.Errorf("parseSeccompMode(no Seccomp line) = %d, want seccompModeUnknown: a kernel without "+
			"CONFIG_SECCOMP omits the field and must not read as mode 0", got)
	}
	if got := parseSeccompMode("Seccomp:\tnonsense\n"); got != seccompModeUnknown {
		t.Errorf("parseSeccompMode(unparsable) = %d, want seccompModeUnknown", got)
	}
}

// TestPipeDeadlineCallbacksEndBeforeTheirCaller: sendSpec and readControl bound their pipe I/O with a
// deadline that a ctx callback sets, on a goroutine of its own. Once ctx has ended the callback has started,
// and it must be done before sendSpec or readControl returns. Otherwise it reads the Child's pipe field
// while Ack or Close clears it, the data race `go test -race` reports, and it can set sendSpec's deadline
// again after sendSpec cleared it, so the Ack write that follows fails with a timeout. Each round has the
// pipe ready before the call, so the write or the read completes at once whether or not the callback, which
// an ended ctx starts at once, has run yet, and the race detector sees any access it makes after the call.
func TestPipeDeadlineCallbacksEndBeforeTheirCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		bR, bW, err := os.Pipe() // pipe B: the spec and the ack byte, both far below its buffer
		if err != nil {
			t.Fatal(err)
		}
		aR, aW, err := os.Pipe() // pipe A: the control message, written before readControl reads
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aW.Write(encodeNoListener()); err != nil {
			t.Fatal(err)
		}
		c := &Child{ControlR: aR, controlW: bW, release: make(chan struct{})}
		switch err := sendSpec(ctx, c, wireSpec{}); {
		case err == nil:
			// The write went through before the callback cut it, so the Ack write must meet no deadline.
			if err := c.Ack(); err != nil {
				t.Fatalf("Ack after a spec that went through: %v", err)
			}
		case !errors.Is(err, context.Canceled):
			t.Fatalf("sendSpec on an ended ctx: %v", err)
		}
		if _, err := c.readControl(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("readControl on an ended ctx: %v", err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		_ = bR.Close()
		_ = aW.Close()
	}
}
