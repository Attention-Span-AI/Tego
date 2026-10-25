// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// These tests moved here from internal/runtime/lock_test.go with the unexported code they test.

func FuzzParseStartBootNS(f *testing.F) {
	for _, s := range []string{
		"1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 1 2 3 4 20 0 1 0 4990 0 0",
		"", "1 (a b) S", "1 )", "1 (x) " + "0 ",
	} {
		f.Add([]byte(s))
	}
	f.Add([]byte("1 (x) S 0 1 1 0 -1 4194560 100 0 0 0 1 2 3 4 20 0 1 0 18446744073709551615 0 0"))
	// Never a panic on a torn or foreign /proc line, and a start time that is the line's own starttime in
	// nanoseconds, whole ticks and never wrapped (this target checked nothing).
	f.Fuzz(func(t *testing.T, b []byte) {
		ns, err := parseStartBootNS(b)
		if err != nil {
			return
		}
		st, err := proc.ParseStat(b)
		if err != nil || ns%proc.NanosPerTick != 0 || ns/proc.NanosPerTick != st.StartTicks {
			t.Fatalf("parseStartBootNS(%q) = %d, not starttime %d in nanoseconds (%v)", b, ns, st.StartTicks, err)
		}
	})
}

func TestParseStartBootNSCommWithSpaces(t *testing.T) {
	// The comm field may hold spaces and parentheses; starttime is the 20th field after the last ')'.
	stat := []byte("42 (my ) proc) S 1 42 42 0 -1 0 0 0 0 0 11 22 33 44 20 0 1 0 500 0 0 0")
	got, err := parseStartBootNS(stat)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := uint64(500 * proc.NanosPerTick); got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

// openRun creates a run directory with a live ledger writer, which is what holds the lock (R1).
func TestFlockHeldBy(t *testing.T) {
	table := []byte("1: POSIX  ADVISORY  WRITE 7 08:01:99 0 EOF\n" +
		"2: FLOCK  ADVISORY  WRITE 42 fd:01:5678 0 EOF\n" +
		"2: -> FLOCK  ADVISORY  WRITE 43 fd:01:5678 0 EOF\n")
	for _, c := range []struct {
		pid  int
		ino  uint64
		want bool
	}{{42, 5678, true}, {43, 5678, false}, {42, 5679, false}, {7, 99, false}} {
		if got := flockHeldBy(table, c.pid, c.ino); got != c.want {
			t.Errorf("flockHeldBy(%d, %d) = %v, want %v", c.pid, c.ino, got, c.want)
		}
	}
}

// TestOpenStopTargetForRefusesAnotherPidNamespace: a lock line that records a pid namespace other than the

// Also pins runtime-launch.md E15, E32: a start-time mismatch on the held pidfd is not running.
func TestOpenStopTargetRejectsAStaleStartTime(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	start, err := StartBootNS(pid)
	if err != nil {
		t.Fatalf("StartBootNS: %v", err)
	}
	target, err := openPidfdTarget(pid, start)
	if err != nil {
		t.Fatalf("OpenStopTarget: %v", err)
	}
	if target.PID() != pid {
		t.Fatalf("PID %d, want %d", target.PID(), pid)
	}
	if err := target.Signal(syscall.SIGCONT); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// The pid is alive but started at another time, so it is not the process the lock named.
	if _, err := openPidfdTarget(pid, start+1); !errors.Is(err, ErrStale) {
		t.Fatalf("stale start time: %v, want ErrStale", err)
	}
}

// TestStopTargetSignalAfterCloseIsErrClosed is lock.go's StopTarget as an owner of its pidfd (ADR 0023 C9): a Signal
// after Close is os.ErrClosed and reaches no process, and a Close while the pidfd is borrowed (as a Signal borrows
// it) keeps the number open, still the target's pidfd, until the borrow returns: a Close racing a Signal no longer
// frees the number under it.
func TestStopTargetSignalAfterCloseIsErrClosed(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	start, err := StartBootNS(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("StartBootNS: %v", err)
	}
	target, err := openPidfdTarget(cmd.Process.Pid, start)
	if err != nil {
		t.Fatalf("OpenStopTarget: %v", err)
	}
	if err := target.fd.Borrow(func(n int) error {
		if err := target.Close(); err != nil {
			return err
		}
		// The number is the target's pidfd still: the deferred close has not run.
		return sys.PidfdSendSignal(n, 0)
	}); err != nil {
		t.Fatalf("a Close during a borrow: %v, want the borrowed pidfd usable until it returns", err)
	}
	if err := target.Signal(syscall.SIGTERM); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Signal after Close = %v, want os.ErrClosed", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("the target is gone after a Signal on a closed StopTarget: %v", err)
	}
	var nilTarget *StopTarget
	if err := nilTarget.Signal(syscall.SIGTERM); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Signal on a nil StopTarget = %v, want os.ErrClosed", err)
	}
}

func TestOpenStopTargetGonePID(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Skipf("no /bin/true: %v", err)
	}
	if _, err := openPidfdTarget(cmd.Process.Pid, 1); err == nil {
		t.Fatal("a reaped pid must not be signalable")
	}
}
