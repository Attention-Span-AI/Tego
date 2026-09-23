// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStopNotRunning covers R29/R25's stop contract for §6 case 11: a run whose launcher has
// already finished (no lock held) sends no signal, touches nothing else, and still exits 0 —
// "not running" is not a failure. Nothing in this package exercised `stop` past its usage-error
// argument checks before this (main_test.go only ever fed it a malformed run id).
//
// Also pins runtime-launch.md E11: stop on a free lock says not running, sends no signal and does no full
// sweep.
func TestStopNotRunning(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	code, out, errs := run(t, "stop", id)
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitOK, out, errs)
	}
	if !strings.Contains(out, id+": not running") {
		t.Errorf("stdout %q", out)
	}
}

// TestStopUnknownRunIsUsage covers the run-not-found branch (R25: the caller named a run id that
// exists nowhere under the ledger root, a usage error, distinct from the malformed-shape branch
// main_test.go already pins).
func TestStopUnknownRunIsUsage(t *testing.T) {
	gcRoot(t)
	code, _, errs := run(t, "stop", "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if code != identity.ExitUsage {
		t.Fatalf("exit %d, want %d (stderr %q)", code, identity.ExitUsage, errs)
	}
	if !strings.Contains(errs, "no such run") {
		t.Errorf("stderr %q", errs)
	}
}

// TestStopGraceMustBePositive: --grace is written into the marker as the launcher's own stop_grace,
// so a zero or negative one is refused as a usage error rather than silently meaning the default.
func TestStopGraceMustBePositive(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	for _, g := range []string{"0s", "-1s"} {
		code, _, errs := run(t, "stop", id, "--grace", g)
		if code != identity.ExitUsage || !strings.Contains(errs, "positive") {
			t.Errorf("--grace %s: exit %d, want 2 (stderr %q)", g, code, errs)
		}
	}
	if code, _, errs := run(t, "stop", id, "--grace", "30s"); code != identity.ExitOK {
		t.Errorf("--grace 30s on a finished run: exit %d (stderr %q)", code, errs)
	}
	// The machine config's grammar: a day is a grace, a week is not a unit.
	if code, _, errs := run(t, "stop", id, "--grace", "1d"); code != identity.ExitOK {
		t.Errorf("--grace 1d on a finished run: exit %d (stderr %q)", code, errs)
	}
	if code, _, errs := run(t, "stop", id, "--grace", "1w"); code != identity.ExitUsage || !strings.Contains(errs, "[usage]") {
		t.Errorf("--grace 1w: exit %d (stderr %q), want a usage error", code, errs)
	}
}

// TestSecondStopKeepsTheFirstGrace is R29's "a second stop keeps the first one's grace" for stop's own
// backstop, not only the launcher's timer: a plain `stop` after `stop --grace <long>` used to write
// cgroup.kill itself once its own grace was up, cutting the first stop's grace short. The same holds when
// the first stop gave no --grace: its grace is the machine's stop_grace, which the launcher's timer runs
// to, and a later `stop --grace <short>` used to write cgroup.kill after its own short grace. The run here
// is live — this test holds its lock — and never ends, so the backstop fires; what matters is when.
func TestSecondStopKeepsTheFirstGrace(t *testing.T) {
	const long, short = 700 * time.Millisecond, 50 * time.Millisecond
	for _, tc := range []struct {
		name string
		// first and second are what each stop's --grace asks for (0: a plain stop); machine is the
		// machine's stop_grace.
		first, second, machine time.Duration
	}{
		{"a plain stop after stop --grace <long>", long, 0, short},
		{"stop --grace <short> after a plain stop", 0, short, long},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, id, info := liveRun(t)
			if err := tegoruntime.RequestStopGraceThen(t.Context(), dir, tc.first, nil); err != nil { // the first stop
				t.Fatal(err)
			}
			var (
				mu        sync.Mutex
				escalated time.Duration
			)
			began := time.Now()
			prev := escalateRun
			escalateRun = func(string, string, io.Writer) {
				mu.Lock()
				defer mu.Unlock()
				escalated = time.Since(began)
			}
			defer func() { escalateRun = prev }()
			var out, errs bytes.Buffer
			own := tc.second // runStop's own grace: --grace, else the machine's stop_grace
			if own == 0 {
				own = tc.machine
			}
			if code := stopRun(t.Context(), dir, id, info, tc.second, own, tc.machine, &out, &errs); code != identity.ExitOK {
				t.Fatalf("exit %d: %s", code, errs.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if escalated < long {
				t.Fatalf("the second stop wrote cgroup.kill after %v, before the first stop's %v grace was up", escalated, long)
			}
			if !strings.Contains(out.String(), "still running after "+long.String()) {
				t.Errorf("stdout %q, want the wait to be the first stop's grace", out.String())
			}
			if got := backstopAfter(dir, 2*long, tc.machine); got != 2*long {
				t.Errorf("a longer own grace: backstop after %v, want %v", got, 2*long)
			}
		})
	}
}

// liveRun is a run whose lock this test holds, with a process standing in for its launcher that a stop
// can signal, verified by its start time as the lock says.
func liveRun(t *testing.T) (dir, id string, info tegoruntime.LockInfo) {
	t.Helper()
	root := gcRoot(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(root, string(rid))
	w, err := ledger.Open(dir, record.RunRef{ID: string(rid), Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	// The stand-in launcher is a process that holds the run's flock itself: stop signals only a pid that does
	// (runtime.OpenStopTarget), so a process that merely exists would be refused. The test's own writer lets go
	// of the lock first, and the process ignores SIGTERM so the run stays live however the stop goes.
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	sleeper := exec.Command(os.Args[0], "-test.run=^TestStopLockHolderHelper$")
	sleeper.Env = append(os.Environ(), "TEGO_TEST_HOLD_LOCK="+filepath.Join(dir, ledger.LockFile), "TEGO_TEST_HOLD_READY="+ready)
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stand-in launcher never took the lock")
		}
	}
	start, err := tegoruntime.StartBootNS(sleeper.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return dir, string(rid), tegoruntime.LockInfo{PID: sleeper.Process.Pid, StartBootNS: start}
}

// TestStopInterruptedDoesNotEscalate: a SIGINT or SIGTERM to `tego stop` while it waits out the grace
// cancels the command's context. That is the user giving up the wait, not the grace expiring, so stop
// must not write the backstop cgroup.kill; it used to, killing the run at once and then reporting it as
// "still running after <grace>".
func TestStopInterruptedDoesNotEscalate(t *testing.T) {
	dir, id, info := liveRun(t)
	escalated := false
	prev := escalateRun
	escalateRun = func(string, string, io.Writer) { escalated = true }
	defer func() { escalateRun = prev }()
	ctx, cancel := context.WithCancel(t.Context())
	// The cancellation comes while stop waits out the grace, after it placed its marker: a fixed 100 ms could land
	// before the marker on a loaded machine, where stop rightly fails ("place stop marker: context canceled"),
	// which is not the case this test is about.
	go func() {
		marker := filepath.Join(dir, tegoruntime.StopRequestFile)
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if _, err := os.Stat(marker); err == nil {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	var out, errs bytes.Buffer
	const grace = time.Hour
	began := time.Now()
	if code := stopRun(ctx, dir, id, info, grace, grace, grace, &out, &errs); code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if time.Since(began) > 30*time.Second {
		t.Fatalf("stop waited %v after its context was cancelled", time.Since(began))
	}
	if escalated {
		t.Fatal("an interrupted stop wrote the backstop cgroup.kill before the grace was up")
	}
	if strings.Contains(out.String(), "still running after") {
		t.Errorf("stdout %q: an interrupted wait is not an expired grace", out.String())
	}
	if !strings.Contains(out.String(), "stopped waiting") {
		t.Errorf("stdout %q, want it to say the wait was abandoned", out.String())
	}
}

// TestStopLauncherGoneAtDelivery: the launcher exits between the verified pidfd and the SIGTERM, so
// pidfd_send_signal answers ESRCH. That is the run ending on its own: exit 0, never a 125 [io] (R29).
func TestStopLauncherGoneAtDelivery(t *testing.T) {
	dir, id, info := liveRun(t)
	prevSig, prevEsc := signalTarget, escalateRun
	signalTarget = func(*tegoruntime.StopTarget, syscall.Signal) error {
		return fmt.Errorf("runtime: pidfd_send_signal: %w", syscall.ESRCH)
	}
	escalateRun = func(string, string, io.Writer) {}
	defer func() { signalTarget, escalateRun = prevSig, prevEsc }()
	var out, errs bytes.Buffer
	const grace = 200 * time.Millisecond
	if code := stopRun(t.Context(), dir, id, info, grace, grace, grace, &out, &errs); code != identity.ExitOK {
		t.Fatalf("exit %d, want %d (stderr %q)", code, identity.ExitOK, errs.String())
	}
	if errs.Len() != 0 {
		t.Errorf("stderr %q, want none", errs.String())
	}
}

// TestAwaitLockInfoWaitsForTheHolderToIdentifyItself: a held lock whose pid/start line is not written
// yet must not send stop to pid 0 (pidfd_open(0) is EINVAL, a 125 with the marker already left).
func TestAwaitLockInfoWaitsForTheHolderToIdentifyItself(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, ledger.LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(100*time.Millisecond, func() {
		_, _ = f.WriteAt([]byte(tegoruntime.LockInfo{PID: 4242, StartBootNS: 7}.String()), 0)
	})
	held, info, err := awaitLockInfo(t.Context(), dir)
	if err != nil || !held || info.PID != 4242 {
		t.Fatalf("held=%v info=%+v err=%v, want the line the holder wrote", held, info, err)
	}
	// A holder that never writes it: the wait is bounded and reports the empty info.
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	prev := lockInfoWait
	lockInfoWait = 50 * time.Millisecond
	defer func() { lockInfoWait = prev }()
	held, info, err = awaitLockInfo(t.Context(), dir)
	if err != nil || !held || info.PID != 0 {
		t.Fatalf("held=%v info=%+v err=%v, want held with no pid after the bound", held, info, err)
	}
	// The lock frees while waiting: not running.
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if held, _, err = awaitLockInfo(t.Context(), dir); err != nil || held {
		t.Fatalf("held=%v err=%v, want a free lock", held, err)
	}
}

// TestStopWaitsBrieflyAfterTheBackstopKill: cgroup.kill is one asynchronous write, so the wait after it
// is postKillWait, not a second full grace.
func TestStopWaitsBrieflyAfterTheBackstopKill(t *testing.T) {
	dir, id, info := liveRun(t)
	prevEsc, prevWait := escalateRun, postKillWait
	escalateRun = func(string, string, io.Writer) {}
	postKillWait = 50 * time.Millisecond
	defer func() { escalateRun, postKillWait = prevEsc, prevWait }()
	const grace = 1500 * time.Millisecond
	var out, errs bytes.Buffer
	began := time.Now()
	if code := stopRun(t.Context(), dir, id, info, grace, grace, grace, &out, &errs); code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if took := time.Since(began); took > grace+900*time.Millisecond {
		t.Errorf("stop blocked %v; want about one grace (%v) plus the short post-kill wait", took, grace)
	}
	if !strings.Contains(out.String(), "still running after "+grace.String()) {
		t.Errorf("stdout %q", out.String())
	}
}

// TestStopLockHolderHelper is liveRun's stand-in launcher: it holds a run's lock until it is killed and
// ignores SIGTERM. It does nothing in a normal run.
func TestStopLockHolderHelper(t *testing.T) {
	path := os.Getenv("TEGO_TEST_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process only")
	}
	signal.Ignore(syscall.SIGTERM)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("TEGO_TEST_HOLD_READY"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

// TestStopLeavesNoMarkerWhenTheLauncherIsNotVerified: a stop that cannot prove the pid holds the run's lock
// exits without placing stop.request, or the live run's next Ctrl-C would be recorded as reason=stopped (R22).
func TestStopLeavesNoMarkerWhenTheLauncherIsNotVerified(t *testing.T) {
	dir, id, info := liveRun(t)
	self := os.Getpid()
	start, err := tegoruntime.StartBootNS(self)
	if err != nil {
		t.Fatal(err)
	}
	info.PID, info.StartBootNS = self, start // alive, but it is the stand-in that holds the lock
	var out, errs bytes.Buffer
	if code := stopRun(t.Context(), dir, id, info, time.Second, time.Second, time.Second, &out, &errs); code != identity.ExitError {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitError, out.String(), errs.String())
	}
	if _, err := os.Stat(filepath.Join(dir, tegoruntime.StopRequestFile)); !os.IsNotExist(err) {
		t.Fatalf("stop.request after a refused stop: %v", err)
	}
}

// TestR1StopFailedDeliveryMarkerRollback drives the verified live holder through
// the existing signal seam. The kernel delivery error is injected; the child,
// flock and verified pidfd are actual. A rejected delivery must not manufacture
// a stop reason for a later unrelated signal, or delete an earlier request.
func TestR1StopFailedDeliveryMarkerRollback(t *testing.T) {
	for _, prior := range []bool{false, true} {
		t.Run(fmt.Sprintf("prior-%t", prior), func(t *testing.T) {
			dir, id, info := liveRun(t)
			if prior {
				if err := tegoruntime.RequestStopGraceThen(t.Context(), dir, 7*time.Second, nil); err != nil {
					t.Fatal(err)
				}
			}
			prev := signalTarget
			signalTarget = func(*tegoruntime.StopTarget, syscall.Signal) error {
				return fmt.Errorf("controlled delivery: %w", syscall.EPERM)
			}
			t.Cleanup(func() { signalTarget = prev })
			var out, errs bytes.Buffer
			got := stopRun(t.Context(), dir, id, info, time.Second, time.Second, time.Second, &out, &errs)
			if got != identity.ExitError || !strings.Contains(errs.String(), "operation not permitted") {
				t.Fatalf("exit=%d stderr=%q", got, errs.String())
			}
			if held := tegoruntime.StopRequested(dir); held != prior {
				t.Fatalf("after rejected signal, stop marker=%v want prior=%v; later ordinary signal would falsely acquire stop reason", held, prior)
			}
			if prior && tegoruntime.StopRequestGrace(dir) != 7*time.Second {
				t.Fatal("earlier stop grace changed")
			}
		})
	}
}
