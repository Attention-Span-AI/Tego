// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// callerRun makes refuseCrossRun read the caller's own run as id (or, with err, fail to read it) for the test.
func callerRun(t *testing.T, id string, err error) {
	t.Helper()
	old := selfRun
	selfRun = func() (string, error) { return id, err }
	t.Cleanup(func() { selfRun = old })
}

// outsideEveryRun makes the commands see their caller outside every run, whatever cgroup the test itself runs in.
func outsideEveryRun(t *testing.T) {
	t.Helper()
	old := selfInRun
	selfInRun = func() (bool, error) { return false, nil }
	t.Cleanup(func() { selfInRun = old })
}

// TestBlockCrossRunRefused: a process inside run A may not block in run B, a process inside B may; outside
// every run any process may; and a process inside a run whose own run cannot be named is refused whatever the target (fail closed).
// A refused block writes nothing.
func TestBlockCrossRunRefused(t *testing.T) {
	// Run B is the live run every block names; run A is the caller's own in the cross-run case, another run's id
	// (liveRun gives each run its own ledger root, so A need not exist under B's).
	dirB, idB, _ := liveRun(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now().Add(-time.Minute), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idA := string(rid)
	blocks := func(dir, id string) int {
		t.Helper()
		o, err := liveblock.Read(dir, id)
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		return len(o.Blocks)
	}

	t.Run("inside A, blocking B: refused", func(t *testing.T) {
		governedCaller(t, nil)
		callerRun(t, idA, nil)
		code, out, errs := run(t, "block", idB, "exec", "ls")
		if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "a process inside a tego run cannot change another run's governance") ||
			!strings.Contains(errs, "inside run "+idA+", and the change names run "+idB) || !strings.Contains(errs, "[governed]") ||
			!strings.Contains(errs, "run it from a terminal outside any tego run") {
			t.Errorf("exit %d stdout %q stderr %q", code, out, errs)
		}
		if n := blocks(dirB, idB); n != 0 {
			t.Errorf("run B holds %d blocks after a refused cross-run block", n)
		}
	})
	t.Run("inside B, blocking B: allowed", func(t *testing.T) {
		governedCaller(t, nil)
		callerRun(t, idB, nil)
		if code, out, errs := run(t, "block", idB, "exec", "ls"); code != identity.ExitOK || !strings.Contains(out, idB+": blocked") {
			t.Errorf("exit %d stdout %q stderr %q", code, out, errs)
		}
		if n := blocks(dirB, idB); n != 1 {
			t.Errorf("run B holds %d blocks, want 1", n)
		}
	})
	t.Run("outside every run: allowed", func(t *testing.T) {
		outsideEveryRun(t)
		callerRun(t, "", errors.New("must not be read outside a run"))
		if code, out, errs := run(t, "block", idB, "net", "example.com:443"); code != identity.ExitOK || !strings.Contains(out, idB+": blocked") {
			t.Errorf("exit %d stdout %q stderr %q", code, out, errs)
		}
	})
	t.Run("own run unknown: refused", func(t *testing.T) {
		for name, set := range map[string]func(*testing.T){
			"cgroup names no run": func(t *testing.T) { governedCaller(t, nil); callerRun(t, "", nil) },
			"cgroup unreadable": func(t *testing.T) {
				governedCaller(t, nil)
				callerRun(t, "", errors.New("runscope: the cgroup file names no single cgroup v2 path"))
			},
			"InRun cannot tell": func(t *testing.T) {
				governedCaller(t, errors.New("runscope: this process is in cgroup namespace 4026532000, not the initial one"))
				callerRun(t, idB, nil) // a namespaced path may look like B's own; it is not trusted
			},
		} {
			t.Run(name, func(t *testing.T) {
				set(t)
				before := blocks(dirB, idB)
				code, _, errs := run(t, "block", idB, "exec", "sh")
				if code != identity.ExitFinding || !strings.Contains(errs, "own run cannot be named") || !strings.Contains(errs, "[governed]") {
					t.Errorf("exit %d stderr %q", code, errs)
				}
				if n := blocks(dirB, idB); n != before {
					t.Errorf("a refused block was written: %d blocks, had %d", n, before)
				}
			})
		}
	})
	t.Run("unblock and pause name both", func(t *testing.T) {
		governedCaller(t, nil)
		callerRun(t, idA, nil)
		for _, args := range [][]string{{"unblock", idB, "exec", "ls"}, {"pause", idB}} {
			code, _, errs := run(t, args...)
			if code != identity.ExitFinding || !strings.Contains(errs, "a governed agent cannot change its own governance, nor another run's") {
				t.Errorf("%v: exit %d stderr %q", args, code, errs)
			}
		}
	})
}

// liveRunWithGaps is liveRun with the given gap lines written after run_start, as the run's launcher writes them,
// and a stand-in launcher holding the run's lock.
func liveRunWithGaps(t *testing.T, gaps []record.GapPayload) (dir, id string) {
	t.Helper()
	root := gcRoot(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id = string(rid)
	dir = filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock", RecordMinor: record.Minor}); err != nil {
		t.Fatal(err)
	}
	for _, g := range gaps {
		ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
		if err := ev.SetPayload(g); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
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
			return dir, id
		}
		if time.Now().After(deadline) {
			t.Fatal("the stand-in launcher never took the lock")
		}
	}
}

// pauseGap is the launcher's line for a pause or a resume of serial.
func pauseGap(why string, serial uint64) record.GapPayload {
	op := liveblock.OpPause
	if why == record.GapRunResumed || why == record.GapResumeFailed {
		op = liveblock.OpResume
	}
	return record.GapPayload{What: record.GapEnforce, Why: why, LiveControl: &record.LiveControlChange{Op: op,
		By: "uid:1000 pid:9 cli", Serial: serial, At: time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)}}
}

// TestStatusShowsPaused: a live run whose launcher recorded a pause reads "paused" in STATE, and --json keeps
// the derived state and adds "paused": true; after a resume line it reads running again.
func TestStatusShowsPaused(t *testing.T) {
	_, id := liveRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	code, out, errs := run(t, "status", id)
	if code != identity.ExitOK || !strings.Contains(out, id+"  tester  paused") {
		t.Fatalf("status of a paused run: exit %d stdout %q stderr %q", code, out, errs)
	}
	code, out, errs = run(t, "status", id, "--json")
	var got map[string]any
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("status --json: exit %d stdout %q stderr %q", code, out, errs)
	}
	if got["state"] != string(status.Running) || got["paused"] != true || got["pause_pending"] != nil {
		t.Errorf("status --json of a paused run: state %v paused %v pause_pending %v", got["state"], got["paused"], got["pause_pending"])
	}

	_, rid := liveRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1), pauseGap(record.GapRunResumed, 2)})
	if code, out, _ := run(t, "status", rid); code != identity.ExitOK || !strings.Contains(out, rid+"  tester  running") {
		t.Errorf("status after a resume: exit %d stdout %q", code, out)
	}
	if code, out, _ := run(t, "status", rid, "--json"); code != identity.ExitOK || strings.Contains(out, `"paused"`) {
		t.Errorf("status --json after a resume names paused: %q", out)
	}
	// A pause that failed leaves the run running; a resume that failed leaves it paused.
	_, fid := liveRunWithGaps(t, []record.GapPayload{pauseGap(record.GapPauseFailed, 1)})
	if _, out, _ := run(t, "status", fid); !strings.Contains(out, fid+"  tester  running") {
		t.Errorf("status after a failed pause: %q", out)
	}
	_, xid := liveRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1), pauseGap(record.GapResumeFailed, 2)})
	if _, out, _ := run(t, "status", xid); !strings.Contains(out, xid+"  tester  paused") {
		t.Errorf("status after a failed resume: %q", out)
	}
}

// TestStatusShowsPausePending: a pause the overlay asks that the launcher has not confirmed reads "pausing", and
// --json says pause_pending "pause" without claiming paused.
func TestStatusShowsPausePending(t *testing.T) {
	old := pauseConfirmWait
	pauseConfirmWait = 50 * time.Millisecond
	t.Cleanup(func() { pauseConfirmWait = old })
	outsideEveryRun(t)
	dir, id, _ := liveRun(t)
	if err := liveblock.MarkControl(dir); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, "pause", id); code != identity.ExitOK {
		t.Fatalf("pause: exit %d %s", code, errs)
	}
	if code, out, _ := run(t, "status", id); code != identity.ExitOK || !strings.Contains(out, id+"  tester  pausing") {
		t.Errorf("status of an unconfirmed pause: exit %d stdout %q", code, out)
	}
	_, out, _ := run(t, "status", id, "--json")
	if !strings.Contains(out, `"pause_pending":"pause"`) || strings.Contains(out, `"paused"`) {
		t.Errorf("status --json of an unconfirmed pause: %s", out)
	}
}

// TestPauseFactState: the STATE words for each pause, and an ended run's state never reads paused.
func TestPauseFactState(t *testing.T) {
	for _, tc := range []struct {
		p    pauseFact
		st   status.State
		want string
	}{
		{pauseFact{}, status.Running, "running"},
		{pauseFact{Paused: true}, status.Running, "paused"},
		{pauseFact{Paused: true}, status.Stalled, "paused"},
		{pauseFact{Paused: true}, status.WaitingApproval, "paused"},
		{pauseFact{Pending: pendPause}, status.Running, "pausing"},
		{pauseFact{Paused: true, Pending: pendResume}, status.Running, "resuming"},
		{pauseFact{Paused: true}, status.Done, "done"},
		{pauseFact{Paused: true}, status.Lost, "lost"},
	} {
		if got := tc.p.state(tc.st); got != tc.want {
			t.Errorf("%+v in %s: %q, want %q", tc.p, tc.st, got, tc.want)
		}
	}
	// A paused run that stalled is not a finding; one that is not paused is.
	snaps := []*status.Snapshot{{Run: "r-a", St: status.Stalled}}
	if c := statusExit(snaps, map[string]pauseFact{"r-a": {Paused: true}}); c != identity.ExitOK {
		t.Errorf("a paused, stalled run: exit %d", c)
	}
	if c := statusExit(snaps, nil); c != identity.ExitFinding {
		t.Errorf("a stalled run: exit %d", c)
	}
}

// TestLastPauseLineSkipsLongLines: a line longer than the reader's buffer is skipped, not taken for the end.
func TestLastPauseLineSkipsLongLines(t *testing.T) {
	dir, _ := controlLedger(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	path := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	long := append(bytes.Repeat([]byte("x"), 200<<10), '\n')
	if err := os.WriteFile(path, append(long, data...), 0o600); err != nil {
		t.Fatal(err)
	}
	if why, serial := lastPauseLine(path); why != record.GapRunPaused || serial != 1 {
		t.Errorf("lastPauseLine = %q %d, want %q 1", why, serial, record.GapRunPaused)
	}
}
