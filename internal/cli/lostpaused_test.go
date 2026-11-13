// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// lostRunWithGaps writes a run whose launcher died after the given gap lines: run_start, the gaps, and no run_end,
// with its lock free and its pause mark made, as a launcher that read pauses and was then killed leaves it.
func lostRunWithGaps(t *testing.T, gaps []record.GapPayload) (dir, id string) {
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
	if err := w.Abandon(); err != nil { // the launcher's death: no run_end, the lock free
		t.Fatal(err)
	}
	if err := liveblock.MarkControl(dir); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

// scopeIs makes tego status and tego stop read every run's scope as f, as a stand-in for the freezer.
func scopeIs(t *testing.T, f scopeFact) {
	t.Helper()
	old := readScope
	readScope = func(string, string) scopeFact { return f }
	t.Cleanup(func() { readScope = old })
}

var (
	scopeFrozen  = scopeFact{Known: true, Populated: true, Frozen: true}
	scopeRunning = scopeFact{Known: true, Populated: true}
)

// staleLockLine makes dir's lock line name a launcher that is gone (a reaped process) while a stand-in still holds
// the lock: the case where a process other than the launcher holds a run's lock after the launcher died.
func staleLockLine(t *testing.T, dir string) {
	t.Helper()
	gone := exec.Command("/bin/true")
	if err := gone.Run(); err != nil {
		t.Skipf("no /bin/true: %v", err)
	}
	line := runlock.LockInfo{PID: gone.Process.Pid, StartBootNS: 1}.String()
	if err := os.WriteFile(filepath.Join(dir, ledger.LockFile), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestStatusShowsLostWhilePaused: a run whose launcher died with its last recorded state paused reads lost, says
// under the table that paused is the last state recorded and what its scope shows now, names tego stop, and is a
// finding (exit 1); --json says state lost, paused, launcher_gone and scope_now. STATE reads "lost, frozen" only when
// the scope is frozen now: a stop thaws the run without a line before it signals, so a launcher killed during the stop's
// grace leaves a run whose record says paused and whose processes run, and that one reads lost and NOT frozen. A lock
// still held by a process that is not the launcher (its lock line names a pid that is gone) reads the same, while the
// same lock held with no lock line, a launcher still starting, reads paused. A lost run that was not paused, or was
// resumed, reads lost as before.
func TestStatusShowsLostWhilePaused(t *testing.T) {
	scopeIs(t, scopeFrozen)
	_, id := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	code, out, errs := run(t, "status", id)
	if code != identity.ExitFinding || !strings.Contains(out, id+"  tester  lost, frozen") ||
		!strings.Contains(out, "lost "+id+": its launcher died, and the last state it recorded was paused, with no resume after it.") ||
		!strings.Contains(out, "Now its processes are frozen (its scope's cgroup.events says frozen 1).") ||
		!strings.Contains(out, "Tego never thaws a run with no launcher; tego stop "+id+" ends what is left and closes the record (run_end orphaned).") {
		t.Fatalf("status of a lost run last recorded paused: exit %d stdout %q stderr %q", code, out, errs)
	}
	code, out, _ = run(t, "status", id, "--json")
	var got map[string]any
	if code != identity.ExitFinding || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("status --json: exit %d stdout %q", code, out)
	}
	if got["state"] != string(status.Lost) || got["paused"] != true || got["launcher_gone"] != true || got["scope_now"] != "frozen" {
		t.Errorf("status --json: state %v paused %v launcher_gone %v scope_now %v", got["state"], got["paused"], got["launcher_gone"], got["scope_now"])
	}

	// Paused, then a stop thawed it without a line, then the launcher died: the record says paused, the scope runs.
	t.Run("thawed by a stop before the launcher died", func(t *testing.T) {
		scopeIs(t, scopeRunning)
		_, rid := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
		code, out, _ := run(t, "status", rid)
		if code != identity.ExitFinding || !strings.Contains(out, rid+"  tester  lost ") || strings.Contains(out, "lost, frozen") ||
			!strings.Contains(out, "the last state it recorded was paused") || !strings.Contains(out, "Now its processes are NOT frozen") {
			t.Errorf("status: exit %d stdout %q", code, out)
		}
		if _, out, _ := run(t, "status", rid, "--json"); !strings.Contains(out, `"scope_now":"running"`) {
			t.Errorf("status --json: %s", out)
		}
	})
	t.Run("a scope that cannot be read", func(t *testing.T) {
		scopeIs(t, scopeFact{})
		_, uid := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
		if _, out, _ := run(t, "status", uid); !strings.Contains(out, uid+"  tester  lost ") ||
			!strings.Contains(out, "Now whether its processes are still frozen could not be read from its scope.") {
			t.Errorf("status: %q", out)
		}
	})

	// A failed resume leaves the run frozen too.
	_, fid := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1), pauseGap(record.GapResumeFailed, 2)})
	if _, out, _ := run(t, "status", fid); !strings.Contains(out, fid+"  tester  lost, frozen") {
		t.Errorf("status of a run lost after a failed resume: %q", out)
	}
	for name, gaps := range map[string][]record.GapPayload{
		"never paused": nil,
		"resumed":      {pauseGap(record.GapRunPaused, 1), pauseGap(record.GapRunResumed, 2)},
		"pause failed": {pauseGap(record.GapPauseFailed, 1)},
	} {
		_, lid := lostRunWithGaps(t, gaps)
		code, out, _ := run(t, "status", lid)
		if code != identity.ExitFinding || !strings.Contains(out, lid+"  tester  lost ") || strings.Contains(out, "lost, frozen") ||
			strings.Contains(out, "the last state it recorded was paused") {
			t.Errorf("%s, then lost: exit %d stdout %q", name, code, out)
		}
	}

	// The lock held, but not by the launcher its line names: lost, not paused.
	sdir, sid := liveRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	if _, out, _ := run(t, "status", sid); !strings.Contains(out, sid+"  tester  paused") {
		t.Fatalf("a held lock with no lock line yet: %q", out)
	}
	staleLockLine(t, sdir)
	code, out, _ = run(t, "status", sid)
	if code != identity.ExitFinding || !strings.Contains(out, sid+"  tester  lost, frozen") {
		t.Errorf("a paused run whose lock a process other than its launcher holds: exit %d stdout %q", code, out)
	}
	if _, out, _ := run(t, "status", sid, "--json"); !strings.Contains(out, `"state":"lost"`) || !strings.Contains(out, `"launcher_gone":true`) {
		t.Errorf("status --json of it: %s", out)
	}
}

// TestPauseResumeRefuseALostPausedRun: neither tego pause nor tego resume reaches a run whose launcher is gone; a run
// lost while paused is refused [lost-paused] with the command that ends it, and nothing is written to its overlay. A
// lock held by a process that is not the run's launcher is refused the same way: the pid alone never passes.
func TestPauseResumeRefuseALostPausedRun(t *testing.T) {
	outsideEveryRun(t)
	lost := func() (string, string) {
		return lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	}
	stale := func() (string, string) {
		sdir, sid := liveRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
		if err := liveblock.MarkControl(sdir); err != nil {
			t.Fatal(err)
		}
		staleLockLine(t, sdir)
		return sdir, sid
	}
	for _, mk := range []func() (string, string){lost, stale} {
		dir, id := mk() // each makes its own ledger root and points TEGO_CONFIG at it
		tc := struct{ dir, id string }{dir, id}
		for _, name := range []string{"resume", "pause"} {
			code, out, errs := run(t, name, tc.id)
			if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "[lost-paused]") ||
				!strings.Contains(errs, tc.id+" is lost: its launcher died, and the last state it recorded was paused") ||
				!strings.Contains(errs, "Tego never resumes a run with no launcher") || !strings.Contains(errs, "tego stop "+tc.id) {
				t.Errorf("%s of %s: exit %d stdout %q stderr %q", name, tc.id, code, out, errs)
			}
		}
		if _, err := liveblock.Read(tc.dir, tc.id); err == nil {
			t.Errorf("a refused resume of %s wrote the overlay", tc.id)
		}
	}
	// A lost run that was not paused is not running, as before.
	_, nid := lostRunWithGaps(t, nil)
	if code, _, errs := run(t, "resume", nid); code != identity.ExitFinding || !strings.Contains(errs, "[not-running]") {
		t.Errorf("resume of a lost run never paused: exit %d stderr %q", code, errs)
	}
}

// TestStopEndsALostPausedRun: tego stop on a run lost while paused says what the scope showed and that its record closed
// with run_end orphaned. It succeeds (exit 0) only when the scope is confirmed empty, and fails (exit 125,
// [lost-paused]) when the sweep could not end it, since its descendants may remain.
func TestStopEndsALostPausedRun(t *testing.T) {
	oldSweep, oldRead := sweepLive, readScope
	t.Cleanup(func() { sweepLive, readScope = oldSweep, oldRead })
	scopeNow := scopeFrozen
	readScope = func(string, string) scopeFact { return scopeNow }
	// The ledger's own pass closes the record as the real sweep does after cleanup. The scope may already be empty,
	// so the resulting ended state does not prove cgroup.kill was needed or ran.
	sweepLive = func(ctx context.Context, root string, _ ...tegoruntime.SweepOption) (tegoruntime.SweepResult, error) {
		_, err := ledger.GC(ctx, root, tegoruntime.KeepForever, false)
		scopeNow = scopeFact{Known: true}
		return tegoruntime.SweepResult{}, err
	}
	dir, id := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	code, out, errs := run(t, "stop", id)
	if code != identity.ExitOK || !strings.Contains(out, id+": lost; its launcher had died, and the last state it recorded was paused. "+
		"Before the stop its processes are frozen (its scope's cgroup.events says frozen 1). "+
		"After the stop no process is left in its scope. "+
		"Tego closed its orphaned record (run_end orphaned).") || strings.Contains(out, "cgroup.kill") {
		t.Fatalf("stop of a run lost while paused: exit %d stdout %q stderr %q", code, out, errs)
	}
	if st, err := ledger.NewRunRepository(filepath.Dir(dir)).State(context.Background(), id); err != nil || st != ledger.StateEnded {
		t.Fatalf("after the stop: state %v err %v, want ended", st, err)
	}
	// Once ended it is not running, and it is no longer lost while paused.
	if code, out, _ := run(t, "stop", id); code != identity.ExitOK || !strings.Contains(out, id+": not running") {
		t.Errorf("a second stop: exit %d stdout %q", code, out)
	}
	t.Run("scope already absent or empty", func(t *testing.T) {
		scopeIs(t, scopeFact{Known: true})
		_, emptyID := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
		code, out, errs := run(t, "stop", emptyID)
		if code != identity.ExitOK || !strings.Contains(out, "Before the stop no process is left in its scope. "+
			"After the stop no process is left in its scope. "+
			"Tego closed its orphaned record (run_end orphaned).") || strings.Contains(out, "cgroup.kill") {
			t.Errorf("stop with no scope processes: exit %d stdout %q stderr %q", code, out, errs)
		}
	})

	sweepLive = func(context.Context, string, ...tegoruntime.SweepOption) (tegoruntime.SweepResult, error) {
		return tegoruntime.SweepResult{}, nil // a sweep that could not end it (its tree would not die)
	}
	_, kid := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	code, out, errs = run(t, "stop", kid)
	if code != identity.ExitError || out != "" || !strings.Contains(errs, "[lost-paused]") ||
		!strings.Contains(errs, kid+" is lost, its last recorded state paused, and what is left of it could not be ended yet") {
		t.Errorf("stop whose sweep did not end the run: exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestStopLostPausedReadsScopeAfterSweep keeps the pre-sweep freezer reading apart from the current scope:
// only an empty scope succeeds; remaining processes or an unreadable scope fail even if the record closed.
func TestStopLostPausedReadsScopeAfterSweep(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after scopeFact
		words string
		code  int
		why   string
	}{
		{"empty", scopeFact{Known: true}, "no process is left in its scope", identity.ExitOK, ""},
		{"frozen", scopeFrozen, "its processes are frozen (its scope's cgroup.events says frozen 1)", identity.ExitError, "its scope still has processes"},
		{"running", scopeRunning, "its processes are NOT frozen: they run with no launcher deciding or recording what they do (a stop's thaw before the launcher died, or a write to the scope's cgroup.freeze, does that)", identity.ExitError, "its scope still has processes"},
		{"unknown", scopeFact{}, "whether its processes are still frozen could not be read from its scope", identity.ExitError, "cannot tell whether its scope is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, id := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
			oldSweep, oldRead := sweepLive, readScope
			t.Cleanup(func() { sweepLive, readScope = oldSweep, oldRead })
			swept, reads := false, 0
			readScope = func(gotDir, gotID string) scopeFact {
				if gotDir != dir || gotID != id {
					t.Fatalf("scope read for %q %q, want %q %q", gotDir, gotID, dir, id)
				}
				reads++
				if swept {
					return tc.after
				}
				return scopeFrozen
			}
			sweepLive = func(ctx context.Context, root string, _ ...tegoruntime.SweepOption) (tegoruntime.SweepResult, error) {
				_, err := ledger.GC(ctx, root, tegoruntime.KeepForever, false)
				swept = true
				return tegoruntime.SweepResult{}, err
			}
			code, out, errs := run(t, "stop", id)
			if code != tc.code || !strings.Contains(out,
				"Before the stop its processes are frozen (its scope's cgroup.events says frozen 1). "+
					"After the stop "+tc.words+". Tego closed its orphaned record (run_end orphaned).") ||
				strings.Contains(out, "cgroup.kill") {
				t.Errorf("stop after scope became %s: exit %d stdout %q stderr %q", tc.name, code, out, errs)
			}
			if tc.code == identity.ExitError {
				if !strings.Contains(errs, "stop did not complete: "+tc.why) || !strings.Contains(errs, "[lost-paused]") {
					t.Errorf("incomplete stop diagnostic: %q", errs)
				}
			} else if strings.Contains(errs, "[lost-paused]") {
				t.Errorf("completed stop reported lost-paused: %q", errs)
			}
			if reads != 2 {
				t.Errorf("scope read %d times, want once before and once after the sweep", reads)
			}
		})
	}
}

// TestStatusShowsAnUnknownLauncher: a held lock whose lock line names a live process that does not hold it (here this
// test process) cannot be judged: the run reads as its state with "(launcher unknown)", a line says which check failed
// and what to do, --json carries launcher_unknown, and nothing calls it lost; tego pause writes the request and says
// only a live launcher answers it.
func TestStatusShowsAnUnknownLauncher(t *testing.T) {
	old := pauseConfirmWait
	pauseConfirmWait = 50 * time.Millisecond
	t.Cleanup(func() { pauseConfirmWait = old })
	outsideEveryRun(t)
	dir, id := liveRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	start, err := runlock.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.LockFile), []byte(runlock.LockInfo{PID: os.Getpid(), StartBootNS: start}.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "status", id)
	if !strings.Contains(out, id+"  tester  paused (launcher unknown)") || !strings.Contains(out, "launcher unknown "+id+": its lock is held") ||
		!strings.Contains(out, "does not hold the run's lock") || !strings.Contains(out, "run the command in the launcher's pid namespace") ||
		strings.Contains(out, "lost") {
		t.Errorf("status of a run whose launcher cannot be judged: exit %d stdout %q", code, out)
	}
	if _, out, _ := run(t, "status", id, "--json"); !strings.Contains(out, `"launcher_unknown":`) || strings.Contains(out, `"launcher_gone"`) {
		t.Errorf("status --json: %s", out)
	}
	if err := liveblock.MarkControl(dir); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "resume", id)
	if code == identity.ExitFinding && strings.Contains(errs, "[lost-paused]") || !strings.Contains(errs, "[launcher-unknown]") {
		t.Errorf("resume of a run whose launcher cannot be judged: exit %d stderr %q", code, errs)
	}
}

// TestReadScopeKeepsUnreadableApart: readScope through the stop's own discovery (tegoruntime.RunScope over a stand-in
// cgroup tree): a frozen scope reads frozen, a missing one empty, and one that exists but cannot be looked at (its
// parent unsearchable: EACCES) unknown, never empty: "no process is left" is said only on confirmed absence.
func TestReadScopeKeepsUnreadableApart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory whatever its mode, so the unsearchable parent cannot be stood up")
	}
	dir, id := lostRunWithGaps(t, []record.GapPayload{pauseGap(record.GapRunPaused, 1)})
	tree := t.TempDir()
	slice := filepath.Join(tree, identity.TopSlice, identity.AgentSlice("tester"))
	scope := filepath.Join(slice, identity.RunScope(identity.RunID(id)))
	m := &treeCgroups{root: tree, ids: map[string]uint64{}}
	prev := stopCgroups
	stopCgroups = func(int) (cgroup.Manager, error) { return m, nil }
	t.Cleanup(func() { stopCgroups = prev })

	if got := readScope(dir, id); got != (scopeFact{Known: true}) {
		t.Errorf("no scope: %+v, want known and empty", got)
	}
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope, "cgroup.events"), []byte("populated 1\nfrozen 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readScope(dir, id); got != scopeFrozen {
		t.Errorf("a frozen scope: %+v, want frozen", got)
	}
	if err := os.Chmod(slice, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(slice, 0o755) })
	if got := readScope(dir, id); got.Known {
		t.Errorf("a scope behind an unsearchable folder: %+v, want unknown", got)
	}
}
