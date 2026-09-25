// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// endedListedRun leaves a run that ended, recorded cgroup id in its run_start, and is still listed in the live
// index, with launcher as its lock line: a launcher that died between Close and clearing its entry, or one
// still between the two.
func endedListedRun(t *testing.T, root, id string, cgroupID uint64, launcher LockInfo) {
	t.Helper()
	w := openRun(t, root, id)
	if err := ledger.MarkLive(root, id); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStartIn(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}, cgroupID); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteLockInfo([]byte(launcher.String())); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// liveLauncher is this test process, standing for a launcher still alive.
func liveLauncher(t *testing.T) LockInfo {
	t.Helper()
	start, err := StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return LockInfo{PID: os.Getpid(), StartBootNS: start}
}

// TestSweepLiveRemovesTheScopeAnEndedRunsLauncherLeft: the launcher removes its
// run's scope after Close and clears the live entry in between, so one that died after run_end left an ended,
// still-listed run whose scope nothing removed: the sweep cleared the entry after one tail read. The sweep now
// finds the scope as an orphan's (the id run_start recorded) and removes it, killing anything left in it; a
// launcher that is still alive, between Close and its own clear, is left to finish.
func TestSweepLiveRemovesTheScopeAnEndedRunsLauncherLeft(t *testing.T) {
	const id = "r-00000000-000000000000a-ended0"
	for _, tc := range []struct {
		name     string
		launcher func(t *testing.T) LockInfo
		wantKill bool
	}{
		{"the launcher is gone", goneLauncher, true},
		{"the launcher is alive", liveLauncher, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, scopes := t.TempDir(), t.TempDir()
			endedListedRun(t, root, id, 77, tc.launcher(t))
			scope := scopeUnder(t, scopes, id)
			m := &scopeCgroups{fakeCgroups: fakeCgroups{root: scopes}, ids: map[string]uint64{scope: 77}}
			prev := orphanRoots
			orphanRoots = func(cgroup.Manager, markDir, runDir) []string { return []string{scopes} }
			t.Cleanup(func() { orphanRoots = prev })

			res, err := SweepLive(context.Background(), root, WithSweepManager(m))
			if err != nil || len(res.Errs) != 0 {
				t.Fatalf("SweepLive: %v %v", err, res.Errs)
			}
			if killed := len(m.killed) == 1 && m.killed[0] == scope && m.removed == 1; killed != tc.wantKill {
				t.Errorf("killed %v removed %d, want the scope killed and removed: %v", m.killed, m.removed, tc.wantKill)
			}
			_, err = os.Lstat(filepath.Join(root, ledger.LiveDir, id))
			if listed := err == nil; listed == tc.wantKill {
				t.Errorf("listed after the sweep: %v, want %v", listed, !tc.wantKill)
			}
			if res.Orphaned != 0 {
				t.Errorf("an ended run is not an orphan: orphaned %d", res.Orphaned)
			}
		})
	}
}

// TestASweepLeavesAnotherHostsRun: the lock line's pid is a pid of the host that minted the run, and a sweep over a
// ledger root shared between machines took it for one of its own. A dead pid here reclaimed another host's live run —
// its tree killed through a scope of the same name — and a lost run of another host had a scope here killed. A run
// whose host8 is not this host's is neither reclaimed nor has anything killed. Nor is a lost one ended any more: its
// lock is only a lock on this machine, so its launcher may be alive on its own host, and run_end{orphaned} would end a
// live run.
//
// Also pins runtime-launch.md E28: a sweep never acts on another host's run in a shared ledger root.
func TestASweepLeavesAnotherHostsRun(t *testing.T) {
	const (
		held = "r-deadbeef-000000000000a-held00"
		lost = "r-deadbeef-000000000000b-lost00"
	)
	if localHost8() == "deadbeef" {
		t.Skip("this host's host8 is deadbeef")
	}
	root, scopes := t.TempDir(), t.TempDir()
	lostRunIn(t, root, held, 0)
	lock := filepath.Join(root, held, ledger.LockFile)
	if err := os.WriteFile(lock, []byte(goneLauncher(t).String()), 0o600); err != nil {
		t.Fatal(err)
	}
	holdLock(t, lock)
	lostRunIn(t, root, lost, 0)
	scopeUnder(t, scopes, held)
	scopeUnder(t, scopes, lost)
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: scopes}}
	prev := orphanRoots
	orphanRoots = func(cgroup.Manager, markDir, runDir) []string { return []string{scopes} }
	t.Cleanup(func() { orphanRoots = prev })

	if _, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m)); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(m.killed) != 0 {
		t.Errorf("killed %v: nothing of another host's is in this host's cgroup tree", m.killed)
	}
	repo := ledger.NewRunRepository(root)
	if st, err := repo.State(context.Background(), held); err != nil || st != ledger.StateRunning {
		t.Errorf("another host's held run: %s %v, want running", st, err)
	}
	if st, err := repo.State(context.Background(), lost); err != nil || st != ledger.StateLost {
		t.Errorf("another host's lost run: %s %v, want lost: nothing here may end it", st, err)
	}
}

// TestRunScopeFindsTheScopeWhereItsLauncherMadeIt is RunScope, what `tego stop`'s backstop kill now uses:
// the run's scope is looked for under every root it can be under, and a same-named
// scope under the stopper's own root whose id is not the one run_start recorded is not the run's.
func TestRunScopeFindsTheScopeWhereItsLauncherMadeIt(t *testing.T) {
	const id = "r-00000000-000000000000a-stop00"
	root, own, other := t.TempDir(), t.TempDir(), t.TempDir()
	lostRunIn(t, root, id, 77)
	scope := scopeUnder(t, other, id)
	decoy := scopeUnder(t, own, id)
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: own}, ids: map[string]uint64{scope: 77, decoy: 99}}
	prev := orphanRoots
	orphanRoots = func(cgroup.Manager, markDir, runDir) []string { return []string{own, other} }
	t.Cleanup(func() { orphanRoots = prev })

	c, ok, err := RunScope(m, root, id, "tester")
	if err != nil || !ok || c.Path != scope {
		t.Fatalf("RunScope: %+v %v %v, want %s", c, ok, err, scope)
	}
	delete(m.ids, scope)
	if c, ok, err := RunScope(m, root, id, "tester"); err != nil || ok {
		t.Fatalf("with no scope of the run's id left: %+v %v %v, want none", c, ok, err)
	}
	if _, _, err := RunScope(m, root, id, "Not An Agent"); err == nil {
		t.Fatal("an agent id that does not parse must be an error")
	}
}
