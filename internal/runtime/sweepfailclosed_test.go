// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

func runState(t *testing.T, root, id string) ledger.RunState {
	t.Helper()
	st, err := ledger.NewRunRepository(root).State(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestSweepKeepsARunLostWhoseScopeWillNotBeRemoved: the tree is gone (populated 0) but rmdir stays busy after
// the retries. The run used to be ended, its live entry cleared and its empty scope leaked with nothing
// listing it again. runtime-launch.md case 9: "log, leave for next sweep".
func TestSweepKeepsARunLostWhoseScopeWillNotBeRemoved(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	root, own := t.TempDir(), t.TempDir()
	lostRunIn(t, root, id, 77)
	scope := scopeUnder(t, own, id)
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: own}, ids: map[string]uint64{scope: 77},
		removeErr: cgroup.ErrBusy}
	prev := orphanRoots
	orphanRoots = func(cgroup.Manager, markDir, runDir) []string { return []string{own} }
	t.Cleanup(func() { orphanRoots = prev })

	if _, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m)); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if st := runState(t, root, id); st == ledger.StateEnded {
		t.Fatal("a run whose scope could not be removed was ended: nothing lists its scope again")
	}
	// The next pass, with the scope removable, finishes it.
	m.removeErr = nil
	if _, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m)); err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if st := runState(t, root, id); st != ledger.StateEnded {
		t.Fatalf("state %s after the retry, want ended", st)
	}
}

// TestSweepWithoutACgroupManagerLeavesLostRuns: a sweeper that cannot detect cgroups cannot kill an orphan's
// tree, so it must not write run_end over one; the run stays lost for a sweeper that can (R20).
func TestSweepWithoutACgroupManagerLeavesLostRuns(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	root := t.TempDir()
	startedRun(t, root, id)
	prev := detectCgroups
	detectCgroups = func(int) (*cgroup.FS, error) { return nil, errors.New("no cgroup2 access") }
	t.Cleanup(func() { detectCgroups = prev })

	res, err := Sweep(context.Background(), root, KeepForever)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Orphaned != 0 || runState(t, root, id) == ledger.StateEnded {
		t.Fatalf("a lost run was ended with no way to kill its tree (orphaned %d, errs %v)", res.Orphaned, res.Errs)
	}
}
