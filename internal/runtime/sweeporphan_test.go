// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// runCgroupID is the cgroup id run_start recorded, or 0 when absent or unreadable.
// Production scope decisions use runStartOfChecked and preserve its error.
func runCgroupID(dir runDir) uint64 { return runStartOf(dir).cgroup }

// orphanFixture is a lost run with a populated scope, and the fake manager over the scope's tree.
func orphanFixture(t *testing.T, id string) (root string, m *scopeCgroups, scope string) {
	t.Helper()
	root, own := t.TempDir(), t.TempDir()
	lostRunIn(t, root, id, 77)
	scope = scopeUnder(t, own, id)
	m = &scopeCgroups{fakeCgroups: fakeCgroups{root: own}, ids: map[string]uint64{scope: 77}}
	prev := orphanRoots
	orphanRoots = func(cgroup.Manager, markDir, runDir) ([]string, error) { return []string{own}, nil }
	t.Cleanup(func() { orphanRoots = prev })
	return root, m, scope
}

func testSweepOptions(m cgroup.Manager) sweepOptions {
	return sweepOptions{manager: m, log: slog.New(slog.DiscardHandler), marks: rootMarkDir}
}

func TestKillOrphanRefusalsAreFailClosed(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	ref := record.RunRef{ID: id, Agent: "tester"}

	t.Run("a refused kill keeps the run lost", func(t *testing.T) {
		root, m, _ := orphanFixture(t, id)
		m.killErr = errors.New("EPERM")
		err := killOrphan(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, ref.ID)), ref)
		if !errors.Is(err, errOrphanAlive) {
			t.Fatalf("err = %v, want errOrphanAlive", err)
		}
		if m.removed != 0 {
			t.Fatal("the scope of a tree still running must not be removed")
		}
	})
	t.Run("a tree that never empties keeps the run lost", func(t *testing.T) {
		root, m, _ := orphanFixture(t, id)
		m.waitErr = context.DeadlineExceeded
		if err := killOrphan(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, ref.ID)), ref); !errors.Is(err, errOrphanAlive) {
			t.Fatalf("err = %v, want errOrphanAlive", err)
		}
	})
	t.Run("a scope that will not go is not the tree being alive", func(t *testing.T) {
		root, m, _ := orphanFixture(t, id)
		m.removeErr = errors.New("EIO")
		err := killOrphan(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, ref.ID)), ref)
		if err == nil || errors.Is(err, errOrphanAlive) {
			t.Fatalf("err = %v, want a plain remove failure", err)
		}
	})
	t.Run("an unparsable agent is refused before anything is touched", func(t *testing.T) {
		root, m, _ := orphanFixture(t, id)
		err := killOrphan(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, id)), record.RunRef{ID: id, Agent: "../x"})
		if err == nil || len(m.killed) != 0 {
			t.Fatalf("err = %v, killed %v", err, m.killed)
		}
	})
	t.Run("no manager is nothing to kill", func(t *testing.T) {
		if err := killOrphan(context.Background(), sweepOptions{}, pathDir(filepath.Join(t.TempDir(), ref.ID)), ref); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a run whose scope is gone is not an error", func(t *testing.T) {
		root, m, scope := orphanFixture(t, id)
		if err := os.RemoveAll(scope); err != nil {
			t.Fatal(err)
		}
		if err := killOrphan(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, ref.ID)), ref); err != nil || len(m.killed) != 0 {
			t.Fatalf("err = %v, killed %v", err, m.killed)
		}
	})
}

func TestOrphanScopeIgnoresAScopeWithAnotherCgroupID(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	root, m, scope := orphanFixture(t, id)
	m.ids[scope] = 78 // a scope of the same name made since the run_start
	agent, err := identity.ParseAgentID("tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := orphanScopeChecked(m, rootMarkDir, pathDir(filepath.Join(root, id)), record.RunRef{ID: id, Agent: "tester"}, agent); ok || err != nil {
		t.Fatal("a scope whose id is not the recorded one must never be taken as the run's")
	}
	m.ids[scope] = 77
	c, ok, err := orphanScopeChecked(m, rootMarkDir, pathDir(filepath.Join(root, id)), record.RunRef{ID: id, Agent: "tester"}, agent)
	if !ok || err != nil || c.Path != scope {
		t.Fatalf("got %v, %v; want the run's own scope", c, ok)
	}
}

func TestEndedListedLeavesWhatItCannotJudge(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	root, m, _ := orphanFixture(t, id)
	ref := record.RunRef{ID: id, Agent: "tester"}

	if done, err := endedListed(context.Background(), testSweepOptions(nil), pathDir(filepath.Join(root, ref.ID)), ref); done || !errors.Is(err, errOrphanAlive) {
		t.Errorf("no manager: %v, %v; want the entry kept for cleanup", done, err)
	}
	if done, err := endedListed(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, "r-deadbeef-000000000000a-other0")),
		record.RunRef{ID: "r-deadbeef-000000000000a-other0", Agent: "tester"}); !done || err != nil || len(m.killed) != 0 {
		t.Errorf("another host's run: %v, %v, killed %v", done, err, m.killed)
	}
	if done, err := endedListed(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, id)),
		record.RunRef{ID: id, Agent: "../x"}); done || err == nil {
		t.Errorf("bad agent: %v, %v; want the entry kept with an error", done, err)
	}
	m.killErr = errors.New("EPERM")
	done, err := endedListed(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, ref.ID)), ref)
	if done || !errors.Is(err, errOrphanAlive) {
		t.Errorf("a tree that survives: %v, %v; want the entry kept", done, err)
	}
}

func TestRunStartOfReadsWhatARecordedRunStartHolds(t *testing.T) {
	root := t.TempDir()
	const id = "r-00000000-000000000000a-hashed"
	w := openRun(t, root, id)
	if err := w.WriteRunStartIn(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "cgroup", BPFHash: "abc123"}, 4242); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	got := runStartOf(pathDir(filepath.Join(root, id)))
	if got.cgroup != 4242 || got.hash != "abc123" {
		t.Fatalf("runStartOf = %+v", got)
	}
	if z := runStartOf(pathDir(filepath.Join(root, "absent"))); z != (runStart{}) {
		t.Fatalf("a missing run reads as the zero value, got %+v", z)
	}
	if runCgroupID(pathDir(filepath.Join(root, "absent"))) != 0 {
		t.Fatal("no run_start, no cgroup id")
	}
}
