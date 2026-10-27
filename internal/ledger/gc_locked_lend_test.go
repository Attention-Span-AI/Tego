// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// swapRunAfterLock is a GCOption that, once the pass holds run id's lock, renames the run's directory away and
// makes an empty decoy at its name: what someone who can write the ledger root could do between the lock and
// the hook. It reports where the locked directory went.
func swapRunAfterLock(t *testing.T, root, id string) (GCOption, string) {
	moved := filepath.Join(root, "moved-"+id)
	return func(o *gcOptions) {
		o.locked = func(got string) {
			if got != id {
				return
			}
			if err := os.Rename(filepath.Join(root, id), moved); err != nil {
				t.Errorf("swap the run's name: %v", err)
				return
			}
			if err := os.Mkdir(filepath.Join(root, id), 0o700); err != nil {
				t.Errorf("make the decoy: %v", err)
			}
		}
	}, moved
}

// lentStat is the device and inode dir lends.
func lentStat(t *testing.T, dir sys.Lender) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := dir.Borrow(func(n int) error { return unix.Fstat(n, &st) }); err != nil {
		t.Errorf("the lent run directory: %v", err)
	}
	return st
}

// TestHooksAreLentTheDirectoryThePassLocked: a sweep, an empty run's sweep and an ended run's hook are each lent
// the run directory whose lock the pass took, not whatever holds the run's name by the time the hook runs. The
// sweep used to reopen the run by name for its hook after its Writer had locked it, so a directory swapped in
// at the name between the two fed every orphan check of the hook (its cgroup id, its launched mark) while
// run_end{orphaned} went into the locked run: the run was ended over a tree no check had looked at.
func TestHooksAreLentTheDirectoryThePassLocked(t *testing.T) {
	ctx := context.Background()
	t.Run("sweep", func(t *testing.T) {
		root := t.TempDir()
		ref := makeRun(t, root, fixedStart, "swap01", StateLost)
		testutil.NoFDLeak(t)
		swap, moved := swapRunAfterLock(t, root, ref.ID)
		var lent []unix.Stat_t
		hook := WithSweepHook(func(_ context.Context, dir sys.Lender, _ record.RunRef) error {
			lent = append(lent, lentStat(t, dir))
			return nil
		})
		rep, err := GC(ctx, root, keepAll, false, hook, swap, WithWriterOptions(WithAnchor(&memAnchor{})))
		if err != nil {
			t.Fatal(err)
		}
		requireLentOnce(t, lent, statDir(t, moved))
		if len(rep.Swept) != 1 {
			t.Fatalf("swept %v, want the locked run", rep.Swept)
		}
		requireState(t, moved, StateEnded)
	})
	t.Run("empty", func(t *testing.T) {
		root := t.TempDir()
		ref := record.RunRef{ID: runID(fixedStart, "swap02"), Agent: "retriever"}
		w, err := Open(filepath.Join(root, ref.ID), ref, WithAnchor(&memAnchor{}),
			WithContract([]byte("version: 0\nname: retriever\ncommand: [\"/bin/true\"]\n")))
		if err != nil {
			t.Fatal(err)
		}
		w.release() // died before its first line, the lock free
		w.closeDirs()
		testutil.NoFDLeak(t)
		swap, moved := swapRunAfterLock(t, root, ref.ID)
		var lent []unix.Stat_t
		var agents []string
		hook := WithSweepHook(func(_ context.Context, dir sys.Lender, run record.RunRef) error {
			lent = append(lent, lentStat(t, dir))
			agents = append(agents, run.Agent)
			return nil
		})
		if _, err := GC(ctx, root, keepAll, false, hook, swap); err != nil {
			t.Fatal(err)
		}
		requireLentOnce(t, lent, statDir(t, moved))
		if agents[0] != "retriever" {
			t.Fatalf("the hook's agent %q, want the locked run's contract's", agents[0])
		}
	})
	t.Run("ended", func(t *testing.T) {
		root := t.TempDir()
		ref := makeRun(t, root, fixedStart, "swap03", StateEnded)
		if err := MarkLive(root, ref.ID); err != nil {
			t.Fatal(err)
		}
		testutil.NoFDLeak(t)
		swap, moved := swapRunAfterLock(t, root, ref.ID)
		var lent []unix.Stat_t
		var agents []string
		hook := WithEndedHook(func(_ context.Context, dir sys.Lender, run record.RunRef) (bool, error) {
			lent = append(lent, lentStat(t, dir))
			agents = append(agents, run.Agent)
			return true, nil
		})
		if _, err := SweepLive(ctx, root, hook, swap, WithWriterOptions(WithAnchor(&memAnchor{}))); err != nil {
			t.Fatal(err)
		}
		requireLentOnce(t, lent, statDir(t, moved))
		if agents[0] != ref.Agent {
			t.Fatalf("the hook's agent %q, want the locked run's %q", agents[0], ref.Agent)
		}
	})
}

// requireLentOnce fails the test unless one hook call was lent the directory want names.
func requireLentOnce(t *testing.T, lent []unix.Stat_t, want unix.Stat_t) {
	t.Helper()
	if len(lent) != 1 {
		t.Fatalf("the hook ran %d times, want once", len(lent))
	}
	if lent[0].Dev != want.Dev || lent[0].Ino != want.Ino {
		t.Fatalf("the hook was lent %d:%d, the directory the pass locked is %d:%d (the decoy at the run's name was lent)",
			lent[0].Dev, lent[0].Ino, want.Dev, want.Ino)
	}
}

// requireState fails the test unless the run directory dir reads state.
func requireState(t *testing.T, dir string, want RunState) {
	t.Helper()
	rd, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	st, err := rd.State()
	if err != nil || st != want {
		t.Fatalf("%s reads %v, %v; want %v", dir, st, err, want)
	}
}
