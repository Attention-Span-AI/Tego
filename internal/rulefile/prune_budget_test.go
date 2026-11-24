// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Spending the budget before attempting journal.lock must leave the old journal and all its blobs intact.
func TestPruneBudgetSpentBeforeJournalRewrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, first, second := twoGone(t)
		ageBlobs(t, g.LedgerRoot, 60*day)
		before := tree(t, g.LedgerRoot)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		prev := hook
		t.Cleanup(func() { hook = prev })
		locks := 0
		hook = func(step string) error {
			if step == "lock" {
				locks++
				if locks == 1 {
					time.Sleep(2 * time.Second) // the prune lock leaves no budget to begin the journal operation
					synctest.Wait()
				}
			}
			return nil
		}
		p, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
		hook = prev
		if !errors.Is(err, context.DeadlineExceeded) || p != (Pruned{}) || locks != 1 {
			t.Errorf("pruned %+v, %v, %d locks; want deadline before any journal change", p, err, locks)
		}
		if left := contractsLeft(t, g.LedgerRoot); !slices.Equal(left, []string{first, second}) {
			t.Errorf("contracts left %v; want both", left)
		}
		if after := tree(t, g.LedgerRoot); !maps.Equal(before, after) {
			t.Error("a spent budget changed the journal, blobs or locks")
		}
		if p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)}); err != nil || p != (Pruned{Lines: 4, Blobs: 3, Locks: 2}) {
			t.Errorf("next pass: %+v, %v; want all expired lines, blobs and contract locks removed", p, err)
		}
	})
}

// The locked read, filter and rewrite form one operation. Expiry during filtering must not discard its progress.
func TestPruneLockedRewriteOutlastsBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, _ := twoGone(t)
		j, err := openJournalRead(g.LedgerRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer j.close()
		unlock, err := j.flock(context.Background(), pruneLock, unix.LOCK_EX, "test prune")
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		const budget = 30 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		edge := time.Now().Add(-30 * day)
		spent := false
		r := keepRule{before: edge, edge: edge, there: func(string) bool {
			if !spent {
				spent = true
				f, err := os.OpenFile(filepath.Join(g.LedgerRoot, JournalDirName, LocksDir, "journal.lock"), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err := sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
					t.Fatalf("filter's journal lock: %v; want held", err)
				}
				time.Sleep(budget) // controlled filtering time, with journal.lock held
				synctest.Wait()
			}
			return false
		}}
		var p Pruned
		_, _, err = j.pruneLines(ctx, PruneOptions{Before: edge}, r, &p)
		if !spent || !errors.Is(ctx.Err(), context.DeadlineExceeded) || err != nil || p != (Pruned{Lines: 4}) {
			t.Fatalf("locked rewrite: %+v, %v, context %v, spent %v; want four lines committed after expiry", p, err, ctx.Err(), spent)
		}
		if left := contractsLeft(t, g.LedgerRoot); len(left) != 0 {
			t.Fatalf("expired locked rewrite left contracts %v", left)
		}
	})
}

// A short pass stops at the first checkpoint after a completed journal rewrite.
// Later passes each finish one cleanup entry. Four lines, three blobs and two locks take at most six such passes.
func TestPruneShortBudgetsMakeProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, _ := twoGone(t)
		ageBlobs(t, g.LedgerRoot, 60*day)
		o := PruneOptions{Before: time.Now().Add(-30 * day)}
		var total Pruned
		for pass := range 6 {
			initial := len(names(t, g.LedgerRoot, BlobsDir)) + len(names(t, g.LedgerRoot, LocksDir))
			const budget = 30 * time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			spent := false
			controlled := cancelAtPrunePoint{ctx, cancel, func() bool {
				ready := len(contractsLeft(t, g.LedgerRoot)) == 0
				if pass > 0 {
					ready = len(names(t, g.LedgerRoot, BlobsDir))+len(names(t, g.LedgerRoot, LocksDir)) < initial
				}
				if ready && !spent {
					spent = true
					time.Sleep(budget)
					synctest.Wait()
				}
				return false // the controlled clock, rather than cancel, expires this context
			}}
			p, err := Prune(controlled, g.LedgerRoot, o)
			cancel()
			want := Pruned{Lines: 4}
			if pass > 0 && pass <= 3 {
				want = Pruned{Blobs: 1}
			} else if pass > 3 {
				want = Pruned{Locks: 1}
			}
			if !errors.Is(err, context.DeadlineExceeded) || p != want {
				t.Fatalf("pass %d: %+v, %v; want deadline and %+v", pass+1, p, err, want)
			}
			total.Lines += p.Lines
			total.Blobs += p.Blobs
			total.Locks += p.Locks
		}
		if total != (Pruned{Lines: 4, Blobs: 3, Locks: 2}) || len(contractsLeft(t, g.LedgerRoot)) != 0 {
			t.Fatalf("six short passes: %+v; want all garbage pruned", total)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if p, err := Prune(ctx, g.LedgerRoot, o); err != nil || p != (Pruned{}) {
			t.Fatalf("final short pass: %+v, %v; want nothing left to prune", p, err)
		}
	})
}

// A lock held by a writer can spend the budget too. Report the context error so the caller can identify the
// unfinished budgeted pass, and release every lock this pass did acquire before a subsequent pass runs.
func TestPruneBudgetSpentWaitingForLocks(t *testing.T) {
	for _, name := range []string{pruneLock, "journal.lock"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g, _, _ := twoGone(t)
				ageBlobs(t, g.LedgerRoot, 60*day)
				j, err := openJournalRead(g.LedgerRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer j.close()
				unlock, err := j.flock(context.Background(), name, unix.LOCK_EX, "test holds this lock")
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
				before := tree(t, g.LedgerRoot)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				o := PruneOptions{Before: time.Now().Add(-30 * day)}
				p, err := Prune(ctx, g.LedgerRoot, o)
				if !errors.Is(err, context.DeadlineExceeded) || p != (Pruned{}) {
					t.Errorf("pruned %+v, %v; want deadline with nothing pruned", p, err)
				}
				if !maps.Equal(tree(t, g.LedgerRoot), before) {
					t.Error("lock wait changed the journal, blobs or locks")
				}
				unlock()
				if p, err := Prune(context.Background(), g.LedgerRoot, o); err != nil || p != (Pruned{Lines: 4, Blobs: 3, Locks: 2}) {
					t.Errorf("next pass: %+v, %v; want all expired lines, blobs and contract locks removed", p, err)
				}
			})
		})
	}
}

// cancelAtPrunePoint cancels when a completed filesystem operation is first visible at a cancellation checkpoint.
// This uses effects, not a count of Err calls, so adding a checkpoint cannot move cancellation earlier.
type cancelAtPrunePoint struct {
	context.Context
	cancel context.CancelFunc
	when   func() bool
}

func (c cancelAtPrunePoint) Err() error {
	if c.when() {
		c.cancel()
	}
	return c.Context.Err()
}

// Each cleanup operation may finish, but no next operation may start after cancellation. The journal is already
// committed, its kept lines still name readable blobs, and a subsequent pass removes only the leftovers.
func TestPruneCancellationBetweenCleanupOperations(t *testing.T) {
	for _, stage := range []string{"temps", "journal", "blobs", "locks"} {
		t.Run(stage, func(t *testing.T) {
			g, first, second := twoGone(t)
			// Keep a live contract's journal and blobs alongside the removed contracts'.
			kept := filepath.Join(filepath.Dir(first), "kept.yaml")
			if err := os.WriteFile(kept, []byte(textA), 0o600); err != nil {
				t.Fatal(err)
			}
			write(t, g, kept, textA, "version: 0\n# kept\n")
			ageBlobs(t, g.LedgerRoot, 60*day)
			temp1, temp2 := journalTemp+"0000000000000000", journalTemp+"1111111111111111"
			for _, n := range []string{temp1, temp2} {
				if err := os.WriteFile(filepath.Join(g.LedgerRoot, JournalDirName, n), []byte("unfinished"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			dir := BlobsDir
			switch stage {
			case "temps":
				dir = "."
			case "locks":
				dir = LocksDir
			}
			// Prune can create the journal lock files, so count only the initial files that disappear.
			initial := names(t, g.LedgerRoot, dir)
			removed := func() int {
				current := names(t, g.LedgerRoot, dir)
				gone := 0
				for _, n := range initial {
					if !slices.Contains(current, n) {
						gone++
					}
				}
				return gone
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			when := func() bool { return removed() > 0 }
			if stage == "journal" {
				// Regression guard of existing behaviour: the parent already checked after the committed rewrite.
				when = func() bool { return slices.Equal(contractsLeft(t, g.LedgerRoot), []string{kept}) }
			}
			controlled := cancelAtPrunePoint{ctx, cancel, when}
			o := PruneOptions{Before: time.Now().Add(-30 * day)}
			p, err := Prune(controlled, g.LedgerRoot, o)
			wantRemoved := 1
			if stage == "journal" {
				wantRemoved = 0
			}
			if !errors.Is(err, context.Canceled) || removed() != wantRemoved {
				t.Errorf("pruned %+v, %v, removed %d %s; want cancellation after %d", p, err, removed(), stage, wantRemoved)
			}
			want := Pruned{}
			left := []string{first, second, kept}
			switch stage {
			case "journal":
				want = Pruned{Lines: 4}
				left = []string{kept}
			case "blobs":
				want = Pruned{Lines: 4, Blobs: 1}
				left = []string{kept}
			case "locks":
				want = Pruned{Lines: 4, Blobs: 2, Locks: 1}
				left = []string{kept}
			}
			if p != want || !slices.Equal(contractsLeft(t, g.LedgerRoot), left) {
				t.Errorf("pruned %+v, contracts %v; want %+v, %v", p, contractsLeft(t, g.LedgerRoot), want, left)
			}
			es, err := ReadJournal(g.LedgerRoot)
			if err != nil {
				t.Fatal(err)
			}
			j, err := openJournalRead(g.LedgerRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			for _, e := range es {
				for _, sum := range []string{e.OldSHA256, e.NewSHA256} {
					if _, err := j.readBlob(sum); err != nil {
						t.Errorf("kept journal line %s names unreadable blob: %v", e.ID, err)
					}
				}
			}
			next, err := Prune(context.Background(), g.LedgerRoot, o)
			if err != nil || p.Lines+next.Lines != 4 || p.Blobs+next.Blobs != 2 || p.Locks+next.Locks != 2 {
				t.Errorf("next pass %+v, %v, after %+v; want exactly the remaining garbage", next, err, p)
			}
			if left := contractsLeft(t, g.LedgerRoot); !slices.Equal(left, []string{kept}) {
				t.Errorf("next pass left %v; want only the kept contract", left)
			}
		})
	}
}

// Opening a retry can spend the last budget after an earlier flock proved contention.
func TestLockDeadlineAfterRetryOpenKeepsBusyCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, _ := twoGone(t)
		j, err := openJournalRead(g.LedgerRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer j.close()
		held, err := j.flock(context.Background(), pruneLock, unix.LOCK_SH, "test holder")
		if err != nil {
			t.Fatal(err)
		}
		defer held()
		const budget = 30 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		prev := hook
		t.Cleanup(func() { hook = prev })
		attempts := 0
		hook = func(step string) error {
			if step == "lock" {
				attempts++
				if attempts == 2 {
					deadline, _ := ctx.Deadline()
					time.Sleep(time.Until(deadline))
					synctest.Wait()
				}
			}
			return nil
		}
		const busy = "test lock is held by another writer"
		unlock, err := j.flock(ctx, pruneLock, unix.LOCK_EX, busy)
		if unlock != nil {
			unlock()
			t.Fatal("acquired a held lock")
		}
		if attempts != 2 || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), busy) {
			t.Fatalf("attempts=%d error=%v; want deadline with %q after retry open", attempts, err, busy)
		}
	})
}
