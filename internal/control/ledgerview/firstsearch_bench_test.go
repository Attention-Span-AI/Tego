// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

// firstSearchRoot is runs ended runs of n generated lines each (agentLines), as a long-used ledger holds them.
func firstSearchRoot(tb testing.TB, runs, n int) string {
	tb.Helper()
	root := tb.TempDir()
	rng := rand.New(rand.NewPCG(81, 81))
	for i := range runs {
		id := fmt.Sprintf("r-aaaa-%04d-srchxx", i+1)
		ls := agentLines(id, 0, n, 5000, 40*time.Millisecond, rng)
		ls = append(ls, line(id, "codex", n+1, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), "run_end", `"reason":"exit","exit_code":0`))
		writeRun(tb, root, id, ls...)
	}
	return root
}

// allHeld fails the benchmark unless every run of snap has its lines in memory: a run read back from disk is the
// store's own cost, not the search's.
func allHeld(b *testing.B, snap *Snapshot) {
	b.Helper()
	for _, r := range snap.Runs {
		if len(r.heldEvents()) == 0 {
			b.Fatalf("run %s is not resident: the benchmark's ledger passes the store's residency budget", r.ID)
		}
	}
}

// BenchmarkLogsFirstSearch is the first text search of a store that holds 16 runs of 4,000 lines (about 68,000 lines, all resident:
// more would pass the store's residency budget and be read from disk again) and has searched nothing: every run's haystack is built, then searched. The
// runs are read before the timer starts and their text indexes are dropped before each search, so what is timed is the
// first search (GAPS C81).
func BenchmarkLogsFirstSearch(b *testing.B) {
	root := firstSearchRoot(b, 16, 4000)
	s := Open(root)
	snap, err := s.Snapshot()
	if err != nil {
		b.Fatal(err)
	}
	allHeld(b, snap)
	b.ReportAllocs()
	for range b.N {
		b.StopTimer()
		for _, r := range snap.Runs {
			r.memo.hayOnce = sync.Once{}
			r.memo.hayBuilt.Store(false)
			r.memo.hay, r.memo.hayOff, r.memo.hits = nil, nil, nil
		}
		b.StartTimer()
		if pg := snap.Query(Filter{Text: "chatgpt", PageSize: 100}); pg.Matched == 0 {
			b.Fatal("no match")
		}
	}
}

// BenchmarkHaystacksBuild is the haystacks alone of the same store: built run after run, as the first search used to
// build them, or by warmText on separate cores.
func BenchmarkHaystacksBuild(b *testing.B) {
	root := firstSearchRoot(b, 16, 4000)
	snap, err := Open(root).Snapshot()
	if err != nil {
		b.Fatal(err)
	}
	allHeld(b, snap)
	reset := func() {
		for _, r := range snap.Runs {
			r.memo.hayOnce = sync.Once{}
			r.memo.hayBuilt.Store(false)
			r.memo.hay, r.memo.hayOff, r.memo.hits = nil, nil, nil
		}
	}
	b.Run("serial", func(b *testing.B) {
		for range b.N {
			b.StopTimer()
			reset()
			b.StartTimer()
			for _, r := range snap.Runs {
				r.memo.buildHay(r.AllEvents())
			}
		}
	})
	b.Run("warm", func(b *testing.B) {
		f := Filter{Text: "chatgpt"}
		m := newMatcher(&f)
		for range b.N {
			b.StopTimer()
			reset()
			b.StartTimer()
			m.warmText(snap.Runs)
		}
		for _, r := range snap.Runs {
			if !r.memo.hayBuilt.Load() {
				b.Fatalf("warmText left %s unbuilt: lines %d held %d wants %v", r.ID, r.Lines, len(r.heldEvents()), f.wantsRun(r))
			}
		}
	})
}
