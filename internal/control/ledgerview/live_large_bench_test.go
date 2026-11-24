// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"testing"
	"time"
)

// liveLargeLines is the length of the live run the benchmarks below read: the "200,000-line live run" that
// the dashboard's read-model notes said was never measured (GAPS C67).
const liveLargeLines = 200_000

// BenchmarkLiveLargeAppend is what a viewer of a 24/7 agent's page pays when the run gains a few lines: each
// iteration appends 10 lines to a 200,000-line run that is still live (its lock held, listed in .live), reads the new
// version, and builds one view of it. A version's views are built from its lines alone, so each costs a full pass: this
// is the price of one refresh of that page while the agent writes (C66 would make it incremental). The time and B/op of
// every view are the numbers in docs/DASHBOARD.md, "A live run of 200,000 lines".
func BenchmarkLiveLargeAppend(b *testing.B) {
	views := []struct {
		name string
		read func(s *Store, r *Run)
	}{
		{"timeline", func(_ *Store, r *Run) { TimelineOf(r, false).Len() }},
		{"refusals", func(_ *Store, r *Run) { r.runRefusals() }},
		{"logs", func(s *Store, r *Run) { snapQuery(b, s, Filter{PageSize: 100}) }},
		{"logs-facets", func(s *Store, r *Run) { snapQuery(b, s, Filter{PageSize: 100, Facets: true}) }},
		{"logs-text", func(s *Store, r *Run) { snapQuery(b, s, Filter{PageSize: 100, Text: "chatgpt"}) }},
		{"signal", func(_ *Store, r *Run) { Signal(r, benchSens) }},
	}
	for _, v := range views {
		b.Run(v.name, func(b *testing.B) {
			s, root, id, rng := liveBig(b, liveLargeLines)
			r, err := s.Run(id)
			if err != nil {
				b.Fatal(err)
			}
			v.read(s, r)
			if r.Lines < liveLargeLines {
				b.Fatalf("run has %d lines, want at least %d", r.Lines, liveLargeLines)
			}
			seq := liveLargeLines
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				ls := agentLines(id, seq, 10, 5000, 40*time.Millisecond, rng)
				appendLines(b, root, id, ls...)
				seq += 10
				want := r.Lines + len(ls)
				if r, err = s.Run(id); err != nil || r.Lines != want {
					b.Fatalf("run: %v, %d lines, want %d", err, r.Lines, want)
				}
				b.StartTimer()
				v.read(s, r)
			}
			b.ReportMetric(float64(len(r.AllEvents())), "events-held")
		})
	}
	// The read itself: the store reads only the appended bytes of a live run (cache.go), so gaining 10 lines costs
	// the same at 200,000 lines as at 2,000.
	b.Run("append-read", func(b *testing.B) {
		s, root, id, rng := liveBig(b, liveLargeLines)
		if _, err := s.Run(id); err != nil {
			b.Fatal(err)
		}
		seq := liveLargeLines
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			b.StopTimer()
			ls := agentLines(id, seq, 10, 5000, 40*time.Millisecond, rng)
			appendLines(b, root, id, ls...)
			seq += 10
			b.StartTimer()
			if _, err := s.Run(id); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkLiveLargeOpen is the first read of a live 200,000-line run by a store that has none of it: what the first
// page after `tego serve` starts pays for it, with its views.
func BenchmarkLiveLargeOpen(b *testing.B) {
	_, root, id, _ := liveBig(b, liveLargeLines)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s := Open(root)
		r, err := s.Run(id)
		if err != nil {
			b.Fatal(err)
		}
		TimelineOf(r, false).Len()
	}
}

func snapQuery(tb testing.TB, s *Store, f Filter) Page {
	tb.Helper()
	snap, err := s.Snapshot()
	if err != nil {
		tb.Fatal(err)
	}
	return snap.Query(f)
}
