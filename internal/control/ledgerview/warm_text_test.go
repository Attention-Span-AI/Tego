// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"
)

// TestFirstSearchBuildsHaystacksTogetherAndAnswersAsBefore: a text search over many resident runs builds their
// haystacks on separate cores before its walk (warmText), and answers exactly what a search that built them one by
// one answers; a run whose lines are not in memory is left for the walk, which reads it back alone (GAPS C81).
func TestFirstSearchBuildsHaystacksTogetherAndAnswersAsBefore(t *testing.T) {
	root := firstSearchRoot(t, 6, warmMinEvents/4) // 6 runs, over warmMinEvents lines in all
	s := Open(root)
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range snap.Runs {
		if len(r.heldEvents()) == 0 {
			t.Fatalf("run %s is not resident", r.ID)
		}
		if r.memo.hayBuilt.Load() {
			t.Fatalf("run %s has its haystacks before any search", r.ID)
		}
	}
	// What the answer is, counted by hand: the lines whose haystack holds the text, a refused action's mirror left out.
	want := 0
	for _, r := range snap.Runs {
		for i := range r.AllEvents() {
			e := &r.AllEvents()[i]
			if !e.Mirror && strings.Contains(string(haystack(nil, e)), "chatgpt") {
				want++
			}
		}
	}
	pg := snap.Query(Filter{Text: "chatgpt", PageSize: 10})
	if pg.Matched != want || want == 0 {
		t.Fatalf("search matched %d lines, counted %d by hand", pg.Matched, want)
	}
	for _, r := range snap.Runs {
		if !r.memo.hayBuilt.Load() {
			t.Errorf("run %s has no haystacks after a search", r.ID)
		}
	}

	// A run that is not resident is not read back by the warm-up: after the store lets the lines of every run go, a
	// new snapshot holds none of them in memory.
	old := MaxResidentBytes
	defer func() { MaxResidentBytes = old }()
	MaxResidentBytes = 1
	s.mu.Lock()
	s.evict(nil)
	s.mu.Unlock()
	snap, err = s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	f := Filter{Text: "chatgpt"}
	newMatcher(&f).warmText(snap.Runs)
	for _, r := range snap.Runs {
		if r.memo.hayBuilt.Load() && len(r.heldEvents()) == 0 {
			t.Errorf("run %s was warmed although its lines were evicted", r.ID)
		}
	}
}
