// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// ownedRun is a small live run in a store of its own, and a way to add a line to it and read its newest version.
func ownedRun(t *testing.T) (s *Store, add func() *Run) {
	t.Helper()
	root := t.TempDir()
	id := "r-aaaa-0042-ownedx"
	t0 := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, id,
		line(id, "own", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p"`),
		line(id, "own", 1, t0.Add(time.Second), "fs", `"verdict":"allow","rule":"fs.read[/p]","op":"open","path":"/p/a.txt"`))
	markLive(t, root, id, true)
	s = Open(root)
	seq := 2
	add = func() *Run {
		appendLines(t, root, id, line(id, "own", seq, t0.Add(time.Duration(seq)*time.Second), "fs",
			fmt.Sprintf(`"verdict":"allow","rule":"fs.read[/p]","op":"open","path":"/p/f%d.txt"`, seq)))
		seq++
		r, err := s.Run(id)
		if err != nil || r.Lines != seq {
			t.Fatalf("run: %v, %d lines, want %d", err, r.Lines, seq)
		}
		return r
	}
	return s, add
}

// TestFacetTalliesBelongToTheRunVersion: the tallies kept for a run belong to the version of the run that was counted,
// so a version's leave with it, and a person who tries many searches on one version keeps the newest few, not none
// (GAPS C82; the cache used to be one package-level map dropped whole past 16,384 entries, where an old version's
// tallies stayed until the drop).
func TestFacetTalliesBelongToTheRunVersion(t *testing.T) {
	s, add := ownedRun(t)
	query := func(f Filter) Page {
		snap, err := s.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		f.Facets = true
		return snap.Query(f)
	}
	// Many versions of one run, the same search each: one tally for the newest version, none for the old ones.
	var r *Run
	for range 2 * maxKeptPerVersion {
		r = add()
		if pg := query(Filter{Text: "f"}); pg.Facets == nil || pg.Matched == 0 {
			t.Fatalf("search found %d lines, facets %v", pg.Matched, pg.Facets)
		}
	}
	if n := keptTallyCount(r); n != 1 {
		t.Errorf("after %d versions the newest holds %d tallies, want 1 (its search)", 2*maxKeptPerVersion, n)
	}
	if n := keptTallyTotal(r); n != 1 {
		t.Errorf("the run has %d tallies kept over all its versions, want 1: an old version's are not kept", n)
	}

	// Many different searches on one version: bounded, the newest kept.
	r = add()
	for i := range 3 * maxKeptPerVersion {
		query(Filter{Text: fmt.Sprintf("f%d", i)})
	}
	if n := keptTallyCount(r); n != maxKeptPerVersion {
		t.Errorf("after many searches on one version %d tallies are kept, want %d (not dropped whole, not unbounded)", n, maxKeptPerVersion)
	}
}

// TestGroupsBelongToTheRunVersion: grouped counts are kept the same way, bounded per version.
func TestGroupsBelongToTheRunVersion(t *testing.T) {
	s, add := ownedRun(t)
	group := func(f Filter) {
		snap, err := s.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		snap.Group(f, GroupTarget, 10, nil)
	}
	var r *Run
	for range 2 * maxKeptPerVersion {
		r = add()
		group(Filter{Text: "f"})
	}
	if n := keptGroupTotal(r); n != 1 {
		t.Errorf("after many versions the run holds %d groupings over all its versions, want 1", n)
	}
	for i := range 3 * maxKeptPerVersion {
		group(Filter{Text: fmt.Sprintf("f%d", i)})
	}
	if n := keptGroupCount(r); n != maxKeptPerVersion {
		t.Errorf("after many groupings on one version %d are kept, want %d", n, maxKeptPerVersion)
	}
}

// TestKeptTalliesAndGroupsAreNeverServedForAnotherVersionFilterOrRun: what a version of a run keeps is served only for
// that version, that filter and that run. Each answer from a store that has kept a great deal is compared with the one
// a store that has kept nothing gives for the same ledger, after a line is added to a run (a new version), under
// another filter on the same version, and for a second run whose lines are other ones (GAPS C82).
func TestKeptTalliesAndGroupsAreNeverServedForAnotherVersionFilterOrRun(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	ids := []string{"r-aaaa-0042-ownedx", "r-bbbb-0043-ownedy"}
	seq := map[string]int{}
	add := func(id, file string, verdict string) {
		n := seq[id]
		appendLines(t, root, id, line(id, "own", n, t0.Add(time.Duration(n)*time.Second), "fs",
			fmt.Sprintf(`"verdict":%q,"rule":"fs.read[/p]","op":"open","path":"/p/%s"`, verdict, file)))
		seq[id]++
	}
	for i, id := range ids {
		writeRun(t, root, id, line(id, "own", 0, t0.Add(time.Duration(i)*time.Hour), "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p"`))
		seq[id] = 1
		markLive(t, root, id, true)
	}
	warm := Open(root)
	facets := func(s *Store, f Filter) Page {
		snap, err := s.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		f.Facets = true
		return snap.Query(f)
	}
	groups := func(s *Store, f Filter, by string) Grouped {
		snap, err := s.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		return snap.Group(f, by, 50, nil)
	}
	same := func(step string, f Filter) {
		t.Helper()
		got, want := facets(warm, f), facets(Open(root), f)
		if got.Matched != want.Matched || !reflect.DeepEqual(got.Facets, want.Facets) {
			t.Errorf("%s: a search under %+v gave %d lines and facets %+v from the store that kept, %d and %+v from a fresh one",
				step, f, got.Matched, got.Facets, want.Matched, want.Facets)
		}
		for _, by := range []string{GroupTarget, GroupRule, GroupProcess} {
			if g, w := groups(warm, f, by), groups(Open(root), f, by); !reflect.DeepEqual(g, w) {
				t.Errorf("%s: grouping by %s under %+v gave %+v from the store that kept, %+v from a fresh one", step, by, f, g, w)
			}
		}
	}
	for i := range 3 {
		add(ids[0], fmt.Sprintf("f%d.txt", i), "allow")
		add(ids[1], fmt.Sprintf("g%d.txt", i), "allow")
	}
	filters := []Filter{{Text: "f"}, {Text: "g"}, {Text: "f1"}, {Text: ".txt"}, {Text: "refused"}}
	for _, f := range filters {
		same("first look", f)
		same("second look, kept", f)
	}
	// A new version of one run: its kept answers go with the old version, the other run's stay and are still right.
	add(ids[0], "f9.txt", "refuse")
	for _, f := range filters {
		same("one run grew", f)
	}
	add(ids[1], "g9.txt", "refuse")
	add(ids[0], "f10.txt", "allow")
	for _, f := range filters {
		same("both runs grew", f)
	}
	// A filter that differs only in what a tally does not hold (paging, the run chosen) is the same one, so the kept
	// answers serve it and must still be this ledger's.
	same("one run chosen", Filter{Text: "f", Run: ids[0]})
	same("the other run chosen", Filter{Text: "f", Run: ids[1]})
}
