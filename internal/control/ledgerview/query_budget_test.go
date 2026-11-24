// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"
	"time"
)

// budgetLedger writes a seeded ledger of runs generated runs of lines lines each under a fresh root (the lines
// agentLines gives, so the records are the ones the store reads in production) and reads it. The seed is fixed: the
// same call is the same ledger, line for line.
func budgetLedger(t testing.TB, runs, lines int) *Snapshot {
	t.Helper()
	root := t.TempDir()
	rng := rand.New(rand.NewPCG(11, 350))
	for k := range runs {
		id := fmt.Sprintf("r-aaaa-%04d-budget", k+1)
		writeRun(t, root, id, agentLines(id, 0, lines, 5000, 40*time.Millisecond, rng)...)
	}
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Runs) != runs || s.Lines < runs*lines {
		t.Fatalf("read %d runs and %d lines of %d runs of %d", len(s.Runs), s.Lines, runs, lines)
	}
	return s
}

// budgetCase is one query of the budget LG-F11 set, as the Logs page asks it. flat is a query that no line's count
// may move: the page is built from what a version of a run memoized, so a warm plain page costs the same on any
// ledger. The others cost what their matched lines cost.
type budgetCase struct {
	name string
	f    Filter
	flat bool
}

func budgetCases(end time.Time) []budgetCase {
	return []budgetCase{
		{"plain", Filter{}, true},
		{"verdict:refused", Filter{Verdicts: []string{"refused"}}, false},
		{"kind:exec", Filter{Kinds: []string{"exec"}}, false},
		{"-kind:fs", Filter{Not: Exclude{Kinds: []string{"fs"}}}, false},
		{"host:chatgpt.com", Filter{Hosts: []string{"chatgpt.com"}}, false},
		{"rule:fs.*", Filter{Rules: []string{"fs.*"}}, false},
		{"pid:4242", Filter{PID: 4242}, false},
		{"path:~/.ssh", Filter{PathPrefix: "~/.ssh"}, false},
		{"source:kernel", Filter{Source: "kernel"}, false},
		{"since:24h", Filter{Since: end.Add(-24 * time.Hour)}, false},
		{"since (all)", Filter{Since: time.Unix(0, 0)}, false},
		{"q=.ssh (builds the haystacks)", Filter{Text: ".ssh"}, false},
		{"word curl", Filter{Words: []string{"curl"}}, false},
		{"-word unlink", Filter{Not: Exclude{Words: []string{"unlink"}}}, false},
	}
}

// allocated is what f allocates: bytes and allocations, from the runtime's own counters.
func allocated(f func()) (bytes, allocs uint64) {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc, b.Mallocs - a.Mallocs
}

// The budgets, by construction. LG-F11 set them as wall-clock figures on a 350,000-line ledger: a plain query under
// 60 ms first and 5 ms again, any one filter under 60 ms first and 25 ms again. Time on a shared runner proves
// nothing, so this test holds what makes those figures true, counted exactly:
//
//   - A warm plain page does no work per line. Its allocations are the same on a ledger of one and of four times the
//     lines (the fold is memoized once per version of a run, memo.go allFolded).
//   - A filtered query is one walk that allocates only for the lines it matches (and the rows it folds from them):
//     what it allocates beyond a small ledger's is bounded per extra matched line, and a filter that matches nothing
//     allocates the same few objects on either ledger. A walk that allocated per line scanned (decoding, building a
//     key, a haystack) would fail here, on any machine.
//   - The first plain query builds its fold in under a quarter of an allocation per line.
//   - The text search builds its haystacks once per version (memo.go, D-CACHE): the second search, and every word
//     after it, allocates a tenth of the first.
//
// Each query also gives the same count again as it did the first time, on both ledgers.
func TestQueryBudget(t *testing.T) {
	const perMatch, slack = 4, 64 // allocations a matched line may cost (the host facet's is the dearest, under 2), and a query's fixed few
	const flatWarm = 200          // a warm plain page's allocations (143 measured): its 100 rows, its counts and its facets
	small := budgetLedger(t, 3, 3000)
	big := budgetLedger(t, 3, 12000)
	end := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	t.Logf("small ledger %d lines, big ledger %d lines (%d runs each)", small.Lines, big.Lines, len(big.Runs))

	// The first query of each: the plain fold, built from the lines once.
	for _, c := range []struct {
		name string
		s    *Snapshot
	}{{"small", small}, {"big", big}} {
		_, allocs := allocated(func() { c.s.Query(Filter{Facets: true}) })
		if lim := uint64(c.s.Lines / 4); allocs > lim {
			t.Errorf("%s: the first plain query allocated %d objects for %d lines, budget %d (a quarter per line)", c.name, allocs, c.s.Lines, lim)
		}
	}

	var textBytes uint64
	for _, c := range budgetCases(end) {
		f := c.f
		f.Facets = true
		var matchedSmall, matchedBig int
		var allocsSmall, allocsBig float64
		var firstBytes uint64
		for _, l := range []struct {
			s       *Snapshot
			matched *int
			allocs  *float64
		}{{small, &matchedSmall, &allocsSmall}, {big, &matchedBig, &allocsBig}} {
			var pg Page
			bytes, _ := allocated(func() { pg = l.s.Query(f) })
			if l.s == big {
				firstBytes = bytes
			}
			if again := l.s.Query(f); again.Matched != pg.Matched {
				t.Errorf("%s: %d then %d lines", c.name, pg.Matched, again.Matched)
			}
			*l.matched = pg.Matched
			*l.allocs = testing.AllocsPerRun(5, func() { l.s.Query(f) })
		}
		t.Logf("%-32s small %6d lines %6.0f allocs; big %6d lines %6.0f allocs", c.name, matchedSmall, allocsSmall, matchedBig, allocsBig)
		var lim float64
		switch {
		case c.flat:
			lim = min(allocsSmall+16, flatWarm)
		default:
			lim = allocsSmall + perMatch*float64(matchedBig-matchedSmall) + slack
		}
		if allocsBig > lim {
			t.Errorf("%s: %.0f allocations on the big ledger (%d matched), %.0f on the small (%d matched), budget %.0f: the query pays for lines it does not match",
				c.name, allocsBig, matchedBig, allocsSmall, matchedSmall, lim)
		}
		if c.f.PID == 4242 && (matchedBig != 0 || allocsBig > slack) {
			t.Errorf("%s matches nothing, so it may allocate only its fixed few: %d matched, %.0f allocations", c.name, matchedBig, allocsBig)
		}
		switch c.name {
		case "q=.ssh (builds the haystacks)":
			textBytes = firstBytes
		case "word curl":
			// The haystacks of the search before are this one's: it builds none.
			if textBytes == 0 || firstBytes > textBytes/10 {
				t.Errorf("%s allocated %d bytes after the text search's %d: the haystacks were built again", c.name, firstBytes, textBytes)
			}
		}
	}

	// A warm text search reuses its haystacks too (the same word again, as a page refresh asks it).
	f := Filter{Text: ".ssh", Facets: true}
	if bytes, _ := allocated(func() { big.Query(f) }); textBytes == 0 || bytes > textBytes/10 {
		t.Errorf("a repeated text search allocated %d bytes, the first %d: its haystacks were built again", bytes, textBytes)
	}
}

// TestBlockHostOfNamesCostNothing: a host that is a name is returned as it is, as ParseAddr's failure would leave it,
// without parsing (the Logs walk asks it of every line's host), and an address still loses its zone and its form.
func TestBlockHostOfNamesCostNothing(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "chatgpt.com": "chatgpt.com", "API.Example.com": "API.Example.com", "1password.com": "1password.com",
		"10.0.0.1": "10.0.0.1", "::ffff:10.0.0.1": "::ffff:10.0.0.1", "fe80::1%2": "fe80::1", "2001:db8::0:1": "2001:db8::1",
		"::1": "::1", "unix:/run/bus": "unix:/run/bus", "[::1]": "[::1]",
	} {
		if got := BlockHostOf(in); got != want {
			t.Errorf("BlockHostOf(%q) = %q, want %q", in, got, want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { BlockHostOf("chatgpt.com") }); n != 0 {
		t.Errorf("a host name cost %.0f allocations", n)
	}
	if hostIn(nil, "10.0.0.1") || hostIn([]string{}, "fe80::1%2") {
		t.Error("an empty list named a host")
	}
	if !hostIn([]string{"fe80::1"}, "fe80::1%2") || !hostIn([]string{"a.com"}, "a.com") || hostIn([]string{"b.com"}, "a.com") {
		t.Error("hostIn lost a match")
	}
}
