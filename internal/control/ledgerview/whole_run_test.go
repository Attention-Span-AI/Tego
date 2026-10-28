// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWholeRun: only one run and nothing else is the whole run; any narrowing, or two runs, is not.
func TestWholeRun(t *testing.T) {
	for _, c := range []struct {
		name string
		f    Filter
		want bool
	}{
		{"the form's run", Filter{Run: qRunA}, true},
		{"the query's run", Filter{Runs: []string{qRunA}}, true},
		{"both naming it", Filter{Run: qRunA, Runs: []string{qRunA}}, true},
		{"paging is not narrowing", Filter{Run: qRunA, Before: "x", PageSize: 5, Facets: true}, true},
		{"no run", Filter{}, false},
		{"two runs", Filter{Runs: []string{qRunA, qRunB}}, false},
		{"a kind", Filter{Run: qRunA, Kinds: []string{"fs"}}, false},
		{"a verdict", Filter{Run: qRunA, Verdicts: []string{"refused"}}, false},
		{"text", Filter{Run: qRunA, Text: "x"}, false},
		{"a time", Filter{Run: qRunA, Since: qt0}, false},
		{"system lookups hidden", Filter{Run: qRunA, HideSys: true}, false},
		{"the run left out", Filter{Run: qRunA, Not: Exclude{Runs: []string{qRunA}}}, false},
		{"a word left out", Filter{Run: qRunA, Not: Exclude{Words: []string{"x"}}}, false},
	} {
		if id, ok := c.f.WholeRun(); ok != c.want || (ok && id != qRunA) {
			t.Errorf("%s: %q %v, want %v", c.name, id, ok, c.want)
		}
	}
}

// TestEachLedgerIsTheEventsFile: with Ledger and one whole run, Each gives the events file byte for byte, its mirror
// line included, in both orders; with any narrowing it gives the lines Logs counts, the mirror left out.
func TestEachLedgerIsTheEventsFile(t *testing.T) {
	root, s := queryFixture(t)
	file, err := os.ReadFile(filepath.Join(root, qRunA, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	all := func(f Filter, o Order) (out []byte) {
		s.Each(f, o, func(_ *Event, raw func() ([]byte, error)) bool {
			b, err := raw()
			if err != nil {
				t.Fatal(err)
			}
			out = append(append(out, b...), '\n')
			return true
		})
		return out
	}
	if got := all(Filter{Run: qRunA, Ledger: true}, OldestFirst); !bytes.Equal(got, file) {
		t.Errorf("the whole run is not its events file:\n%s", got)
	}
	lines := bytes.SplitAfter(file, []byte("\n"))
	lines = lines[:len(lines)-1]
	var rev []byte
	for i := len(lines) - 1; i >= 0; i-- {
		rev = append(rev, lines[i]...)
	}
	if got := all(Filter{Runs: []string{qRunA}, Ledger: true}, NewestFirst); !bytes.Equal(got, rev) {
		t.Errorf("newest first is not the file reversed:\n%s", got)
	}
	if n := bytes.Count(all(Filter{Run: qRunA}, OldestFirst), []byte("\n")); n != 8 {
		t.Errorf("without Ledger: %d lines, want the 8 Logs counts (the mirror left out)", n)
	}
	if n := bytes.Count(all(Filter{Run: qRunA, Ledger: true, Kinds: []string{"exec", "net"}}, OldestFirst), []byte("\n")); n != 3 {
		t.Errorf("Ledger with a kind: %d lines, want 3 (narrowed, so not the ledger)", n)
	}
}

// TestQueryKindRefusedListsMirrors: where=kind:refused lists the mirror lines, as the form's Kind=refused does.
func TestQueryKindRefusedListsMirrors(t *testing.T) {
	_, s := queryFixture(t)
	wf, _, err := ParseQueryAt("kind:refused run:"+qRunA, qt0, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	q, form := s.Query(wf), s.Query(Filter{Run: qRunA, Kind: "refused"})
	if q.Matched != 2 || form.Matched != 2 {
		t.Errorf("kind:refused %d lines, the form's Kind=refused %d, want 2 each", q.Matched, form.Matched)
	}
}

// TestFacetsWatchedRules: a rule key counted only on a watched run (tier observe) is marked, so Logs words it as
// watched; one also counted on an enforced run is not.
func TestFacetsWatchedRules(t *testing.T) {
	root := t.TempDir()
	const watched, enforced = "r-aaaa-0003-watchx", "r-aaaa-0004-enforx"
	writeRun(t, root, watched,
		qline(watched, "watch-codex", 0, 0, 300, "run_start", "supervisor", `"tier":"observe","command":["codex"],"cwd":"/w/x/proj"`),
		qline(watched, "watch-codex", 1, 1, 301, "fs", "kernel", `"rule":"unmatched","op":"open","path":"/w/x/home/.config/token","flags":0`),
		qline(watched, "watch-codex", 2, 2, 301, "fs", "kernel", `"rule":"fs.read[/etc]","op":"open","path":"/etc/hosts","flags":0`))
	writeRun(t, root, enforced,
		qline(enforced, "codex", 0, 0, 400, "run_start", "supervisor", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		qline(enforced, "codex", 1, 1, 401, "fs", "supervisor", `"verdict":"allow","rule":"fs.read[/etc]","op":"open","path":"/etc/hosts","flags":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	fs := s.Query(Filter{Facets: true}).Facets
	if fs == nil {
		t.Fatal("no facets")
	}
	if !fs.WatchedRules["unmatched"] {
		t.Errorf("unmatched, counted only on the watched run, is not marked: %v", fs.WatchedRules)
	}
	if fs.WatchedRules["fs.read[/etc]"] {
		t.Error("fs.read[/etc], counted on the enforced run too, is marked watched")
	}
	if fs := s.Query(Filter{Run: enforced, Facets: true}).Facets; len(fs.WatchedRules) != 0 {
		t.Errorf("an enforced run alone marks %v", fs.WatchedRules)
	}
}
