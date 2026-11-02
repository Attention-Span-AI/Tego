// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"testing"
	"time"
)

const qRunP = "r-aaaa-0003-pathax"

// pathFixture is one run whose lines name /a/b, names under it and /a/bc beside it, in each place path: reads: an fs
// line's two names, a refused line's target, an exec line's program and argv, the run's command and an ask's and an
// answer's target. The run's home is /home/u (its launcher), with /home/ux beside it.
func pathFixture(t testing.TB) *Snapshot {
	t.Helper()
	root := t.TempDir()
	read := func(p string) string {
		return `"verdict":"allow","rule":"fs.read[/]","op":"open","flags":0,"path":"` + p + `"`
	}
	rename := func(from, to string) string {
		return `"verdict":"allow","rule":"fs.write[/]","op":"rename","path":"` + from + `","path2":"` + to + `"`
	}
	writeRun(t, root, qRunP,
		qline(qRunP, "gamma", 0, 0, 300, "run_start", "supervisor", `"tier":"landlock","command":["/a/b/tool","--flag"],"launcher_user":"u"`),
		qline(qRunP, "gamma", 1, 1, 301, "fs", "supervisor", read("/a/b")),
		qline(qRunP, "gamma", 2, 2, 301, "fs", "supervisor", read("/a/b/c.txt")),
		qline(qRunP, "gamma", 3, 3, 301, "fs", "supervisor", read("/a/bc/d.txt")),
		qline(qRunP, "gamma", 4, 4, 301, "fs", "supervisor", rename("/x/old", "/a/b/new")),
		qline(qRunP, "gamma", 5, 5, 301, "fs", "supervisor", rename("/a/bc/x", "/y/z")),
		qline(qRunP, "gamma", 6, 6, 302, "refused", "supervisor", `"rule":"fs.deny_read[/a/b/k]","reason":"read-denied","op":"open","target":"/a/b/k"`),
		qline(qRunP, "gamma", 7, 7, 302, "refused", "supervisor", `"rule":"fs.deny_read[/a/bc]","reason":"read-denied","op":"open","target":"/a/bc"`),
		qline(qRunP, "gamma", 8, 8, 303, "exec", "supervisor", `"verdict":"allow","rule":"exec.allow[python3]","path":"/usr/bin/python3.12","argv":["/usr/bin/python3","x.py"]`),
		qline(qRunP, "gamma", 9, 9, 304, "ask", "supervisor", `"ask_id":"q1","hold":"open","op":"open","target":"/a/bc/plan.md","ask_rule":"fs.ask[/a]"`),
		qline(qRunP, "gamma", 10, 10, 304, "ask", "supervisor", `"ask_id":"q2","hold":"mutation","op":"rename","target":"/a/b/m","target2":"/q/n","ask_rule":"fs.ask[/a]"`),
		qline(qRunP, "gamma", 11, 11, 304, "answer", "supervisor", `"ask_id":"q2","by":"uid:1000","after_s":1,"approved":true,"op":"rename","target":"/a/b/m","target2":"/q/n","ask_rule":"fs.ask[/a]"`),
		qline(qRunP, "gamma", 12, 12, 305, "fs", "supervisor", read("/home/u/.ssh/id_rsa")),
		qline(qRunP, "gamma", 13, 13, 305, "fs", "supervisor", read("/home/ux/f")),
		qline(qRunP, "gamma", 14, 14, 300, "run_end", "supervisor", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pathSeqs is the seqs of the lines f matches, oldest first.
func pathSeqs(s *Snapshot, f Filter) []uint64 {
	var out []uint64
	s.Each(f, OldestFirst, func(e *Event, _ func() ([]byte, error)) bool {
		out = append(out, e.Seq)
		return true
	})
	return out
}

// TestPathMatchesWholeNames: path:/a/b is /a/b and the names under it, never /a/bc beside it, wherever a line names a
// path; a prefix ending in / is the names under it alone, and on a command line a space ends the program's path.
func TestPathMatchesWholeNames(t *testing.T) {
	s := pathFixture(t)
	for q, want := range map[string][]uint64{
		"path:/a/b":                {0, 1, 2, 4, 6, 10, 11},
		"path:/a/b/":               {0, 2, 4, 6, 10, 11},
		"path:/a/bc":               {3, 5, 7, 9},
		"path:/a":                  {0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11},
		"path:/a/b/new":            {4},      // a rename's second name
		"path:/a/b/m":              {10, 11}, // a held rename's first name
		"path:/q/n":                {10, 11}, // and its second, as an fs rename line's
		"path:/a/b/tool":           {0},      // the run's command: its program, then a space
		"path:/a/b/to":             nil,
		"path:/usr/bin/python3":    {8}, // the program the argv starts with
		"path:/usr/bin/python3.12": {8}, // the program's path
		"path:/usr/bin/python3.1":  nil,
		"path:~":                   {12},
		"path:~/.ssh":              {12},
	} {
		f, _, err := ParseQueryAt(q, qt0, time.UTC)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if got := pathSeqs(s, f); !slices.Equal(got, want) {
			t.Errorf("%q: lines %v, want %v", q, got, want)
		}
		if got := s.Query(f).Matched; got != len(want) {
			t.Errorf("%q: Query matched %d, want %d", q, got, len(want))
		}
	}
}

// TestPathAndAgreesWithBoth: two path filters joined match the lines both match, by the same rule as each alone. The
// prefixes leave out a rename's two sides apart (/x and /a/b): And keeps one prefix, so it cannot ask for a line
// naming one under each.
func TestPathAndAgreesWithBoth(t *testing.T) {
	s := pathFixture(t)
	prefixes := []string{"", "/a", "/a/", "/a/b", "/a/b/", "/a/bc", "/a/b/c.txt", "/a/b/tool", "/a/b/tool --flag",
		"/usr/bin/python3", "/usr/bin/python3.1", "~", "~/.ssh"}
	for _, a := range prefixes {
		for _, b := range prefixes {
			fa, fb := Filter{PathPrefix: a}, Filter{PathPrefix: b}
			inB := pathSeqs(s, fb)
			var want []uint64
			for _, seq := range pathSeqs(s, fa) {
				if slices.Contains(inB, seq) {
					want = append(want, seq)
				}
			}
			if got := pathSeqs(s, fa.And(fb)); !slices.Equal(got, want) {
				t.Errorf("%q and %q: lines %v, want %v (joined: %q)", a, b, got, want, fa.And(fb).PathPrefix)
			}
		}
	}
}
