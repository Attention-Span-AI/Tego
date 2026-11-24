// SPDX-License-Identifier: Apache-2.0

package ledgerview

import "testing"

// TestGroupTargetOneIdentityPerTarget: lines that name one target in different spellings are one group in By target,
// under one readable name, and the group counts add up to the search's. A spelling that names another thing (a
// command line, another file) stays apart.
func TestGroupTargetOneIdentityPerTarget(t *testing.T) {
	x := newXRun(t, "r-tgt")
	fs := func(p string) uint64 {
		return x.add(10, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"`+p+`"`)
	}
	fs("/w/proj/a.txt")
	fs("/w/proj//a.txt")
	fs("/w/proj/./a.txt")
	fs("/w/proj/sub/../a.txt")
	fs("/w/proj/b.txt")
	x.add(10, `"kind":"ask","source":"supervisor","ask_id":"q-1","ask_rule":"fs.ask[./]","hold":"open","op":"read","target":"/w/proj/a.txt"`)
	x.add(10, `"kind":"answer","source":"supervisor","ask_id":"q-1","by":"me","approved":true,"op":"read","target":"/w/proj/a.txt"`)
	x.add(10, `"kind":"net","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","dst":"93.184.216.34:443","host":"Example.com","proto":"tcp"`)
	x.add(10, `"kind":"net","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","dst":"93.184.216.34:443","host":"example.com.","proto":"tcp"`)
	x.add(10, `"kind":"net","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","dst":"93.184.216.34:443","host":"example.com","proto":"tcp"`)
	x.add(10, `"kind":"exec","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","argv":["/bin/cat","/w//x"],"path":"/bin/cat"`)
	x.add(10, `"kind":"exec","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","argv":["/bin/cat","/w/x"],"path":"/bin/cat"`)
	s := &Snapshot{Runs: []*Run{x.write(t)}}
	g := s.Group(Filter{}, GroupTarget, 0, nil)
	got := map[string]int{}
	sum := g.Keyless
	for _, row := range g.Rows {
		got[row.Target] = row.Lines
		sum += row.Lines
		if row.Key != row.Target {
			t.Errorf("group key %q is not its target %q", row.Key, row.Target)
		}
	}
	if sum != g.Matched || g.Matched != s.Query(Filter{}).Matched {
		t.Errorf("groups hold %d lines, Matched %d, the search %d", sum, g.Matched, s.Query(Filter{}).Matched)
	}
	want := map[string]int{
		"/w/proj/a.txt":                   6, // four spellings of one file, its question and its answer
		"/w/proj/b.txt":                   1,
		"example.com (93.184.216.34:443)": 3, // Example.com, example.com. and example.com
		"/bin/cat /w//x":                  1, // a command line is kept as it was written
		"/bin/cat /w/x":                   1,
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("target %q: %d lines, want %d (groups: %v)", k, got[k], n, got)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok && k != "run r-tgt" {
			t.Logf("other group %q: %d", k, got[k])
		}
	}
}

// TestTargetQueryIsTheGroup: target:<a group's name> lists exactly the group's lines, in every spelling, and
// -target: leaves them out, so a group's link and its count agree.
func TestTargetQueryIsTheGroup(t *testing.T) {
	x := newXRun(t, "r-tq")
	for _, p := range []string{"/w/a", "/w//a", "/w/a/", "/w/b"} {
		x.add(10, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"`+p+`"`)
	}
	s := &Snapshot{Runs: []*Run{x.write(t)}}
	count := func(q string) int {
		t.Helper()
		f, _, err := ParseQuery(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return s.Query(f).Matched
	}
	all := count("")
	for q, want := range map[string]int{"target:/w/a": 3, "target:/w/b": 1, "target:/w/a target:/w/b": 4, "-target:/w/a": all - 3, "target:/w/a/": 0} {
		if n := count(q); n != want {
			t.Errorf("%s: %d lines, want %d", q, n, want)
		}
	}
	for _, row := range s.Group(Filter{}, GroupTarget, 0, nil).Rows {
		if n := count("target:" + row.Target); n != row.Lines {
			t.Errorf("group %q holds %d lines, target:%s lists %d", row.Target, row.Lines, row.Target, n)
		}
	}
}
