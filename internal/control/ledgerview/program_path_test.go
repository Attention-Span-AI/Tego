// SPDX-License-Identifier: Apache-2.0

package ledgerview

import "testing"

// TestQueryProgramByPath: prog: with a / reads as a path, the program's own pathname or a folder it is under, whole names
// only, so a program can be told from another of its name in another folder; prog: with no / is still its name.
func TestQueryProgramByPath(t *testing.T) {
	x, seqs := codexShaped(t)
	x.lines[seqs["curl"]] = replaceOnce(t, x.lines[seqs["curl"]], `"path":"/usr/bin/curl"`, `"path":"/opt/tools/bin/curl"`)
	r := x.write(t)
	s := &Snapshot{Runs: []*Run{r}}
	count := func(q string) int {
		t.Helper()
		f, _, err := ParseQuery(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return s.Query(f).Matched
	}
	all := count("")
	for _, c := range []struct {
		q    string
		want int
	}{
		{"prog:curl", 2},
		{"prog:/opt/tools/bin/curl", 2},
		{"prog:/opt/tools", 2},
		{"prog:/opt/tools/", 2},
		{"prog:/opt/tool", 0}, // whole names: /opt/tools is not under /opt/tool
		{"prog:/usr/bin/curl", 0},
		{"prog:/usr/bin", 4}, // codex's 3 lines and bash's 1
		{"prog:/usr/bin prog:curl", 6},
		{"prog:/opt/tools OR prog:/usr/bin/codex", 5},
		{"-prog:/opt/tools", all - 2},
		{"prog:/OPT/tools", 0}, // a path is read as written, as path: is
		{"prog:~/bin", 0},      // the run has no home known
	} {
		if n := count(c.q); n != c.want {
			t.Errorf("%s: %d lines, want %d", c.q, n, c.want)
		}
	}
	f, toks, err := ParseQuery("prog:/Opt/Tools -prog:CURL")
	if err != nil || len(f.Programs) != 1 || f.Programs[0] != "/Opt/Tools" || f.Not.Programs[0] != "curl" || FormatQuery(toks) != "prog:/Opt/Tools -prog:CURL" {
		t.Errorf("parse: %+v %v %v", f, toks, err)
	}
}
