// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var qt0 = time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)

// qline is a ledger line with its pid, source and second chosen; a mirror repeats its action's pid and second, so its
// monotonic clock (the second) pairs it with that action.
func qline(run, agent string, seq, sec, pid int, kind, source, extra string) string {
	l := fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"%s","pid":%d,"tid":%d,"cgroup":1,"kind":"%s","source":"%s"`,
		seq, seq+1, qt0.Add(time.Duration(sec)*time.Second).Format(time.RFC3339Nano), sec+1, run, agent, pid, pid, kind, source)
	if extra != "" {
		l += "," + extra
	}
	return l + "}\n"
}

const (
	qRunA = "r-aaaa-0001-filtax"
	qRunB = "r-aaaa-0002-filtbx"
)

// queryFixture is two runs whose lines exercise every filter. Run B's line 1 has the same time as run A's line 1, for
// the after-cursor's tie across runs. Counted lines (mirrors left out): A 8, B 5.
func queryFixture(t testing.TB) (string, *Snapshot) {
	t.Helper()
	root := t.TempDir()
	deny := `"verdict":"refused","rule":"net.deny[chatgpt.com]","reason":"net-not-allowed","proto":"tcp","dst":"104.18.32.47:443","host":"chatgpt.com"`
	writeRun(t, root, qRunA,
		qline(qRunA, "alpha", 0, 0, 100, "run_start", "supervisor", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		qline(qRunA, "alpha", 1, 1, 101, "exec", "supervisor", `"verdict":"allow","rule":"exec.allow[curl]","path":"/usr/bin/curl","argv":["curl","https://chatgpt.com"]`),
		qline(qRunA, "alpha", 2, 2, 101, "net", "supervisor", deny),
		qline(qRunA, "alpha", 3, 2, 101, "refused", "supervisor", `"rule":"net.deny[chatgpt.com]","reason":"net-not-allowed","op":"connect","target":"104.18.32.47:443"`),
		qline(qRunA, "alpha", 4, 3, 102, "fs", "supervisor", `"verdict":"refused","rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","path":"/w/x/home/.ssh/id_rsa","flags":0`),
		qline(qRunA, "alpha", 5, 4, 102, "fs", "supervisor", `"verdict":"allow","rule":"fs.write[/w/x/proj]","op":"open","path":"/w/x/proj/out.txt","flags":577`),
		qline(qRunA, "alpha", 6, 5, 103, "net", "kernel", `"verdict":"allow","rule":"net.allow[10.0.0.1]","proto":"tcp","dst":"10.0.0.1:80"`),
		qline(qRunA, "alpha", 7, 6, 104, "refused", "supervisor", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`),
		qline(qRunA, "alpha", 8, 7, 100, "run_end", "supervisor", `"reason":"exit","exit_code":0`))
	writeRun(t, root, qRunB,
		qline(qRunB, "beta", 0, 0, 200, "run_start", "supervisor", `"tier":"landlock","command":["sh"],"cwd":"/x/proj"`),
		qline(qRunB, "beta", 1, 1, 201, "exec", "supervisor", `"verdict":"allow","rule":"exec.allow[ls]","path":"/bin/ls","argv":["ls","-la"]`),
		qline(qRunB, "beta", 2, 8, 201, "net", "supervisor", deny),
		qline(qRunB, "beta", 3, 9, 202, "fs", "kernel", `"verdict":"allow","rule":"fs.read[/etc]","op":"open","path":"/etc/passwd","flags":0`),
		qline(qRunB, "beta", 4, 10, 200, "run_end", "supervisor", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, s
}

func TestQueryFilters(t *testing.T) {
	_, s := queryFixture(t)
	at := func(sec int) time.Time { return qt0.Add(time.Duration(sec) * time.Second) }
	for _, c := range []struct {
		name string
		f    Filter
		want int
	}{
		{"none", Filter{}, 13},
		{"kinds", Filter{Kinds: []string{"exec", "net"}}, 5},
		{"kind run groups start and end", Filter{Kinds: []string{"run"}}, 4},
		{"kind refused lists mirrors as the form does (r9 QG-5)", Filter{Kinds: []string{"refused"}}, 2},
		{"legacy kind refused lists mirrors", Filter{Kind: "refused"}, 2},
		{"not kinds", Filter{Not: Exclude{Kinds: []string{"run", "fs"}}}, 6},
		{"pid", Filter{PID: 101}, 2},
		{"rule exact", Filter{Rules: []string{"fs.deny_read[~/.ssh]"}}, 1},
		{"rule prefix", Filter{Rules: []string{"net.*"}}, 3},
		{"not rule prefix", Filter{Not: Exclude{Rules: []string{"net.deny*"}}}, 11},
		{"path under the run's home", Filter{PathPrefix: "~/.ssh"}, 1},
		{"path absolute", Filter{PathPrefix: "/w/x/proj/"}, 1},
		{"path of an exec", Filter{PathPrefix: "/usr/bin/"}, 1},
		{"path of a refused target", Filter{PathPrefix: "unix:/var/run"}, 1},
		{"host", Filter{Hosts: []string{"ChatGPT.com"}}, 2},
		{"host from dst", Filter{Hosts: []string{"10.0.0.1"}}, 1},
		{"not host", Filter{Not: Exclude{Hosts: []string{"chatgpt.com"}}}, 11},
		{"source", Filter{Source: "kernel"}, 2},
		{"since", Filter{Since: at(7)}, 4},
		{"until", Filter{Until: at(2)}, 4},
		{"since and until", Filter{Since: at(2), Until: at(5)}, 3},
		{"runs", Filter{Runs: []string{qRunB}}, 5},
		{"not runs", Filter{Not: Exclude{Runs: []string{qRunB}}}, 8},
		{"agents", Filter{Agents: []string{"beta"}}, 5},
		{"not agents", Filter{Not: Exclude{Agents: []string{"beta"}}}, 8},
		{"words all", Filter{Words: []string{"curl", "chatgpt"}}, 1},
		{"not words", Filter{Not: Exclude{Words: []string{"chatgpt"}}}, 10},
		{"not verdicts", Filter{Not: Exclude{Verdicts: []string{"none"}}}, 9},
		{"verdict refused", Filter{Verdicts: []string{"refused"}}, 4},
		{"combined", Filter{Kinds: []string{"net"}, Verdicts: []string{"refused"}, Hosts: []string{"chatgpt.com"}, Since: at(5)}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			if pg := s.Query(c.f); pg.Matched != c.want {
				t.Errorf("matched %d, want %d", pg.Matched, c.want)
			}
		})
	}
}

func TestQueryFiltersFromTheLanguage(t *testing.T) {
	_, s := queryFixture(t)
	now := qt0.Add(10*time.Second + 500*time.Millisecond)
	for q, want := range map[string]int{
		"kind:exec verdict:allow":                           2,
		"verdict:refused host:chatgpt.com since:5s":         1,
		"rule:fs.deny_read* path:~/.ssh":                    1,
		"-kind:run -verdict:none":                           9,
		`"https://chatgpt"`:                                 1,
		"-chatgpt":                                          10,
		"pid:201 run:" + qRunB:                              2,
		"until:2026-10-27T01:00:02Z":                        4,
		"since:2026-10-27T01:00:07Z agent:beta":             3,
		"unix:/var/run/nscd":                                1, // not a key: a word
		"kind:exec kind:net":                                5,
		"source:kernel -host:10.0.0.1":                      1,
		"after:" + cursorOf(qt0.Add(time.Second), qRunB, 1): 9,
	} {
		f, _, err := ParseQueryAt(q, now, time.UTC)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if pg := s.Query(f); pg.Matched != want {
			t.Errorf("%q: matched %d, want %d", q, pg.Matched, want)
		}
	}
}

func cursorOf(ts time.Time, run string, seq uint64) string {
	return Row{Event: Event{TS: ts, Run: run, Seq: seq}}.Cursor()
}

// TestFacetsAgreeWithFilters: each facet value's count is what the search plus that value matches.
func TestFacetsAgreeWithFilters(t *testing.T) {
	_, s := queryFixture(t)
	for _, base := range []Filter{{}, {Not: Exclude{Kinds: []string{"run"}}}, {Verdicts: []string{"refused"}}, {Text: "chatgpt"}, {HideSys: true}} {
		for range 2 { // the second pass reads the cached tallies
			base.Facets = true
			pg := s.Query(base)
			fs := pg.Facets
			if fs == nil {
				t.Fatal("no facets")
			}
			check := func(name string, facet Facet, narrow func(Filter, string) Filter) {
				sum := 0
				for _, v := range facet.Values {
					sum += v.Count
					f := narrow(base, v.Value)
					f.Facets = false
					if got := s.Query(f).Matched; got != v.Count {
						t.Errorf("%+v: %s %q counts %d, the filter matches %d", base, name, v.Value, v.Count, got)
					}
				}
				// Kind's "refused" also counts the refusal notes kind:refused lists (r9 QG-5), so kind adds up to more.
				if (name == "verdict" || name == "run") && sum != pg.Matched {
					t.Errorf("%+v: %s counts sum to %d, matched %d", base, name, sum, pg.Matched)
				}
			}
			check("kind", fs.Kind, func(f Filter, v string) Filter { f.Kinds = []string{v}; return f })
			check("verdict", fs.Verdict, func(f Filter, v string) Filter {
				return f.And(Filter{Verdicts: []string{v}})
			})
			check("rule", fs.Rule, func(f Filter, v string) Filter { f.Rules = []string{v}; return f })
			check("host", fs.Host, func(f Filter, v string) Filter { f.Hosts = []string{v}; return f })
			check("run", fs.Run, func(f Filter, v string) Filter { f.Runs = []string{v}; return f })
		}
	}
	pg := s.Query(Filter{Facets: true})
	if pg.Facets.Host.Distinct != 2 || pg.Facets.Host.Values[0] != (FacetValue{"chatgpt.com", 2}) {
		t.Errorf("host facet %+v", pg.Facets.Host)
	}
	if pg.Facets.Run.Values[0] != (FacetValue{qRunA, 8}) || pg.Facets.Run.Values[1] != (FacetValue{qRunB, 5}) {
		t.Errorf("run facet %+v", pg.Facets.Run)
	}
	if pg := s.Query(Filter{}); pg.Facets != nil {
		t.Error("facets counted though not asked for")
	}
}

// TestAfterCursorAcrossRuns: for every line's cursor, the lines after it and the lines at or before it are all the
// lines, with none in both, though two runs have a line at the same time.
func TestAfterCursorAcrossRuns(t *testing.T) {
	_, s := queryFixture(t)
	all := s.Query(Filter{PageSize: 100})
	if all.Matched != 13 || len(all.Rows) != 13 {
		t.Fatalf("matched %d rows %d", all.Matched, len(all.Rows))
	}
	for k, r := range all.Rows {
		after := s.Query(Filter{After: r.Cursor(), PageSize: 100})
		if after.Matched != k {
			t.Errorf("after %s: %d lines, want the %d newer", r.Cursor(), after.Matched, k)
		}
		for i, a := range after.Rows {
			if a.Run != all.Rows[i].Run || a.Seq != all.Rows[i].Seq {
				t.Errorf("after %s: row %d is %s#%d, want %s#%d", r.Cursor(), i, a.Run, a.Seq, all.Rows[i].Run, all.Rows[i].Seq)
			}
		}
	}
	// The tie: run B's line 1 and run A's line 1 have one time; after B's, A's is not newer, and after A's, B's is.
	if pg := s.Query(Filter{After: cursorOf(qt0.Add(time.Second), qRunB, 1), Runs: []string{qRunA}, Kinds: []string{"exec"}}); pg.Matched != 0 {
		t.Errorf("after B#1, A#1 counted: %d", pg.Matched)
	}
	if pg := s.Query(Filter{After: cursorOf(qt0.Add(time.Second), qRunA, 1), Runs: []string{qRunB}, Kinds: []string{"exec"}}); pg.Matched != 1 {
		t.Errorf("after A#1, B#1 not counted: %d", pg.Matched)
	}
	if pg := s.Query(Filter{After: "nonsense"}); pg.Matched != 0 {
		t.Errorf("an unreadable cursor matched %d lines", pg.Matched)
	}
}

func TestEachGivesExactLines(t *testing.T) {
	root, s := queryFixture(t)
	file := func(run string) [][]byte {
		b, err := os.ReadFile(filepath.Join(root, run, "events.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	}
	a, b := file(qRunA), file(qRunB)
	var got []string
	s.Each(Filter{Verdicts: []string{"refused"}}, OldestFirst, func(e *Event, raw func() ([]byte, error)) bool {
		line, err := raw()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(line))
		return true
	})
	want := []string{string(a[2]), string(a[4]), string(a[7]), string(b[2])}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("oldest first:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	n := 0
	var first *Event
	s.Each(Filter{}, NewestFirst, func(e *Event, raw func() ([]byte, error)) bool {
		if first == nil {
			first = e
		}
		n++
		return n < 5
	})
	if n != 5 || first.Run != qRunB || first.Seq != 4 {
		t.Errorf("newest first stopped after %d, first %+v", n, first)
	}
	// A file replaced under the read model: raw says the line moved rather than giving another line's bytes.
	if err := os.WriteFile(filepath.Join(root, qRunB, "events.jsonl"), []byte(strings.Repeat("x", 4000)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Each(Filter{Runs: []string{qRunB}}, OldestFirst, func(e *Event, raw func() ([]byte, error)) bool {
		if _, err := raw(); err == nil {
			t.Errorf("line %d read from a replaced file", e.Seq)
		}
		return true
	})
}

// TestHostFilterHoldsAScopedLine: the Logs filter and its facet are on Event.Host, the view a person opens on a host they
// just blocked, and a scope id on the agent's connects took each such line out of it.
func TestHostFilterHoldsAScopedLine(t *testing.T) {
	root := t.TempDir()
	const allow = `"verdict":"allow","rule":"net[tcp://2001:db8::/32:443]","proto":"tcp","dst":`
	writeRun(t, root, qRunA,
		qline(qRunA, "alpha", 0, 0, 100, "run_start", "supervisor", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		qline(qRunA, "alpha", 1, 1, 101, "net", "supervisor", allow+`"[2001:db8::1]:443"`),
		qline(qRunA, "alpha", 2, 2, 101, "net", "supervisor", allow+`"[2001:db8::1%1]:443"`),
		qline(qRunA, "alpha", 3, 3, 101, "refused", "supervisor", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"[2001:db8::1%7]:8443"`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	count := func(f Filter) (n int) {
		s.Each(f, OldestFirst, func(*Event, func() ([]byte, error)) bool { n++; return true })
		return n
	}
	if got := count(Filter{Hosts: []string{"2001:db8::1"}}); got != 3 {
		t.Errorf("host filter holds %d lines of the host, want 3", got)
	}
	if got := count(Filter{Not: Exclude{Hosts: []string{"2001:db8::1"}}}); got != 1 {
		t.Errorf("left out the host and %d lines stayed, want the run_start alone", got)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"tcp://chatgpt.com:443": "chatgpt.com", "ChatGPT.com:443": "chatgpt.com", "93.184.216.34:443": "93.184.216.34",
		"[::1]:443": "::1", "::1": "::1", "example.org": "example.org", "unix:/var/run/nscd/socket": "", "family(16)": "",
		"/etc/passwd": "", "<script>alert(1)</script>": "", "a b": "", "word:thing": "", "": "",
		// An address as a block holds it and every matcher compares it: unmapped, with no zone.
		"[2001:db8::1%1]:443": "2001:db8::1", "[2001:db8::1%1]": "2001:db8::1", "2001:db8::1%1": "2001:db8::1",
		"tcp://[fe80::1%2]:22": "fe80::1", "[::ffff:203.0.113.9]:443": "203.0.113.9", "[2001:DB8::1]:443": "2001:db8::1",
		"a%b.example:443": "a%b.example",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
