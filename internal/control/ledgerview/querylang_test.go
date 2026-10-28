// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseQuery(t *testing.T) {
	now := time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		q    string
		want Filter
		toks []Token
		err  string
	}{
		{q: "", want: Filter{}},
		{q: "kind:exec verdict:refused", want: Filter{Kinds: []string{"exec"}, Verdicts: []string{"refused"}},
			toks: []Token{{Key: "kind", Value: "exec"}, {Key: "verdict", Value: "refused"}}},
		{q: "KIND:Exec verdict:Blocked", want: Filter{Kinds: []string{"exec"}, Verdicts: []string{"refused"}},
			toks: []Token{{Key: "kind", Value: "Exec"}, {Key: "verdict", Value: "Blocked"}}},
		{q: "kind:answer kind:run_end", want: Filter{Kinds: []string{"ask", "run"}},
			toks: []Token{{Key: "kind", Value: "answer"}, {Key: "kind", Value: "run_end"}}},
		{q: "pid:123 rule:fs.deny_read* path:~/.ssh host:ChatGPT.com", want: Filter{PID: 123, Rules: []string{"fs.deny_read*"},
			PathPrefix: "~/.ssh", Hosts: []string{"chatgpt.com"}},
			toks: []Token{{Key: "pid", Value: "123"}, {Key: "rule", Value: "fs.deny_read*"}, {Key: "path", Value: "~/.ssh"}, {Key: "host", Value: "ChatGPT.com"}}},
		{q: "run:r-a agent:x source:Kernel", want: Filter{Runs: []string{"r-a"}, Agents: []string{"x"}, Source: "kernel"},
			toks: []Token{{Key: "run", Value: "r-a"}, {Key: "agent", Value: "x"}, {Key: "source", Value: "Kernel"}}},
		{q: "since:15m until:2026-10-27T01:00", want: Filter{Since: now.Add(-15 * time.Minute), Until: time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)},
			toks: []Token{{Key: "since", Value: "15m"}, {Key: "until", Value: "2026-10-27T01:00"}}},
		{q: "since:2d until:01:30", want: Filter{Since: now.Add(-48 * time.Hour), Until: time.Date(2026, 10, 27, 1, 30, 0, 0, time.UTC)},
			toks: []Token{{Key: "since", Value: "2d"}, {Key: "until", Value: "01:30"}}},
		{q: `-word "quoted phrase" -"rm -rf"`, want: Filter{Words: []string{"quoted phrase"}, Not: Exclude{Words: []string{"word", "rm -rf"}}},
			toks: []Token{{Value: "word", Neg: true}, {Value: "quoted phrase"}, {Value: "rm -rf", Neg: true}}},
		{q: `-kind:fs -verdict:none -rule:x* -host:a.b -run:r-x -agent:y`,
			want: Filter{Not: Exclude{Kinds: []string{"fs"}, Verdicts: []string{"none"}, Rules: []string{"x*"}, Hosts: []string{"a.b"}, Runs: []string{"r-x"}, Agents: []string{"y"}}},
			toks: []Token{{Key: "kind", Value: "fs", Neg: true}, {Key: "verdict", Value: "none", Neg: true}, {Key: "rule", Value: "x*", Neg: true},
				{Key: "host", Value: "a.b", Neg: true}, {Key: "run", Value: "r-x", Neg: true}, {Key: "agent", Value: "y", Neg: true}}},
		{q: `path:"/tmp/my dir" rule:"a \"b\""`, want: Filter{PathPrefix: "/tmp/my dir", Rules: []string{`a "b"`}},
			toks: []Token{{Key: "path", Value: "/tmp/my dir"}, {Key: "rule", Value: `a "b"`}}},
		// Keys the language does not know stay words, as written.
		{q: "unix:/var/run/nscd/socket tcp://chatgpt.com:443 foo:bar", want: Filter{Words: []string{"unix:/var/run/nscd/socket", "tcp://chatgpt.com:443", "foo:bar"}},
			toks: []Token{{Value: "unix:/var/run/nscd/socket"}, {Value: "tcp://chatgpt.com:443"}, {Value: "foo:bar"}}},
		{q: "- lone", want: Filter{Words: []string{"-", "lone"}}, toks: []Token{{Value: "-"}, {Value: "lone"}}},
		{q: "pid:abc kind:exec", want: Filter{Kinds: []string{"exec"}}, toks: []Token{{Key: "kind", Value: "exec"}}, err: "pid:abc"},
		{q: "verdict:maybe", err: "not a verdict"},
		{q: "-pid:3", err: "cannot be left out"},
		{q: "since:yesterday", err: "not a time"},
		{q: "kind:", err: "needs a value"},
		{q: `"open phrase`, err: "quote is not closed"},
		{q: "after:junk", err: "not a line cursor"},
	} {
		t.Run(c.q, func(t *testing.T) {
			f, toks, err := ParseQueryAt(c.q, now, time.UTC)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("error %v, want one naming %q", err, c.err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if c.err == "" || c.want.Kinds != nil {
				if !reflect.DeepEqual(f, c.want) {
					t.Errorf("filter\n%+v\nwant\n%+v", f, c.want)
				}
				if !reflect.DeepEqual(toks, c.toks) {
					t.Errorf("tokens %+v, want %+v", toks, c.toks)
				}
			}
		})
	}
}

// TestFormatQueryRoundTrip: what FormatQuery writes, ParseQuery reads back as the same tokens and the same filter.
func TestFormatQueryRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)
	for _, q := range []string{
		`kind:exec verdict:refused pid:123 rule:fs.deny_read* path:~/.ssh host:chatgpt.com run:r-x agent:x since:15m until:2026-10-27T01:00 -word "quoted phrase"`,
		`-"-rf" "run:literal" "a\\b" "say \"hi\"" path:"/a b" rule:"x\"y" "kind:exec"`,
		`unix:/run/x -host:a.b "-" tab	sep`,
	} {
		f1, t1, err := ParseQueryAt(q, now, time.UTC)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		out := FormatQuery(t1)
		f2, t2, err := ParseQueryAt(out, now, time.UTC)
		if err != nil {
			t.Fatalf("%q → %q: %v", q, out, err)
		}
		if !reflect.DeepEqual(t1, t2) || !reflect.DeepEqual(f1, f2) {
			t.Errorf("%q → %q:\n%+v\n%+v", q, out, t1, t2)
		}
	}
	// Built tokens too: a word that would read as a key or a negation is quoted.
	toks := []Token{{Value: "path:x"}, {Value: "-x"}, {Value: ""}, {Key: "rule", Value: "\"q"}, {Value: "a b", Neg: true}}
	_, back, err := ParseQueryAt(FormatQuery(toks), now, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if want := []Token{toks[0], toks[1], toks[3], toks[4]}; !reflect.DeepEqual(back, want) { // an empty word is dropped
		t.Errorf("%q read back as %+v", FormatQuery(toks), back)
	}
}

func TestFilterAnd(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		a, b Filter
		want Filter
	}{
		{"verdicts intersect", Filter{Verdicts: []string{"refused", "allow"}}, Filter{Verdicts: []string{"allow"}}, Filter{Verdicts: []string{"allow"}}},
		{"disjoint verdicts match nothing", Filter{Verdicts: []string{"refused"}}, Filter{Verdicts: []string{"allow"}}, Filter{none: true}},
		{"texts both apply", Filter{Text: "a"}, Filter{Text: "b", Words: []string{"c"}}, Filter{Text: "a", Words: []string{"b", "c"}}},
		{"runs differ", Filter{Run: "r-a"}, Filter{Run: "r-b"}, Filter{Run: "r-a", none: true}},
		{"time narrows", Filter{Since: t0, Until: t0.Add(time.Hour)}, Filter{Since: t0.Add(time.Minute), Until: t0.Add(2 * time.Hour)},
			Filter{Since: t0.Add(time.Minute), Until: t0.Add(time.Hour)}},
		{"path narrows", Filter{PathPrefix: "/a"}, Filter{PathPrefix: "/a/b"}, Filter{PathPrefix: "/a/b"}},
		{"paths apart", Filter{PathPrefix: "/a"}, Filter{PathPrefix: "/b"}, Filter{PathPrefix: "/a", none: true}},
		{"rules", Filter{Rules: []string{"fs.*", "net.x"}}, Filter{Rules: []string{"fs.deny*", "net.*"}}, Filter{Rules: []string{"net.x", "fs.deny*"}}},
		{"excludes add up", Filter{Not: Exclude{Kinds: []string{"fs"}}}, Filter{Not: Exclude{Kinds: []string{"run"}}, HideSys: true},
			Filter{Not: Exclude{Kinds: []string{"fs", "run"}}, HideSys: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := c.a.And(c.b)
			norm := func(f Filter) Filter { // nil and empty lists are the same filter
				for _, p := range []*[]string{&f.Words, &f.Not.Kinds, &f.Not.Verdicts, &f.Not.Rules, &f.Not.Hosts, &f.Not.Runs, &f.Not.Agents, &f.Not.Words} {
					if len(*p) == 0 {
						*p = nil
					}
				}
				return f
			}
			if g, w := norm(got), norm(c.want); !reflect.DeepEqual(g, w) {
				t.Errorf("got\n%+v\nwant\n%+v", g, w)
			}
		})
	}
}
