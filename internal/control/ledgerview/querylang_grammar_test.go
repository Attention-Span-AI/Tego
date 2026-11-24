// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"reflect"
	"testing"
	"time"
)

// TestQueryGrammarErrors is the table of what the Logs query says when it cannot be read in full: each invalid query
// has exactly one error, in these words, and each valid one has none. A query with an error lists no line (see
// TestUnreadQueryMatchesNothing), so every row here is a case where the person must fix the query.
func TestQueryGrammarErrors(t *testing.T) {
	now := time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)
	const orWords = "OR: a query matches lines that fit every term; to ask for either value, repeat the key (kind:exec kind:net)." +
		" Words, pid, path, source, since, until and after cannot be joined with OR. To search for the word OR, put it in quotes"
	for _, c := range []struct {
		q    string
		want string // "" when the query is valid
		toks []Token
	}{
		// Valid.
		{q: "kind:exec OR kind:net", toks: []Token{{Key: "kind", Value: "exec"}, {Key: "kind", Value: "net"}}},
		{q: "-host:a.b OR -host:c.d", toks: []Token{{Key: "host", Value: "a.b", Neg: true}, {Key: "host", Value: "c.d", Neg: true}}},
		{q: "kind:exec AND verdict:refused", toks: []Token{{Key: "kind", Value: "exec"}, {Key: "verdict", Value: "refused"}}},
		{q: `"OR" and or`, toks: []Token{{Value: "OR"}, {Value: "and"}, {Value: "or"}}},
		{q: "AND", toks: []Token{{Value: "AND"}}},
		{q: "unix:/run/x http://host port:80x", toks: []Token{{Value: "unix:/run/x"}, {Value: "http://host"}, {Value: "port:80x"}}},
		{q: `"verdit:refused"`, toks: []Token{{Value: "verdit:refused"}}},
		// Invalid, each with its own words.
		{q: "kind:exec OR verdict:refused", want: orWords},
		{q: "OR kind:exec", want: orWords},
		{q: "kind:exec OR", want: orWords},
		{q: "foo OR bar", want: orWords},
		{q: "pid:1 OR pid:2", want: orWords},
		{q: "-kind:fs OR kind:net", want: orWords},
		{q: "verdit:refused", want: "verdit:refused: verdit is not a search key; did you mean verdict:refused? To search for the text as written, put it in quotes"},
		{q: "hots:example.com", want: "hots:example.com: hots is not a search key; did you mean host:example.com? To search for the text as written, put it in quotes"},
		{q: "program:curl", want: "program:curl: program is not a search key; did you mean prog:curl? To search for the text as written, put it in quotes"},
		{q: "-status:ok", want: "-status:ok: status is not a search key; did you mean -verdict:ok? To search for the text as written, put it in quotes"},
		{q: "pid:abc", want: "pid:abc: not a process number"},
		{q: "pid:0", want: "pid:0: not a process number"},
		{q: "verdict:maybe", want: "verdict:maybe: not a verdict; use refused, allow, ask, observed or none"},
		{q: "-pid:3", want: "-pid: cannot be left out; only kind, verdict, prog, rule, host, run, agent, target and words can"},
		{q: "since:yesterday", want: "since:yesterday: not a time; use 15m, 2h, 7d, 2026-10-27, 2026-10-27T01:00 or 01:00"},
		{q: "kind:", want: "kind: needs a value, as in kind:exec"},
		{q: `"open phrase`, want: `a quote is not closed: end the phrase with "`},
		{q: "after:junk", want: "after:junk: not a line cursor"},
	} {
		t.Run(c.q, func(t *testing.T) {
			f, toks, err := ParseQueryAt(c.q, now, time.UTC)
			if c.want == "" {
				if err != nil {
					t.Fatalf("a valid query read as an error: %v", err)
				}
				if !reflect.DeepEqual(toks, c.toks) {
					t.Errorf("tokens %+v, want %+v", toks, c.toks)
				}
				return
			}
			if err == nil {
				t.Fatalf("no error, want %q (filter %+v)", c.want, f)
			}
			if err.Error() != c.want {
				t.Errorf("error\n%q\nwant\n%q", err.Error(), c.want)
			}
		})
	}
}

// TestOrBetweenOneKindIsEither: kind:exec OR kind:net asks the same as kind:exec kind:net, which the filter reads as
// either value.
func TestOrBetweenOneKindIsEither(t *testing.T) {
	a, _, err := ParseQuery("kind:exec OR kind:net")
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := ParseQuery("kind:exec kind:net")
	if !reflect.DeepEqual(a, b) || len(a.Kinds) != 2 {
		t.Errorf("OR: %+v, without it: %+v", a, b)
	}
}

// TestUnreadQueryMatchesNothing: the filter of a query that could not be read lists no line, whatever else it holds.
func TestUnreadQueryMatchesNothing(t *testing.T) {
	x, _ := codexShaped(t)
	s := &Snapshot{Runs: []*Run{x.write(t)}}
	f, _, err := ParseQuery("pid:abc kind:exec")
	if err == nil {
		t.Fatal("no error")
	}
	if n := s.Query(f).Matched; n == 0 {
		t.Fatal("the unread query's valid part matches nothing: the fixture proves nothing")
	}
	if n := s.Query(f.Nothing()).Matched; n != 0 {
		t.Errorf("Nothing matched %d lines", n)
	}
}
