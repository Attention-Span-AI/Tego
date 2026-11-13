// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"strings"
	"testing"
)

func TestGenericRetainedLengthSettlement(t *testing.T) {
	for _, n := range []int{1, 31} {
		words := strings.Fields(strings.Repeat("a ", n))
		p, err := Parse("tool "+strings.Join(words, " ")+" --", ListAllow, NewRows())
		if err != nil {
			t.Fatal(err)
		}
		ix := NewIndex(NewRows(), []*Pattern{p}, IndexOptions{})
		f := Facts{Requested: "tool", Image: "tool", Argv0: "tool", Argv: append([]string{"tool"}, words...)}
		if r := ix.Decide(&f); r.Final {
			t.Errorf("%d operands: incomplete refusal settled: %+v", n, r)
		}
		f.Argv = append(f.Argv, "--")
		f.ArgvComplete = true
		if r := ix.Decide(&f); r.Outcome != OutcomeAllowed {
			t.Errorf("complete: %+v", r)
		}
	}
}

func TestMissingRetainedReadingsFailClosed(t *testing.T) {
	row := &Row{Tool: "tool", Root: &Level{Subs: map[string]*Level{"run": {}}}}
	rs := NewRows(row)
	for _, list := range []List{ListAllow, ListDeny, ListAsk} {
		p, err := Parse("tool run", list, rs)
		if err != nil {
			t.Fatal(err)
		}
		ix := NewIndex(rs, []*Pattern{p}, IndexOptions{})
		inv := Invocation{Tool: "tool", Row: row, Tokens: []string{"run"}, Readings: NewNormalizer(row, nil).Normalize([]string{"run"})}
		got := ix.matchPattern(p, &inv)
		if list == ListAllow && got != MatchNone || list != ListAllow && got == MatchNone {
			t.Errorf("%s missing retained readings: %s", list, got)
		}
	}
}

func TestSeparatorLevelEveryDepth(t *testing.T) {
	p := &Pattern{Row: &Row{Root: &Level{Subs: map[string]*Level{"run": {}}}}}
	for _, depth := range []int{-1, 0, 1, 2, int(^uint(0) >> 1)} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("depth %d panicked: %v", depth, r)
				}
			}()
			got := p.separatorLevel(&Reading{Path: []string{"run"}}, depth)
			if (depth < 0 || depth > 1) && got != nil {
				t.Errorf("invalid depth %d got a level", depth)
			}
		}()
	}
}

func TestRetainedReadingBudget(t *testing.T) {
	row := &Row{Tool: "tool", Root: &Level{Subs: map[string]*Level{"run": {}}}}
	toks := append(strings.Fields(strings.Repeat("--future ", MaxReadings+1)), "run")
	for _, open := range []bool{false, true} {
		for _, rr := range [][]Reading{NewNormalizer(row, nil).NormalizeOpen(toks, open), newReleaseNormalizer(row, nil).NormalizeOpen(toks, open)} {
			if len(rr) != 1 || !rr[0].Unlocatable {
				t.Fatalf("open=%v: budget did not fail closed: %+v", open, rr)
			}
		}
	}
}

func TestInterpreterRetainedDispatchAndSettlement(t *testing.T) {
	row := &Row{Tool: "interpreter", Root: &Level{}, Interp: &InterpSpec{}}
	ix := NewIndex(NewRows(row), nil, IndexOptions{})
	inv := Invocation{Tool: row.Tool, Row: row, Tokens: []string{"script"}, Readings: []Reading{{Dispatch: 0, DispatchAfter: -1}}, releaseReadings: []Reading{{Pending: true, Dispatch: -1, DispatchAfter: -1}}}
	if ix.interpSettled(&inv) {
		t.Fatal("corrected script hid pending retained reading")
	}
	inv.Readings = []Reading{{Dispatch: -1, DispatchAfter: -1}}
	inv.releaseReadings = []Reading{{Dispatch: 0, DispatchAfter: -1}}
	b := builder{ix: ix}
	ix.dispatchInterp(&b, inv)
	if len(b.out) == 0 || b.out[0].Tool != "script" {
		t.Fatalf("lost retained script dispatch: %+v", b.out)
	}
	inv.releaseReadings = nil
	b = builder{ix: ix}
	ix.dispatchInterp(&b, inv)
	if !b.overflow {
		t.Fatal("missing retained dispatch reading did not fail closed")
	}
}

func TestMissingReaderCannotSettleOrUseClosure(t *testing.T) {
	row := &Row{Tool: "tool", Root: &Level{Subs: map[string]*Level{"run": {}, "helper": {}}}, Closure: map[string][]string{"run": {"helper"}}}
	rs := NewRows(row)
	p, err := Parse("tool run", ListAllow, rs)
	if err != nil {
		t.Fatal(err)
	}
	ix := NewIndex(rs, []*Pattern{p}, IndexOptions{})
	inv := Invocation{Tool: "tool", Row: row, Tokens: []string{"helper"}, Readings: NewNormalizer(row, nil).Normalize([]string{"helper"})}
	if _, ok := ix.allowedBy(ix.tools["tool"], &inv); ok {
		t.Error("missing retained reading admitted helper closure")
	}
	if ix.settled([]Invocation{inv}, nil) {
		t.Error("missing retained reading settled ordinary invocation")
	}
	deny, err := Parse("tool run", ListDeny, rs)
	if err != nil {
		t.Fatal(err)
	}
	dx := NewIndex(rs, []*Pattern{deny}, IndexOptions{})
	if dx.denySettled([]Invocation{inv}) {
		t.Error("missing retained reading settled multicall invocation")
	}
}

func TestMissingRetainedPatternCannotAllow(t *testing.T) {
	row := &Row{Tool: "tool", Root: &Level{Subs: map[string]*Level{"run": {}}}}
	rs := NewRows(row)
	p, err := Parse("tool run", ListAllow, rs)
	if err != nil {
		t.Fatal(err)
	}
	ix := NewIndex(rs, []*Pattern{p}, IndexOptions{})
	invs := ix.Interpretations(&Facts{Requested: "tool", Image: "tool", Argv0: "tool", Argv: []string{"tool", "run"}, ArgvComplete: true})
	p.released = nil
	if ix.matchPattern(p, &invs[0]) != MatchNone {
		t.Fatal("missing retained allow pattern admitted")
	}
}
