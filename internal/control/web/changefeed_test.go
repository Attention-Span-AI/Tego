// SPDX-License-Identifier: Apache-2.0

package web

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// TestPlacedChanges: a change goes before the newest row not newer than it; one newer than every row only on the
// newest page, one older than every row only on the oldest; with no rows, only on a page that is both.
func TestPlacedChanges(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	row := func(sec int) ledgerview.Row {
		var r ledgerview.Row
		r.Run, r.Seq, r.TS = "r-x", uint64(sec), t0.Add(time.Duration(sec)*time.Second)
		return r
	}
	ch := func(id string, sec int) changeRow {
		return changeRow{FeedEntry: rules.FeedEntry{ID: id, At: t0.Add(time.Duration(sec) * time.Second)}, Key: "rc-" + id}
	}
	rows := []ledgerview.Row{row(30), row(20), row(10)} // newest first
	cs := []changeRow{ch("top", 40), ch("mid", 25), ch("same", 20), ch("old", 5)}
	ids := func(xs []changeRow) []string {
		var out []string
		for _, x := range xs {
			out = append(out, x.ID)
		}
		return out
	}
	for _, tc := range []struct {
		name        string
		top, bottom bool
		before      map[uint64][]string
		tail        []string
	}{
		{"only page", true, true, map[uint64][]string{30: {"top"}, 20: {"mid", "same"}}, []string{"old"}},
		{"newest of several", true, false, map[uint64][]string{30: {"top"}, 20: {"mid", "same"}}, nil},
		{"oldest of several", false, true, map[uint64][]string{20: {"mid", "same"}}, []string{"old"}},
		{"middle", false, false, map[uint64][]string{20: {"mid", "same"}}, nil},
	} {
		b, tail := placedChanges(rows, cs, tc.top, tc.bottom)
		for _, r := range rows {
			if got := ids(b[r.Cursor()]); !slices.Equal(got, tc.before[r.Seq]) {
				t.Errorf("%s: before #%d %v, want %v", tc.name, r.Seq, got, tc.before[r.Seq])
			}
		}
		if got := ids(tail); !slices.Equal(got, tc.tail) {
			t.Errorf("%s: tail %v, want %v", tc.name, got, tc.tail)
		}
	}
	if _, tail := placedChanges(nil, cs, true, true); len(tail) != 4 {
		t.Errorf("no rows, one page: tail %v", ids(tail))
	}
	if _, tail := placedChanges(nil, cs, false, true); len(tail) != 0 {
		t.Errorf("no rows on an older page: tail %v", ids(tail))
	}
	if got := ids(changesAfter(cs, t0.Add(20*time.Second))); !slices.Equal(got, []string{"top", "mid"}) {
		t.Errorf("changesAfter %v", got)
	}
}

// TestLogsChangesOnlyByContext: rule-change rows join a Logs search that narrows by run, agent and time only, each
// kept by those; a term about ledger lines (kind, verdict, text, host, rule, path) leaves them out.
func TestLogsChangesOnlyByContext(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	feed := []rules.FeedEntry{
		{ID: "a", At: t0.Add(time.Hour), Agent: "codex", Run: "r-1", Line: 4},
		{ID: "b", At: t0, Agent: "claude", Runs: []string{"r-2"}},
	}
	snap := &ledgerview.Snapshot{}
	got := func(f ledgerview.Filter) string {
		var out []string
		for _, c := range logsChanges(feed, f, snap) {
			out = append(out, c.ID)
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		name string
		f    ledgerview.Filter
		want string
	}{
		{"none", ledgerview.Filter{}, "a,b"},
		{"agent", ledgerview.Filter{Agent: "codex"}, "a"},
		{"not agent", ledgerview.Filter{Not: ledgerview.Exclude{Agents: []string{"codex"}}}, "b"},
		{"run made from", ledgerview.Filter{Run: "r-1"}, "a"},
		{"since", ledgerview.Filter{Since: t0.Add(time.Minute)}, "a"},
		{"until", ledgerview.Filter{Until: t0.Add(time.Minute)}, "b"},
		{"kind", ledgerview.Filter{Kind: "exec"}, ""},
		{"verdict", ledgerview.Filter{Verdicts: []string{"refused"}}, ""},
		{"text", ledgerview.Filter{Text: "token"}, ""},
		{"host", ledgerview.Filter{Hosts: []string{"x"}}, ""},
		{"not word", ledgerview.Filter{Not: ledgerview.Exclude{Words: []string{"x"}}}, ""},
	} {
		if g := got(tc.f); g != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, g, tc.want)
		}
	}
	r := rowOf(feed[0], "")
	if r.From != "/runs/r-1/lines/4#act" || r.FromWords != "line #4 of "+shortRun("r-1") || r.Key != "rc-a" {
		t.Errorf("row: %+v", r)
	}
	if r := rowOf(feed[0], "r-1"); r.FromWords != "line #4 of this run" {
		t.Errorf("row on its run: %q", r.FromWords)
	}
}

// TestRuleChangeRows: after Never allow with Also apply now on a live run, Logs and the run's timeline show the
// change as a row at its time, with its words, the line it came from and the live block it placed; a Logs search by
// verdict does not; the live timeline's poll after the line before the change brings the change row with the new
// rows, and after the newest line brings none.
func TestRuleChangeRows(t *testing.T) {
	s, _, _ := savedWithBlock(t)
	c := login(t, s)
	logs := do(s, "GET", "/logs", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "Logs", logs, `class="rc-row"`, "Rule change", "Cannot run git", "In the dashboard, from <a class=\"link\" href=\"/runs/"+actRun+"/lines/4#act\">line #4 of",
		"live on "+shortRun(actRun)+": Running git", ">History<")
	if page := do(s, "GET", "/logs?verdict=refused", "127.0.0.1:8484", c).Body.String(); strings.Contains(page, `class="rc-row"`) {
		t.Error("a verdict search shows a rule change")
	}
	if page := do(s, "GET", "/logs?run="+actRun, "127.0.0.1:8484", c).Body.String(); !strings.Contains(page, `class="rc-row"`) {
		t.Error("the run's own search lacks its rule change")
	}
	run := do(s, "GET", "/runs/"+actRun, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the timeline", run, `class="tl rc-tl"`, "Rule change:", "line #4 of this run", "live on this run: Running git")
	if strings.Count(run, `class="tl rc-tl"`) != 1 {
		t.Errorf("the timeline shows the change %d times", strings.Count(run, `class="tl rc-tl"`))
	}
	if page := do(s, "GET", "/runs/"+actRun+"?verdict=refused", "127.0.0.1:8484", c).Body.String(); strings.Contains(page, "rc-tl") {
		t.Error("the refused-only timeline shows a rule change")
	}
	rr, err := ledgerview.LoadRun(s.cfg.Ledger, actRun)
	if err != nil {
		t.Fatal(err)
	}
	// The change came after every line of this fixture: a poll after the newest line brings it once more, keyed, so the
	// page keeps one copy at the top; a poll after #0 brings it with the newer rows.
	last := rr.Events[len(rr.Events)-1].Seq
	for _, after := range []uint64{last, 0} {
		body := do(s, "GET", "/runs/"+actRun+"/rows?after="+strconv.FormatUint(after, 10), "127.0.0.1:8484", c).Body.String()
		if strings.Count(body, `data-k="rc-`) != 1 {
			t.Errorf("a poll after #%d: %d change rows, want 1:\n%s", after, strings.Count(body, `data-k="rc-`), body)
		}
	}
	// A change older than the poll's line is on the page already and does not come again.
	if got := liveChanges([]rules.FeedEntry{{ID: "old", At: rr.Events[0].TS, Run: actRun}}, rr, nil, last, ""); len(got.Tail) != 0 || len(got.Before) != 0 {
		t.Errorf("an older change came again: %+v", got)
	}
}
