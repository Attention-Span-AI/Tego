// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// TestLogsChangeTerm (C97): kind:change asks for the rule changes directly. It keeps the other context terms (run,
// agent, time), leaves the event lines out, and can be joined with another kind (either), but kind:change with a term
// about ledger lines (a verdict) still shows none, as without it.
func TestLogsChangeTerm(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	feed := []rules.FeedEntry{{ID: "a", At: t0.Add(time.Hour), Agent: "codex"}, {ID: "b", At: t0, Agent: "claude"}}
	snap := &ledgerview.Snapshot{}
	got := func(q string) string {
		f, _, err := ledgerview.ParseQueryAt(q, t0, time.UTC)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		var out []string
		for _, c := range logsChanges(feed, f, snap) {
			out = append(out, c.ID)
		}
		return strings.Join(out, ",")
	}
	for q, want := range map[string]string{
		"kind:change":                 "a,b",
		"kind:change agent:codex":     "a",
		"kind:change kind:exec":       "a,b",
		"kind:change verdict:refused": "",
		"-kind:change":                "",
		"kind:exec":                   "",
		"":                            "a,b",
	} {
		if g := got(q); g != want {
			t.Errorf("%q: %q, want %q", q, g, want)
		}
	}
}

// TestLogsChangeTermPage (C97): the page for kind:change lists the rule change and no event line.
func TestLogsChangeTermPage(t *testing.T) {
	s, _, _ := savedWithBlock(t)
	c := login(t, s)
	page := do(s, "GET", "/logs?where="+url.QueryEscape("kind:change"), "127.0.0.1:8484", c).Body.String()
	mustContain(t, "kind:change", page, `class="rc-row"`, "Rule change")
	if strings.Contains(page, `class="lq-r `) {
		t.Error("kind:change lists event lines")
	}
}

// TestLogsChangesWithoutEventRows (C98): a filtered page with no event line in its window still shows the rule changes
// made in it.
func TestLogsChangesWithoutEventRows(t *testing.T) {
	s, _, _ := savedWithBlock(t)
	c := login(t, s)
	es, ok := s.cfg.Rules.(ChangeFeed)
	if !ok {
		t.Fatal("no change feed")
	}
	feed, err := es.(*rules.Service).ForRequest(context.Background()).Feed()
	if err != nil || len(feed) == 0 {
		t.Fatalf("feed %v %v", feed, err)
	}
	at := feed[0].At
	where := "since:" + at.Add(-time.Millisecond).UTC().Format(time.RFC3339Nano) + " until:" + at.Add(time.Millisecond).UTC().Format(time.RFC3339Nano)
	page := do(s, "GET", "/logs?where="+url.QueryEscape(where), "127.0.0.1:8484", c).Body.String()
	if strings.Contains(page, `class="lq-r `) {
		t.Fatal("the window holds an event line: the test needs a window with none")
	}
	mustContain(t, "a window with a rule change and no lines", page, `class="rc-row"`, "Rule change")
}

// TestLiveStateMovesWithRuleChange (C99): the live state carries the rule-change journal's revision, which moves when
// the journal does and not otherwise, and a Logs page names the revision its change rows were read at; so the page asks
// for its rows again when a rule changes, with no ledger line and no new loop.
func TestLiveStateMovesWithRuleChange(t *testing.T) {
	s, _, _ := savedWithBlock(t)
	c := login(t, s)
	crev := func() string {
		var st liveState
		if err := json.Unmarshal(do(s, "GET", "/status.json", "127.0.0.1:8484", c).Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		return st.Crev
	}
	before := crev()
	if before == "" || crev() != before {
		t.Fatalf("revision %q then %q: want one steady value", before, crev())
	}
	page := do(s, "GET", "/logs", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the Logs rows", page, `data-crev="`+before+`"`)
	j := rules.JournalPath(s.cfg.Ledger)
	if err := os.Chtimes(j, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.live.mu.Lock()
	s.live.at = time.Time{} // the state is kept for a fraction of a tick: ask again
	s.live.mu.Unlock()
	if after := crev(); after == before {
		t.Errorf("the revision stayed %q after the journal changed", after)
	}
}

// TestLogsChangesFragment (C99): GET /logs/changes is the search's rule-change rows, as the page writes them, with the
// revision they were read at; a search that shows none gets none.
func TestLogsChangesFragment(t *testing.T) {
	s, _, _ := savedWithBlock(t)
	c := login(t, s)
	w := do(s, "GET", "/logs/changes", "127.0.0.1:8484", c)
	mustContain(t, "the fragment", w.Body.String(), `class="rc-row"`, "Rule change", `<time datetime="`)
	if w.Header().Get("X-Tego-Crev") != s.changeRev() {
		t.Errorf("X-Tego-Crev %q, want %q", w.Header().Get("X-Tego-Crev"), s.changeRev())
	}
	if b := do(s, "GET", "/logs/changes?where=verdict:refused", "127.0.0.1:8484", c).Body.String(); strings.Contains(b, "rc-row") {
		t.Error("a verdict search gets a rule change")
	}
}
