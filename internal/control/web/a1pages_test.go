// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestOverviewPrioritiesAndRecovery(t *testing.T) {
	s := newServer(t, fixture(t))
	s.cfg.Now = func() time.Time { return time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC) }
	b := get(t, s, login(t, s), "/")
	for _, want := range []string{"1 request needs you", `class="overview-summary"`, `class="record-seal"`, `class="summary-counts"`, "4 refused today", `class="ov-phone-runs phone-list"`, `href="/runs/` + harmRun + `"`, `id="h-last-runs"`} {
		if !strings.Contains(b, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, id := range []string{"r-ov-head", "r-ov-tiles", "r-ov-recent", "r-ov-refusals", "r-ov-guide", "r-ov-live", "r-ov-asks"} {
		if strings.Count(b, `data-live="`+id+`"`) != 1 {
			t.Errorf("lost or duplicated %s", id)
		}
	}
}

func TestOverviewBrokenRecordNeedsAttention(t *testing.T) {
	root, anchor := chainFixture(t, true)
	s := chainServer(t, root, anchor)
	b := get(t, s, login(t, s), "/")
	if !strings.Contains(b, "<h1>Record needs attention</h1>") || strings.Contains(b, "<h1>Nothing needs you</h1>") {
		t.Error("a broken record must lead with the problem, rather than an all-clear heading")
	}
}

func TestPageWordsDoNotInferSafety(t *testing.T) {
	if got := eventAction(ledgerview.Event{Kind: "refused", Op: "net"}); got != "Connect to a destination" {
		t.Fatal(got)
	}
	r := &ledgerview.Run{}
	st := storyOfRun(ledgerview.Verdict{}, r)
	if strings.Contains(st.Title, "attack") || !strings.Contains(st.Title, "recorded") {
		t.Fatal(st.Title)
	}
	e := ledgerview.Event{Kind: "fs", Verdict: "allow", Target: "/home/u/.ssh/key", Raw: `{"op":"open","flags":0}`}
	ctx := readContextOf(r, &ledgerview.RunSignal{Secrets: []ledgerview.SecretTouch{{Path: e.Target}}})
	c, _, w := pageVerdict(e, ctx)
	if c != "through" || w != "Read allowed" {
		t.Fatal(c, w)
	}
	e.Raw = `{"op":"open","flags":1}`
	c, _, _ = pageVerdict(e, ctx)
	if c == "through" {
		t.Fatal("write-only open called a read")
	}
}

func TestOverviewNamedRunChart(t *testing.T) {
	runs := []*ledgerview.Run{{ID: "new", Agent: "Mira", Refusals: 2}, {ID: "middle", Agent: "Atlas", Refusals: 4}, {ID: "old", Agent: "Invoices", Refusals: 0}, {ID: "older", Refusals: 90}}
	c := overviewCharts(runs, nil)
	if len(c.Last) != 3 || c.Last[0].Name != "Mira" || c.Last[0].Width != "50.0" || c.Last[1].Width != "100.0" || c.Last[2].Count != 0 {
		t.Fatalf("%+v", c.Last)
	}
}

// pageElement reads the selected semantic region independently of its position.
func pageElement(t *testing.T, body, key, value string) string {
	t.Helper()
	var out strings.Builder
	found := false
	walk(parseHTML(t, "page", body), func(n *html.Node) {
		if found {
			return
		}
		if v, _ := attr(n, key); v == value {
			found = true
			if err := html.Render(&out, n); err != nil {
				t.Fatal(err)
			}
		}
	})
	if !found {
		t.Fatalf("missing %s=%s", key, value)
	}
	return strings.ReplaceAll(strings.ReplaceAll(out.String(), "&#39;", "'"), "></use>", "/>")
}
