// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"golang.org/x/net/html"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestOverviewDailyRefusalsCompleteOrQualified(t *testing.T) {
	for _, tc := range []struct {
		name              string
		crossing, evicted bool
	}{
		{"truncated-today", false, false}, {"evicted-today", false, true},
		{"truncated-midnight", true, false}, {"evicted-midnight", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldBudget := ledgerview.MaxResidentBytes
			if tc.evicted {
				ledgerview.MaxResidentBytes = 1
			}
			t.Cleanup(func() { ledgerview.MaxResidentBytes = oldBudget })
			root := t.TempDir()
			id := "r-aaaaaaaa-0000000000099-counts"
			today := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
			start := today
			if tc.crossing {
				start = today.Add(-time.Hour)
			}
			var lines strings.Builder
			seq := 0
			add := func(at time.Time, kind, extra string) {
				fmt.Fprintf(&lines, `{"v":1,"seq":%d,"id":"%064x","prev":"","ts":%q,"run":%q,"agent":"counter","pid":7,"tid":7,"cgroup":1,"mono_ns":1,"source":"supervisor","kind":%q,%s}`+"\n", seq, seq+1, at.Format(time.RFC3339Nano), id, kind, extra)
				seq++
			}
			add(start, "run_start", `"tier":"observe","command":["sh"]`)
			if tc.crossing {
				add(start, "refused", `"op":"exec","target":"curl","rule":"exec.deny[0]","reason":"exec-not-allowed"`)
			}
			add(today.Add(time.Minute), "refused", `"op":"exec","target":"curl","rule":"exec.deny[0]","reason":"exec-not-allowed"`)
			// Pass the actual resident-window limit, so the day's refusal disappears.
			for range 33000 {
				add(today.Add(2*time.Minute), "gap", `"what":"record","why":"routine"`)
			}
			add(today.Add(3*time.Minute), "run_end", `"reason":"exit","exit_code":0`)
			if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(lines.String()), 0600); err != nil {
				t.Fatal(err)
			}
			snap, err := ledgerview.Load(root)
			if err != nil {
				t.Fatal(err)
			}
			rr := snap.Find(id)
			if rr == nil || !rr.Cut {
				t.Fatal("fixture must lose its early event window")
			}
			for _, e := range rr.AllEvents() {
				if e.Refusal() {
					t.Fatal("fixture retained an early refusal")
				}
			}
			if tc.evicted && len(rr.Events) > 0 {
				t.Fatal("fixture was not evicted")
			}
			receipt, err := ledgerview.LoadReceipt(t.Context(), root, id)
			if err != nil {
				t.Fatalf("complete record link must have a readable receipt: %v", err)
			}
			wantTotal := 1
			if tc.crossing {
				wantTotal = 2
			}
			if receipt.Refusals.Total != wantTotal {
				t.Fatalf("complete record has %d refusals, want %d", receipt.Refusals.Total, wantTotal)
			}
			s := newServer(t, root)
			s.cfg.Now = func() time.Time { return today.Add(12 * time.Hour) }
			body := get(t, s, login(t, s), "/")
			summary := pageElement(t, body, "class", "overview-summary")
			if tc.crossing {
				for _, want := range []string{"at least 0 refused today", "Retained event windows omit part of today", `href="/runs/` + id + `/receipt"`} {
					if !strings.Contains(summary, want) {
						t.Errorf("missing %q in %s", want, summary)
					}
				}
			} else if !strings.Contains(summary, ">1 refused today</a>") || strings.Contains(summary, "at least") {
				t.Errorf("complete run aggregate not used: %s", summary)
			}
		})
	}
}

func TestDailyRefusalsRespectsCalendarAndMissingRuns(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.FixedZone("offset", -5*60*60))
	start := time.Date(2026, 11, 13, 0, 0, 0, 0, now.Location())
	// A clock moved backwards: start/end cannot establish the refusal's date.
	r := &ledgerview.Run{ID: "r-clock", Start: now, Last: now, Refusals: 2, RefusalFirst: start.Add(-time.Second), RefusalLast: start.Add(time.Hour), Cut: true, Events: []ledgerview.Event{{Kind: "refused", TS: start.Add(time.Hour)}}}
	n, lower, records := dailyRefusals(&ledgerview.Snapshot{Runs: []*ledgerview.Run{r}}, now)
	if n != 1 || !lower || len(records) != 1 {
		t.Fatalf("clock reordered total %d lower=%v records=%d", n, lower, len(records))
	}
	future := *r
	future.Cut = false
	future.Events = []ledgerview.Event{{Kind: "refused", TS: start.AddDate(0, 0, 1)}}
	future.RefusalFirst, future.RefusalLast = future.Events[0].TS, future.Events[0].TS
	if n, _, _ := dailyRefusals(&ledgerview.Snapshot{Runs: []*ledgerview.Run{&future}}, now); n != 0 {
		t.Fatal("tomorrow counted today")
	}
	if _, lower, _ := dailyRefusals(&ledgerview.Snapshot{RunsCut: true}, now); !lower {
		t.Fatal("omitted runs claimed exact")
	}
}

func TestOverviewDailyCountLinkKeepsExactPeriod(t *testing.T) {
	s := newServer(t, fixture(t))
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	s.cfg.Now = func() time.Time { return now }
	body := get(t, s, login(t, s), "/")
	found := false
	walk(parseHTML(t, "overview", body), func(n *html.Node) {
		href, _ := attr(n, "href")
		if n.Data != "a" || !strings.Contains(text(n), "refused today") {
			return
		}
		found = true
		u, err := url.Parse(href)
		if err != nil {
			t.Fatal(err)
		}
		if got := u.Query().Get("where"); got != "since:2026-10-25T00:00:00Z" {
			t.Errorf("period encoded twice: %q", got)
		}
	})
	if !found {
		t.Fatal("missing daily count link")
	}
}

func TestOverviewDailyUnreadableRecordsAreLowerBounds(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(fmt.Sprint(known), func(t *testing.T) {
			root := t.TempDir()
			id := "r-aaaaaaaa-0000000000098-badcnt"
			at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
			data := line(id, "counter", 0, at, "run_start", `"tier":"landlock","command":["sh"]`) + "{damaged refusal record}\n"
			n := 0
			if known {
				data += line(id, "counter", 1, at, "refused", `"op":"exec","target":"curl","rule":"unmatched","reason":"exec-not-allowed"`)
				n = 1
			}
			data += line(id, "counter", 2, at, "run_end", `"reason":"exit","exit_code":0`)
			if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			snap, err := ledgerview.Load(root)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Find(id).Bad == 0 {
				t.Fatal("fixture must contain an unreadable record")
			}
			s := newServer(t, root)
			s.cfg.Now = func() time.Time { return at }
			b := get(t, s, login(t, s), "/")
			summary := pageElement(t, b, "class", "overview-summary")
			for _, want := range []string{fmt.Sprintf("at least %d refused today", n), "Some record lines could not be read.", "/logs.jsonl?run=" + id} {
				if !strings.Contains(summary, want) {
					t.Errorf("missing %q: %s", want, summary)
				}
			}
		})
	}
}
