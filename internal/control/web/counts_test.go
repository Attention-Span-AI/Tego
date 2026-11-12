// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const pairRun = "r-aaaaaaaa-0000000000004-pairsx"

// pairFixture is fixture plus an ended run with two refused connects, each written as the action line and its
// mirror, the way the runtime writes them (the mirror copies the action's pid and monotonic clock).
func pairFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	t0 := time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC)
	l := func(seq int, mono uint64, kind, extra string) string {
		return fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"demo-pair","pid":7,"tid":7,"cgroup":1,"kind":"%s","source":"supervisor",%s}`+"\n",
			seq, seq+1, t0.Add(time.Duration(seq)*time.Millisecond).Format(time.RFC3339Nano), mono, pairRun, kind, extra)
	}
	conn := `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:43437"`
	mirror := `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:43437"`
	lines := l(0, 1, "run_start", `"tier":"landlock","command":["sh"]`) +
		l(1, 10, "gap", `"what":"record","why":"no-price-table"`) +
		l(2, 20, "net", conn) + l(3, 20, "refused", mirror) +
		l(4, 30, "net", conn) + l(5, 30, "refused", mirror) +
		l(6, 40, "run_end", `"reason":"exit","exit_code":0`)
	if err := os.MkdirAll(filepath.Join(root, pairRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, pairRun, "events.jsonl"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

var refusedTile = regexp.MustCompile(`href="/logs\?verdict=refused" aria-label="(\d+) refused`)
var logsLede = regexp.MustCompile(`([\d,]+) lines? · <span class="n-refused">([\d,]+) refused`)

// TestLogsCountsOncePerAction: two refused connects are two refusals, not four lines: Logs says "2 refused" from one
// run, the run page counts 2 and shows one row each, and the line page's Similar counts 2.
func TestLogsCountsOncePerAction(t *testing.T) {
	s := newServer(t, pairFixture(t))
	c := login(t, s)
	b := do(s, "GET", "/logs?q=43437", "127.0.0.1:8484", c).Body.String()
	m := logsLede.FindStringSubmatch(b)
	if m == nil || m[1] != "2" || m[2] != "2" {
		t.Fatalf("logs lede %q, want 2 lines, 2 blocked", m)
	}
	run := do(s, "GET", "/runs/"+pairRun, "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(run, `Refused <span class="n">2</span>`) {
		t.Error("the run page does not count 2 refusals")
	}
	if n := strings.Count(run, `class="tl v-`); n != 3 {
		t.Errorf("%d timeline rows, want 3 (run_start, one folded row for the two connects, run_end; no mirror, no price-table gap)", n)
	}
	if strings.Contains(run, "no-price-table") {
		t.Error("the timeline shows the no-price-table gap")
	}
	line := do(s, "GET", "/runs/"+pairRun+"/lines/2", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(line, "<strong>2</strong> lines in 1 run, 2 refused") {
		t.Error("the line page's Similar does not count the two connects once each")
	}
}

// TestOverviewTileMatchesLogs: the Overview's Refused tile is the number the Logs page it links to shows.
func TestOverviewTileMatchesLogs(t *testing.T) {
	s := newServer(t, pairFixture(t))
	c := login(t, s)
	tile := refusedTile.FindStringSubmatch(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String())
	lede := logsLede.FindStringSubmatch(do(s, "GET", "/logs?verdict=refused", "127.0.0.1:8484", c).Body.String())
	if tile == nil || lede == nil || tile[1] != lede[2] {
		t.Fatalf("Overview tile %q, Logs %q: they differ", tile, lede)
	}
}

// TestLostRunAskIsNotWaiting: an ask of a run that crashed (no run_end, not live) is not waiting: no banner, no
// count, not on Approvals as a card, and status.json counts none; Approvals lists it as never answered.
func TestLostRunAskIsNotWaiting(t *testing.T) {
	root := fixture(t)
	if err := os.Remove(filepath.Join(root, ".live", harmRun)); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	if b := do(s, "GET", "/status.json", "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, `"pending":0`) {
		t.Errorf("status.json counts a lost run's ask: %s", b)
	}
	for _, p := range []string{"/", "/runs/" + harmRun} {
		b := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
		if strings.Contains(b, `id="ask-banner"`) || strings.Contains(b, "<title>(1)") || strings.Contains(b, `name="ask" value="ask-7"`) {
			t.Errorf("%s offers to answer a lost run's ask", p)
		}
	}
	if b := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, "nobody answered") {
		t.Error("the lost run's page does not say its ask was never answered")
	}
	w := do(s, "GET", "/approvals", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `value="approve"`) {
		t.Errorf("Approvals offers to answer a lost run's ask: %d", w.Code)
	}
}
