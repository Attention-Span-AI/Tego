// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mergeCostLedger is a root with n ended runs of a few lines each and the fixture's live run, so the Overview and Runs
// pages hold as many rows as a long-used machine's.
func mergeCostLedger(t *testing.T, n int) string {
	t.Helper()
	root := fixture(t)
	t0 := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	for i := range n {
		id := fmt.Sprintf("r-mc%02d-%04d-merged", i%100, i)
		at := t0.Add(time.Duration(i) * time.Minute)
		ls := []string{line(id, "agent-"+strconv.Itoa(i%7), 0, at, "run_start", `"tier":"landlock","command":["sh","agent.sh"]`)}
		for k := 1; k <= 6; k++ {
			ls = append(ls, line(id, "agent-"+strconv.Itoa(i%7), k, at.Add(time.Duration(k)*time.Second), "fs",
				fmt.Sprintf(`"verdict":"allow","op":"open","path":"/p/f%d.txt","flags":0`, k)))
		}
		if i%5 == 0 {
			ls = append(ls, line(id, "agent-"+strconv.Itoa(i%7), 7, at.Add(7*time.Second), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`))
		}
		ls = append(ls, line(id, "agent-"+strconv.Itoa(i%7), 8, at.Add(8*time.Second), "run_end", `"reason":"exit","exit_code":0`))
		if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// mergeCounters is Chrome's own time totals (Performance.getMetrics), in seconds: script, layout and style
// recalculation.
func mergeCounters(t *testing.T, tb *tab) (script, layout, style float64) {
	t.Helper()
	var r struct {
		Metrics []struct {
			Name  string
			Value float64
		}
	}
	if err := json.Unmarshal(tb.c.call(t, tb.session, "Performance.getMetrics", map[string]any{}), &r); err != nil {
		t.Fatal(err)
	}
	for _, m := range r.Metrics {
		switch m.Name {
		case "ScriptDuration":
			script = m.Value
		case "LayoutDuration":
			layout = m.Value
		case "RecalcStyleDuration":
			style = m.Value
		}
	}
	return script, layout, style
}

// TestMergeCostInChrome measures what a live update costs the browser (GAPS C80): on the Overview, the Runs page and a
// running run's page, over a ledger of TEGO_MERGE_RUNS ended runs (default 300) and the live run, a line is appended
// to the live run every 1.2 s, and each page's script, layout and style time (Chrome's own counters) is divided by the
// number of times live.js merged a fresh answer into it (the tego:merged event). Every page's figures are logged
// (go test -v); the test fails when a page took no merge, scrolls sideways, or the median merge costs more than
// TEGO_MERGE_MAX_MS (default 1000: a pathology, not a budget; set it lower on a quiet box to hold a number).
func TestMergeCostInChrome(t *testing.T) {
	runs, limit := 300, 1000.0
	if v, err := strconv.Atoi(os.Getenv("TEGO_MERGE_RUNS")); err == nil && v > 0 {
		runs = v
	}
	if v, err := strconv.ParseFloat(os.Getenv("TEGO_MERGE_MAX_MS"), 64); err == nil {
		limit = v
	}
	root := mergeCostLedger(t, runs)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := b11Browser(t)
	pages := []struct{ name, path string }{{"overview", "/"}, {"runs", "/runs"}, {"run", "/runs/" + harmRun}}
	seq := 100
	for _, p := range pages {
		tb := c.open(t, "merge", "about:blank")
		c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target}) // a background tab's timers are held back
		c.call(t, tb.session, "Performance.enable", map[string]any{})
		c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": false})
		c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + p.path + "?t=tok123"})
		tb.until(t, "signed in", `document.readyState === "complete" && !location.search && !!document.body.dataset.sig`)
		time.Sleep(2 * time.Second) // the stream's first state and the clocks' first refresh settle before the count starts
		tb.eval(t, `window.__merges = 0; document.addEventListener('tego:merged', () => { window.__merges++ }); true`)
		s0, l0, y0 := mergeCounters(t, tb)
		m0, _ := strconv.Atoi(tb.eval(t, `window.__merges`))
		var each []float64
		prev := [3]float64{s0, l0, y0}
		prevM := m0
		for range 6 {
			appendLine(t, root, harmRun, line(harmRun, "demo-harm", seq, time.Now(), "fs", fmt.Sprintf(`"verdict":"allow","op":"open","path":"/p/live%d.txt","flags":0`, seq)))
			seq++
			time.Sleep(1200 * time.Millisecond)
			s, l, y := mergeCounters(t, tb)
			m, _ := strconv.Atoi(tb.eval(t, `window.__merges`))
			if m > prevM {
				each = append(each, 1000*((s-prev[0])+(l-prev[1])+(y-prev[2]))/float64(m-prevM))
			}
			prev, prevM = [3]float64{s, l, y}, m
		}
		s1, l1, y1 := mergeCounters(t, tb)
		merges := prevM - m0
		rows := tb.eval(t, `document.querySelectorAll('tr').length`)
		wide := tb.eval(t, `document.documentElement.scrollWidth > document.documentElement.clientWidth`)
		if merges < 1 {
			t.Errorf("%s: the page took no merge in 7 s of appended lines (conn %s, regions %s)", p.name,
				tb.eval(t, `document.body.getAttribute('data-conn')`), tb.eval(t, `document.querySelectorAll('[data-live]').length`))
			c.closeTarget(t, tb.target)
			continue
		}
		sort.Float64s(each)
		med := each[len(each)/2]
		t.Logf("%s (%s rows, %d runs): %d merges; per merge script %.1f ms, layout %.1f ms, style %.1f ms; median window %.1f ms of %v",
			p.name, rows, runs, merges, 1000*(s1-s0)/float64(merges), 1000*(l1-l0)/float64(merges), 1000*(y1-y0)/float64(merges), med, each)
		if wide == "true" {
			t.Errorf("%s scrolls sideways at 1440 px", p.name)
		}
		if med > limit {
			t.Errorf("%s: the median merge costs %.1f ms, over %.0f ms", p.name, med, limit)
		}
		c.closeTarget(t, tb.target)
	}
}
