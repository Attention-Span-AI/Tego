// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chartEscRun is the run whose agent named files with U+202E and HTML in them.
const chartEscRun = "r-aaaaaaaa-0000000000004-chartx"

// chartEscHTML is an agent-written piece of HTML in a target: it must reach a page escaped, never as markup.
const chartEscHTML = `<img src=x onerror=alert(1)>&"'`

// svgsOf is every <svg …>…</svg> of class cls in page, in order.
func svgsOf(page, cls string) []string {
	var out []string
	for rest := page; ; {
		i := strings.Index(rest, `<svg class="`+cls+`"`)
		if i < 0 {
			return out
		}
		rest = rest[i:]
		j := strings.Index(rest, "</svg>")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j+len("</svg>")])
		rest = rest[j:]
	}
}

// TestChartsEscapeAgentTargets: a target the agent wrote with U+202E and HTML in it shows on the run page only as
// ⟦U+202E⟧ and escaped text, never as the raw character or as markup, and the Overview's charts carry neither.
func TestChartsEscapeAgentTargets(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 4, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	html := strings.ReplaceAll(strings.ReplaceAll(chartEscHTML, `\`, `\\`), `"`, `\"`)
	ls := []string{
		line(chartEscRun, "esc-agent", 0, at(0), "run_start", `"tier":"landlock","cwd":"/p/proj","command":["sh"]`),
		line(chartEscRun, "esc-agent", 1, at(1), "refused", `"rule":"unmatched","reason":"read-denied","op":"open","target":"/p/proj/secret/c`+rlo+`fdp.exe"`),
		line(chartEscRun, "esc-agent", 2, at(2), "refused", `"rule":"unmatched","reason":"read-denied","op":"open","target":"/p/proj/`+html+`.txt"`),
		line(chartEscRun, "esc-agent", 3, at(3), "run_end", `"reason":"exit","exit_code":0`),
	}
	if err := os.MkdirAll(filepath.Join(root, chartEscRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, chartEscRun, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)

	w := do(s, "GET", "/runs/"+chartEscRun, "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("run page: %d", w.Code)
	}
	if b := w.Body.String(); strings.Contains(b, "<img src=x") {
		t.Errorf("the run page writes the agent's HTML as markup")
	}
	noRawHidden(t, "run page", w.Body.Bytes())

	w = do(s, "GET", "/", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("overview: %d", w.Code)
	}
	body := w.Body.String()
	var charts []string
	for _, cls := range []string{"ch-spark", "ch-stack", "ch-meter"} {
		charts = append(charts, svgsOf(body, cls)...)
	}
	if len(charts) == 0 {
		t.Fatalf("the Overview draws no chart")
	}
	for _, ch := range charts {
		if strings.Contains(ch, rlo) || strings.Contains(ch, "<img") || strings.Contains(ch, "fdp.exe") {
			t.Errorf("an Overview chart carries the agent's target: %s", ch)
		}
	}
	if strings.Contains(body, "<img src=x") {
		t.Errorf("the Overview writes the agent's HTML as markup")
	}
	noRawHidden(t, "overview", w.Body.Bytes())
}
