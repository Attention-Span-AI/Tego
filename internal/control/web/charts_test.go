// SPDX-License-Identifier: Apache-2.0

package web

import (
	"flag"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

var updateCharts = flag.Bool("update-charts", false, "rewrite testdata/charts/*.svg")

// render writes c with the "chart" template, as a page does.
func render(t *testing.T, c *svgChart) string {
	t.Helper()
	tm, err := template.New("t").Funcs(funcs).ParseFS(assets, "templates/charts.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := tm.ExecuteTemplate(&b, "chart", c); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// golden compares got with testdata/charts/<name>.svg, rewriting it under -update-charts.
func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "charts", name+".svg")
	if *updateCharts {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got+"\n"), 0o644); err != nil { //nolint:gosec // a test golden
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p) //nolint:gosec // a fixed test path
	if err != nil {
		t.Fatalf("%v (run with -update-charts)", err)
	}
	if strings.TrimSuffix(string(want), "\n") != got {
		t.Errorf("%s differs from %s:\n%s", name, p, got)
	}
}

// checkSVG holds what every chart must have: its words as screen-reader text, an svg hidden from the accessibility
// tree (a11y_test's rule), a title and a desc.
func checkSVG(t *testing.T, s string) {
	t.Helper()
	for _, part := range []string{`<span class="sr">`, "<svg ", `aria-hidden="true"`, "<title>", "<desc>", "</svg>"} {
		if !strings.Contains(s, part) {
			t.Errorf("chart lacks %q: %s", part, s)
		}
	}
}

func TestChartsGolden(t *testing.T) {
	segs := []chartSeg{{"Secret reads", 4, "ch-k1"}, {"Network sends", 2, "ch-k2"}, {"Programs", 0, "ch-k3"}, {"Other files", 1, "ch-k4"}}
	cases := []struct {
		name string
		svg  string
	}{
		{"spark", render(t, sparkline([]int{0, 3, 1, 5, 2}, "Refusals in each of the last 5 runs"))},
		{"spark-empty", render(t, sparkline(nil, "Refusals"))},
		{"spark-one", render(t, sparkline([]int{4}, "Refusals"))},
		{"spark-zero", render(t, sparkline([]int{0, 0, 0}, "Refusals"))},
		{"stack", render(t, stackBar(segs, "Refusals by kind"))},
		{"stack-empty", render(t, stackBar([]chartSeg{{"Protected", 0, "ch-refused"}}, "Secrets"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkSVG(t, c.svg)
			golden(t, c.name, c.svg)
		})
	}
}

// renderSpark writes c with the "spark" template, as the Overview's tile and Secrets panel do.
func renderSpark(t *testing.T, c *svgChart) string {
	t.Helper()
	tm, err := template.New("t").Funcs(funcs).ParseFS(assets, "templates/charts.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := tm.ExecuteTemplate(&b, "spark", c); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestSparkEnds holds the sparkline's reading aids: the line has no axis, so its oldest and newest values are written
// at its ends and the newest point is dotted; with fewer than two runs there is no line at all, only words, because a
// flat line through one point would read as a trend.
func TestSparkEnds(t *testing.T) {
	s := renderSpark(t, sparkline([]int{4, 0, 9, 29}, "Refusals in each of the last 4 runs"))
	checkSVG(t, s)
	for _, want := range []string{`<span class="ch-sv" aria-hidden="true">4</span>`, `<span class="ch-sv ch-sv-last" aria-hidden="true">29</span>`,
		`<line class="ch-dot" x1="120.0" y1="3.0" x2="120.0" y2="3.0"`, "Oldest to newest: 4, 0, 9, 29."} {
		if !strings.Contains(s, want) {
			t.Errorf("sparkline lacks %q: %s", want, s)
		}
	}
	golden(t, "spark-row", s)
	for _, tc := range []struct {
		vals []int
		note string
	}{{nil, "No runs yet"}, {[]int{7}, "Trend after 2 runs"}} {
		c := sparkline(tc.vals, "Refusals")
		s := renderSpark(t, c)
		if c.Line != "" || strings.Contains(s, "<svg") || !strings.Contains(s, tc.note) {
			t.Errorf("%d values: want only %q, got %s", len(tc.vals), tc.note, s)
		}
	}
	if renderSpark(t, nil) != "" {
		t.Error("a nil sparkline writes something")
	}
}

// TestStackBarThinPart holds that a part too thin to see is widened to a visible mark while the bar still fits its
// width, and the hover keeps its real count.
func TestStackBarThinPart(t *testing.T) {
	c := stackBar([]chartSeg{{"Secret reads", 558, "ch-k1"}, {"Network sends", 8, "ch-k2"}, {"Programs", 800, "ch-k3"}, {"Asks denied", 1, "ch-k5"}}, "x")
	if len(c.Parts) != 4 {
		t.Fatalf("got %d parts, want 4", len(c.Parts))
	}
	end := 0.0
	for _, p := range c.Parts {
		x, _ := strconv.ParseFloat(p.X, 64)
		w, _ := strconv.ParseFloat(p.W, 64)
		if w < 9.9 {
			t.Errorf("%s is %.1f wide, want at least 10 of 1000", p.Title, w)
		}
		end = x + w
	}
	if end > 1000.05 {
		t.Errorf("the bar ends at %.1f, past its 1000 width", end)
	}
	if c.Parts[1].Title != "Network sends: 8" || c.Parts[3].Title != "Asks denied: 1" {
		t.Errorf("thin parts lost their counts: %q %q", c.Parts[1].Title, c.Parts[3].Title)
	}
}

func TestStackBarParts(t *testing.T) {
	s := render(t, stackBar([]chartSeg{{"A", 3, "ch-k1"}, {"B", 0, "ch-k2"}, {"C", 1, "ch-k3"}}, "x"))
	if strings.Contains(s, "ch-k2") {
		t.Errorf("a part with no count is drawn: %s", s)
	}
	if !strings.Contains(s, "<title>A: 3</title>") || !strings.Contains(s, "<title>C: 1</title>") {
		t.Errorf("parts lack their hover titles: %s", s)
	}
	if !strings.Contains(s, "A 3, C 1 (4 in all).") {
		t.Errorf("desc does not add up: %s", s)
	}
}

func TestChartsEscape(t *testing.T) {
	evil := `</title><script>alert(1)</script>"&`
	for name, s := range map[string]string{
		"spark": render(t, sparkline([]int{1, 2}, evil)),
		"stack": render(t, stackBar([]chartSeg{{evil, 1, `x" onload="y`}}, evil)),
	} {
		if strings.Contains(s, "<script>") || strings.Contains(s, `" onload="`) || strings.Count(s, "</title>") != strings.Count(s, "<title>") {
			t.Errorf("%s: text not escaped: %s", name, s)
		}
	}
}

func TestOverviewCharts(t *testing.T) {
	runs := []*ledgerview.Run{
		{ID: "b", Refusals: 2, Events: []ledgerview.Event{
			{Seq: 1, Kind: "fs", Verdict: "refused", Op: "read", Target: "/home/u/.env"},
			{Seq: 2, Kind: "net", Verdict: "refused", Op: "connect", Target: "10.0.0.9:443"},
		}},
		{ID: "a", Refusals: 1, Events: []ledgerview.Event{{Seq: 1, Kind: "exec", Verdict: "refused", Op: "exec", Target: "curl"}}},
	}
	v := map[string]ledgerview.Verdict{"a": {Exposed: []string{"/x"}}, "b": {Kept: []string{"/home/u/.env"}}}
	c := overviewCharts(runs, v)
	if c.Protected != 1 || c.Exposed != 1 || c.SparkRuns != 2 {
		t.Errorf("protected %d exposed %d runs %d, want 1 1 2", c.Protected, c.Exposed, c.SparkRuns)
	}
	if !strings.Contains(render(t, c.RefSpark), "Oldest to newest: 1, 2.") {
		t.Errorf("sparkline not oldest first: %s", c.RefSpark)
	}
}
