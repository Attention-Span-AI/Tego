// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// Detections in a real browser: a reviewed mark is kept through a filter click, the view changes in place with the
// chip where it stood, and a refused line the run writes reaches the open page with no reload and keeps its mark. At a
// phone's width a bare number keeps its column's name, and on a wide screen Logs shows a row's severity and its verdict
// whole.
// Run it by hand, through the box's memory slice:
//
//	go test -tags chrome -run 'TestDetectionsInChrome|TestSeverityNamesStayInChrome' ./internal/control/web

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestDetectionsInChrome(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000010-chrome"
	connect := func(target string) [2]string {
		return [2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"` + target + `"`}
	}
	root := detectionsRoot(t, run, "landlock", connect("203.0.113.9:443"), connect("198.51.100.7:443"),
		[2]string{"refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/grep"`})
	c := placeChrome(t)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	tb := c.open(t, "detections", "http://"+addr+"/detections?t=tok123")
	tb.until(t, "loaded", `document.readyState === "complete" && document.querySelectorAll("tr.dt-row").length === 3`)
	tb.eval(t, `(function () { var m = {}; m[document.querySelector('tr[data-sev="High"]').getAttribute("data-review-key")] = 1; localStorage.setItem("tego.reviewed", JSON.stringify(m)); })()`)
	tb.eval(t, `location.reload()`)
	tb.until(t, "reloaded with its mark", `document.readyState === "complete" && document.querySelectorAll("tr.is-reviewed").length === 1`)
	tb.eval(t, `window.__tegoMark = "kept"`)
	kept := func(when string) {
		t.Helper()
		if tb.eval(t, `window.__tegoMark`) != `"kept"` {
			t.Fatalf("the page loaded anew %s", when)
		}
	}
	chip := `document.querySelector('.dt-filter a[href="/detections?sev=high"]')`
	top := pxOf(t, tb, chip+`.getBoundingClientRect().top`)
	tb.eval(t, chip+`.click()`)
	tb.until(t, "the High view", `location.search === "?sev=high" && document.querySelectorAll("tr.dt-row").length === 2`)
	kept("after a filter click")
	tb.until(t, "the mark after the filter click", `document.querySelectorAll("tr.is-reviewed").length === 1`)
	tb.until(t, "the count after the filter click", `document.getElementById("dt-progress").textContent === "1 of 2 High reviewed"`)
	near(t, tb, "the chip's place", chip+`.getBoundingClientRect().top`, top)

	ev, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Date(2026, 11, 1, 11, 0, 0, 0, time.UTC)
	if _, err := fmt.Fprint(ev, line(run, "agent", 9, later, "refused", connect("192.0.2.5:443")[1])); err != nil {
		t.Fatal(err)
	}
	if err := ev.Close(); err != nil {
		t.Fatal(err)
	}
	tb.until(t, "the new block on the open page", `document.querySelectorAll("tr.dt-row").length === 3`)
	kept("after a new line")
	tb.until(t, "the mark after a live update", `document.querySelectorAll("tr.is-reviewed").length === 1`)
	tb.until(t, "the count after a live update", `document.getElementById("dt-progress").textContent === "1 of `+strconv.Itoa(3)+` High reviewed"`)
}

func TestSeverityNamesStayInChrome(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000012-chrome"
	root := detectionsRoot(t, run, "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`},
		[2]string{"refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/grep"`})
	c := placeChrome(t)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	viewport := func(tb *tab, width, height int, mobile bool) {
		t.Helper()
		c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": height, "deviceScaleFactor": 1, "mobile": mobile})
	}
	label := func(tb *tab, cell string) string {
		t.Helper()
		return tb.eval(t, `getComputedStyle(document.querySelector('`+cell+`'), "::before").content`)
	}

	tb := c.open(t, "names", "http://"+addr+"/logs?verdict=refused&t=tok123")
	viewport(tb, 1440, 900, false)
	tb.until(t, "the rows with their severities", `document.readyState === "complete" && document.querySelectorAll("td.c-verdict .sev").length === 2`)
	if v := tb.eval(t, `[...document.querySelectorAll("td.c-verdict")].filter(function (c) { return c.querySelector(".sev") && c.scrollWidth > c.clientWidth }).map(function (c) { return c.innerText })`); v != "[]" {
		t.Errorf("Logs clips a verdict: %s", v)
	}

	viewport(tb, 390, 844, true)
	tb.eval(t, `location.href = "/"`)
	tb.until(t, "the Overview's grid", `document.readyState === "complete" && document.querySelector("table.sev-grid td") !== null`)
	for i, want := range []string{"Files", "Programs", "Network", "All"} {
		if got := label(tb, `table.sev-grid tbody tr td:nth-of-type(`+strconv.Itoa(i+1)+`)`); got != strconv.Quote(strconv.Quote(want)) {
			t.Errorf("the grid's cell %d on a phone is named %s, want %s", i+1, got, want)
		}
	}
	tb.eval(t, `location.href = "/detections"`)
	tb.until(t, "the Detections rows", `document.readyState === "complete" && document.querySelector("tr.dt-row") !== null`)
	for _, cell := range []struct{ sel, want string }{{"td.num", "Times"}, {"td.num + td", "Last"}} {
		if got := label(tb, `tr.dt-row `+cell.sel); got != strconv.Quote(strconv.Quote(cell.want)) {
			t.Errorf("%s on a phone is named %s, want %s", cell.sel, got, cell.want)
		}
	}
}
