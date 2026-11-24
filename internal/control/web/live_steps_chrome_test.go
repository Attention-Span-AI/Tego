// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// A live run's timeline groups its rows under model-step headers (ledgerview.GroupSteps, drawn again on the page by
// run.js's regroup pass after live.js has put the new rows on top). This test appends lines to a live run in a real
// browser, with no reload, and reads the whole timeline after each one: the rows newest first, each group under one
// header, a line the record ties to no step closing the group around it, and a reader who scrolled down keeps the row
// they were looking at where it was.
//
//	go test -tags chrome -run TestLiveStepGroupsInChrome ./internal/control/web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// liveStepsGroup is one group of the timeline as the page draws it: a header and the rows under it, newest first.
type liveStepsGroup struct {
	head string
	ids  []string
}

// liveStepsText is the timeline as one line: "[header] l9 l8 [header] l7 ...".
func liveStepsText(gs []liveStepsGroup) string {
	var parts []string
	for _, g := range gs {
		parts = append(parts, "["+g.head+"]", strings.Join(g.ids, " "))
	}
	return strings.Join(parts, " ")
}

// liveStepsTimeline is the JavaScript that reads the timeline the way liveStepsText writes it, from the first child of
// #tl-rows to the last (headers and rows only: a rule change or an empty note is not one of them).
const liveStepsTimeline = `Array.prototype.filter.call(document.getElementById("tl-rows").children, function (e) {
	return e.classList.contains("tl") || e.classList.contains("tl-step");
}).map(function (e) { return e.classList.contains("tl-step") ? "[" + e.querySelector(".tl-step-w").textContent + "]" : e.id; }).join(" ")`

func TestLiveStepGroupsInChrome(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaaaaaa-0000000000701-livestp"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	// The run so far: twelve model steps of three lines each (lines 1 to 36), each line tied to its step by the tool id.
	stepLine := func(seq, step int) string {
		return line(run, "stepper", seq, t0.Add(time.Duration(seq)*time.Second), "fs",
			fmt.Sprintf(`"rule":"unmatched","verdict":"allow","authority":"rule","op":"open","path":"/work/f%d.txt","attribution":{"confidence":"likely","method":"tool_id","step":%d,"tool_use_id":"toolu_%d"}`, seq, step, step))
	}
	// A line the record ties to no step: no attribution at all.
	untied := func(seq int) string {
		return line(run, "stepper", seq, t0.Add(time.Duration(seq)*time.Second), "fs",
			fmt.Sprintf(`"rule":"unmatched","verdict":"allow","authority":"rule","op":"open","path":"/work/g%d.txt"`, seq))
	}
	ledgerRun(t, root, run, "stepper", t0, "", time.Time{}, func(add func(time.Time, string, string)) {
		for seq := 1; seq <= 36; seq++ {
			step := (seq + 2) / 3
			add(t0.Add(time.Duration(seq)*time.Second), "fs",
				fmt.Sprintf(`"rule":"unmatched","verdict":"allow","authority":"rule","op":"open","path":"/work/f%d.txt","attribution":{"confidence":"likely","method":"tool_id","step":%d,"tool_use_id":"toolu_%d"}`, seq, step, step))
		}
	})
	markLive(t, root, run)
	srv, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	srv.cfg.Now = func() time.Time { return time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC) }

	stepHead := func(n int) string { return fmt.Sprintf("Model step %d (likely)", n) }
	const notTied = "Not tied to a model step"
	// groups is what the page must show above the old rows, then the old rows themselves, as ledgerview.GroupSteps groups
	// them: the lines of steps 12, 11, ... down to the one whose rows still fit in the bound the test reads.
	old := func(fromStep int) []liveStepsGroup {
		var gs []liveStepsGroup
		for step := fromStep; step >= 1; step-- {
			g := liveStepsGroup{head: stepHead(step)}
			for seq := 3 * step; seq > 3*step-3; seq-- {
				g.ids = append(g.ids, fmt.Sprintf("l%d", seq))
			}
			gs = append(gs, g)
		}
		return append(gs, liveStepsGroup{head: notTied, ids: []string{"l0"}})
	}
	want := old(12)

	c := placeChrome(t)
	tb := c.open(t, "run page", "about:blank")
	c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1280, "height": 600, "deviceScaleFactor": 1, "mobile": false})
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + run + "?t=tok123"})
	tb.until(t, "loaded", `document.readyState === "complete" && !!document.body.dataset.sig && !!document.querySelector("#tl-rows[data-rows]")`)
	tb.eval(t, `window.__tegoMark = "kept"`)
	for deadline := time.Now().Add(10 * time.Second); srv.streams.Load() < 1; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no /events stream open: the page does not follow the run")
		}
	}

	read := func() string {
		t.Helper()
		var s string
		if err := json.Unmarshal([]byte(tb.eval(t, liveStepsTimeline)), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if got := read(); got != liveStepsText(want) {
		t.Fatalf("the timeline as first drawn reads\n%s\nwant\n%s", got, liveStepsText(want))
	}

	// check waits for the page to show want, reads the whole timeline and fails on any difference, then checks that the
	// page was never reloaded and that no two headers stand side by side (a header over no row).
	check := func(what string, gs []liveStepsGroup) {
		t.Helper()
		text := liveStepsText(gs)
		tb.until(t, what, `(`+liveStepsTimeline+`) === `+jsString(text))
		if got := read(); got != text {
			t.Errorf("%s: the timeline reads\n%s\nwant\n%s", what, got, text)
		}
		if tb.eval(t, `window.__tegoMark`) != `"kept"` {
			t.Fatalf("%s: the page reloaded", what)
		}
		if n := tb.eval(t, `document.querySelectorAll("#tl-rows > .tl-step + .tl-step").length`); n != "0" {
			t.Errorf("%s: %s headers stand with no row between them", what, n)
		}
		if n := tb.eval(t, `document.querySelectorAll("#tl-rows > .tl-step").length`); n != fmt.Sprint(len(gs)) {
			t.Errorf("%s: %s headers, want one for each of the %d groups", what, n, len(gs))
		}
	}
	// place scrolls the window so the element (a selector) sits at the top of the view and returns where it is; held
	// then reads it again: the reader's place is the same row (or header) at the same height, when rows came above it.
	place := func(sel string) float64 {
		t.Helper()
		tb.eval(t, `(function () { var e = document.querySelector(`+jsString(sel)+`); window.scrollTo(0, e.getBoundingClientRect().top + window.scrollY - 40); })()`)
		tb.until(t, "the scroll", `Math.abs(document.querySelector(`+jsString(sel)+`).getBoundingClientRect().top - 40) <= 1 && window.scrollY > 100`)
		var top float64
		if err := json.Unmarshal([]byte(tb.eval(t, `document.querySelector(`+jsString(sel)+`).getBoundingClientRect().top`)), &top); err != nil {
			t.Fatal(err)
		}
		return top
	}
	held := func(what, sel string, was float64) {
		t.Helper()
		// A frame after the merge: the browser's own scroll adjustment for the rows above is made at layout.
		tb.eval(t, `new Promise(function (r) { requestAnimationFrame(function () { requestAnimationFrame(r); }); })`)
		var top float64
		if err := json.Unmarshal([]byte(tb.eval(t, `document.querySelector(`+jsString(sel)+`).getBoundingClientRect().top`)), &top); err != nil {
			t.Fatal(err)
		}
		if d := top - was; d < -2 || d > 2 {
			t.Errorf("%s: the reader's place moved: %s was %.0f px from the top of the window, now %.0f", what, sel, was, top)
		}
	}
	next := 36
	add := func(l string) { next++; appendLine(t, root, run, l) }

	// 1. A line of a new step (13) arrives: a header of its own over it, and step 12's header still over step 12's lines.
	add(stepLine(next+1, 13))
	want = append([]liveStepsGroup{{head: stepHead(13), ids: []string{"l37"}}}, want...)
	check("a line of a new step", want)

	// 2. Another line of that step: it joins the group, with no second header.
	add(stepLine(next+1, 13))
	want[0].ids = append([]string{"l38"}, want[0].ids...)
	check("a line of the same step", want)

	// 3. A line tied to no step, with the reader scrolled down to a header: the line has the "not tied" header, the step's
	// group below keeps its own, and the header the reader was looking at does not move.
	sel := `#tl-rows > .tl-step[data-sk="8/tool_id"]`
	was := place(sel)
	add(untied(next + 1))
	want = append([]liveStepsGroup{{head: notTied, ids: []string{"l39"}}}, want...)
	check("a line tied to no step", want)
	held("a line tied to no step", sel, was)

	// 4. Lines of step 13 again, after that line: the untied line closed step 13's group, so a second group of step 13
	// has its own header; the reader, now at a row in the middle of a group, stays on it.
	sel = `#l20`
	was = place(sel)
	add(stepLine(next+1, 13))
	want = append([]liveStepsGroup{{head: stepHead(13), ids: []string{"l40"}}}, want...)
	check("a line of step 13 after the untied one", want)
	held("a line of step 13 after the untied one", sel, was)

	// 5. Another line of that group, still scrolled down: one row more, no header more.
	was = place(sel)
	add(stepLine(next+1, 13))
	want[0].ids = append([]string{"l41"}, want[0].ids...)
	check("a second line of the new group", want)
	held("a second line of the new group", sel, was)

	// 6. Back at the top, two lines tied to no step in a row (one header over both), then a line of step 14.
	tb.eval(t, `window.scrollTo(0, 0)`)
	add(untied(next + 1))
	add(untied(next + 1))
	add(stepLine(next+1, 14))
	want = append([]liveStepsGroup{{head: stepHead(14), ids: []string{"l44"}}, {head: notTied, ids: []string{"l43", "l42"}}}, want...)
	check("two untied lines and a line of a new step, back to back", want)
}
