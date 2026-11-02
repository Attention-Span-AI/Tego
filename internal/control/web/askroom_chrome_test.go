// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The floating ask banner and the Overview's lists in a real browser, both measured on the screen. Run it by hand,
// through the box's memory slice:
//
//	go test -tags chrome -run 'TestAskBannerRoomInChrome|TestOverviewRowHoldsInChrome' ./internal/control/web

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// settle runs expr (a number) until it stops changing: the banner's room comes with the merge, after the region does.
func settle(t *testing.T, tb *tab, expr string) int {
	t.Helper()
	last, n := -1<<30, 0
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		v, err := strconv.Atoi(tb.eval(t, "Math.round("+expr+")"))
		if err != nil {
			t.Fatal(err)
		}
		if v == last {
			if n++; n >= 3 {
				return v
			}
		} else {
			last, n = v, 0
		}
	}
	return last
}

// TestAskBannerRoomInChrome: an ask that arrives moves nothing on the screen, what the banner lies over can be scrolled
// into view, the answer moves nothing back, and a page loaded with the banner up shows its heading below it when
// scrolled to the top.
func TestAskBannerRoomInChrome(t *testing.T) {
	root := fixture(t)
	now := time.Now()
	// The fixture's ask is answered, so the Overview opens with no banner.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":true,"by":"uid:1000 pid:9"`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	base := "http://" + addr
	ov := c.open(t, "overview", base+"/?t=tok123")
	ov.c.call(t, ov.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": false})
	ov.until(t, "loaded", `document.readyState === "complete" && !!window.tegoLive && !!window.tegoLive.steady`)
	const h1 = `document.querySelector("main h1").getBoundingClientRect().top`
	before := settle(t, ov, h1)

	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now, "ask", `"ask_id":"ask-8","hold":"fs","op":"write","target":"/p/held.txt"`))
	ov.until(t, "the banner", `!!document.getElementById("ask-banner") && (window.tegoRoom || 0) > 0`)
	near(t, ov, "the heading when the ask came", h1, before)
	if ov.eval(t, `document.querySelector("main h1").getBoundingClientRect().top < document.getElementById("ask-banner").getBoundingClientRect().bottom`) != "true" {
		t.Error("the heading is not under the banner, so this test measures nothing")
	}
	if got, _ := strconv.Atoi(ov.eval(t, `document.querySelector("[data-live=r-ov-recent]") ? window.scrollY : 0`)); got <= 0 {
		t.Errorf("the page did not scroll by the room: %d", got)
	}
	ov.eval(t, `window.scrollTo(0, 0); ""`)
	if ov.eval(t, `document.querySelector("main h1").getBoundingClientRect().top >= document.getElementById("ask-banner").getBoundingClientRect().bottom`) != "true" {
		t.Error("scrolled to the top, the heading is still under the banner")
	}
	// Back to where the ask found the page, and the answer moves nothing.
	ov.eval(t, `window.scrollTo(0, window.tegoRoom); ""`)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now, "answer", `"ask_id":"ask-8","approved":false,"by":"uid:1000 pid:9"`))
	ov.until(t, "the banner gone", `!document.getElementById("ask-banner") && !window.tegoRoom`)
	near(t, ov, "the heading after the answer", h1, before)

	// A page loaded with an ask waiting.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 10, now, "ask", `"ask_id":"ask-9","hold":"fs","op":"write","target":"/p/held2.txt"`))
	ov.until(t, "the banner again", `!!document.getElementById("ask-banner") && (window.tegoRoom || 0) > 0`)
	ov.eval(t, `location.reload(); ""`)
	time.Sleep(300 * time.Millisecond)
	ov.until(t, "reloaded", `document.readyState === "complete" && !!window.tegoLive && !!window.tegoLive.steady && (window.tegoRoom || 0) > 0`)
	ov.eval(t, `window.scrollTo(0, 0); ""`)
	if ov.eval(t, `document.querySelector("main h1").getBoundingClientRect().top >= document.getElementById("ask-banner").getBoundingClientRect().bottom`) != "true" {
		t.Error("loaded with an ask, the heading is under the banner")
	}
}

// mainShifts is the sum of the layout shifts the page has recorded that moved something in <main>, those a person's
// input explains left out. The top bar's own settling (the theme select, the Live pill) is not the page's content.
func mainShifts(t *testing.T, tb *tab) string {
	t.Helper()
	tb.eval(t, `window.shiftSeen = 0; new PerformanceObserver(function (l) { l.getEntries().forEach(function (e) { if (!e.hadRecentInput && e.sources.some(function (s) { return s.node && s.node.closest && s.node.closest("main"); })) window.shiftSeen += e.value; }); }).observe({ type: "layout-shift", buffered: true }); ""`)
	time.Sleep(500 * time.Millisecond)
	return strings.Trim(tb.eval(t, `String(window.shiftSeen)`), `"`)
}

// TestAskBannerOpenedWithAskInChrome: a page opened while an ask waits, the default for anyone who loads one, keeps the
// same promise. Its first paint does not drop, the answer moves nothing, a reader looking at the room when the answer
// comes is left where they are until they scroll past it, and a reload does not add the room again.
func TestAskBannerOpenedWithAskInChrome(t *testing.T) {
	root := manyRunsFixture(t) // the fixture's ask-7 waits
	now := time.Now()
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	base := "http://" + addr
	ov := c.open(t, "overview", base+"/?t=tok123")
	ov.c.call(t, ov.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": false})
	ov.until(t, "signed in", `document.readyState === "complete" && !!window.tegoLive && !!window.tegoLive.steady`)
	load := func(what, path string) {
		t.Helper()
		ov.eval(t, `location.href = "`+path+`"; ""`)
		time.Sleep(300 * time.Millisecond)
		ov.until(t, what, `location.pathname === "`+path+`" && document.readyState === "complete" && !!window.tegoLive && !!window.tegoLive.steady && (window.tegoRoom || 0) > 0`)
	}
	reload := func(what string) {
		t.Helper()
		ov.eval(t, `location.reload(); ""`)
		time.Sleep(300 * time.Millisecond)
		ov.until(t, what, `document.readyState === "complete" && !!window.tegoLive && !!window.tegoLive.steady && (window.tegoRoom || 0) > 0`)
	}

	load("Runs with the banner", "/runs")
	if got := mainShifts(t, ov); got != "0" {
		t.Errorf("opening Runs with an ask waiting shifted the page by %s", got)
	}

	// A reload at the page's own place, in a view a chip pushed: the browser brings back a scroll that holds the room.
	ov.eval(t, `document.querySelector('nav.chips a.chip[href*="state=ended"]').click(); ""`)
	ov.until(t, "the Ended view", `location.search === "?state=ended"`)
	ov.eval(t, `window.scrollTo(0, 700); ""`)
	time.Sleep(400 * time.Millisecond) // the scroll's spot, kept 250 ms after it
	for i := range 2 {
		reload("Runs reloaded")
		if got := settle(t, ov, `window.scrollY`); got < 696 || got > 704 {
			t.Errorf("reload %d left the window at %d, want 700: the room was added to a scroll that held it", i+1, got)
		}
	}

	load("the Overview with the banner", "/")
	const h1 = `document.querySelector("main h1").getBoundingClientRect().top`
	before := settle(t, ov, h1)
	if got := pxOf(t, ov, `window.scrollY`); got != pxOf(t, ov, `window.tegoRoom`) {
		t.Errorf("the page opened at %d, not scrolled by its room", got)
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":true,"by":"uid:1000 pid:9"`))
	ov.until(t, "the banner gone", `!document.getElementById("ask-banner") && !window.tegoRoom`)
	near(t, ov, "the heading after the answer", h1, before)

	// The room is what the reader looks at when the answer comes: it stays, and it goes when the reader has passed it.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now, "ask", `"ask_id":"ask-8","hold":"fs","op":"write","target":"/p/held.txt"`))
	ov.until(t, "the banner again", `!!document.getElementById("ask-banner") && (window.tegoRoom || 0) > 0`)
	ov.eval(t, `window.scrollTo(0, 0); ""`)
	top := settle(t, ov, h1)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now, "answer", `"ask_id":"ask-8","approved":false,"by":"uid:1000 pid:9"`))
	ov.until(t, "the banner gone again", `!document.getElementById("ask-banner")`)
	time.Sleep(300 * time.Millisecond)
	near(t, ov, "the heading of a reader in the room", h1, top)
	ov.eval(t, `window.scrollTo(0, window.tegoRoom); ""`)
	ov.until(t, "the room gone", `!window.tegoRoom`)
	near(t, ov, "the heading when the room went", h1, before)
}

// TestOverviewRowHoldsInChrome: a new refusal does not move the row under the pointer, the list follows once the
// pointer leaves, and a pointer left resting does not keep it stale for good.
func TestOverviewRowHoldsInChrome(t *testing.T) {
	root := fixture(t)
	now := time.Now()
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/first.txt"`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	ov := c.open(t, "overview", "http://"+addr+"/?t=tok123")
	ov.c.call(t, ov.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": false})
	ov.until(t, "loaded", `document.readyState === "complete" && !!window.tegoLive && !!window.tegoLive.steady`)
	const list = `document.querySelector("[data-live=r-ov-refusals]")`
	ov.until(t, "the refusal listed", list+`.textContent.includes("/p/first.txt")`)
	var box struct{ X, Y float64 }
	b := ov.eval(t, `JSON.stringify((function () { var r = `+list+`.querySelector("li").getBoundingClientRect(); return { X: r.left + 40, Y: r.top + 8 }; })())`)
	s, err := strconv.Unquote(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(s), &box); err != nil {
		t.Fatal(err)
	}
	mouse := func(x, y float64) {
		c.call(t, ov.session, "Input.dispatchMouseEvent", map[string]any{"type": "mouseMoved", "x": x, "y": y})
	}
	mouse(box.X, box.Y)
	ov.until(t, "the pointer on the list", list+`.matches(":hover")`)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now.Add(time.Second), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/second.txt"`))
	time.Sleep(2500 * time.Millisecond) // the stream's change, and a merge a second later had it moved
	if strings.Contains(ov.eval(t, list+`.textContent`), "/p/second.txt") {
		t.Error("the list moved under the pointer")
	}
	mouse(5, 5)
	ov.until(t, "the list after the pointer left", list+`.textContent.includes("/p/second.txt")`)

	mouse(box.X, box.Y)
	ov.until(t, "the pointer back on the list", list+`.matches(":hover")`)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now.Add(2*time.Second), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/third.txt"`))
	ov.until(t, "the list with the pointer left resting", list+`.textContent.includes("/p/third.txt")`)
}
