// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The edges of keeping the reader's place (static/place.js), each found by a night review, in
// headless Chrome on its own profile: a reload and a Back from another page come back at their scroll from the first
// frames (no top-then-jump); Runs' Older runs gives the focus to the list it paged, in the window; a view fetch that
// stalls loads the page after STALL; a run's Older rows says the rows' range; Logs keeps its Filters panel open and the
// focus in the page when the last query chip's × or Clear filters goes with the view; text typed in the search while
// the view loads stays; MCP tools and Model routes (pages with no live regions) change their view in place, and an MCP
// switch's post comes back to where it was pressed. Run it by hand, through the box's memory slice:
//
//	go test -tags chrome -run TestKeepPlaceEdgesInChrome ./internal/control/web

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// edgeProbe runs before each page's own scripts: it records window.scrollY at each of the first 60 animation frames
// (__ys), and lets the test slow (__delay ms) or stall (__stall, a part of the address) the page's fetches that carry no
// header (place.js's view fetches; live.js's region fetches carry one).
const edgeProbe = `(function () {
	window.__ys = []; var n = 0;
	function f() { window.__ys.push(Math.round(window.scrollY)); if (++n < 60) requestAnimationFrame(f); }
	requestAnimationFrame(f);
	var F = window.fetch; window.__delay = 0; window.__stall = "";
	window.fetch = function (u, o) {
		var s = String(u), sg = o && o.signal;
		if (o && o.headers) return F(u, o);
		if (window.__stall && s.indexOf(window.__stall) >= 0) return new Promise(function (ok, no) { if (sg) sg.addEventListener("abort", function () { no(new DOMException("aborted", "AbortError")); }); });
		if (window.__delay) { var d = window.__delay; return new Promise(function (ok) { setTimeout(ok, d); }).then(function () { return F(u, o); }); }
		return F(u, o);
	};
})()`

// edgeTab opens url in a new window of w×h with edgeProbe on every document it loads.
func edgeTab(t *testing.T, c *cdp, name, url string, w, h int) *tab {
	t.Helper()
	tb := c.open(t, name, "about:blank")
	tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": h, "deviceScaleFactor": 1, "mobile": false})
	tb.c.call(t, tb.session, "Page.enable", map[string]any{})
	tb.c.call(t, tb.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": edgeProbe})
	tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": url})
	tb.until(t, "loaded", `document.readyState === "complete" && !!window.tegoLive && !!document.querySelector('script[src="/static/place.js"]')`)
	time.Sleep(200 * time.Millisecond) // place.js, loaded by live.js
	tb.eval(t, `window.__tegoMark = "kept"`)
	return tb
}

// topFrames is how many of the first frames the page painted at the top before it came back to y (±4), and the
// frames themselves.
func topFrames(t *testing.T, tb *tab, y int) (int, string) {
	t.Helper()
	raw := strings.Trim(tb.eval(t, `window.__ys.join(" ")`), `"`)
	n := 0
	for _, f := range strings.Fields(raw) {
		v, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("frame %q: %v", f, err)
		}
		if v >= y-4 && v <= y+4 {
			return n, raw
		}
		if v == 0 {
			n++
		}
	}
	return n, raw
}

func TestKeepPlaceEdgesInChrome(t *testing.T) {
	c := placeChrome(t)
	root := manyRunsFixture(t)
	t0 := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 170; i++ { // 232 runs: Runs has an Older runs page
		run := fmt.Sprintf("r-cccccccc-%013d-endedx", 100+i)
		at := t0.Add(time.Duration(i) * time.Minute)
		ls := line(run, "demo-older", 0, at, "run_start", `"tier":"landlock","command":["sh","-c","make test"]`) +
			line(run, "demo-older", 1, at.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`)
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(ls), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var tl strings.Builder // 450 more lines on the live run: its timeline has Older rows
	for i := 7; i < 457; i++ {
		tl.WriteString(line(harmRun, "demo-harm", i, time.Date(2026, 10, 25, 12, 1, 0, 0, time.UTC).Add(time.Duration(i)*time.Second), "fs", fmt.Sprintf(`"verdict":"allow","op":"open","path":"/p/f%d.txt","flags":0`, i)))
	}
	appendLine(t, root, harmRun, tl.String())
	_, addr, _ := liveServer(t, root, 10*time.Second, 120*time.Second)
	chip := func(word string) string {
		return `Array.prototype.find.call(document.querySelectorAll('nav.chips a.chip'), function (a) { return a.textContent.indexOf(` + strconv.Quote(word) + `) === 0; })`
	}

	// 1. A reload after view changes, and a Back from another page: at the scroll from the first frames, as without
	// place.js (it once made every history entry 'manual', so the top showed for a few frames, then a jump).
	rn := edgeTab(t, c, "runs", "http://"+addr+"/runs?t=tok123", 1280, 800)
	for i := 0; i < 2; i++ {
		rn.eval(t, chip("Ended")+`.click()`)
		rn.until(t, "the Ended view", `location.search === "?state=ended" && !document.querySelector("main").hasAttribute("aria-busy")`)
		rn.eval(t, chip("All")+`.click()`)
		rn.until(t, "the All view", `location.search === "" && !document.querySelector("main").hasAttribute("aria-busy")`)
		if m := rn.eval(t, `history.scrollRestoration`); m != `"manual"` { // its views' scroll is in their state
			t.Errorf("after a view change the scroll restoration is %s, want manual", m)
		}
		rn.eval(t, `window.scrollTo(0, 1500)`)
		rn.until(t, "scrolled", `Math.round(window.scrollY) === 1500`)
		time.Sleep(400 * time.Millisecond)
		if i == 0 {
			rn.eval(t, `location.reload()`)
		} else { // the browser's own reload, as the reader's key or button
			rn.c.call(t, rn.session, "Page.reload", map[string]any{})
		}
		rn.until(t, "reloaded", `window.__tegoMark === undefined && document.readyState === "complete" && window.__ys.length >= 30`)
		n, fr := topFrames(t, rn, 1500)
		t.Logf("reload %d, scrollY at each frame: %s", i, fr)
		if n > 0 {
			t.Errorf("reload %d: %d frames at the top before 1500: %s", i, n, fr)
		}
		for _, f := range strings.Fields(fr) {
			if v, err := strconv.Atoi(f); err != nil || v > 1504 { // the banner's room, added to a scroll that held it
				t.Errorf("reload %d: a frame past 1500: %s", i, fr)
				break
			}
		}
		// Until its first view change a page keeps the browser's own restore, which works from the first paint.
		if m := rn.eval(t, `history.scrollRestoration`); m != `"auto"` {
			t.Errorf("reload %d: the reloaded page's scroll restoration is %s, want the browser's (auto)", i, m)
		}
		near(t, rn, "scrollY after the reload", `window.scrollY`, 1500)
		rn.eval(t, `window.__tegoMark = "kept"`)
		rn.eval(t, `document.querySelector('main a[href="/runs/`+cleanRun+`"]').click()`)
		rn.until(t, "the run page", `location.pathname === "/runs/`+cleanRun+`" && document.readyState === "complete"`)
		time.Sleep(300 * time.Millisecond)
		rn.eval(t, `history.back()`)
		rn.until(t, "Back on Runs", `location.pathname === "/runs" && document.readyState === "complete" && (window.__ys.length >= 30 || window.__tegoMark === "kept")`)
		time.Sleep(300 * time.Millisecond)
		if rn.eval(t, `window.__tegoMark`) != `"kept"` { // loaded anew, not from the back/forward cache: its frames
			n, fr := topFrames(t, rn, 1500)
			t.Logf("Back %d, scrollY at each frame: %s", i, fr)
			if n > 0 {
				t.Errorf("Back %d: %d frames at the top before 1500: %s", i, n, fr)
			}
		}
		near(t, rn, "scrollY after Back", `window.scrollY`, 1500)
		rn.eval(t, `window.__tegoMark = "kept"`)
	}

	// 2. Older runs: the list shows from its first row and has the focus, in the window (the Newest runs link, its
	// link's twin, stood thousands of pixels below).
	rn.eval(t, `(function () { var a = Array.prototype.find.call(document.querySelectorAll(".runs-pager a"), function (a) { return /Older/.test(a.textContent); }); a.scrollIntoView({block: "end"}); a.focus(); a.click(); })()`)
	rn.until(t, "the older page", `/before=/.test(location.search) && !document.querySelector("main").hasAttribute("aria-busy")`)
	if rn.eval(t, `window.__tegoMark`) != `"kept"` {
		t.Fatal("Older runs loaded the page anew")
	}
	if rn.eval(t, `document.activeElement.getAttribute("tabindex") === "-1" && document.activeElement.contains(document.querySelector(".runs-pager"))`) != "true" {
		t.Errorf("the focus after Older runs is on %s", rn.eval(t, `document.activeElement.tagName + " " + document.activeElement.className + " " + (document.activeElement.textContent || "").trim().slice(0, 30)`))
	}
	if top := pxOf(t, rn, `document.activeElement.getBoundingClientRect().top`); top < -4 || top > 800 {
		t.Errorf("the focused list's top is %d, out of the window", top)
	}

	// 3. A view fetch that stalls: the busy bar shows, and after STALL the page loads as the link would.
	rn.eval(t, `window.scrollTo(0, 0); window.__stall = "state=running"`)
	rn.eval(t, chip("Running")+`.click()`)
	rn.until(t, "the busy bar", `document.body.classList.contains("nav-busy")`)
	start := time.Now()
	rn.until(t, "the page loaded after the stall", `window.__tegoMark === undefined && location.search === "?state=running" && document.readyState === "complete"`)
	if d := time.Since(start); d < 7*time.Second {
		t.Errorf("the stalled view loaded its page after %s, before STALL", d)
	}

	// 4. A run's Older rows: the new range is said, not just the page's heading.
	rp := edgeTab(t, c, "run", "http://"+addr+"/runs/"+harmRun, 1280, 800)
	rp.eval(t, `(function () { var a = document.getElementById("tl-older"); a.scrollIntoView({block: "end"}); a.focus(); a.click(); })()`)
	rp.until(t, "the older rows", `/before=/.test(location.search) && !document.querySelector("main").hasAttribute("aria-busy")`)
	rp.until(t, "the rows' range said", `/older rows/.test((document.getElementById("nav-say") || {}).textContent || "")`)
	if rp.eval(t, `window.__tegoMark`) != `"kept"` {
		t.Error("Older rows loaded the page anew")
	}

	// 5. Logs: the × of the last query chip and Clear filters, with Filters open.
	lroot, _ := progFixture(t)
	_, laddr, _ := liveServer(t, lroot, 10*time.Second, 120*time.Second)
	lg := edgeTab(t, c, "logs", "http://"+laddr+"/logs?t=tok123&where=prog%3Acurl", 1280, 800)
	lg.eval(t, `document.querySelector("details.fsheet").open = true; document.querySelector("details.lq-adv").open = true`)
	lg.eval(t, `(function () { var x = document.querySelector(".lq-chips a.x"); x.focus(); x.click(); })()`)
	lg.until(t, "the unfiltered view", `!/where=/.test(location.search) && !document.querySelector(".lq-chips") && !document.querySelector("main").hasAttribute("aria-busy")`)
	if lg.eval(t, `window.__tegoMark`) != `"kept"` {
		t.Fatal("the chip's × loaded the page anew")
	}
	if lg.eval(t, `document.querySelector("details.lq-adv").open`) != "true" {
		t.Error("the Filters panel shut when the last chip went")
	}
	if a := lg.eval(t, `document.activeElement.tagName + " " + (document.activeElement.name || "")`); a != `"INPUT q"` {
		t.Errorf("the focus after the last chip's × is on %s, want the search field", a)
	}
	if lg.eval(t, `document.querySelectorAll("[data-k^='~']").length`) != "0" {
		t.Error("the merge's own keys stayed on the page")
	}
	lg.eval(t, `(function () { var q = document.querySelector(".lq-where input"); q.value = "verdict:allow"; q.form.requestSubmit(); })()`)
	lg.until(t, "a filtered view", `/where=verdict/.test(location.search) && !document.querySelector("main").hasAttribute("aria-busy")`)
	lg.eval(t, `document.querySelector("details.lq-adv").open = true`)
	lg.eval(t, `(function () { var a = Array.prototype.find.call(document.querySelectorAll("details.lq-adv a"), function (a) { return a.textContent.trim() === "Clear filters"; }); a.focus(); a.click(); })()`)
	lg.until(t, "the cleared view", `location.search === "" && location.pathname === "/logs" && !document.querySelector("main").hasAttribute("aria-busy")`)
	if lg.eval(t, `document.querySelector("details.lq-adv").open`) != "true" {
		t.Error("the Filters panel shut on Clear filters")
	}
	if a := lg.eval(t, `document.activeElement === document.body`); a != "false" {
		t.Error("the focus fell to <body> after Clear filters")
	}

	// 6. Text typed in the search while a slow view loads is the reader's.
	lg.eval(t, `window.__delay = 1200; (function () { var q = document.querySelector(".lq-text input"); q.focus(); q.value = "curl"; q.form.requestSubmit(); setTimeout(function () { q.value = "curl exa"; }, 300); })()`)
	lg.until(t, "the searched view", `/[?&]q=curl/.test(location.search) && !document.querySelector("main").hasAttribute("aria-busy")`)
	if v := lg.eval(t, `document.querySelector(".lq-text input").value`); v != `"curl exa"` {
		t.Errorf("the search field after the slow view is %s, want the text typed meanwhile", v)
	}
	lg.eval(t, `window.__delay = 0`)

	// 7. MCP tools: no live regions, and still the picker in place and a switch's post back where it was pressed.
	mroot := mcpLiveFixture(t)
	_, maddr, _ := liveServer(t, mroot, 10*time.Second, 120*time.Second)
	mp := edgeTab(t, c, "mcp", "http://"+maddr+"/mcp?t=tok123&run="+mcpRun, 1280, 420)
	if mp.eval(t, `!!document.body.dataset.sig`) != "false" {
		t.Fatal("MCP tools now has a signature: this part tests a page without one")
	}
	mp.eval(t, `(function () { var f = document.querySelector("main form.mcp-pick"); f.querySelector("select").value = "`+mcpRun+`"; f.requestSubmit(); })()`)
	mp.until(t, "the picked run", `location.search === "?run=`+mcpRun+`" && !document.querySelector("main").hasAttribute("aria-busy")`)
	if mp.eval(t, `window.__tegoMark`) != `"kept"` {
		t.Error("MCP tools' picker loaded the page anew")
	}
	deny := `document.querySelector('form.mcp-switch[aria-label="read_file on files"] button[value="deny"]')`
	mp.eval(t, `(function () { var b = `+deny+`; window.scrollTo(0, b.getBoundingClientRect().top + window.scrollY - 250); })()`)
	time.Sleep(200 * time.Millisecond)
	if y := pxOf(t, mp, `window.scrollY`); y < 100 {
		t.Fatalf("MCP tools did not scroll (scrollY %d): the window is too tall for the test", y)
	}
	btop := pxOf(t, mp, deny+`.getBoundingClientRect().top`)
	mp.eval(t, deny+`.click()`)
	mp.until(t, "the switch's answer", `window.__tegoMark === undefined && document.readyState === "complete" && !!document.getElementById("flash")`)
	mp.until(t, "the switch where it was pressed", `Math.abs(`+deny+`.getBoundingClientRect().top - `+strconv.Itoa(btop)+`) <= 4`)

	// 8. Model routes: the picker in place.
	rroot := routesLiveFixture(t)
	_, raddr, _ := liveServer(t, rroot, 10*time.Second, 120*time.Second)
	ro := edgeTab(t, c, "routes", "http://"+raddr+"/routes?t=tok123&run="+routesRun, 1280, 800)
	ro.eval(t, `(function () { var f = document.querySelector("main form.rt-pick"); f.querySelector("select").value = "`+routesRun+`"; f.requestSubmit(); })()`)
	ro.until(t, "the picked run", `location.search === "?run=`+routesRun+`" && !document.querySelector("main").hasAttribute("aria-busy")`)
	if ro.eval(t, `window.__tegoMark`) != `"kept"` {
		t.Error("Model routes' picker loaded the page anew")
	}
	fmt.Println("keep place edges in chrome: reload and Back at their scroll, pager focus, stall, Logs' Filters, typed text, MCP tools and Model routes in place")
}
