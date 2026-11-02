// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// Keeping the reader's place in a real browser (static/place.js on live.js's merge): headless Chrome over the
// DevTools pipe (chrome_test.go's cdp) opens Runs with 60 ended runs and Logs with 153 lines, both long enough to
// scroll, and checks, with a marker on the window that a page load would clear: a Runs status chip and a Logs facet
// change the view in place, the address changes with them, the window stays where it was (the chip or facet where it
// stood), the content is the filtered view, focus stays on the control and the new view is said politely; Back and
// Forward bring the earlier view back at its own scroll; a Ctrl-click is left to the browser; a plain form post comes
// back to where it was sent from; Logs' search form, a run page's Receipt tab (the timeline still following the run
// after it, on one stream), Compare's picks and the Rules picker change in place; a keyboard's Deny keeps the focus.
// Run it by hand, through the box's memory slice:
//
//	go test -tags chrome -run TestKeepPlaceInChrome ./internal/control/web
//
// Without JavaScript the same addresses render the filtered pages (TestViewLinksWithoutJS, a plain GET).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// placeChrome starts a headless Chrome on its own profile and returns its DevTools connection.
func placeChrome(t *testing.T) *cdp {
	t.Helper()
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prof := filepath.Join(t.TempDir(), "profile")
	cmd := exec.Command(chrome, "--headless=new", "--remote-debugging-pipe", "--user-data-dir="+prof, "--no-first-run",
		"--no-default-browser-check", "--disable-gpu", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-component-update", "about:blank")
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = cmdR.Close()
	_ = outW.Close()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("chrome stderr:\n%s", stderr.String())
		}
	})
	c := &cdp{w: cmdW, wait: map[int]chan json.RawMessage{}}
	go c.read(outR)
	return c
}

// manyRunsFixture is fixture's ledger root (a clean ended run and a live run with an ask) with 60 more ended runs, so
// Runs is long enough to scroll with the Ended chip on.
func manyRunsFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	t0 := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 60; i++ {
		run := fmt.Sprintf("r-bbbbbbbb-%013d-endedx", 100+i)
		at := t0.Add(time.Duration(i) * time.Minute)
		ls := line(run, "demo-many", 0, at, "run_start", `"tier":"landlock","command":["sh","-c","make test"]`) +
			line(run, "demo-many", 1, at.Add(time.Second), "fs", `"verdict":"allow","op":"open","path":"out/r.txt","flags":577`) +
			line(run, "demo-many", 2, at.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`)
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(ls), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// near fails unless the number expr evaluates to is within 4 pixels of want.
func near(t *testing.T, tb *tab, what, expr string, want int) int {
	t.Helper()
	got, err := strconv.Atoi(tb.eval(t, `Math.round(`+expr+`)`))
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if got < want-4 || got > want+4 {
		t.Errorf("%s: %d, want %d (±4)", what, got, want)
	}
	return got
}

func pxOf(t *testing.T, tb *tab, expr string) int {
	t.Helper()
	n, err := strconv.Atoi(tb.eval(t, `Math.round(`+expr+`)`))
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	return n
}

func TestKeepPlaceInChrome(t *testing.T) {
	c := placeChrome(t)
	root1 := manyRunsFixture(t)
	_, addr, _ := liveServer(t, root1, 10*time.Second, 30*time.Second)

	// 1. Runs: the Ended chip, with the window scrolled down a little.
	rn := c.open(t, "runs", "http://"+addr+"/runs?t=tok123")
	rn.c.call(t, rn.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": false})
	rn.until(t, "loaded", `document.readyState === "complete" && document.querySelectorAll('tbody tr[data-k]').length === 62`)
	rn.eval(t, `window.__tegoMark = "kept"`)
	kept := func(tb *tab, when string) {
		t.Helper()
		if tb.eval(t, `window.__tegoMark`) != `"kept"` {
			t.Fatalf("%s: the page loaded anew %s", tb.name, when)
		}
	}
	chip := func(word string) string {
		return `Array.prototype.find.call(document.querySelectorAll('nav.chips a.chip'), function (a) { return a.textContent.indexOf(` + strconv.Quote(word) + `) === 0; })`
	}
	rn.eval(t, `window.scrollTo(0, 60)`)
	rn.until(t, "scrolled", `Math.round(window.scrollY) === 60`)
	top := pxOf(t, rn, chip("Ended")+`.getBoundingClientRect().top`)
	if top < 0 || top > 800 {
		t.Fatalf("the Ended chip is out of the window (top %d)", top)
	}
	rn.eval(t, chip("Ended")+`.click()`)
	rn.until(t, "the Ended view", `location.search === "?state=ended" && `+chip("Ended")+`.getAttribute("aria-current") === "true"`)
	kept(rn, "after the Ended chip")
	if rn.eval(t, `!!document.querySelector('tr[data-k="`+harmRun+`"]')`) != "false" ||
		rn.eval(t, `document.querySelectorAll('tbody tr[data-k]').length`) != "61" {
		t.Error("the Ended view still lists the running run, or lacks an ended one")
	}
	near(t, rn, "scrollY after the Ended chip", `window.scrollY`, 60)
	near(t, rn, "the Ended chip's place in the window", chip("Ended")+`.getBoundingClientRect().top`, top)
	if rn.eval(t, `document.activeElement === `+chip("Ended")) != "true" {
		t.Error("focus left the Ended chip")
	}
	rn.until(t, "the new view said", `(document.getElementById("nav-say") || {}).textContent === "Ended 61"`)
	if rn.eval(t, `document.querySelectorAll(".live-new").length`) != "0" {
		t.Error("the view's rows were marked new")
	}

	// 2. All, then lower down; Back brings Ended back at 60 and Forward All at its own scroll.
	rn.eval(t, chip("All")+`.click()`)
	rn.until(t, "the All view", `location.search === "" && location.pathname === "/runs" && document.querySelectorAll('tbody tr[data-k]').length === 62`)
	near(t, rn, "scrollY after the All chip", `window.scrollY`, 60)
	rn.eval(t, `window.scrollTo(0, 1500)`)
	rn.until(t, "scrolled down", `Math.round(window.scrollY) === 1500`)
	time.Sleep(400 * time.Millisecond) // the scroll's place goes in the history entry a moment after it stops
	rn.eval(t, `history.back()`)
	rn.until(t, "Back to Ended", `location.search === "?state=ended" && document.querySelectorAll('tbody tr[data-k]').length === 61 && `+chip("Ended")+`.getAttribute("aria-current") === "true"`)
	rn.until(t, "Ended's scroll", `Math.abs(window.scrollY - 60) <= 4`)
	rn.eval(t, `history.forward()`)
	rn.until(t, "Forward to All", `location.search === "" && document.querySelectorAll('tbody tr[data-k]').length === 62`)
	rn.until(t, "All's scroll", `Math.abs(window.scrollY - 1500) <= 4`)
	kept(rn, "after Back and Forward")

	// 3. A Ctrl-click and a link to another page keep the browser's own behaviour: no view change in place.
	// (A listener on the window, after live.js's on the document, stops the browser's own new tab.)
	if rn.eval(t, `(function () { var e = new MouseEvent("click", {bubbles: true, cancelable: true, ctrlKey: true, button: 0}); window.addEventListener("click", function (x) { x.preventDefault(); }, {once: true}); `+chip("Ended")+`.dispatchEvent(e); return location.search; })()`) != `""` {
		t.Error("a Ctrl-click changed the view in place")
	}
	time.Sleep(300 * time.Millisecond)
	if rn.eval(t, `location.search === "" && !document.body.classList.contains("nav-busy") && document.querySelector("main").getAttribute("aria-busy") === null`) != "true" {
		t.Error("a Ctrl-click started a view change")
	}

	// 3b. A plain form post (Pause, which answers with its page) comes back to where it was sent from, and the line it
	// left is said in a toast, since its banner is at the top, out of sight. (The form is put on the page here; Pause
	// refuses a run that waits on a request, so nothing changes.)
	rn.eval(t, `(function () { var f = document.createElement("form"); f.method = "post"; f.action = "/runs/`+harmRun+`/pause"; f.id = "place-probe";
		var c = document.createElement("input"); c.type = "hidden"; c.name = "csrf"; c.value = document.querySelector('input[name="csrf"]').value; f.appendChild(c);
		var b = document.createElement("button"); b.type = "submit"; b.textContent = "Pause probe"; f.appendChild(b);
		document.querySelector(".runs-panel").appendChild(f); window.scrollTo(0, 1200); })()`)
	rn.until(t, "scrolled to the probe", `Math.round(window.scrollY) === 1200`)
	rn.eval(t, `document.getElementById("place-probe").requestSubmit()`)
	rn.until(t, "the page the post answered with", `window.__tegoMark === undefined && document.readyState === "complete" && !!document.getElementById("flash")`)
	rn.until(t, "back where the form was sent from", `Math.abs(window.scrollY - 1200) <= 4`)
	rn.until(t, "its line in a toast", `Array.prototype.some.call(document.querySelectorAll(".toast"), function (x) { return x.textContent.indexOf("Not done") === 0; })`)
	rn.eval(t, `window.__tegoMark = "kept"`)

	// 4. Logs, already narrowed to curl's lines (its query chip is there): a facet in the folded filters, with the
	// window scrolled to it. The facet adds a second chip beside the first, so nothing above it changes height.
	root, _ := progFixture(t)
	_, laddr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	lg := c.open(t, "logs", "http://"+laddr+"/logs?t=tok123&where=prog%3Acurl")
	lg.c.call(t, lg.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": false})
	lg.until(t, "loaded", `document.readyState === "complete" && document.documentElement.classList.contains("lq-js")`)
	lg.eval(t, `window.__tegoMark = "kept"`)
	allRows := lg.eval(t, `document.querySelectorAll("#lq-rows tr.lq-r").length`)
	lg.eval(t, `document.querySelector("details.fsheet").open = true; document.querySelector("details.lq-adv").open = true`)
	facet := `Array.prototype.find.call(document.querySelectorAll(".lq-facets a.lq-add"), function (a) { return a.querySelector(".lq-l").textContent === "Allowed"; })`
	if lg.eval(t, `!!`+facet) != "true" {
		t.Fatalf("no Allowed facet: %s", lg.eval(t, `document.querySelector(".lq-facets").textContent`))
	}
	lg.eval(t, `window.scrollTo(0, `+facet+`.getBoundingClientRect().top + window.scrollY - 150)`)
	time.Sleep(100 * time.Millisecond)
	y0 := pxOf(t, lg, `window.scrollY`)
	if y0 < 200 {
		t.Fatalf("Logs did not scroll (scrollY %d): the page is too short for the test", y0)
	}
	ftop := pxOf(t, lg, facet+`.getBoundingClientRect().top`)
	lg.eval(t, facet+`.click()`)
	lg.until(t, "the allowed view", `/verdict(%3A|=)allow/.test(location.search) && document.querySelectorAll("#lq-rows tr.lq-r").length === 100 && /151 lines/.test(document.querySelector("main .lede").textContent) && !document.querySelector('#lq-rows tr[data-k="`+progRun+`-2"]')`)
	kept(lg, "after the facet")
	near(t, lg, "Logs scrollY after the facet", `window.scrollY`, y0)
	near(t, lg, "the facet's place in the window", `document.activeElement.getBoundingClientRect().top`, ftop)
	if lg.eval(t, `document.querySelector("details.fsheet").open && document.querySelector("details.lq-adv").open`) != "true" {
		t.Error("the filters folded away after the facet")
	}
	lg.until(t, "the facet and the rows' count said", `(document.getElementById("nav-say") || {}).textContent === "Allowed 151. 100 of 151 rows shown"`)
	// The rows follow the new view: Older lines and the live tail are the new view's, with one set of listeners.
	if lg.eval(t, `!!document.querySelector('[data-live="r-logs-rows"]')`) != "false" {
		t.Error("the new view's rows region went back to live.js")
	}

	// 5. Back brings curl's lines back, at the scroll they had.
	lg.eval(t, `history.back()`)
	lg.until(t, "Back to curl's lines", `location.search === "?where=prog%3Acurl" && String(document.querySelectorAll("#lq-rows tr.lq-r").length) === `+strconv.Quote(allRows))
	lg.until(t, "its scroll", `Math.abs(window.scrollY - `+strconv.Itoa(y0)+`) <= 4`)
	kept(lg, "after Back")

	// 6. The query form: a search submitted in place, the address its fields.
	lg.eval(t, `window.scrollTo(0, 0)`)
	lg.eval(t, `(function () { var q = document.querySelector(".lq-text input"); q.value = "late"; q.form.requestSubmit(); })()`)
	lg.until(t, "the searched view", `/[?&]q=late/.test(location.search) && /No matching lines/.test(document.querySelector("main").textContent)`)
	kept(lg, "after the search form")
	if v := lg.eval(t, `document.querySelector(".lq-text input").value`); v != `"late"` {
		t.Errorf("the search field after the search is %s", v)
	}
	if !strings.Contains(lg.eval(t, `document.title`), "Logs") {
		t.Error("the title lost the page's name")
	}
	// 7. A run page's tabs: Receipt in place (with its own stylesheet), Back to the timeline, which still follows the
	// run: a new line comes in at the top, with one stream as before.
	// Each EventSource the page makes is counted from before its scripts run.
	rp := c.open(t, "run", "about:blank")
	rp.c.call(t, rp.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": false})
	rp.c.call(t, rp.session, "Page.enable", map[string]any{})
	rp.c.call(t, rp.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": `(function () { var E = window.EventSource; window.__es = 0;
		window.EventSource = function (u, o) { window.__es++; return new E(u, o); }; window.EventSource.prototype = E.prototype; })()`})
	rp.c.call(t, rp.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + harmRun})
	rp.until(t, "loaded", `document.readyState === "complete" && !!document.querySelector("#tl-rows[data-rows]")`)
	rp.eval(t, `window.__tegoMark = "kept"`)
	tabLink := func(word string) string {
		return `Array.prototype.find.call(document.querySelectorAll("nav.tabs a"), function (a) { return a.textContent.indexOf(` + strconv.Quote(word) + `) === 0; })`
	}
	rp.eval(t, tabLink("Receipt")+`.click()`)
	rp.until(t, "the Receipt tab", `location.pathname === "/runs/`+harmRun+`/receipt" && `+tabLink("Receipt")+`.getAttribute("aria-current") === "page" && !document.getElementById("tl-rows")`)
	kept(rp, "after the Receipt tab")
	if rp.eval(t, `Array.prototype.some.call(document.styleSheets, function (s) { return /receipt\.css$/.test(s.href || ""); })`) != "true" {
		t.Error("the Receipt tab's stylesheet is not loaded")
	}
	rp.eval(t, `history.back()`)
	rp.until(t, "Back to the timeline", `location.pathname === "/runs/`+harmRun+`" && !!document.querySelector("#tl-rows[data-rows]")`)
	appendLine(t, root1, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 1, 7, 0, time.UTC), "fs", `"verdict":"allow","op":"open","path":"/p/after-the-tab.txt","flags":0`))
	rp.until(t, "the new line at the top of the timeline", `/after-the-tab/.test(document.querySelector("#tl-rows").firstElementChild.textContent)`)
	if n := rp.eval(t, `window.__es`); n != "1" { // one stream since the page loaded: a view change opens none
		t.Errorf("the page opened %s event streams, want 1", n)
	}
	kept(rp, "after Back and a new line")

	// 7b. A keyboard's Deny (posted in the background; with no broker it fails and the card stays): the focus comes
	// back to the button its sending disabled, not to nothing.
	rp.eval(t, `(function () { var b = document.querySelector('#ask-7 button[value="deny"]'); b.focus(); document.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", bubbles: true})); b.form.requestSubmit(b); })()`)
	rp.until(t, "the failed Deny's toast", `!!document.querySelector(".toast-err") && document.querySelector(".toast-err").textContent.indexOf("Not done") >= 0`)
	rp.until(t, "the focus back on Deny", `document.activeElement === document.querySelector('#ask-7 button[value="deny"]')`)
	kept(rp, "after the keyboard's Deny")

	// 8. Compare's picks: another run B, compared in place; the form shows the pair the page compares.
	cp := c.open(t, "compare", "http://"+addr+"/compare?a="+cleanRun+"&b="+harmRun)
	cp.c.call(t, cp.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": false})
	cp.until(t, "loaded", `document.readyState === "complete" && !!document.querySelector("main .cmp-form")`)
	cp.eval(t, `window.__tegoMark = "kept"`)
	other := "r-bbbbbbbb-0000000000159-endedx"
	cp.eval(t, `(function () { var f = document.querySelector("main .cmp-form"); f.querySelector('select[name="b"]').value = "`+other+`"; f.requestSubmit(); })()`)
	cp.until(t, "the new pair", `location.pathname === "/compare" && location.search.indexOf("b=`+other+`") >= 0 && document.querySelector('main .cmp-form select[name="b"]').value === "`+other+`" && document.querySelector("main").textContent.indexOf("demo-many") >= 0`)
	kept(cp, "after Compare")

	// 9. The Rules page's picker: another run of the same rules file, shown in place.
	rf := newRulesFix(t)
	_, raddr, _ := liveServer(t, rf.root, 10*time.Second, 30*time.Second)
	ru := c.open(t, "rules", "http://"+raddr+"/rules?t=tok123")
	ru.c.call(t, ru.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": false})
	ru.until(t, "signed in", `document.readyState === "complete" && !!document.body.dataset.sig`)
	ru.c.call(t, ru.session, "Page.navigate", map[string]any{"url": "http://" + raddr + "/rules?c=" + rules.Ref(rf.source) + "&run=" + rulesRunA})
	ru.until(t, "loaded", `document.readyState === "complete" && location.search.indexOf("`+rulesRunA+`") >= 0 && !!document.querySelector("main .rules-pick")`)
	ru.eval(t, `window.__tegoMark = "kept"`)
	ru.eval(t, `(function () { var f = document.querySelector("main .rules-pick"); f.querySelector('select[name="run"]').value = "`+rulesRunB+`"; f.requestSubmit(); })()`)
	ru.until(t, "the other run's rules", `location.search.indexOf("run=`+rulesRunB+`") >= 0 && document.querySelector('main .rules-pick select[name="run"]').value === "`+rulesRunB+`" && document.querySelector("main").textContent.indexOf("Policy · rules-demo") >= 0`)
	kept(ru, "after the Rules picker")

	fmt.Println("keep place in chrome: Runs chips and a Logs facet and search in place, at the same scroll, Back and Forward at theirs; no reload")
}
