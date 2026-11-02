// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The main journey by keyboard alone, in a real browser (DASH-G4): headless Chrome over the DevTools pipe
// (chrome_test.go's cdp) at 390, 768 and 1440 px wide, in the light theme and the dark, presses only Tab and Enter:
// the Overview's skip link and the main nav to Approvals; Allow once there, and the request's run; the run's Stop run
// and its confirm, whose first stop in <main> is the waiting request's banner; Deny on the run's waiting request and
// its Receipt tab; a timeline line's page and the line as written; a Logs row opened in place. Every Tab must land on
// a control after the one before it in the page's order, inside the window, not wholly under another element (the
// sticky top bar, the phone's bottom bar, the banner; a toast over it is logged, not failed), and drawn with its
// focus ring; after Allow once and Deny the focus is back on the button pressed. Every page reached must fit its
// width (no sideways scroll), log no console error, uncaught exception or failed load and break no Content Security
// Policy rule (chrome_test.go's watch), and at 390 px wide every button-like control on it must be at least 24 by 24
// px (WCAG 2.5.8). TestReceiptTabInChrome holds the Receipt tab of four runs to the same at every width and theme. A
// screen reader pass is still owed by hand. Run them by hand, one Chrome at a time, through the box's memory slice:
//
//	go test -tags chrome -run 'TestJourneyByKeyboardInChrome|TestReceiptTabInChrome' ./internal/control/web
//
// With TEGO_CHROME_SHOTS set they save each page they reach there, as journey-<page>-<width>-<scheme>.png and
// receipt-<run>-<width>-<scheme>.png.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sweepSizes are the widths the pages are held at, a phone's, a tablet's and a laptop's, each with a common height.
var sweepSizes = [][2]int{{390, 844}, {768, 1024}, {1440, 900}}

// sweepTab opens a window of w×h in scheme on c, watched for page errors (watch), with the page told it has the
// focus, as the window a person types into does.
func sweepTab(t *testing.T, c *cdp, name string, w, h int, scheme string) *tab {
	t.Helper()
	tb := c.open(t, name, "about:blank")
	c.watch(t, tb)
	c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": h, "deviceScaleFactor": 1, "mobile": w < 600})
	c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
	c.call(t, tb.session, "Emulation.setFocusEmulationEnabled", map[string]any{"enabled": true})
	c.call(t, tb.session, "Page.bringToFront", map[string]any{})
	return tb
}

// smallControls lists the button-like controls on the page that are shown and smaller than 24 by 24 CSS px, the
// least WCAG 2.5.8 lets a pointer or finger target be.
const smallControls = `(function () {
	var out = [];
	document.querySelectorAll("button, input[type=button], input[type=submit], input[type=reset], [role=button], a.btn, summary, select").forEach(function (e) {
		var r = e.getBoundingClientRect();
		if (!r.width || !r.height || getComputedStyle(e).visibility === "hidden") return;
		if (r.width < 23.95 || r.height < 23.95) out.push(e.tagName.toLowerCase() + "." + e.className + " \"" + (e.getAttribute("aria-label") || e.textContent || "").trim().replace(/\s+/g, " ").slice(0, 40) + "\" " + r.width.toFixed(1) + "x" + r.height.toFixed(1));
	});
	return out.join("\n");
})()`

// pageChecks holds the page tb is on to what every page owes at width w: no sideways scroll, no page error since the
// last take, and at 390 px no button-like control under 24 by 24 px. With TEGO_CHROME_SHOTS set it saves the window,
// as the person sees it (scrolled to the element at names first, when at is not ""), as <shot>.png there.
func pageChecks(t *testing.T, tb *tab, page string, w int, shot, at string) {
	t.Helper()
	if v := tb.eval(t, `(function () { var d = document.documentElement; return d.scrollWidth > d.clientWidth ? d.scrollWidth + " px wide in a " + d.clientWidth + " px window" : ""; })()`); v != `""` {
		t.Errorf("%s: %s scrolls sideways: %s", tb.name, page, v)
	}
	if w == 390 {
		if v := tb.eval(t, smallControls); v != `""` {
			var list string
			_ = json.Unmarshal([]byte(v), &list)
			t.Errorf("%s: %s: controls under 24 by 24 px:\n%s", tb.name, page, list)
		}
	}
	tb.clean(t, page)
	if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
		if at != "" { // just under the sticky top bar
			tb.eval(t, `window.scrollTo(0, document.querySelector(`+strconv.Quote(at)+`).getBoundingClientRect().top + window.scrollY - 64), ""`)
			time.Sleep(100 * time.Millisecond)
		}
		var r struct{ Data []byte }
		_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
		if err := os.WriteFile(filepath.Join(dir, shot+".png"), r.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// arrive waits until the page tb is on is the one cond names, loaded and idle (no view change under way).
func arrive(t *testing.T, tb *tab, page, cond string) {
	t.Helper()
	tb.until(t, page, `document.readyState === "complete" && !!window.tegoLive && !document.querySelector("main[aria-busy]") && (`+cond+`)`)
}

// stopProbe describes the control the focus is on after a Tab, for tabTo: whether it is the one sel names, whether
// it is shown (inside the window) and not wholly covered (at some of nine points across it, it or a child is the
// topmost element), whether it has its focus ring, and whether it comes after the stop before it (window.__tegoPrev)
// in the page's order. A point under a toast is counted apart (Toasted): a toast lies over the page's corner, or a
// phone's width above its bar, for its 6 s, and a control Tab brings up there can be under it.
func stopProbe(sel string) string {
	return `(function (sel) {
	var e = document.activeElement, p = window.__tegoPrev;
	window.__tegoPrev = e;
	if (!e || e === document.body || e === document.documentElement) return {Out: true};
	var name = (e.getAttribute("aria-label") || e.textContent || e.value || "").trim().replace(/\s+/g, " ").slice(0, 40);
	var what = e.tagName.toLowerCase() + (e.id ? "#" + e.id : "") + " \"" + name + "\"" + (e.getAttribute("href") ? " → " + e.getAttribute("href") : "");
	var shown = false, unhid = false, toasted = false, rs = e.getClientRects();
	for (var i = 0; i < rs.length; i++) {
		var r = rs[i];
		if (r.width <= 0 || r.height <= 0) continue;
		if (r.right > 0 && r.bottom > 0 && r.left < innerWidth && r.top < innerHeight) shown = true;
		for (var fx = 1; fx < 6; fx += 2) for (var fy = 1; fy < 6; fy += 2) {
			var x = document.elementFromPoint(r.left + r.width * fx / 6, r.top + r.height * fy / 6);
			if (x && (x === e || e.contains(x))) unhid = true;
			else if (x && x.closest("#toasts")) toasted = true;
		}
	}
	var cs = getComputedStyle(e);
	return {What: what, Match: e.matches(sel), Shown: shown, Unhid: unhid, Toasted: toasted,
		Ring: e.matches(":focus-visible") && cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) >= 1,
		Stayed: e === p, Before: !!p && p !== e && p.isConnected && !(p.compareDocumentPosition(e) & Node.DOCUMENT_POSITION_FOLLOWING)};
})(` + strconv.Quote(sel) + `)`
}

// tabTo presses Tab until the focus is on the control sel names, at most max times. It fails the test when a stop on
// the way is out of the window, wholly covered, drawn without its focus ring or before the stop it came from in the
// page's order, when a Tab leaves the focus where it was, and when the focus leaves the page's controls (or max Tabs
// pass) before it gets there. A stop hidden only by a toast is logged, not failed (stopProbe).
func tabTo(t *testing.T, tb *tab, where, sel string, max int) {
	t.Helper()
	tb.eval(t, `window.__tegoPrev = document.activeElement, ""`)
	for i := 1; i <= max; i++ {
		tb.press(t, "Tab")
		var s struct {
			What                                                    string
			Out, Match, Shown, Unhid, Toasted, Ring, Stayed, Before bool
		}
		if err := json.Unmarshal([]byte(tb.eval(t, stopProbe(sel))), &s); err != nil {
			t.Fatalf("%s: %s: the stop after Tab %d: %v", tb.name, where, i, err)
		}
		switch {
		case s.Out:
			t.Fatalf("%s: %s: Tab %d took the focus off the page's controls before %s", tb.name, where, i, sel)
		case s.Stayed:
			t.Fatalf("%s: %s: Tab %d left the focus on %s", tb.name, where, i, s.What)
		}
		if !s.Unhid && s.Toasted {
			t.Logf("%s: %s: Tab %d's stop %s lies under a toast", tb.name, where, i, s.What)
		}
		for _, bad := range []struct {
			is   bool
			says string
		}{{!s.Shown, "is out of the window"}, {!s.Unhid && !s.Toasted, "is wholly covered by another element"}, {!s.Ring, "shows no focus ring"},
			{s.Before, "comes before the stop it was reached from"}} {
			if bad.is {
				t.Errorf("%s: %s: Tab %d's stop %s %s", tb.name, where, i, s.What, bad.says)
			}
		}
		if s.Match {
			return
		}
	}
	t.Fatalf("%s: %s: %s is not reached in %d Tabs", tb.name, where, sel, max)
}

// toMain takes the skip link, the page's first stop, to <main>.
func toMain(t *testing.T, tb *tab, where string) {
	t.Helper()
	tabTo(t, tb, where, "a.skip", 1)
	tb.press(t, "Enter")
	tb.until(t, where+": the skip link put the focus on <main>", `document.activeElement === document.getElementById("main")`)
}

// toast waits for the toast that says words.
func toast(t *testing.T, tb *tab, where, words string) {
	t.Helper()
	tb.until(t, where+": the toast "+strconv.Quote(words), `Array.prototype.some.call(document.querySelectorAll(".toast"), function (x) { return x.textContent.indexOf(`+strconv.Quote(words)+`) >= 0; })`)
}

// answerByKey presses Enter on the focused answer button sel, waits for the toast that says words, and holds that the
// focus comes back to the button (live.js disables a form's buttons while it posts, which drops the focus).
func answerByKey(t *testing.T, tb *tab, where, sel, words string) {
	t.Helper()
	tb.press(t, "Enter")
	toast(t, tb, where, words)
	tb.until(t, where+": the focus back on "+sel, `document.activeElement === document.querySelector(`+strconv.Quote(sel)+`)`)
}

func TestJourneyByKeyboardInChrome(t *testing.T) {
	fakeBroker(t) // Allow once and Deny reach a stand-in broker; the fixture's ask stays waiting for the next pass
	c := placeChrome(t)
	root := fixture(t)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	base := "http://" + addr
	run := "/runs/" + harmRun

	// The collector is no help unless it hears: an inline style, a console error and a throw are all reported.
	cy := sweepTab(t, c, "canary", 1440, 900, "light")
	cy.c.call(t, cy.session, "Page.navigate", map[string]any{"url": base + "/?t=tok123"})
	arrive(t, cy, "the Overview", `location.pathname === "/" && !location.search`)
	cy.clean(t, "the Overview")
	cy.eval(t, `document.body.setAttribute("style", "outline: 1px solid red"); console.error("canary"); setTimeout(function () { throw new Error("canary"); }, 0); ""`)
	time.Sleep(300 * time.Millisecond)
	cy.eval(t, `0`)
	got := strings.Join(cy.problems(), "\n")
	for _, want := range []string{"securitypolicyviolation: style-src-attr", "Content Security Policy", `console.error: "canary"`, "uncaught exception"} {
		if !strings.Contains(got, want) {
			t.Errorf("the page error collector did not report %q; it has:\n%s", want, got)
		}
	}
	cy.c.call(t, "", "Target.closeTarget", map[string]any{"targetId": cy.target})

	for _, sz := range sweepSizes {
		w := sz[0]
		for _, scheme := range []string{"light", "dark"} {
			cfg := fmt.Sprintf("%d-%s", w, scheme)
			tb := sweepTab(t, c, "journey at "+cfg, w, sz[1], scheme)
			tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + "/?t=tok123"})
			arrive(t, tb, "the Overview", `location.pathname === "/" && !location.search`)
			pageChecks(t, tb, "the Overview", w, "journey-overview-"+cfg, "")

			// 1. The Overview's first stop is the skip link; the main nav goes on to Approvals.
			tabTo(t, tb, "the Overview", "a.skip", 1)
			tabTo(t, tb, "the Overview", `nav.side a[href="/approvals"]`, 20)
			tb.press(t, "Enter")
			arrive(t, tb, "Approvals", `location.pathname === "/approvals"`)
			pageChecks(t, tb, "Approvals", w, "journey-approvals-"+cfg, "")

			// 2. Approvals: Allow once on the waiting request, then the request's run.
			toMain(t, tb, "Approvals")
			tabTo(t, tb, "Approvals", `#ask-7 button[value="approve"]`, 10)
			answerByKey(t, tb, "Approvals", `#ask-7 button[value="approve"]`, "Allowed once")
			tabTo(t, tb, "Approvals", `#ask-7 a[href="`+run+`"]`, 10)
			tb.press(t, "Enter")
			arrive(t, tb, "the run page", `location.pathname === "`+run+`"`)
			pageChecks(t, tb, "the run page", w, "journey-run-"+cfg, "")

			// 3. Stop run, and its confirm, where the waiting request's banner is the first stop in <main>; the run is
			// not running (no launcher holds its lock), so the stop says so on the run's page.
			toMain(t, tb, "the run page")
			tabTo(t, tb, "the run page", `main a[href="`+run+`/stop"]`, 20)
			tb.press(t, "Enter")
			arrive(t, tb, "the Stop page", `location.pathname === "`+run+`/stop"`)
			pageChecks(t, tb, "the Stop page", w, "journey-stop-"+cfg, "")
			toMain(t, tb, "the Stop page")
			tabTo(t, tb, "the Stop page", `#ask-banner button[value="approve"]`, 1)
			tabTo(t, tb, "the Stop page", `form[action="`+run+`/stop"] button[type="submit"]`, 10)
			tb.press(t, "Enter")
			arrive(t, tb, "the run page after Stop", `location.pathname === "`+run+`"`)
			toast(t, tb, "the run page after Stop", "nothing to stop")

			// 4. Deny on the run's waiting request, then its Receipt tab, in place.
			toMain(t, tb, "the run page")
			tabTo(t, tb, "the run page", `#ask-7 button[value="deny"]`, 20)
			answerByKey(t, tb, "the run page", `#ask-7 button[value="deny"]`, "Denied")
			tabTo(t, tb, "the run page", `nav.tabs a[href="`+run+`/receipt"]`, 30)
			tb.press(t, "Enter")
			arrive(t, tb, "the Receipt tab", `location.pathname === "`+run+`/receipt" && !!document.getElementById("h-rc")`)
			pageChecks(t, tb, "the Receipt tab", w, "journey-receipt-"+cfg, "")

			// 5. A timeline line's page, and the line as written.
			tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + run})
			arrive(t, tb, "the run page", `location.pathname === "`+run+`" && !!document.getElementById("tl-rows")`)
			toMain(t, tb, "the run page")
			tabTo(t, tb, "the run page", `#tl-rows a[href="`+run+`/lines/1"]`, 60)
			tb.press(t, "Enter")
			arrive(t, tb, "the line page", `location.pathname === "`+run+`/lines/1"`)
			toMain(t, tb, "the line page")
			tabTo(t, tb, "the line page", `details.ev-asis > summary`, 30)
			tb.press(t, "Enter")
			tb.until(t, "the line as written", `document.querySelector("details.ev-asis").open`)
			pageChecks(t, tb, "the line page", w, "journey-line-"+cfg, "")

			// 6. A Logs row opened in place.
			tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + "/logs"})
			arrive(t, tb, "Logs", `location.pathname === "/logs" && document.documentElement.classList.contains("lq-js")`)
			toMain(t, tb, "Logs")
			tabTo(t, tb, "Logs", `#lq-rows tr.lq-r .lx-tog`, 60)
			tb.press(t, "Enter")
			tb.until(t, "the row opened in place", `!!document.querySelector("tr.lx-row:not([hidden]) .lx-fields")`)
			pageChecks(t, tb, "Logs", w, "journey-logs-"+cfg, "")
			tb.c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
		}
	}
	fmt.Println("journey by keyboard in chrome: Tab and Enter alone at 390, 768 and 1440, light and dark; every stop shown with its ring, in order; no page error")
}

// TestReceiptTabInChrome renders the Receipt tab of four runs (a live run with refusals and a waiting request, a clean
// ended one, and markFixture's watched and enforced takes, with secrets read and refused) at 390, 768 and 1440 px
// wide, light and dark, and holds each to pageChecks.
func TestReceiptTabInChrome(t *testing.T) {
	c := placeChrome(t)
	root := fixture(t)
	marks := markFixture(t)
	for _, r := range []string{markWatchRun, markGuardRun} {
		if err := os.Rename(filepath.Join(marks, r), filepath.Join(root, r)); err != nil {
			t.Fatal(err)
		}
	}
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	base := "http://" + addr
	runs := []struct{ name, id, want string }{
		{"live", harmRun, "Refused, by rule"}, {"clean", cleanRun, "What this receipt can vouch for"},
		{"watched", markWatchRun, "Files written"}, {"enforced", markGuardRun, "Refused, by rule"},
	}
	for _, sz := range sweepSizes {
		for _, scheme := range []string{"light", "dark"} {
			cfg := fmt.Sprintf("%d-%s", sz[0], scheme)
			tb := sweepTab(t, c, "receipts at "+cfg, sz[0], sz[1], scheme)
			tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + "/?t=tok123"})
			arrive(t, tb, "the Overview", `location.pathname === "/" && !location.search`)
			for _, r := range runs {
				tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + "/runs/" + r.id + "/receipt"})
				arrive(t, tb, r.name+" receipt", `location.pathname === "/runs/`+r.id+`/receipt" && !!document.getElementById("h-rc") && document.querySelector("main").textContent.indexOf(`+strconv.Quote(r.want)+`) >= 0`)
				pageChecks(t, tb, "the "+r.name+" run's Receipt tab", sz[0], "receipt-"+r.name+"-"+cfg, "section.rc")
			}
			tb.c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
		}
	}
	fmt.Println("receipt tab in chrome: four runs at 390, 768 and 1440, light and dark; no sideways scroll, no small control, no page error")
}
