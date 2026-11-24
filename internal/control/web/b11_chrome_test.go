// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// b11Browser starts headless Chrome over the debugging pipe and returns its driver.
func b11Browser(t *testing.T) *cdp {
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
	// Chrome's helpers can still be writing the profile after the browser is killed: removed best effort, not by
	// t.TempDir, whose cleanup would fail the test.
	prof, err := os.MkdirTemp("", "tego-b11-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(prof) })
	cmd := exec.Command(chrome, "--headless=new", "--remote-debugging-pipe", "--user-data-dir="+prof,
		"--no-first-run", "--no-default-browser-check", "--disable-gpu", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-component-update", "about:blank")
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	var stderr chromeOutput
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

// b11Size sets the viewport and the colour scheme of tb.
func b11Size(t *testing.T, tb *tab, width int, scheme string) {
	t.Helper()
	tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 900, "deviceScaleFactor": 1, "mobile": width < 600})
	tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
}

// b11Shot saves tb's page as name, 1280 or 390 wide, light and dark, when TEGO_CHROME_SHOTS names a folder, and fails
// when the page scrolls sideways at any of them (checked whether or not shots are kept).
func b11Shot(t *testing.T, tb *tab, name, scrollTo string) {
	t.Helper()
	dir := os.Getenv("TEGO_CHROME_SHOTS")
	for _, w := range []int{1280, 390} {
		for _, scheme := range []string{"light", "dark"} {
			b11Size(t, tb, w, scheme)
			if scrollTo != "" {
				tb.eval(t, `(function(){var r=document.querySelector(`+strconv.Quote(scrollTo)+`);if(r)r.scrollIntoView({block:"center"});})()`)
			}
			time.Sleep(200 * time.Millisecond)
			if tb.eval(t, `document.documentElement.scrollWidth > window.innerWidth`) != "false" {
				t.Errorf("%s at %d (%s): the page scrolls sideways", name, w, scheme)
			}
			if dir == "" {
				continue
			}
			tb.c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target})
			var r struct{ Data []byte }
			_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
			if err := os.WriteFile(filepath.Join(dir, name+"-"+strconv.Itoa(w)+"-"+scheme+".png"), r.Data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	b11Size(t, tb, 1280, "light")
}

// TestOpenRowFollowsItsStateInChrome: a Logs row opened in place follows the state behind it. A line that arrives
// changes the panel's "line N of M"; the panel is merged in place: the same elements, the focused button still
// focused, a field list the reader closed still closed, and the page not scrolled.
func TestOpenRowFollowsItsStateInChrome(t *testing.T) {
	root, _ := progFixture(t)
	markLive(t, root, progRun)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := b11Browser(t)
	lg := c.open(t, "logs", "http://"+addr+"/logs?t=tok123")
	b11Size(t, lg, 1280, "light")
	lg.until(t, "loaded", `document.readyState === "complete" && document.documentElement.classList.contains("lq-js")`)
	lg.eval(t, `document.querySelectorAll("#lq-rows tr.lq-r")[1].querySelector(".lx-tog").click()`)
	lg.until(t, "the open row's fields", `!!document.querySelector("tr.lx-row .lx-fields")`)
	total := func() string {
		return lg.eval(t, `(document.querySelector("tr.lx-row .lx-kv").textContent.match(/ of (\d+)/)||[])[1]||""`)
	}
	before := total()
	// The reader closes the field list, focuses Copy, and is a little down the page.
	lg.eval(t, `(function(){var d=document.querySelector("tr.lx-row .lx-all");d.open=false;window.__node=document.querySelector("tr.lx-row .lx-kv");window.__btn=document.querySelector("tr.lx-row .lx-copy");window.__btn.focus();window.scrollTo(0,40);window.__y=window.scrollY})()`)
	appendLine(t, root, progRun, line(progRun, "codex", 153, progT0.Add(153*time.Second), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`))
	lg.until(t, "the panel says the new total", `JSON.stringify((document.querySelector("tr.lx-row .lx-kv").textContent.match(/ of (\d+)/)||[])[1]) !== `+strconv.Quote(before))
	if got := total(); got == before {
		t.Fatalf("the open panel still says %s", got)
	}
	if lg.eval(t, `window.__node === document.querySelector("tr.lx-row .lx-kv")`) != "true" {
		t.Error("the panel's elements were replaced, not merged")
	}
	if lg.eval(t, `document.activeElement === window.__btn`) != "true" {
		t.Error("the focused button lost focus")
	}
	if lg.eval(t, `document.querySelector("tr.lx-row .lx-all").open`) != "false" {
		t.Error("the field list the reader closed was reopened")
	}
	if lg.eval(t, `window.scrollY === window.__y`) != "true" {
		t.Error("the page was scrolled")
	}
	b11Shot(t, lg, "b11-logs-open-row", "tr.lx-row")
}

// TestGroupedLogsCatchUpAtTheTopInChrome: a grouped Logs view follows the record at the top of the page, waits lower
// down, and catches up when the reader scrolls back to the top (C92); it says so on the page.
func TestGroupedLogsCatchUpAtTheTopInChrome(t *testing.T) {
	root, _ := progFixture(t)
	markLive(t, root, progRun)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := b11Browser(t)
	lg := c.open(t, "groups", "http://"+addr+"/logs?t=tok123&group=rule")
	b11Size(t, lg, 1280, "light")
	lg.until(t, "loaded", `document.readyState === "complete" && !!document.querySelector(".t-grp")`)
	if lg.eval(t, `document.querySelector(".lq-live-note").textContent.includes("follow the record while you are at the top")`) != "true" {
		t.Error("the grouped view does not say what follows the record")
	}
	lines := `document.querySelector(".t-grp tbody tr .g-n").textContent.trim()`
	first := lg.eval(t, lines)
	lg.eval(t, `document.querySelector("main").style.minHeight = "3000px"; window.scrollTo(0, 600)`)
	lg.until(t, "scrolled down", `window.scrollY > 300`)
	appendLine(t, root, progRun, line(progRun, "codex", 153, progT0.Add(153*time.Second), "fs", `"verdict":"allow","rule":"fs.read[/w/x/proj]","op":"open","path":"/w/x/proj/late.txt","flags":0`))
	time.Sleep(3 * time.Second) // the stream's state, the throttle of one ask a second, and a refresh that must not come
	if got := lg.eval(t, lines); got != first {
		t.Fatalf("a grouped view moved under a reader lower down: %s, was %s", got, first)
	}
	lg.eval(t, `window.scrollTo(0, 0)`)
	lg.until(t, "the groups caught up at the top", `JSON.stringify(`+lines+`) !== `+strconv.Quote(first))
	b11Shot(t, lg, "b11-logs-groups", "")
}

// TestTimelineDetailsOpenInPlaceInChrome: a run timeline row's details open under the row (C109) with no new page:
// from the keyboard (Enter on the row's link) and the pointer, focus moves into the panel, Escape, Close and the browser's
// Back each close it and return focus to the link, the link stays a link to the line's page (the no-script path), and
// an open panel follows a line that arrives.
func TestTimelineDetailsOpenInPlaceInChrome(t *testing.T) {
	root, _ := progFixture(t)
	markLive(t, root, progRun)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := b11Browser(t)
	tb := c.open(t, "run", "http://"+addr+"/runs/"+progRun+"?t=tok123")
	b11Size(t, tb, 1280, "light")
	tb.until(t, "loaded", `document.readyState === "complete" && !!document.querySelector("#tl-rows a.seq")`)
	tb.eval(t, `window.__mark = "kept"; window.__path = location.pathname + location.search; window.__link = document.querySelector("#tl-rows a.seq")`)
	if tb.eval(t, `/\/runs\/.+\/lines\/\d+$/.test(window.__link.getAttribute("href"))`) != "true" {
		t.Fatal("the row's link is not a link to the line's page")
	}
	same := func(when string) {
		t.Helper()
		if tb.eval(t, `window.__mark === "kept" && location.pathname + location.search === window.__path`) != "true" {
			t.Fatalf("the page was left %s", when)
		}
	}
	state := `JSON.stringify([!!document.querySelector(".tl-detail .lx-fields"), document.activeElement === document.querySelector(".tl-detail"), window.__link.getAttribute("aria-expanded")])`
	// From the keyboard: Enter on the focused link opens the details and focus moves into them.
	tb.eval(t, `window.__link.focus()`)
	tb.press(t, "Enter")
	tb.until(t, "the panel with its fields, focused", state+` === '[true,true,"true"]'`)
	same("when Enter opened the details")
	if tb.eval(t, `document.querySelector(".tl-detail").previousElementSibling === window.__link.closest(".tl")`) != "true" {
		t.Error("the panel is not under its row")
	}
	// Escape closes it and focus returns to the link.
	tb.press(t, "Escape")
	tb.until(t, "Escape closed the panel", `!document.querySelector(".tl-detail") && document.activeElement === window.__link`)
	// The pointer: a click opens it; Close closes it; focus returns to the link.
	tb.eval(t, `window.__link.click()`)
	tb.until(t, "the panel", `!!document.querySelector(".tl-detail .lx-fields")`)
	tb.eval(t, `document.querySelector(".tl-detail-x").click()`)
	tb.until(t, "Close closed the panel", `!document.querySelector(".tl-detail") && document.activeElement === window.__link`)
	// Back closes it too, and stays on the run page.
	tb.eval(t, `window.__link.click()`)
	tb.until(t, "the panel", `!!document.querySelector(".tl-detail .lx-fields")`)
	tb.eval(t, `history.back()`)
	tb.until(t, "Back closed the panel", `!document.querySelector(".tl-detail") && document.activeElement === window.__link`)
	same("when Back closed the details")
	// A line that arrives is followed by the open panel, in place.
	tb.eval(t, `window.__link.click()`)
	tb.until(t, "the panel", `!!document.querySelector(".tl-detail .lx-fields")`)
	of := `JSON.stringify((document.querySelector(".tl-detail .lx-kv").textContent.match(/ of (\d+)/)||[])[1])`
	before := tb.eval(t, of)
	tb.eval(t, `window.__kv = document.querySelector(".tl-detail .lx-kv")`)
	appendLine(t, root, progRun, line(progRun, "codex", 153, progT0.Add(153*time.Second), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`))
	tb.until(t, "the panel says the new total", of+` !== `+strconv.Quote(before))
	if tb.eval(t, `window.__kv === document.querySelector(".tl-detail .lx-kv")`) != "true" {
		t.Error("the open panel was replaced, not merged")
	}
	b11Shot(t, tb, "b11-run-details", ".tl-detail")
	same("at the end")
}

// TestMCPAndRoutesFollowTheLedgerInChrome: the MCP tools and Model routes pages change in place when a call or a
// request is recorded (C77, C78): same document, an open details element still open, a run picker the reader
// is using untouched.
func TestMCPAndRoutesFollowTheLedgerInChrome(t *testing.T) {
	for _, tc := range []struct {
		name, path, region string
		root               func(*testing.T) string
		run, agent         string
		kind, extra        string
		source             string
	}{
		{"mcp", "/mcp?t=tok123&run=" + mcpRun, ".mcp-table", mcpLiveFixture, mcpRun, "mcp-demo", "mcp",
			`"rule":"mcp[files]","verdict":"allow","authority":"rule","name":"files","transport":"stdio","tool":"read_file"`, "proxy"},
		{"routes", "/routes?t=tok123&run=" + routesRun, ".rt-opts", routesLiveFixture, routesRun, "routed-agent", "ssl_request",
			`"endpoint":"anthropic","method":"POST","path":"/v1/messages","host":"api.anthropic.com","size":120,"route":{"name":"corp-proxy","authority":"llm-proxy.corp.example:8443"}`, "forwarder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.root(t)
			_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
			c := b11Browser(t)
			tb := c.open(t, tc.name, "http://"+addr+tc.path)
			b11Size(t, tb, 1280, "light")
			tb.until(t, "loaded", `document.readyState === "complete" && !!document.querySelector(`+strconv.Quote(tc.region)+`)`)
			tb.eval(t, `window.__mark = "kept"; window.__text = document.querySelector(`+strconv.Quote(tc.region)+`).innerText; var d = document.querySelector("details.row-details, details.rt-hist"); if (d) { d.open = true; window.__d = d }`)
			appendLine(t, root, tc.run, strings.Replace(line(tc.run, tc.agent, 40, time.Now(), tc.kind, tc.extra), `"source":"supervisor"`, `"source":"`+tc.source+`"`, 1))
			tb.until(t, "the page shows the new line", `document.querySelector(`+strconv.Quote(tc.region)+`).innerText !== window.__text`)
			if tb.eval(t, `window.__mark === "kept"`) != "true" {
				t.Error("the page reloaded")
			}
			if tb.eval(t, `!window.__d || (window.__d.isConnected && window.__d.open)`) != "true" {
				t.Error("a details element the reader opened was closed or replaced")
			}
			b11Shot(t, tb, "b11-"+tc.name+"-live", "")
		})
	}
}
