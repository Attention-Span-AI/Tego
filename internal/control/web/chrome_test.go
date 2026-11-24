// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The dashboard in a real browser (D-LIVE): headless Chrome, driven over --remote-debugging-pipe (the DevTools protocol
// on fds 3 and 4, no WebSocket and no port), opens the Overview and a live run's page while that run writes lines, an
// ask comes and is answered, an inline Deny reports in a toast, and the run ends. A marker set on each window at load
// must survive to the end: a reload would clear it. Run it by hand, through the box's memory slice:
//
//	go test -tags chrome -run TestLiveInChrome ./internal/control/web
//
// It needs google-chrome (or $TEGO_CHROME) on the machine; it is not part of the default suites.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// chromeOutput is read while Chrome can still write diagnostics.
// A plain bytes.Buffer races with exec.Cmd's stderr copier.
type chromeOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *chromeOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *chromeOutput) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

// cdp is a DevTools protocol connection over Chrome's debugging pipe.
type cdp struct {
	prepared bool
	w        *os.File
	mu       sync.Mutex
	id       int
	wait     map[int]chan json.RawMessage
	// seen is, for each session watch was given, the page errors the reader has met since its tab's problems
	// last took them.
	seen map[string][]string
}

func (c *cdp) call(t *testing.T, session, method string, params any) json.RawMessage {
	t.Helper()
	r, err := c.try(session, method, params)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// try is call without the test: an error the caller may retry (a page swapping its process mid-navigation answers
// Runtime.evaluate with "Cannot find default execution context" for a moment).
func (c *cdp) try(session, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	c.id++
	id := c.id
	ch := make(chan json.RawMessage, 1)
	c.wait[id] = ch
	msg := map[string]any{"id": id, "method": method, "params": params}
	if session != "" {
		msg["sessionId"] = session
	}
	b, _ := json.Marshal(msg)
	_, err := c.w.Write(append(b, 0))
	c.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	select {
	case r := <-ch:
		var resp struct {
			Result json.RawMessage
			Error  *struct{ Message string }
		}
		_ = json.Unmarshal(r, &resp)
		if resp.Error != nil {
			return nil, fmt.Errorf("%s: %s", method, resp.Error.Message)
		}
		return resp.Result, nil
	case <-time.After(20 * time.Second):
		c.mu.Lock()
		delete(c.wait, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("%s: no answer", method)
	}
}

// transientCDP is an error a page gives while it navigates or swaps its renderer process: the evaluation is retried.
func transientCDP(err error) bool {
	m := err.Error()
	return strings.Contains(m, "Cannot find default execution context") || strings.Contains(m, "Execution context was destroyed") ||
		strings.Contains(m, "Cannot find context with specified id")
}

// pageNotReady is the exception a waiting expression gives while the document is being replaced: after a click that
// navigates, the new document has no body for a moment (document.body is null) and an element of the next page is not
// there yet, so `document.body.innerText` or `document.querySelector(...).x` throws "Cannot read properties of null".
// until takes that as "not yet" and asks again inside its one deadline, and names the last such answer if the deadline
// passes; eval, which asks once, still fails on it. Gate 35 failed on exactly this in TestAgentsForgetInChrome on a
// loaded machine (twelve repeats on a quiet one passed).
func pageNotReady(err error) bool {
	m := err.Error()
	return strings.HasPrefix(m, "page evaluation:") && strings.Contains(m, "Cannot read properties of null")
}

// TestPageNotReadyIsOnlyTheNullRead holds pageNotReady to the one exception: any other page error still fails a wait at once.
func TestPageNotReadyIsOnlyTheNullRead(t *testing.T) {
	for msg, want := range map[string]bool{
		"page evaluation: Uncaught: TypeError: Cannot read properties of null (reading 'innerText')": true,
		"page evaluation: Uncaught: TypeError: Cannot read properties of null (reading 'open')":      true,
		"page evaluation: Uncaught: ReferenceError: nosuch is not defined":                           false,
		"page evaluation: Uncaught: SyntaxError: Unexpected token ')'":                               false,
		"page evaluation: Uncaught: TypeError: Cannot read properties of undefined (reading 'x')":    false,
		"Runtime.evaluate: no answer": false,
	} {
		if got := pageNotReady(errors.New(msg)); got != want {
			t.Errorf("pageNotReady(%q) = %v, want %v", msg, got, want)
		}
	}
}

// read hands each answer to the call waiting for it and keeps each page error of a watched session (watch).
func (c *cdp) read(r *os.File) {
	br := bufio.NewReader(r)
	for {
		b, err := br.ReadBytes(0)
		if err != nil {
			return
		}
		b = bytes.TrimSuffix(b, []byte{0})
		var m struct {
			ID      int             `json:"id"`
			Method  string          `json:"method"`
			Session string          `json:"sessionId"`
			Params  json.RawMessage `json:"params"`
		}
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.wait[m.ID]
			delete(c.wait, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- json.RawMessage(b)
			}
			continue
		}
		if p := problemOf(m.Method, m.Params); p != "" {
			c.mu.Lock()
			if got, ok := c.seen[m.Session]; ok {
				c.seen[m.Session] = append(got, p)
			}
			c.mu.Unlock()
		}
	}
}

// cspBinding is the function watch gives every page, which cspListener calls with each Content Security Policy
// violation.
const cspBinding = "tegoCSP"

// cspListener runs before a page's own scripts and reports each securitypolicyviolation event (a style, script,
// image or connection the page's policy refused, an inline style attribute included) through cspBinding.
const cspListener = `document.addEventListener("securitypolicyviolation", function (e) {
	if (typeof window.` + cspBinding + ` === "function") window.` + cspBinding + `(e.effectiveDirective + " refused " +
		(e.blockedURI || "an inline") + " in " + e.sourceFile + ":" + e.lineNumber + (e.sample ? " (" + e.sample + ")" : ""));
}, true);`

// problemOf is the page error a DevTools event reports, or "" when it reports none: an uncaught exception, a
// console.error or a failed console.assert, an error the browser itself logs (a Content Security Policy refusal, a
// resource that failed to load), and a securitypolicyviolation event (cspListener).
func problemOf(method string, params json.RawMessage) string {
	switch method {
	case "Runtime.exceptionThrown":
		var p struct {
			ExceptionDetails struct {
				Text       string
				URL        string
				LineNumber int
				Exception  *struct{ Description string }
			}
		}
		_ = json.Unmarshal(params, &p)
		d := p.ExceptionDetails
		s := "uncaught exception: " + d.Text
		if d.Exception != nil && d.Exception.Description != "" {
			s += " " + d.Exception.Description
		}
		return fmt.Sprintf("%s (%s:%d)", s, d.URL, d.LineNumber)
	case "Runtime.consoleAPICalled":
		var p struct {
			Type string
			Args []struct {
				Value       json.RawMessage
				Description string
			}
		}
		_ = json.Unmarshal(params, &p)
		if p.Type != "error" && p.Type != "assert" {
			return ""
		}
		var words []string
		for _, a := range p.Args {
			if a.Description != "" {
				words = append(words, a.Description)
			} else {
				words = append(words, string(a.Value))
			}
		}
		return "console." + p.Type + ": " + strings.Join(words, " ")
	case "Log.entryAdded":
		var p struct {
			Entry struct{ Source, Level, Text, URL string }
		}
		_ = json.Unmarshal(params, &p)
		if p.Entry.Level != "error" {
			return ""
		}
		return "browser " + p.Entry.Source + " error: " + p.Entry.Text + " " + p.Entry.URL
	case "Runtime.bindingCalled":
		var p struct{ Name, Payload string }
		_ = json.Unmarshal(params, &p)
		if p.Name != cspBinding {
			return ""
		}
		return "securitypolicyviolation: " + p.Payload
	}
	return ""
}

// watch keeps tb's page errors (problemOf) from now on, across its navigations, for problems and clean to take.
// Give it a tab still on about:blank, so the listener is on the first page from its first byte.
func (c *cdp) watch(t *testing.T, tb *tab) {
	t.Helper()
	c.mu.Lock()
	if c.seen == nil {
		c.seen = map[string][]string{}
	}
	c.seen[tb.session] = nil
	c.mu.Unlock()
	for _, m := range []string{"Runtime.enable", "Log.enable", "Page.enable"} {
		c.call(t, tb.session, m, map[string]any{})
	}
	c.call(t, tb.session, "Runtime.addBinding", map[string]any{"name": cspBinding})
	c.call(t, tb.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": cspListener})
}

// problems takes the page errors watch kept on tb since the last take. An answer to a later call on the same session
// comes after the events before it, so an eval first is enough to see what a page did up to then.
func (tb *tab) problems() []string {
	tb.c.mu.Lock()
	defer tb.c.mu.Unlock()
	p := tb.c.seen[tb.session]
	tb.c.seen[tb.session] = nil
	return p
}

// clean fails t with each page error watch kept on tb since the last take, saying when it came.
func (tb *tab) clean(t *testing.T, when string) {
	t.Helper()
	time.Sleep(150 * time.Millisecond) // a failed resource is logged a moment after the page has it
	tb.eval(t, `0`)
	for _, p := range tb.problems() {
		t.Errorf("%s: %s: %s", tb.name, when, p)
	}
}

// keys are the keys press knows, as the DevTools protocol takes them; Enter's text is the keypress a button's
// activation needs (a link's comes on its key down).
var keys = map[string]map[string]any{
	"Escape": {"key": "Escape", "code": "Escape", "windowsVirtualKeyCode": 27},
	"Tab":    {"key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9},
	"Enter":  {"key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "text": "\r", "unmodifiedText": "\r"},
}

// press presses key on tb's page and lets it go, as a keyboard does: the browser's own handling follows (Tab moves
// the focus, Enter follows a link or presses a button).
func (tb *tab) press(t *testing.T, key string) {
	t.Helper()
	k, ok := keys[key]
	if !ok {
		t.Fatalf("press: no key %q", key)
	}
	down := map[string]any{"type": "rawKeyDown"}
	if _, text := k["text"]; text {
		down["type"] = "keyDown"
	}
	up := map[string]any{"type": "keyUp"}
	for n, v := range k {
		down[n] = v
		if n != "text" && n != "unmodifiedText" {
			up[n] = v
		}
	}
	tb.c.call(t, tb.session, "Input.dispatchKeyEvent", down)
	tb.c.call(t, tb.session, "Input.dispatchKeyEvent", up)
}

// tab is one page target.
type tab struct {
	c       *cdp
	session string
	name    string
	target  string
}

// closeTarget waits for the target registry as well as the close acknowledgement.
// Chrome can acknowledge the request before the page has left that registry.
func (c *cdp) closeTarget(t *testing.T, target string) {
	t.Helper()
	listed := func() bool {
		var pages struct{ TargetInfos []struct{ TargetID string } }
		_ = json.Unmarshal(c.call(t, "", "Target.getTargets", map[string]any{}), &pages)
		for _, p := range pages.TargetInfos {
			if p.TargetID == target {
				return true
			}
		}
		return false
	}
	if !listed() {
		return
	}
	if _, err := c.try("", "Target.closeTarget", map[string]any{"targetId": target}); err != nil {
		if strings.Contains(err.Error(), "No target with given id") {
			return
		}
		t.Fatal(err)
	}
	for deadline := time.Now().Add(3 * time.Second); listed(); {
		if time.Now().After(deadline) {
			t.Fatal("closed browser page remained in the target registry")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// open loads url in a new window: a second tab in one window would be hidden behind the first, and a hidden tab
// follows no stream.
func (c *cdp) open(t *testing.T, name, url string) *tab {
	t.Helper()
	// Close the browser's unused startup page, then enforce the shared-host cap.
	var pages struct {
		TargetInfos []struct{ TargetID, Type string }
	}
	_ = json.Unmarshal(c.call(t, "", "Target.getTargets", map[string]any{}), &pages)
	count := 0
	for _, p := range pages.TargetInfos {
		if p.Type != "page" {
			continue
		}
		if !c.prepared {
			c.call(t, "", "Target.closeTarget", map[string]any{"targetId": p.TargetID})
		} else {
			count++
		}
	}
	c.prepared = true
	if count >= 4 {
		t.Fatal("browser page cap: close a page before opening another")
	}
	var target struct{ TargetID string }
	if err := json.Unmarshal(c.call(t, "", "Target.createTarget", map[string]any{"url": url, "newWindow": true}), &target); err != nil || target.TargetID == "" {
		t.Fatalf("create browser target: id %q, decode error %v", target.TargetID, err)
	}
	// Register before attaching: a fatal error there or in a subtest must not leave
	// its renderer open for the remaining matrix. Explicit earlier closes are fine.
	t.Cleanup(func() {
		_, _ = c.try("", "Target.closeTarget", map[string]any{"targetId": target.TargetID})
	})
	var att struct{ SessionID string }
	_ = json.Unmarshal(c.call(t, "", "Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}), &att)
	t.Cleanup(func() { c.closeTarget(t, target.TargetID) })
	return &tab{c, att.SessionID, name, target.TargetID}
}

// eval returns a JavaScript expression's value as JSON text.
func (tb *tab) eval(t *testing.T, expr string) string {
	t.Helper()
	v, err := tb.tryEval(expr)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// tryEval is eval returning its error, for until to retry a transient one.
func (tb *tab) tryEval(expr string) (string, error) {
	var r struct {
		Result struct {
			Value json.RawMessage
		}
		ExceptionDetails *struct {
			Text      string
			Exception struct{ Description string }
		}
	}
	raw, err := tb.c.try(tb.session, "Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true})
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", err
	}
	if r.ExceptionDetails != nil {
		return "", fmt.Errorf("page evaluation: %s: %s", r.ExceptionDetails.Text, r.ExceptionDetails.Exception.Description)
	}
	return string(r.Result.Value), nil
}

// shot saves a screenshot to $TEGO_CHROME_SHOTS/<name>.png when that is set, to look at by hand.
func (tb *tab) shot(t *testing.T, name string) {
	t.Helper()
	dir := os.Getenv("TEGO_CHROME_SHOTS")
	if dir == "" {
		return
	}
	tb.c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target}) // a background tab may not paint
	tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": false})
	var r struct{ Data []byte }
	_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
	if err := os.WriteFile(filepath.Join(dir, name+".png"), r.Data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// until waits for expr to be true.
func (tb *tab) until(t *testing.T, what, expr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var notReady error
	for time.Now().Before(deadline) {
		v, err := tb.tryEval(expr)
		if err != nil && !transientCDP(err) && !pageNotReady(err) {
			t.Fatalf("%s: %s: %v", tb.name, what, err)
		}
		if err != nil && pageNotReady(err) {
			notReady = err
		}
		if v == "true" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	text, err := tb.tryEval("document.body.innerText.slice(0, 3000)")
	t.Fatalf("%s: %s never held (%v; last not-ready answer: %v); page text:\n%s", tb.name, what, err, notReady, text)
}

func TestLiveInChrome(t *testing.T) {
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	root := fixture(t)
	srv, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)

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
	cmd.ExtraFiles = []*os.File{cmdR, outW} // fd 3: commands to Chrome, fd 4: its answers
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

	base := "http://" + addr
	ov := c.open(t, "overview", base+"/?t=tok123")
	run := c.open(t, "run page", base+"/runs/"+harmRun+"?t=tok123")
	for _, tb := range []*tab{ov, run} {
		tb.until(t, "loaded", `document.readyState === "complete" && !!document.body.dataset.sig`)
		tb.eval(t, `window.__tegoMark = "kept"`)
	}
	// Both pages follow the /events stream, not the poll.
	for deadline := time.Now().Add(10 * time.Second); srv.streams.Load() < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d /events streams open, want one per page", srv.streams.Load())
		}
	}
	start := time.Now()
	kept := func(when string) {
		t.Helper()
		t.Logf("%6.2fs %s", time.Since(start).Seconds(), when)
		for _, tb := range []*tab{ov, run} {
			if tb.eval(t, `window.__tegoMark`) != `"kept"` {
				t.Fatalf("%s reloaded %s", tb.name, when)
			}
		}
	}

	// 1. The run writes lines: the run page's timeline adds them, the Overview's refusals show the new one.
	now := time.Now()
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "exec", `"verdict":"allow","op":"exec","path":"/bin/echo"`))
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now, "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/live-refusal-1"`))
	// The new lines carry no model step, so they sit in the "not tied" group: a header, then the newest row (a line of the
	// timeline's top is the first row, with at most its group's header above it).
	run.until(t, "the new rows at the top of the timeline", `!!document.getElementById("l8") && (function () {
		var top = document.querySelector("#tl-rows > .tl"), head = top.previousElementSibling;
		return top.id === "l8" && top.nextElementSibling.id === "l7" && !!head && head.classList.contains("tl-step") &&
			head.textContent.indexOf("Not tied to a model step") === 0 && head === document.getElementById("tl-rows").firstElementChild;
	})()`)
	ov.until(t, "the new refusal in Recent refusals", `document.querySelector("[data-live=r-ov-refusals]").textContent.includes("/p/live-refusal-1")`)
	kept("while the run wrote lines")

	// 2. An ask comes: both pages update the shared band and the navigation count.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now, "fs", `"verdict":"ask","rule":"fs.ask[/p/]","op":"write","path":"/p/held.txt"`))
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 10, now, "ask", `"ask_id":"ask-9","hold":"fs"`))
	ov.until(t, "two asks in the banner", `document.getElementById("ask-banner").textContent.includes("2 requests are waiting") && document.querySelector(".nav .count").textContent.startsWith("2")`)
	ov.until(t, "the tab title count", `document.title.startsWith("(2) ")`)
	run.until(t, "the additional waiting request", `document.querySelector(".nav").dataset.askKeys.includes("ask-9") && document.querySelector("#ask-banner .ab-act a").getAttribute("aria-label").includes("2 waiting")`)
	kept("when an ask came")

	// 3. It is answered (in a terminal): the precise request leaves both bands.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 11, now, "answer", `"ask_id":"ask-9","verdict":"allow"`))
	ov.until(t, "one ask left", `document.getElementById("ask-banner").textContent.includes("demo-harm is waiting for you") && document.title.startsWith("(1) ")`)
	run.until(t, "the answered request gone", `!document.querySelector(".nav").dataset.askKeys.includes("ask-9") && document.querySelector("#ask-banner [name=ask]").value==="ask-7"`)
	kept("when an ask was answered")

	// 4. Deny on the run page posts in the background; with no broker the answer fails, and a toast says so.
	run.eval(t, `document.querySelector('#ask-banner button[value="deny"]').click()`)
	run.until(t, "a toast", `!!document.querySelector(".toast-err") && document.querySelector(".toast-err").textContent.includes("Not done")`)
	kept("after Deny")
	run.shot(t, "run-toast")
	ov.shot(t, "overview-live")

	// 5. The run ends: the run page reads it ended and stops following; the Overview says nothing is running.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 12, now, "run_end", `"reason":"exit","exit_code":0`))
	if err := os.Remove(filepath.Join(root, ".live", harmRun)); err != nil {
		t.Fatal(err)
	}
	run.until(t, "the run ended", `document.querySelector("#run-details .sub-h1").textContent.includes("Exit 0") && !document.querySelector('a[href$="/stop"]')`)
	run.until(t, "the timeline stopped following", `!document.getElementById("tl-rows").hasAttribute("data-rows")`)
	ov.until(t, "nothing running", `document.querySelector("[data-live=r-ov-head]").textContent.includes("Nothing needs you") && !document.querySelector(".ov-running .phone-row")`)
	kept("when the run ended")
	run.shot(t, "run-ended")

	// 6. A hidden tab closes its stream and polls, and opens it again when shown (each page here has a window of its
	// own, so every one is shown; the test hides one by hand).
	waitStreams := func(what string, ok func(int32) bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !ok(srv.streams.Load()); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d streams open", what, srv.streams.Load())
			}
		}
	}
	waitStreams("both pages follow the stream", func(n int32) bool { return n == 2 })
	ov.eval(t, `Object.defineProperty(document, "hidden", {configurable: true, get: function () { return true; }}); document.dispatchEvent(new Event("visibilitychange"))`)
	waitStreams("a hidden tab closes its stream", func(n int32) bool { return n == 1 })
	ov.eval(t, `delete document.hidden; document.dispatchEvent(new Event("visibilitychange"))`)
	waitStreams("a shown tab opens it again", func(n int32) bool { return n == 2 })

	// 7. Exercise five more pages in batches of two. Together with the live
	// Overview and Run this keeps at most four pages open on the shared host.
	for first := 0; first < 5; first += 2 {
		tabs := []*tab{ov, run}
		for i := first; i < first+2 && i < 5; i++ {
			tb := c.open(t, fmt.Sprintf("tab %d", i+3), base+"/runs?t=tok123")
			tb.until(t, "loaded", `document.readyState === "complete" && !!document.body.dataset.sig`)
			tabs = append(tabs, tb)
		}
		time.Sleep(time.Second)
		if n := srv.streams.Load(); n > maxStreams {
			t.Fatalf("%d streams open, more than %d", n, maxStreams)
		}
		for _, tb := range tabs {
			tb.eval(t, `window.__tegoFetch = ""; fetch("/status.json", {cache: "no-store"}).then(function (r) { window.__tegoFetch = String(r.status); })`)
		}
		for _, tb := range tabs {
			tb.until(t, "a fetch with four or fewer pages open", `window.__tegoFetch === "200"`)
		}
		kept("with bounded page batches")
		for _, tb := range tabs[2:] {
			c.closeTarget(t, tb.target)
		}
	}

	// Reserve capacity without opening more browser pages. A rejected stream
	// must fall back to repeated status polling and still merge ledger changes.
	t.Run("saturated-stream-polls", func(t *testing.T) {
		pollRoot := fixture(t)
		ps, pa, _ := liveServer(t, pollRoot, 10*time.Second, 30*time.Second)
		ps.streams.Store(maxStreams)
		defer ps.streams.Store(0)
		tb := c.open(t, "saturated stream", "http://"+pa+"/?t=tok123")
		defer c.closeTarget(t, tb.target)
		tb.until(t, "polling after stream rejection", `performance.getEntriesByType('resource').filter(e=>new URL(e.name).pathname==='/status.json').length>=2`)
		tb.eval(t, `window.__pollPageMark='kept'`)
		appendLine(t, pollRoot, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/poll-fallback-refusal"`))
		tb.until(t, "polling merges new records", `document.querySelector('[data-live=r-ov-refusals]').textContent.includes('/p/poll-fallback-refusal')`)
		if tb.eval(t, `window.__pollPageMark`) != `"kept"` {
			t.Fatal("poll fallback reloaded the page")
		}
		if ps.streams.Load() != maxStreams {
			t.Fatal("a rejected stream changed reserved capacity")
		}
	})

	fmt.Println("live in chrome: no reload; rows, an ask, its answer, a toast and the run's end all shown in place; five additional pages still fetch in bounded batches")
}

// Shared authenticated URL and page cleanup helpers also serve public browser guards.
func a1URL(addr, path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return "http://" + addr + path + sep + "t=tok123"
}

func a1Close(t *testing.T, tb *tab) {
	tb.c.closeTarget(t, tb.target)
}
