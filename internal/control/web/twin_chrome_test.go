// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The Block now panel's terminal twin in a real browser (static/twin.js): headless Chrome over the DevTools pipe
// (chrome_test.go's cdp) opens a live run's page, where the twin shows its placeholders. Typing a value, choosing a
// kind and each kind of time limit writes the command the form makes, each word as shellword.Quote writes it; an
// empty for… or until… field, a value holding a bidi override and an emptied value put the placeholders back; a
// selection of the command outlives a live update that leaves the panel as it is, and words that change under it are
// selected in turn; a live update that merges the server's placeholders in is followed by the fill again; and a
// timeline row's Block link opens the page with its twin filled in. Run it by hand, through the box's memory slice:
//
//	go test -tags chrome -run TestBlockTwinInChrome ./internal/control/web
//
// With TEGO_CHROME_SHOTS set it saves the panel with its twin filled in.

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/shellword"
)

func TestBlockTwinInChrome(t *testing.T) {
	c := placeChrome(t)
	root := fixture(t)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	page := "http://" + addr + "/runs/" + harmRun
	cmd := "tego block " + harmRun
	placeholders := cmd + " <exec|net|path> <value>"
	const twin = `document.querySelector("code[data-twin]").textContent`

	run := c.open(t, "run page", page+"?t=tok123")
	run.until(t, "loaded", `document.readyState === "complete" && !!document.querySelector("code[data-twin]")`)
	says := func(what, want string) {
		t.Helper()
		run.until(t, what+" reads "+want, twin+" === "+jsString(want))
	}
	field := func(name string) string {
		return `document.getElementById("block-form").elements.namedItem(` + jsString(name) + `)`
	}
	// typeIn types text over a field's text, as a keyboard does (an input event per change).
	typeIn := func(name, text string) {
		t.Helper()
		run.eval(t, field(name)+".focus(); "+field(name)+".select()")
		run.c.call(t, run.session, "Input.insertText", map[string]any{"text": text})
	}
	// set gives a field a value and fires what a person's change fires last: change for a select, input for a field.
	set := func(name, value, event string) {
		t.Helper()
		run.eval(t, `(function(){var e = `+field(name)+`; e.value = `+jsString(value)+`; e.dispatchEvent(new Event(`+jsString(event)+`, {bubbles: true}));})()`)
	}
	says("the twin on load", placeholders)

	run.eval(t, `document.getElementById("block-fold").open = true`)
	typeIn("value", "curl")
	says("a typed program", cmd+" exec curl")
	set("kind", "path", "change")
	typeIn("value", "/tmp/it's here")
	path := cmd + " path " + shellword.Quote("/tmp/it's here")
	says("a path with a quote and a space", path)
	set("for", "15m", "change")
	says("a fixed time limit", path+" --for 15m")
	run.shot(t, "block-twin")
	set("for", "for", "change")
	says("for… with nothing typed", placeholders)
	typeIn("span", "1d12h")
	says("a typed span", path+" --for 1d12h")
	set("for", "until", "change")
	says("until… with no time", placeholders)
	set("until", "2026-11-14T17:00", "input")
	says("a time picked", path+" --until '2026-11-14 17:00'")
	set("for", "perm", "change")
	says("permanently", path)
	typeIn("value", "/tmp/a\u202etxt.exe")
	says("a value with a bidi override", placeholders)
	typeIn("value", "curl")
	set("kind", "exec", "change")
	says("a plain program again", cmd+" exec curl")

	// The person selects the command to copy it, and the run writes a line meanwhile: the live update that follows
	// leaves the panel as it is, and the selection with it (the fill rewrote the same words once, which dropped it).
	const selection = `getSelection().toString()`
	run.eval(t, `window.__merged = 0; document.addEventListener("tego:merged", function () { window.__merged++; }); `+
		`document.activeElement.blur(); getSelection().selectAllChildren(document.querySelector("code[data-twin]"))`)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "exec", `"verdict":"allow","op":"exec","path":"/bin/echo"`))
	run.until(t, "a live update with the run's new line", `window.__merged > 0 && !!document.getElementById("l7")`)
	if got := run.eval(t, selection); got != jsString(cmd+" exec curl") {
		t.Errorf("after a live update the selection is %s, want the command", got)
	}
	// Words that change under the selection are selected in turn, so a copy takes the command the form makes now.
	set("kind", "net", "change")
	says("a kind changed under the selection", cmd+" net curl")
	if got := run.eval(t, selection); got != jsString(cmd+" net curl") {
		t.Errorf("after the kind changed the selection is %s, want the new command", got)
	}
	set("kind", "exec", "change")
	says("the program again", cmd+" exec curl")

	// A live update merges the server's twin, its placeholders, back in; the fill that follows it writes the form's.
	run.eval(t, twin+" = "+jsString(placeholders)+`; document.dispatchEvent(new CustomEvent("tego:merged"))`)
	says("after a live update", cmd+" exec curl")
	set("value", "", "input")
	says("an emptied value", placeholders)

	// The Block link on a timeline row opens the panel filled in, and the twin with it.
	pre := c.open(t, "prefilled run page", page+"?block=net&value=example.com%3A443#block")
	pre.until(t, "the prefilled twin", `document.readyState === "complete" && document.querySelector("code[data-twin]").textContent === `+
		jsString(cmd+" net example.com:443"))
}
