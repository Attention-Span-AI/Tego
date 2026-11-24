// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestB15ReceiptTabInChrome: the Receipt tab of a run whose model traffic was priced with the machine's table and
// whose record has a capture gap and another gap, in a real browser at 390 and 1280 px, light and dark. It must say the
// cost the terminal receipt says, give the capture note its own link (to the capture gap lines) and the record note
// its, scroll nowhere sideways, and break no control under 24 by 24 px at 390 px. TEGO_CHROME_SHOTS saves each window.
func TestB15ReceiptTabInChrome(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000073-b15aaa"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	root := t.TempDir()
	finishRun(t, root, run,
		line(run, "py", 0, t0, "run_start", `"tier":"landlock","capture":"uprobe","command":["agent"]`),
		line(run, "py", 1, t0.Add(time.Second), "ssl_response", `"request_seq":1,"status":200,"parser_version":"1","model":"claude-sonnet-4-5-20250929","latency_ms":1,"usage":{"input":1000000,"output":100000}`),
		line(run, "py", 2, t0.Add(2*time.Second), "gap", `"what":"capture","why":"no-openssl","binary":"/usr/bin/curl","count":1`),
		line(run, "py", 3, t0.Add(3*time.Second), "gap", `"what":"record","why":"channel-full","count":3`),
		line(run, "py", 4, t0.Add(4*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	_, addr, _ := liveServerConfig(t, Config{Ledger: root, Machine: pricedMachine(t, sonnetTable)}, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("receipt/%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + run + "/receipt?t=tok123"})
				tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
				// The receipt's details sit in a disclosure; open it to read them.
				tb.eval(t, `document.querySelectorAll('details').forEach(function (d) { d.open = true; }), ""`)
				body := tb.eval(t, `document.body.innerText`)
				if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
					_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("b15-receipt-%d-%s.txt", w, theme)), []byte(body), 0o600)
				}
				for _, want := range []string{"$4.50 est.", "Token counts may be low (1 capture gap)", "gap in the record"} {
					if !strings.Contains(body, want) {
						t.Errorf("the Receipt tab lacks %q in %q", want, body)
					}
				}
				if href := tb.eval(t, `(function () { var a = Array.prototype.filter.call(document.querySelectorAll('a.link'), function (a) { return a.textContent.indexOf('Token counts may be low') >= 0; })[0]; return a ? a.getAttribute('href') : ""; })()`); !strings.Contains(href, "kind=gap") || !strings.Contains(href, "q=gap%20capture%20") {
					t.Errorf("the capture note's link is %s", href)
				}
				if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
					t.Error("rendered contrast failed")
				}
				pageChecks(t, tb, "receipt", w, fmt.Sprintf("b15-receipt-%d-%s", w, theme), ".rc-gaps")
			})
		}
	}
}

// TestB15MalformedAsksInChrome: a run whose record repeats an ask id and holds an answer with no ask shows each as a
// refused line in askpair's words, on the run page, at 390 and 1280 px, light and dark, with no sideways scroll and no
// control under 24 by 24 px at 390 px.
func TestB15MalformedAsksInChrome(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000074-b15bad"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	root := t.TempDir()
	ask := func(seq int, id, target string) string {
		return line(run, "py", seq, t0.Add(time.Duration(seq)*time.Second), "ask", `"ask_id":"`+id+`","hold":"open","op":"open","target":"`+target+`","ask_rule":"fs.ask_read[/w/]"`)
	}
	finishRun(t, root, run,
		line(run, "py", 0, t0, "run_start", `"tier":"landlock","command":["agent"],"cwd":"/w"`),
		ask(1, "q-1", "/w/a"), ask(2, "q-1", "/w/other"),
		line(run, "py", 3, t0.Add(3*time.Second), "answer", `"ask_id":"q-1","by":"uid:1000 pid:9","after_s":1,"approved":true`),
		line(run, "py", 4, t0.Add(4*time.Second), "answer", `"ask_id":"q-9","by":"uid:1000 pid:9","after_s":1,"approved":true`),
		line(run, "py", 5, t0.Add(5*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("malformed/%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + run + "?t=tok123"})
				tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
				body := tb.eval(t, `document.body.innerText`)
				if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
					_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("b15-malformed-%d-%s.txt", w, theme)), []byte(body), 0o600)
				}
				for _, want := range []string{"an ask was recorded twice (ask q-1, line 2)", "an answer has no ask before it (ask q-9, line 4)"} {
					if !strings.Contains(body, want) {
						t.Errorf("the run page lacks %q in %q", want, body)
					}
				}
				if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
					t.Error("rendered contrast failed")
				}
				pageChecks(t, tb, "run", w, fmt.Sprintf("b15-malformed-%d-%s", w, theme), ".banner-danger")
			})
		}
	}
}
