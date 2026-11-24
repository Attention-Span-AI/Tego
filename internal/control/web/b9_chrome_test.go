// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The words and labels of this batch in a real browser, at a phone's and a laptop's width, light and dark. Run it by
// hand (set TEGO_CHROME_SHOTS to a folder to look at the pages):
//
//	go test -tags chrome -run TestB9PagesInChrome ./internal/control/web

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestB9PagesInChrome(t *testing.T) {
	c := placeChrome(t)
	// A watched run with a mark that matched a line, and a request whose exact target is huge.
	root := liveBlockFixture(t)
	p := filepath.Join(root, harmRun, "events.jsonl")
	b := strings.Replace(readFile(t, p), `"verdict":"refused","rule":"live.block[exec:ls]"`, `"verdict":"observed","rule":"live.block[exec:ls]"`, 1)
	b = strings.Replace(b, `"rule":"live.block[exec:ls]","reason":"exec-not-allowed","op":"exec"`, `"rule":"unmatched","reason":"exec-not-allowed","op":"exec"`, 1)
	writeRaw(t, p, strings.Replace(b, `"tier":"landlock"`, `"tier":"observe"`, 1))
	huge := "/p/" + strings.Repeat("a-very-long-folder-name/", 160) + "token.txt"
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 20, time.Now(), "ask", `"ask_id":"ask-huge","hold":"open","op":"open","ask_rule":"fs.ask[./]","target":"`+huge+`"`))
	s, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	s.host = "build-workstation-17.engineering.example-corp.internal"
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				t.Cleanup(func() { c.closeTarget(t, tb.target) })
				go_ := func(path, cond string) {
					sep := "?"
					if strings.Contains(path, "?") {
						sep = "&"
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + sep + "t=tok123"})
					arrive(t, tb, path, cond)
				}
				name := func(page string) string { return fmt.Sprintf("b9-%s-%d-%s", page, w, theme) }

				go_("/approvals", `!!document.querySelector('.approval-queue')`)
				if w == 390 {
					if h := tb.eval(t, `Math.max.apply(null, Array.from(document.querySelectorAll('.approval-queue .ap-request-target')).filter(e=>e.getClientRects().length).map(e=>Math.round(e.getBoundingClientRect().height)))`); atoi(t, h) > 120 {
						t.Errorf("a queue row's target is %s px high on a phone", h)
					}
					pageChecks(t, tb, "approvals queue", w, name("queue"), "")
				}
				go_("/approvals?run="+harmRun+"&ask=ask-huge", `!!document.querySelector('.ut-box')`)
				if w == 390 {
					if h := tb.eval(t, `Math.round(document.querySelector('.ask .ut-box, .ap-card-body .ut-box').getBoundingClientRect().height)`); h == "" || atoi(t, h) > 160 {
						t.Errorf("the exact target box is %s px high on a phone, want at most 160", h)
					}
					if tb.eval(t, `(function(e){return e.scrollHeight > e.clientHeight && getComputedStyle(e).overflowY === 'auto' && e.tabIndex === 0})(document.querySelector('.ask .ut-box, .ap-card-body .ut-box'))`) != "true" {
						t.Error("the capped box does not scroll, or cannot be reached by keyboard")
					}
				}
				if tb.eval(t, `document.querySelector('.ask .ut-box, .ap-card-body .ut-box').textContent.includes('token.txt')`) != "true" {
					t.Error("the full target is not in the page")
				}
				pageChecks(t, tb, "approvals", w, name("approvals"), ".ut-box")

				go_("/runs/"+harmRun, `!!document.querySelector('.run-tl, .tl')`)
				if tb.eval(t, `document.body.textContent.includes('Marked live at') && !document.body.textContent.includes('Blocked live at')`) != "true" {
					t.Error("the watched run's mark is not named")
				}
				pageChecks(t, tb, "watched run", w, name("run"), "")

				go_("/runs/"+harmRun+"/lines/8", `!!document.querySelector('.event-page')`)
				if tb.eval(t, `document.querySelector('#h-act')?.textContent === 'What to do about this' && (document.body.innerText.match(/Decided by/g) || []).length <= 1`) != "true" {
					t.Error("the line page heading or its single Decided by is wrong")
				}
				if w == 1280 {
					if tb.eval(t, `(function(){var d=document.querySelector('.host-more'); if(!d) return false; d.open=true; var r=d.querySelector('.host-name').getBoundingClientRect(); return r.right <= innerWidth && d.querySelector('.host-name').textContent.length > 20})()`) != "true" {
						t.Error("the whole host name is not reachable")
					}
				}
				pageChecks(t, tb, "line page", w, name("line"), "")
			})
		}
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}
