// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shot saves the whole window as <name>.png under TEGO_CHROME_SHOTS, when it is set.
func shotOf(t *testing.T, tb *tab, name string) {
	t.Helper()
	dir := os.Getenv("TEGO_CHROME_SHOTS")
	if dir == "" {
		return
	}
	time.Sleep(150 * time.Millisecond)
	var r struct{ Data []byte }
	_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true}), &r)
	if err := os.WriteFile(filepath.Join(dir, name+".png"), r.Data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// stepRunFixture is a run whose lines the record ties to model steps (1 by time, 2 by tool id, 3 by thread id), with a
// line it ties to none, a request that carries no attribution at all, and a refused action of step 2; and a second run with
// no model capture, whose every action is stamped unattributed with method none.
func stepRunFixture(t *testing.T) (root, withSteps, without string) {
	t.Helper()
	root = t.TempDir()
	withSteps, without = "r-aaaaaaaa-0000000000601-stepsx", "r-aaaaaaaa-0000000000602-nocapx"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	act := func(add func(time.Time, string, string), i int, kind, verdict, attr, extra string) {
		add(t0.Add(time.Duration(i)*time.Second), kind, `"rule":"unmatched","verdict":"`+verdict+`","authority":"rule",`+extra+`,"attribution":`+attr)
	}
	ledgerRun(t, root, withSteps, "stepper", t0, `"reason":"exit","exit_code":0`, t0.Add(time.Minute), func(add func(time.Time, string, string)) {
		act(add, 1, "exec", "allow", `{"confidence":"unattributed","method":"time"}`, `"argv":["git","status"]`)
		act(add, 2, "exec", "allow", `{"confidence":"likely","method":"time","step":1,"thread":"t1"}`, `"argv":["ls","-la"]`)
		act(add, 3, "fs", "allow", `{"confidence":"likely","method":"time","step":1,"thread":"t1"}`, `"op":"open","path":"/work/a.txt"`)
		act(add, 4, "exec", "refused", `{"confidence":"likely","method":"tool_id","step":2,"thread":"t1","tool_use_id":"toolu_1"}`, `"argv":["curl","evil.example"],"reason":"exec-not-allowed"`)
		add(t0.Add(5*time.Second), "ask", `"ask_id":"ask-1","hold":"exec","op":"exec","target":"curl"`)
		act(add, 6, "net", "allow", `{"confidence":"likely","method":"tid","step":3,"thread":"t2"}`, `"op":"connect","dst":"93.184.216.34:443","host":"example.com","proto":"tcp"`)
		act(add, 7, "fs", "allow", `{"confidence":"likely","method":"tid","step":3,"thread":"t2"}`, `"op":"open","path":"/work/b.txt"`)
		act(add, 8, "exec", "allow", `{"confidence":"unattributed","method":"none"}`, `"argv":["echo","done"]`)
	})
	ledgerRun(t, root, without, "nocapture", t0.Add(time.Hour), `"reason":"exit","exit_code":0`, t0.Add(time.Hour+time.Minute), func(add func(time.Time, string, string)) {
		act(add, 3601, "exec", "allow", `{"confidence":"unattributed","method":"none"}`, `"argv":["ls"]`)
		act(add, 3602, "fs", "allow", `{"confidence":"unattributed","method":"none"}`, `"op":"open","path":"/work/c.txt"`)
	})
	return root, withSteps, without
}

// TestModelStepGroupsInChrome: the run timeline groups consecutive rows of one model step under one header in the words
// the model-step design fixed (C108), at 1280 and 390 px, light and dark; a run with no model capture shows no header; the
// header's Logs link is reachable by keyboard on a laptop and left out on a phone; live.js's regrouping keeps one header
// where a group starts; nothing scrolls sideways, no control is under 24 px at 390, contrast passes.
func TestModelStepGroupsInChrome(t *testing.T) {
	root, withSteps, without := stepRunFixture(t)
	s, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	s.cfg.Now = func() time.Time { return time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC) }
	c := placeChrome(t)
	for _, w := range []int{1280, 390} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + withSteps + "?t=tok123"})
				tb.until(t, "the timeline", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('#tl-rows .tl')`)
				got := tb.eval(t, `JSON.stringify([...document.querySelectorAll('#tl-rows > .tl, #tl-rows > .tl-step')].map(e=>e.classList.contains('tl-step')?'['+e.querySelector('.tl-step-w').textContent+']':e.id))`)
				var seq []string
				if err := json.Unmarshal([]byte(unquoteJS(got)), &seq); err != nil {
					t.Fatalf("%v: %s", err, got)
				}
				// Newest first: lines 9 (run_end) and 8 (not tied), 7 and 6 (step 3 by thread), 5 (the ask: the record ties it to no
				// step, so it is under "Not tied" and not under step 3), 4 (step 2), 3 and 2 (step 1 by time), 1 (not tied by
				// time) and 0 (run_start).
				text := strings.Join(seq, " ")
				const want = "[Not tied to a model step] l9 l8 [Model step 3 (likely)] l7 l6 [Not tied to a model step] l5 " +
					"[Model step 2 (likely)] l4 [After model request 1, matched by time (likely)] l3 l2 [Not tied to a model step] l1 l0"
				if text != want {
					t.Errorf("the timeline reads\n%s\nwant\n%s", text, want)
				}
				link := tb.eval(t, `(function(){var a=document.querySelector('.tl-step a.link');return a?getComputedStyle(a).display:'none'})()`)
				if w == 390 && link != `"none"` {
					t.Errorf("a phone shows the Logs link of a header: display %s", link)
				}
				if w == 1280 {
					href := tb.eval(t, `document.querySelector('.tl-step a.link').getAttribute('href')`)
					if !strings.Contains(href, "step:") {
						t.Errorf("the header's link %s asks for no step", href)
					}
					tb.eval(t, `document.querySelector('.tl-step a.link').focus();''`)
					if v := tb.eval(t, `document.activeElement.matches('.tl-step a.link')&&getComputedStyle(document.activeElement).outlineStyle!=='none'`); v != "true" {
						t.Errorf("the header's link takes no focus ring")
					}
				}
				if v := tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`); v != "true" {
					t.Errorf("rendered contrast failed")
				}
				pageChecks(t, tb, "run timeline with model steps", w, fmt.Sprintf("c108-steps-%d-%s", w, theme), "")
				shotOf(t, tb, fmt.Sprintf("c108-steps-full-%d-%s", w, theme))

				// live.js merges new rows on top of the timeline and an old row of a folded group leaves; the regrouping keeps
				// one header where a group starts.
				regroup := tb.eval(t, `(function(){
					var rows=document.getElementById('tl-rows'), first=rows.querySelector('.tl[data-sk]'), key=first.dataset.sk, before=rows.querySelectorAll('.tl-step').length;
					var frag=document.createDocumentFragment(), row=first.cloneNode(true); row.id='lfresh'; frag.appendChild(row);
					var heads=window.tegoSteps.heads(rows,frag);
					rows.insertBefore(frag,rows.firstChild);
					window.tegoSteps.regroup(rows,heads);
					var after=rows.querySelectorAll('.tl-step').length, prev=rows.querySelector('#lfresh').previousElementSibling;
					return JSON.stringify({before:before,after:after,headed:!!prev&&prev.classList.contains('tl-step')&&prev.dataset.sk===key,second:!first.previousElementSibling.classList.contains('tl-step')});
				})()`)
				if !strings.Contains(unquoteJS(regroup), `"before":6,"after":6,"headed":true,"second":true`) {
					t.Errorf("regrouping after a new row of the first group: %s", regroup)
				}
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + without})
				tb.until(t, "the other timeline", `document.readyState==='complete'&&!!document.querySelector('#tl-rows .tl')`)
				if n := tb.eval(t, `document.querySelectorAll('.tl-step').length`); n != "0" {
					t.Errorf("a run with no model capture shows %s model-step headers", n)
				}
				pageChecks(t, tb, "run timeline without model steps", w, fmt.Sprintf("c108-nosteps-%d-%s", w, theme), "")
			})
		}
	}
}

// unquoteJS is the string tb.eval printed for a JSON.stringify result.
func unquoteJS(s string) string {
	var out string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return s
	}
	return out
}
