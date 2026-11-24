// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestCompactAskHoldsInChrome proves a request answered elsewhere cannot replace the compact band's
// controls while a pointer or keyboard focus is on them. The queued request follows when both leave.
func TestCompactAskHoldsInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{390, 1280} {
		for _, mode := range []string{"pointer", "keyboard"} {
			t.Run(fmt.Sprintf("%d/%s", width, mode), func(t *testing.T) {
				root := fixture(t)
				now := time.Now()
				appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "ask", `"ask_id":"ask-next","hold":"fs","op":"write","target":"/p/next.txt"`))
				_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
				tb := sweepTab(t, c, t.Name(), width, 900, "light")
				t.Cleanup(func() { c.closeTarget(t, tb.target) })
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
				tb.until(t, "compact band", `document.readyState === 'complete' && !!window.tegoLive.steady && document.querySelector('#ask-banner.ab-line [name=ask]')?.value === 'ask-7'`)
				// Observe the real response and completed merge, so a passing hold cannot just mean no refresh ran.
				tb.eval(t, `window.bandMerges=0; window.bandReply=''; window.bandMerged='';
					var realFetch=window.fetch; window.fetch=function(input, opts) { return realFetch.apply(this, arguments).then(function(r) {
						if (!opts?.headers?.['X-Tego-Regions']) return r;
						return r.clone().text().then(function(html) { window.bandReply=html; return r; });
					}); };
					document.addEventListener('tego:merged',function(){window.bandMerged=window.bandReply;window.bandMerges++;});
					window.bandRow=document.querySelector('#ask-banner .ab-row'); window.bandButton=document.querySelector('#ask-banner button[value=deny]');
					window.bandHash=document.querySelector('[data-live=r-banner]').dataset.h; ''`)
				mouse := func(x, y float64) {
					c.call(t, tb.session, "Input.dispatchMouseEvent", map[string]any{"type": "mouseMoved", "x": x, "y": y})
				}
				if mode == "pointer" {
					var box struct{ X, Y float64 }
					if err := json.Unmarshal([]byte(tb.eval(t, `(()=>{const r=window.bandButton.getBoundingClientRect();return {X:r.left+r.width/2,Y:r.top+r.height/2};})()`)), &box); err != nil {
						t.Fatal(err)
					}
					mouse(box.X, box.Y)
					tb.until(t, "pointer on Deny", `window.bandButton.matches(':hover')`)
				} else {
					mouse(0, 0)
					for n := 0; n < 40 && tb.eval(t, `document.activeElement === window.bandButton`) != "true"; n++ {
						tb.press(t, "Tab")
					}
					if tb.eval(t, `document.activeElement === window.bandButton`) != "true" {
						t.Fatal("Tab did not reach compact Deny")
					}
				}
				appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now.Add(time.Second), "answer", `"ask_id":"ask-7","approved":false,"by":"uid:1000 pid:9"`))
				tb.until(t, "answer fetched and merged", `window.bandMerged.includes('value="ask-next"') && document.querySelector('.nav').dataset.askKeys.trim().endsWith('ask-next')`)
				assertHeld := func(when string) {
					t.Helper()
					if got := tb.eval(t, `document.querySelector('#ask-banner .ab-row') === window.bandRow && document.querySelector('#ask-banner button[value=deny]') === window.bandButton && document.querySelector('#ask-banner [name=ask]')?.value === 'ask-7'`); got != "true" {
						t.Fatalf("compact request changed %s while %s stayed on it", when, mode)
					}
				}
				assertHeld("after its answer")
				// A resting pointer or focus has no timeout exception. Advance the clock, then observe another merge.
				tb.eval(t, `window.bandBefore=window.bandMerges; var realNow=Date.now; Date.now=()=>realNow()+60000; ''`)
				appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now.Add(2*time.Second), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/held-after-timeout.txt"`))
				tb.until(t, "another refresh beyond hold timeout", `window.bandMerges > window.bandBefore`)
				assertHeld("after 60 seconds")
				if mode == "pointer" {
					// A keyboard can change the view while the pointer rests on Deny. The whole-main merge must hold too.
					tb.eval(t, `window.bandViewEntered=false; document.addEventListener('tego:enter',()=>window.bandViewEntered=true,{once:true}); ''`)
					query := "?state=running"
					if width <= 600 {
						// Exercise the real GET fallback with the modal API unavailable.
						// It changes the view while the pointer remains on Deny.
						tb.eval(t, `document.querySelector('dialog.filter-sheet').showModal=undefined; document.querySelector('[data-filter-open]').focus(); ''`)
						query = "?filters=1"
					} else {
						tb.eval(t, `document.querySelector('.chips a[href="/runs?state=running"]').focus(); ''`)
					}
					tb.press(t, "Enter")
					tb.until(t, "filtered view merged", fmt.Sprintf(`window.bandViewEntered && location.search === %q`, query))
					assertHeld("after changing the view")
					if got := tb.eval(t, `document.querySelector('[data-live=r-banner]').dataset.h === window.bandHash`); got != "true" {
						t.Fatal("held wrapper adopted the next request's hash")
					}
					mouse(0, 0)
				} else {
					for n := 0; n < 10 && tb.eval(t, `document.getElementById('ask-banner').contains(document.activeElement)`) == "true"; n++ {
						tb.press(t, "Tab")
					}
				}
				tb.until(t, "queued request after departure", `document.querySelector('#ask-banner [name=ask]')?.value === 'ask-next'`)
				tb.eval(t, `Date.now=realNow; ''`)
				tb.clean(t, "held request and departure")
			})
		}
	}
}
