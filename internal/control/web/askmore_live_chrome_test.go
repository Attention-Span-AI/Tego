// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestMoreChoicesSurvivesLiveRefreshInChrome: on Approvals with Live on, an open "More choices" stays open through
// live refreshes, so a trusted mouse click on "Allow for this run" reaches the broker and the page says what was done.
func TestMoreChoicesSurvivesLiveRefreshInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", width, theme), func(t *testing.T) {
				got := fakeBroker(t)
				root := fixture(t)
				now := time.Now()
				_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
				tb := sweepTab(t, c, t.Name(), width, 900, theme)
				t.Cleanup(func() { c.closeTarget(t, tb.target) })
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/approvals?run=" + harmRun + "&ask=ask-7&t=tok123"})
				tb.until(t, "approvals", `document.readyState === 'complete' && !!window.tegoLive.steady && !!document.querySelector('details.ask-more')`)
				// A later render of the card has one more block in front of the answers (the card's text grows: a late note, a
				// second paragraph). The merge must still match the disclosure to itself.
				tb.eval(t, `var realFetch=window.fetch; window.fetch=function(input, opts){ return realFetch.apply(this, arguments).then(function(r){
					if(!opts||!opts.headers||!opts.headers['X-Tego-Regions']) return r;
					return r.text().then(function(h){ return new Response(h.replace('<div class="ask-d">','<div class="ap-note"></div><div class="ask-d">'), {status:r.status, headers:r.headers}); }); }); }; ''`)
				tb.eval(t, `window.merges=0; document.addEventListener('tego:merged',function(){window.merges++}); ''`)
				tb.eval(t, `(()=>{const d=document.querySelector('details.ask-more'); d.open=true; document.activeElement&&document.activeElement.blur(); window.moreEl=d; return ''})()`)
				tb.until(t, "open", `window.moreEl.open`)
				tb.eval(t, `window.typed=''; ''`)
				for i := 0; i < 2; i++ {
					before := tb.eval(t, `window.merges`)
					appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7+i, now.Add(time.Duration(i+1)*time.Second), "ask",
						fmt.Sprintf(`"ask_id":"ask-new%d","hold":"fs","op":"write","target":"/p/new%d.txt"`, i, i)))
					tb.until(t, "a live refresh", `window.merges > `+before)
					if tb.eval(t, `!!document.querySelector('.ap-note')`) != "true" {
						t.Fatal("the grown render did not arrive")
					}
					if tb.eval(t, `document.querySelector('details.ask-more').open && document.querySelector('details.ask-more') === window.moreEl`) != "true" {
						t.Fatalf("More choices closed or was replaced by live refresh %d", i+1)
					}
				}
				var box struct{ X, Y float64 }
				if err := json.Unmarshal([]byte(tb.eval(t, `(()=>{const b=document.querySelector('details.ask-more form[action="/approvals/answer"] button[value=approve]');b.scrollIntoView({block:'center'});const r=b.getBoundingClientRect();return {X:r.left+r.width/2,Y:r.top+r.height/2};})()`)), &box); err != nil {
					t.Fatal(err)
				}
				for _, typ := range []string{"mousePressed", "mouseReleased"} {
					c.call(t, tb.session, "Input.dispatchMouseEvent", map[string]any{"type": typ, "x": box.X, "y": box.Y, "button": "left", "clickCount": 1})
				}
				tb.until(t, "the answer said", `!!document.querySelector('#toasts .toast') && document.querySelector('#toasts').textContent.includes('Allowed for the rest of this run')`)
				if got.calls != 1 || !got.always || !got.approve {
					t.Fatalf("broker got %+v", *got)
				}
				if !strings.Contains(tb.eval(t, `document.querySelector('#toasts').textContent`), "rest of this run") {
					t.Error("no plain line")
				}
			})
		}
	}
}
