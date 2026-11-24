// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Overview now has the same compact phone controls as Runs. It must retain the
// precise old request and control geometry while a person is using them.
func TestPhoneOverviewHoldInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{320, 390, 430} {
		for _, mode := range []string{"pointer", "keyboard"} {
			t.Run(fmt.Sprintf("%d/%s", width, mode), func(t *testing.T) {
				root := fixture(t)
				now := time.Now()
				appendLine(t, root, harmRun, line(harmRun, "Mira", 7, now, "ask", `"ask_id":"next","op":"connect","hold":"net","target":"registry.npmjs.org"`))
				_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
				tb := sweepTab(t, c, t.Name(), width, 640, "light")
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/?t=tok123"})
				tb.until(t, "two waiting requests", `document.readyState==='complete' && !!window.tegoLive?.steady && document.querySelector('.nav .count')?.textContent.includes('2')`)
				tb.eval(t, `window.heldButton=document.querySelector('#ask-banner button[value=deny]'); window.heldBox=heldButton.getBoundingClientRect().toJSON(); ''`)
				if mode == "keyboard" {
					tb.eval(t, `heldButton.focus(); ''`)
				} else {
					var box struct{ X, Y float64 }
					_ = json.Unmarshal([]byte(tb.eval(t, `(()=>{const r=heldButton.getBoundingClientRect();return {X:r.left+r.width/2,Y:r.top+r.height/2};})()`)), &box)
					c.call(t, tb.session, "Input.dispatchMouseEvent", map[string]any{"type": "mouseMoved", "x": box.X, "y": box.Y})
				}
				appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now.Add(time.Second), "answer", `"ask_id":"ask-7","approved":false`))
				tb.until(t, "new pending set merged", `document.querySelector('.nav').dataset.askKeys.includes('next') && !document.querySelector('.nav').dataset.askKeys.includes('ask-7')`)
				if tb.eval(t, `(()=>{const b=document.querySelector('#ask-banner button[value=deny]'),r=b.getBoundingClientRect();return b===heldButton && document.querySelector('#ask-banner [name=ask]').value==='ask-7' && Math.abs(r.top-heldBox.top)<1 && Math.abs(r.left-heldBox.left)<1;})()`) != "true" {
					t.Error("Overview replaced or moved the request under pointer/focus")
				}
				tb.eval(t, `document.activeElement.blur(); ''`)
				c.call(t, tb.session, "Input.dispatchMouseEvent", map[string]any{"type": "mouseMoved", "x": 0, "y": 0})
				tb.until(t, "next request after departure", `document.querySelector('#ask-banner [name=ask]')?.value==='next'`)
				tb.clean(t, "Overview request hold")
				c.closeTarget(t, tb.target)
			})
		}
	}
}
