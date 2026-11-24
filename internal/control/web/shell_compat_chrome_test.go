// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The wider content area can fit another legacy tile. Its record value must
// remain visible when that changes each tile's width at the rail boundary.
func TestShellLegacyTileValueInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 390, 768, 860, 861, 900, 901, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", width, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), width, 800, theme)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/?t=tok123"})
				tb.until(t, "record value and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('.value.chain-v a')`)
				if got := tb.eval(t, `JSON.stringify(Array.from(document.querySelectorAll('.value.chain-v')).filter(e=>{const s=getComputedStyle(e);return (/hidden|clip/.test(s.overflowX)&&e.scrollWidth>e.clientWidth+1)||(/hidden|clip/.test(s.overflowY)&&e.scrollHeight>e.clientHeight+1);}).map(e=>({text:e.textContent,w:e.clientWidth,sw:e.scrollWidth,h:e.clientHeight,sh:e.scrollHeight})))`); got != `"[]"` {
					t.Errorf("record tile value clipped: %s", got)
				}
				c.closeTarget(t, tb.target)
			})
		}
	}
}

// Search inputs keep their editable value, signal that it is shortened, and
// expose the full rendered subject without needing to move the caret.
func TestShellEventSearchValueInChrome(t *testing.T) {
	root := fixture(t)
	target := "/home/dana/" + strings.Repeat("customer-support/", 8) + "ticket-00998-labelled.json"
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "fs", `"verdict":"allow","op":"open","path":"`+target+`","flags":577`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 390, 768, 860, 861, 900, 901, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", width, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), width, 800, theme)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + harmRun + "/lines/7?t=tok123"})
				tb.until(t, "search value and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('#ev-q')`)
				tb.eval(t, `document.querySelector(".event-details summary").focus();""`)
				tb.press(t, "Enter")
				tb.until(t, "Event detail search opened", `document.querySelector(".event-details").open`)
				if tb.eval(t, `(()=>{const e=document.getElementById('ev-q');return e.value.includes('ticket-00998')&&e.title===e.value&&getComputedStyle(e).textOverflow==='ellipsis';})()`) != "true" {
					t.Error("search subject is silently clipped or lacks its full value title")
				}
				tb.eval(t, `document.getElementById('ev-q').focus(); ''`)
				for _, key := range []struct {
					name string
					code int
					want string
				}{{"End", 35, "e.value.length"}, {"Home", 36, "0"}} {
					for _, typ := range []string{"rawKeyDown", "keyUp"} {
						c.call(t, tb.session, "Input.dispatchKeyEvent", map[string]any{"type": typ, "key": key.name, "code": key.name, "windowsVirtualKeyCode": key.code})
					}
					if tb.eval(t, `(()=>{const e=document.getElementById('ev-q');return e.selectionStart===`+key.want+`;})()`) != "true" {
						t.Errorf("%s does not reach the search value's edge", key.name)
					}
				}
				c.closeTarget(t, tb.target)
			})
		}
	}
}
