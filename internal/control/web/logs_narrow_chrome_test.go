// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestLogsNarrowButtonsInChrome: a row's program and process are buttons of one shared form. At 390 and 1280 px, light
// and dark, with scripts on and off, the page does not scroll sideways, the buttons are seen and readable, and pressing
// one narrows the search to its program, pressing it again takes the term out. TEGO_CHROME_SHOTS saves the pictures.
func TestLogsNarrowButtonsInChrome(t *testing.T) {
	c := placeChrome(t)
	root, _ := progFixture(t)
	markLive(t, root, progRun)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	for _, width := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, scripts := range []bool{true, false} {
				t.Run(fmt.Sprint(width, theme, scripts), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 844, theme)
					defer c.closeTarget(t, tb.target)
					if !scripts {
						c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": true})
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/logs?t=tok123"})
					tb.until(t, "rows", `document.readyState==='complete' && !!document.querySelector('#lq-rows button.lq-prog')`)
					pageChecks(t, tb, "Logs", width, fmt.Sprintf("logs-narrow-%d-%s-%t", width, theme, scripts), "#lq-rows")
					if width == 1280 {
						// The button reads as the link it was: its own colour, no button frame, the page's text.
						got := tb.eval(t, `(function(){var e=document.querySelector('#lq-rows button.lq-prog'),s=getComputedStyle(e);var r=e.getBoundingClientRect();return [s.borderTopWidth,s.backgroundColor,s.cursor,r.width>0&&r.height>0,s.color!==getComputedStyle(document.body).backgroundColor].join('|');})()`)
						if got != `"0px|rgba(0, 0, 0, 0)|pointer|true|true"` {
							t.Errorf("the program button looks like %s", got)
						}
					}
					if tb.eval(t, `document.querySelector('#lq-rows button.lq-prog') && getComputedStyle(document.querySelector('#lq-rows button.lq-prog')).visibility`) == `"hidden"` {
						return // a layout that hides the column has nothing to press
					}
					tb.eval(t, `document.querySelector('#lq-rows button.lq-prog').click(), ""`)
					tb.until(t, "narrowed", `location.search.indexOf('where=prog%3Acurl') >= 0 && location.search.indexOf('narrow') < 0 && document.readyState==='complete' && !!document.querySelector('#lq-rows button.lq-prog')`)
					if got := tb.eval(t, `document.querySelector('.lq-chip .mono') && document.querySelector('.lq-chip .mono').textContent`); !strings.Contains(got, "prog:curl") {
						t.Errorf("no prog:curl chip after the press: %s", got)
					}
					tb.eval(t, `document.querySelector('#lq-rows button.lq-prog').click(), ""`)
					tb.until(t, "widened", `location.search.indexOf('prog') < 0 && document.readyState==='complete' && !!document.querySelector('#lq-rows button.lq-prog')`)
				})
			}
		}
	}
}
