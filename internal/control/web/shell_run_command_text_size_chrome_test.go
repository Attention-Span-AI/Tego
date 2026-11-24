// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"testing"
	"time"
)

// Commands now live in Run details. Both summary pages must keep the native
// recovery destination, and enlarged text there must retain the exact command.
func TestShellRunCommandTextSizeInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, logsRuleTitleFixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	normal := map[string]float64{}
	for _, large := range []bool{false, true} {
		widths := []int{1280}
		if large {
			widths = []int{768, 861, 1280}
		}
		for _, width := range widths {
			for _, theme := range []string{"light", "dark"} {
				for _, path := range []string{"/", "/runs"} {
					t.Run(fmt.Sprintf("text200=%t/%d/%s/%s", large, width, theme, path), func(t *testing.T) {
						tb := sweepTab(t, c, t.Name(), width, 900, theme)
						standard, fixed := 16, 13
						if large {
							standard, fixed = 32, 26
						}
						c.call(t, tb.session, "Page.setFontSizes", map[string]any{"fontSizes": map[string]int{"standard": standard, "fixed": fixed}})
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, path)})
						tb.until(t, "summary and font", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('.phone-row')`)
						if tb.eval(t, fmt.Sprintf(`Array.from(document.querySelectorAll('a[href="/runs/%s"]')).some(e=>e.checkVisibility({contentVisibilityAuto:true}))`, "r-7f3a9c41-0000000000003-supprt")) != "true" {
							t.Fatal("summary lost the actual Run destination")
						}
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, "/runs/"+"r-7f3a9c41-0000000000003-supprt"+"?details=1")})
						tb.until(t, "native Run details", `document.readyState==='complete'&&document.fonts.status==='loaded'&&document.querySelector('#run-details')?.open`)
						expected := 0.0
						key := theme + path
						if large && width == 1280 {
							expected = normal[key] * 2
						}
						size := assertFullTextAtScale(t, tb, `[...document.querySelectorAll('#run-details dt')].find(e=>e.textContent==='Command')?.nextElementSibling`, "python3 /home/dana/projects/customer-support/automation/triage-worker/src/triage.py", expected)
						if !large {
							normal[key] = size
						}
						tb.clean(t, "enlarged full command")
					})
				}
			}
		}
	}
}
