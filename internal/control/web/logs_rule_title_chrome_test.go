// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Automatic table layout can narrow the rule column enough to trigger its
// native line-clamp ellipsis. The tooltip must retain its rendered words as
// well as the raw key, on both the full and filtered desktop lists.
func TestLogsRuleTitleInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, logsRuleTitleFixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, theme := range []string{"light", "dark"} {
		for _, large := range []bool{false, true} {
			for _, path := range []string{"/logs", "/logs?q=ssh"} {
				t.Run(fmt.Sprintf("%s/text200=%t/%s", theme, large, path), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), 1280, 900, theme)
					if large {
						c.call(t, tb.session, "Page.setFontSizes", map[string]any{"fontSizes": map[string]int{"standard": 32, "fixed": 26}})
					}
					sep := "?"
					if strings.Contains(path, "?") {
						sep = "&"
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + sep + "t=tok123"})
					tb.until(t, "rule labels and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('td.c-rule .clamp')`)
					t.Logf("rule clamps: %s", tb.eval(t, `Array.from(document.querySelectorAll('td.c-rule .clamp')).map(e=>({text:e.textContent,w:e.clientWidth,h:e.clientHeight,sh:e.scrollHeight}))`))
					if tb.eval(t, `Array.from(document.querySelectorAll('td.c-rule .clamp')).every(e=>e.scrollHeight<=e.clientHeight+1&&getComputedStyle(e).overflow!=='hidden')`) != "true" {
						t.Fatal("rule labels still clip instead of wrapping")
					}
					if tb.eval(t, `Array.from(document.querySelectorAll('td.c-rule .clamp')).every(e=>e.title.includes(e.textContent.trim()))`) != "true" {
						t.Error("ellipsized rule label lacks its full displayed value in the title")
					}
					if tb.eval(t, `Array.from(document.querySelectorAll('td.c-rule .clamp')).some(e=>e.textContent.trim()==='Never read: ~/.ssh'&&e.title.includes('fs.deny_read[~/.ssh]'))`) != "true" {
						t.Error("rendered rule title lost its raw key")
					}
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}
