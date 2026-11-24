// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"testing"
	"time"
)

// Larger text narrows the space beside Review. An ellipsis must expose the
// complete metadata, including the full run ID behind its abbreviated label.
func TestShellWaitingMetadataInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, theme := range []string{"light", "dark"} {
		t.Run(theme, func(t *testing.T) {
			tb := sweepTab(t, c, t.Name(), 1280, 900, theme)
			c.call(t, tb.session, "Page.setFontSizes", map[string]any{"fontSizes": map[string]int{"standard": 32, "fixed": 26}})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/?t=tok123"})
			tb.until(t, "waiting metadata and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('.wait-row .meta.ellip')`)
			if tb.eval(t, `Array.from(document.querySelectorAll('.wait-row .meta.ellip')).some(e=>e.scrollWidth>e.clientWidth+1)`) != "true" {
				t.Fatal("fixture does not exercise ellipsized waiting metadata")
			}
			if tb.eval(t, fmt.Sprintf(`Array.from(document.querySelectorAll('.wait-row .meta.ellip')).every(e=>getComputedStyle(e).textOverflow==='ellipsis'&&e.title.includes(e.textContent.trim())&&e.title.includes(%q))`, harmRun)) != "true" {
				t.Error("ellipsized metadata lacks its full displayed value or full run ID")
			}
			c.closeTarget(t, tb.target)
		})
	}
}
