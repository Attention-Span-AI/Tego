// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"testing"
	"time"
)

// The table can scroll internally at larger text sizes. Its hidden last-column
// label must not escape that scroller and enlarge the document as well.
func TestShellDetectionHeaderInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, logsRuleTitleFixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, theme := range []string{"light", "dark"} {
		t.Run(theme, func(t *testing.T) {
			tb := sweepTab(t, c, t.Name(), 1280, 900, theme)
			c.call(t, tb.session, "Page.setFontSizes", map[string]any{"fontSizes": map[string]int{"standard": 32, "fixed": 26}})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/detections?t=tok123"})
			tb.until(t, "detections and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('.dt-table')`)
			if tb.eval(t, `Array.from(document.querySelectorAll('.dt-table')).some(e=>e.parentElement.scrollWidth>e.parentElement.clientWidth+1)`) != "false" {
				t.Fatal("detections table scrolls at doubled text")
			}
			t.Logf("header geometry: %s", tb.eval(t, `(()=>{const d=document.documentElement,t=document.querySelector('.dt-table'),s=t.querySelector('th:last-child .sr'),p=s&&s.parentElement,before={document:d.scrollWidth,table:t.parentElement.scrollWidth};if(s)s.remove();const after={document:d.scrollWidth,table:t.parentElement.scrollWidth};if(s)p.appendChild(s);return {before,after,restored:d.scrollWidth};})()`))
			if tb.eval(t, `document.documentElement.scrollWidth<=document.documentElement.clientWidth+1`) != "true" {
				t.Error("hidden detections header enlarges the document beyond its table scroller")
			}
			var ax struct {
				Nodes []struct {
					Ignored bool
					Role    struct{ Value string }
					Name    struct{ Value string }
				}
			}
			if err := json.Unmarshal(c.call(t, tb.session, "Accessibility.getFullAXTree", map[string]any{}), &ax); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, node := range ax.Nodes {
				found = found || (!node.Ignored && node.Role.Value == "columnheader" && node.Name.Value == "Investigate")
			}
			if !found {
				t.Error("Investigate column lost its accessible header name")
			}
			c.closeTarget(t, tb.target)
		})
	}
}
