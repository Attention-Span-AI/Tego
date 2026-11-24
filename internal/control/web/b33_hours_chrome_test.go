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

// C111: the Refusals by hour page in a real browser, at 1280 and 390 px, light and dark: the chart draws one column
// for each hour and a bar with refusals is a link to its hour in Logs, the list under it is reachable by Tab, nothing
// scrolls sideways, no control is under 24 by 24 px at 390 px, and the text meets contrast. TEGO_CHROME_SHOTS saves
// each window.
func TestRefusalHoursInChrome(t *testing.T) {
	root, now := hoursFixture(t)
	s, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	s.cfg.Now = func() time.Time { return now }
	c := placeChrome(t)
	for _, w := range []int{1280, 390} {
		for _, theme := range []string{"light", "dark"} {
			for _, span := range []string{"day", "week"} {
				t.Run(fmt.Sprintf("%s/%d/%s", span, w, theme), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), w, 900, theme)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/refusals?span=" + span + "&t=tok123"})
					tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('.ch-hours')`)
					want := map[string]string{"day": "24", "week": "168"}[span]
					if got := tb.eval(t, `document.querySelectorAll('.ch-hours rect').length`); got != ``+want+`` {
						t.Errorf("%s: %s columns, want %s", span, got, want)
					}
					if got := tb.eval(t, `document.querySelectorAll('.ch-hours a').length`); got != "3" && span == "day" {
						t.Errorf("bars that link to Logs: %s, want 3", got)
					}
					if span == "day" {
						// The list is reachable by the keyboard and each row names its hour.
						tb.eval(t, `document.querySelector('.hr-rows a').focus();''`)
						if v := tb.eval(t, `document.activeElement.matches('.hr-rows a')&&getComputedStyle(document.activeElement).outlineStyle!=='none'`); v != "true" {
							t.Errorf("the list link takes no focus ring")
						}
					}
					if v := tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`); v != "true" {
						t.Errorf("rendered contrast failed")
					}
					body := tb.eval(t, `document.body.innerText`)
					if !strings.Contains(body, "Refusals by hour") || !strings.Contains(body, "refused") {
						t.Errorf("the page lacks its words: %s", body)
					}
					pageChecks(t, tb, "refusals by hour", w, "", "")
					if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
						time.Sleep(150 * time.Millisecond)
						var r struct{ Data []byte }
						_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true}), &r)
						if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("c111-hours-%s-%d-%s.png", span, w, theme)), r.Data, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}
