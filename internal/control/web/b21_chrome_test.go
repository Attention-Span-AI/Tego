// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestB21CoverageWordsInChrome: the Receipt tab's list of what the receipt can vouch for, in a real browser at 390 and
// 1280 px, light and dark: each gap has its level as a chip beside it (partial, or none for a field the ledger does not
// say anything about), the receipt's own sentence for a gap that may have lost actions and for capture gaps, no sideways
// scroll, no control under 24 by 24 px at 390 px, and rendered contrast that holds. TEGO_CHROME_SHOTS saves each window.
func TestB21CoverageWordsInChrome(t *testing.T) {
	const withGaps, withoutCapture = "r-aaaaaaaa-0000000000075-b21aaa", "r-aaaaaaaa-0000000000076-b21bbb"
	t0 := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	root := t.TempDir()
	finishRun(t, root, withGaps,
		line(withGaps, "py", 0, t0, "run_start", `"tier":"landlock","capture":"uprobe","command":["agent"]`),
		line(withGaps, "py", 1, t0.Add(time.Second), "gap", `"what":"capture","why":"no-openssl","binary":"/usr/bin/curl","count":1`),
		line(withGaps, "py", 2, t0.Add(2*time.Second), "gap", `"what":"record","why":"channel-full","count":3`),
		line(withGaps, "py", 3, t0.Add(3*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	finishRun(t, root, withoutCapture,
		line(withoutCapture, "py", 0, t0, "run_start", `"tier":"landlock","capture":"off","command":["agent"]`),
		line(withoutCapture, "py", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
	_, addr, _ := liveServerConfig(t, Config{Ledger: root, Machine: pricedMachine(t, sonnetTable)}, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, tc := range []struct {
		run   string
		wants []string
	}{
		{withGaps, []string{"Token counts may be low (1 capture gap)", "1 gap in the record (counts are a minimum, 3 events lost)", "partial"}},
		{withoutCapture, []string{"none", "partial", "model traffic capture was off"}},
	} {
		for _, w := range []int{390, 1280} {
			for _, theme := range []string{"light", "dark"} {
				t.Run(fmt.Sprintf("%s/%d/%s", tc.run[len(tc.run)-3:], w, theme), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), w, 900, theme)
					defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + tc.run + "/receipt?t=tok123"})
					tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
					tb.eval(t, `document.querySelectorAll('details').forEach(function (d) { d.open = true; }), ""`)
					body := tb.eval(t, `document.body.innerText`)
					if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
						_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("b21-receipt-%s-%d-%s.txt", tc.run[len(tc.run)-3:], w, theme)), []byte(body), 0o600)
					}
					for _, want := range tc.wants {
						if !strings.Contains(body, want) {
							t.Errorf("the Receipt tab lacks %q in %q", want, body)
						}
					}
					if n := tb.eval(t, `String(document.querySelectorAll('.rc-gaps .rc-lvl').length)`); n == "0" {
						t.Error("no coverage gap has its level chip")
					}
					if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
						t.Error("rendered contrast failed")
					}
					pageChecks(t, tb, "receipt", w, fmt.Sprintf("b21-receipt-%s-%d-%s", tc.run[len(tc.run)-3:], w, theme), ".rc-gaps")
				})
			}
		}
	}
}
