// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"
)

// askColourObserver samples computed colours before the first paint of each newly arrived request set.
// Keeping the sample avoids passing after the temporary row highlight has already expired.
const askColourObserver = `window.askColourSamples=[]; window.askColourKey='';
	new MutationObserver(function() {
		var band=document.getElementById('ask-banner');
		if (!band) return;
		var keys=Array.from(band.querySelectorAll('.ab-row')).map(e=>e.dataset.k), key=keys.join('|');
		if (key === window.askColourKey) return;
		window.askColourKey=key;
		requestAnimationFrame(function() {
			if (!band.isConnected) return;
			var canvas=document.createElement('canvas'); canvas.width=canvas.height=1;
			var ctx=canvas.getContext('2d'), root=getComputedStyle(document.documentElement);
			function rgba(colour) { ctx.clearRect(0,0,1,1);ctx.fillStyle=colour;ctx.fillRect(0,0,1,1);return Array.from(ctx.getImageData(0,0,1,1).data); }
			window.askColourSamples.push({
				keys:keys,
				background:rgba(getComputedStyle(band).backgroundColor),
				foreground:rgba(getComputedStyle(band).color),
				rows:Array.from(band.querySelectorAll('.ab-row')).map(e=>rgba(getComputedStyle(e).backgroundColor)),
				expectedBackground:rgba(root.getPropertyValue('--c-ask-bar').trim()),
				expectedForeground:rgba(root.getPropertyValue('--c-on-ask-bar').trim())
			});
		});
	}).observe(document.querySelector('[data-live=r-banner]'),{childList:true,subtree:true}); ''`

// TestAskBandArrivalColourInChrome proves new requests keep the waiting band's computed colours,
// including its child rows. A neutral list highlight must never paint over its contrasting text.
func TestAskBandArrivalColourInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, motion := range []string{"no-preference", "reduce"} {
				t.Run(fmt.Sprintf("%d/%s/%s", width, theme, motion), func(t *testing.T) {
					root := fixture(t)
					now := time.Now()
					appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":false,"by":"uid:1000 pid:9"`))
					_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
					var full *tab
					var tabs []*tab
					for _, path := range []string{"/runs", "/"} {
						tb := sweepTab(t, c, t.Name()+path, width, 900, theme)
						t.Cleanup(func() { c.closeTarget(t, tb.target) })
						c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{
							{"name": "prefers-color-scheme", "value": theme},
							{"name": "prefers-reduced-motion", "value": motion},
						}})
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + "?t=tok123"})
						tb.until(t, "page without a band", `document.readyState === 'complete' && !!window.tegoLive.steady && !document.getElementById('ask-banner')`)
						tb.eval(t, askColourObserver)
						tabs = append(tabs, tb)
						if path == "/" {
							full = tb
						}
					}
					check := func(tb *tab, requests int, when string) {
						t.Helper()
						tb.until(t, when+" first paint", fmt.Sprintf(`window.askColourSamples.some(s=>s.keys.length === %d)`, requests))
						var sample struct {
							Keys                                   []string
							Background, Foreground                 []int
							Rows                                   [][]int
							ExpectedBackground, ExpectedForeground []int
						}
						if err := json.Unmarshal([]byte(tb.eval(t, fmt.Sprintf(`window.askColourSamples.find(s=>s.keys.length === %d)`, requests))), &sample); err != nil {
							t.Fatal(err)
						}
						t.Logf("%s %s first paint: background=%v foreground=%v rows=%v", tb.name, when, sample.Background, sample.Foreground, sample.Rows)
						if !slices.Equal(sample.Background, sample.ExpectedBackground) || !slices.Equal(sample.Foreground, sample.ExpectedForeground) {
							t.Errorf("%s %s: waiting band colours %v/%v, want %v/%v", tb.name, when, sample.Background, sample.Foreground, sample.ExpectedBackground, sample.ExpectedForeground)
						}
						for i, row := range sample.Rows {
							if len(row) != 4 || (row[3] != 0 && !slices.Equal(row, sample.ExpectedBackground)) {
								t.Errorf("%s %s: request row %d paints %v over the waiting band", tb.name, when, i, row)
							}
						}
					}
					appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now.Add(time.Second), "ask", `"ask_id":"colour-first","hold":"fs","op":"write","target":"/p/first.txt"`))
					for _, tb := range tabs {
						check(tb, 1, "initial arrival")
					}
					// Isolate the later row's own highlight from the initial band arrival highlight on an unfixed build.
					full.until(t, "initial highlight expired", `!document.getElementById('ask-banner').classList.contains('live-new')`)
					appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now.Add(2*time.Second), "ask", `"ask_id":"colour-second","hold":"fs","op":"read","target":"/p/second.txt"`))
					check(full, 2, "second row arrival")
					for _, tb := range tabs {
						tb.clean(t, "request arrival colours")
					}
				})
			}
		}
	}
}
