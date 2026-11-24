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

// Short pages must not distribute spare viewport height above main. Long pages and
// the desktop side-by-side layout exercise both sides of the responsive boundary.
func TestShellNavigationRowsInChrome(t *testing.T) {
	root := fixture(t)
	busyRun(t, root, 120)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{360, 390, 768, 860, 861, 900, 901, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, path := range []string{"/no-such-page", "/logs"} {
				t.Run(fmt.Sprintf("%d/%s/%s", width, theme, path), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 800, theme)
					sep := "?"
					if strings.Contains(path, "?") {
						sep = "&"
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + sep + "t=tok123"})
					tb.until(t, "page and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('main')`)
					gap := `document.querySelector('main').getBoundingClientRect().top - document.querySelector('nav.side').getBoundingClientRect().bottom`
					if width <= 600 || width > 860 {
						gap = `document.querySelector('main').getBoundingClientRect().top - document.querySelector('.topbar').getBoundingClientRect().bottom`
					}
					t.Logf("main gap px: %s", tb.eval(t, gap))
					if tb.eval(t, "Math.abs("+gap+") <= 1") != "true" {
						t.Errorf("main does not start directly after navigation: %s px", tb.eval(t, gap))
					}
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}

// Logs has its own card grid: shell table labels must not create extra grid cells
// or squeeze a path into half the card. Long names must remain readable in full.
func TestShellLogsWhatWrapsInChrome(t *testing.T) {
	root := fixture(t)
	const target = "/home/dana/projects/customer-support/automation/triage-worker/out/tickets/2026-10-25/ticket-00998-labelled.json"
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "fs", `"verdict":"allow","op":"open","path":"`+target+`","flags":577`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 360, 390, 640, 861, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, path := range []string{"/logs", "/logs?q=ticket"} {
				t.Run(fmt.Sprintf("%d/%s/%s", width, theme, path), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 800, theme)
					sep := "?"
					if strings.Contains(path, "?") {
						sep = "&"
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + sep + "t=tok123"})
					tb.until(t, "target row", `document.readyState === 'complete' && document.fonts.status === 'loaded' && Array.from(document.querySelectorAll('div.lw')).some(e=>e.textContent.includes('ticket-00998'))`)
					t.Logf("card geometry: %s", tb.eval(t, `(()=>{const w=Array.from(document.querySelectorAll('div.lw')).find(e=>e.textContent.includes('ticket-00998')),td=w.closest('td');return {columns:getComputedStyle(td.parentElement).gridTemplateColumns,what:td.clientWidth,path:w.scrollWidth,label:getComputedStyle(td,'::before').display};})()`))
					if width < 1100 {
						if tb.eval(t, `Array.from(document.querySelectorAll('.t-log .phone-row')).every(e=>e.getBoundingClientRect().height>=80&&e.querySelector('.phone-who')&&e.querySelector('.phone-when')&&e.querySelectorAll('.b').length===1&&e.querySelectorAll('a,button').length===0)`) != "true" {
							t.Error("Logs does not use single-link three-fact rows")
						}
					} else if got := tb.eval(t, `JSON.stringify(Array.from(document.querySelectorAll('div.lw')).filter(e=>e.scrollWidth>e.clientWidth+1||e.scrollHeight>e.clientHeight+1).map(e=>e.textContent))`); got != `"[]"` {
						t.Errorf("desktop What content clipped: %s", got)
					}
					if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
						t.Error("Logs scrolls sideways")
					}

					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}

// The preview pages share the shell's problem banner. A long file name in its
// error must wrap even when the surrounding page has very little content.
func TestShellProblemWrapsInChrome(t *testing.T) {
	root := fixture(t)
	longRoot := filepath.Join(t.TempDir(), strings.Repeat("contractpath", 18))
	if err := os.Rename(root, longRoot); err != nil {
		t.Fatal(err)
	}
	s, addr, _ := liveServer(t, longRoot, 10*time.Second, 30*time.Second)
	s.cfg.Preview = true
	c := placeChrome(t)
	for _, width := range []int{320, 390, 768, 860, 861, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, path := range []string{"/mcp", "/routes"} {
				t.Run(fmt.Sprintf("%d/%s/%s", width, theme, path), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 800, theme)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + "?run=" + harmRun + "&t=tok123"})
					tb.until(t, "problem", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('main .banner-danger strong')`)
					if got := tb.eval(t, `document.documentElement.scrollWidth <= innerWidth`); got != "true" {
						t.Errorf("problem banner overflows: %s", tb.eval(t, `document.documentElement.scrollWidth - innerWidth`))
					}
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}

// The late note is longer than the fresh note. Reserve its wrapped height from
// first paint so learning that the agent gave up cannot move the answer buttons.
func TestAskBandWaitHeightInChrome(t *testing.T) {
	root := fixture(t)
	now := time.Now()
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":false,"by":"uid:1000 pid:9"`))
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now, "ask", `"ask_id":"fresh","hold":"fs","op":"read","target":"/p/held.txt"`))
	s, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	s.cfg.Now = func() time.Time { return now }
	c := placeChrome(t)
	for _, width := range []int{360, 390, 768, 860, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, path := range []string{"/", "/logs"} {
				t.Run(fmt.Sprintf("%d/%s/%s", width, theme, path), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 800, theme)
					c.call(t, tb.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": fmt.Sprintf("Date.now=()=>%d;", now.UnixMilli())})
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + "?t=tok123"})
					tb.until(t, "fresh wait note", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!window.tegoLive && !!document.querySelector('#ask-banner [data-late-at]')`)
					before := tb.eval(t, `document.getElementById('ask-banner').getBoundingClientRect().height`)
					tb.eval(t, `var realNow=Date.now; Date.now=()=>realNow()+60000; window.tegoLive.after(); Date.now=realNow; ''`)
					if tb.eval(t, `document.querySelector('#ask-banner .ask-wait').textContent.includes('Tego refuses it')`) != "true" {
						t.Error("wait note did not change at threshold")
					}
					if after := tb.eval(t, `document.getElementById('ask-banner').getBoundingClientRect().height`); after != before {
						t.Errorf("wait note moved band controls: height %s -> %s", before, after)
					}
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}

// Base 70a9e8c56 used a 64px icon rail through 900px and a 216px rail above it.
// The shell must not narrow either content budget or increase inherited overflow.
func TestShellLegacyContentRoomInChrome(t *testing.T) {
	root := fixture(t)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC), "refused", `"rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","target":"/home/dana/.ssh/id_ed25519.backup-before-rotation-2026-11-11T2104"`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{861, 900, 901, 1280} {
		rail := 216
		if width <= 900 {
			rail = 64
		}
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", width, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), width, 800, theme)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/?t=tok123"})
				tb.until(t, "Overview and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('.iv-linked')`)
				if tb.eval(t, fmt.Sprintf(`document.querySelector('main').getBoundingClientRect().width + 1 >= document.querySelector('.app').getBoundingClientRect().width - %d`, rail)) != "true" {
					t.Error("shell narrows the base page content budget")
				}
				if tb.eval(t, fmt.Sprintf(`(()=>{const actual=document.documentElement.scrollWidth,old=document.adoptedStyleSheets,s=new CSSStyleSheet();s.replaceSync(':root{--nav-w:%dpx}');document.adoptedStyleSheets=[...old,s];const budget=document.documentElement.scrollWidth;document.adoptedStyleSheets=old;return actual<=budget+1;})()`, rail)) != "true" {
					t.Error("shell increases inherited page overflow beyond the base rail")
				}
				c.closeTarget(t, tb.target)
			})
		}
	}
}
