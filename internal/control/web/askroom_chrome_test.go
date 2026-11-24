// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The in-flow ask band and the Overview's lists in a real browser, both measured on the screen. Run it by hand,
// through the box's memory slice:
//
//	go test -tags chrome -run 'TestAskBannerRoomInChrome|TestOverviewRowHoldsInChrome' ./internal/control/web

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// settle runs expr (a number) until it stops changing after a region merge.
func settle(t *testing.T, tb *tab, expr string) int {
	t.Helper()
	last, n := -1<<30, 0
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		v, err := strconv.Atoi(tb.eval(t, "Math.round("+expr+") + 0"))
		if err != nil {
			t.Fatal(err)
		}
		if v == last {
			if n++; n >= 3 {
				return v
			}
		} else {
			last, n = v, 0
		}
	}
	return last
}

// TestAskBannerRoomInChrome proves native scroll anchoring keeps a reader's row in place when
// an in-flow band arrives or leaves. A fresh load must stay at scroll zero.
func TestAskBannerRoomInChrome(t *testing.T) {
	root := manyRunsFixture(t)
	now := time.Now()
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":true,"by":"uid:1000 pid:9"`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	tb := sweepTab(t, c, "anchoring", 1280, 900, "light")
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
	tb.until(t, "runs", `document.readyState === 'complete' && !!window.tegoLive.steady && document.querySelectorAll('main tbody tr').length > 10`)
	tb.eval(t, `var row = document.querySelectorAll('main tbody tr')[10]; row.id='anchor-row'; window.scrollTo(0, row.getBoundingClientRect().top + scrollY - 300); ""`)
	const anchor = `document.getElementById('anchor-row').getBoundingClientRect().top`
	before := settle(t, tb, anchor)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now, "ask", `"ask_id":"ask-8","hold":"fs","op":"write","target":"/p/held.txt"`))
	tb.until(t, "the new ask", `!!document.getElementById('ask-banner')`)
	near(t, tb, "anchored row when ask arrives", anchor, before)
	if got := tb.eval(t, `getComputedStyle(document.getElementById('ask-banner')).position`); got != `"relative"` && got != `"static"` {
		t.Errorf("band floats: %s", got)
	}
	tb.until(t, "polite announcement", `document.getElementById('ask-say')?.textContent.includes('waiting for you')`)
	if tb.eval(t, `!document.querySelector('.count[aria-live]')`) != "true" {
		t.Error("request has two live announcement regions")
	}
	tb.eval(t, `window.askSaid = document.getElementById('ask-say').textContent; document.dispatchEvent(new CustomEvent('tego:merged')); ""`)
	if got := tb.eval(t, `document.getElementById('ask-say').textContent === window.askSaid`); got != "true" {
		t.Error("same ask announced again")
	}
	// A second request is announced even while the compact band still shows the first one.
	tb.eval(t, `window.askAnnouncements=0; new MutationObserver(()=>{if(document.getElementById('ask-say').textContent) window.askAnnouncements++}).observe(document.getElementById('ask-say'),{childList:true}); ""`)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now.Add(time.Second), "ask", `"ask_id":"ask-second","hold":"fs","op":"read","target":"/p/second.txt"`))
	tb.until(t, "second ask announced", `window.askAnnouncements === 1`)
	if tb.eval(t, `document.querySelectorAll('#ask-banner [data-k]').length === 1 && document.querySelector('#ask-banner [name=ask]').value === 'ask-8' && document.querySelector('#ask-banner a').textContent === 'Details (2)'`) != "true" {
		t.Error("compact band must keep the first request and link the full queue")
	}
	tb.eval(t, `document.dispatchEvent(new CustomEvent('tego:merged')); ""`)
	if tb.eval(t, `window.askAnnouncements === 1`) != "true" {
		t.Error("unchanged requests announced twice")
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 10, now.Add(2*time.Second), "answer", `"ask_id":"ask-second","approved":false,"by":"uid:1000 pid:9"`))
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 11, now.Add(3*time.Second), "answer", `"ask_id":"ask-8","approved":false,"by":"uid:1000 pid:9"`))
	tb.until(t, "answered", `!document.getElementById('ask-banner')`)
	near(t, tb, "anchored row after answer", anchor, before)
}

// TestAskBannerOpenedWithAskInChrome covers the formerly obscured error messages, compact band,
// scripts-off operation, and the old phone age rewrite which changed the band's line count.
func TestAskBannerOpenedWithAskInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{390, 1280} {
		for _, js := range []bool{true, false} {
			for _, path := range []string{"/", "/runs/" + cleanRun, "/logs", "/no-such-page", "/rule", "/rules/change"} {
				t.Run(fmt.Sprintf("%d/js=%t/%s", width, js, path), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 900, "light")
					c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !js})
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + "?t=tok123"})
					tb.until(t, "page", `document.readyState === 'complete' && !!document.getElementById('ask-banner')`)
					if js {
						tb.until(t, "scripts", `!!window.tegoLive.steady`)
					}
					if got := tb.eval(t, `scrollY === 0 && !window.tegoRoom && !document.documentElement.style.getPropertyValue('--ask-room')`); got != "true" {
						t.Error("page opened scrolled by synthetic ask room")
					}
					if got := tb.eval(t, `(()=>{const b=document.getElementById('ask-banner'),h=document.querySelector('main h1,main h3');return h && h.getBoundingClientRect().top >= b.getBoundingClientRect().bottom})()`); got != "true" {
						t.Error("band covers page message")
					}
					if tb.eval(t, `!!document.querySelector('#ask-banner .ab-timing .ask-wait')`) != "true" {
						t.Error("band lacks held-duration and wait context")
					}
					if tb.eval(t, `document.getElementById('ask-banner').getAttribute('role') === 'region' && document.getElementById('ask-say').getAttribute('aria-live') === 'polite'`) != "true" {
						t.Error("band lacks named region and polite announcement")
					}
					if js {
						before := settle(t, tb, `document.getElementById('ask-banner').getBoundingClientRect().height`)
						tb.eval(t, `var bandTime = document.querySelector("#ask-banner [data-ago]"); window.bandTimeBefore = bandTime ? bandTime.textContent : ""; ""`)
						tb.eval(t, `var realNow=Date.now; Date.now=()=>realNow()+864000000000; window.tegoLive.after(); Date.now=realNow; ""`)
						if tb.eval(t, `!window.bandTimeBefore || document.querySelector("#ask-banner [data-ago]").textContent === window.bandTimeBefore`) != "true" {
							t.Error("banner timestamp rewritten after paint")
						}
						if after := settle(t, tb, `document.getElementById('ask-banner').getBoundingClientRect().height`); after != before {
							t.Errorf("band height changed after age tick: %d to %d", before, after)
						}
					}
					if path == "/logs" || path == "/runs/"+cleanRun {
						tb.clean(t, "in-flow band")
					}
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}

// TestOverviewRowHoldsInChrome: a new refusal does not move the row under the pointer, the list follows once the
// pointer leaves, and a pointer left resting does not keep it stale for good.
func TestOverviewRowHoldsInChrome(t *testing.T) {
	root := fixture(t)
	now := time.Now()
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/first.txt"`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	ov := c.open(t, "overview", "http://"+addr+"/?t=tok123")
	ov.c.call(t, ov.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": false})
	ov.until(t, "loaded", `document.readyState === "complete" && !!window.tegoLive && !!window.tegoLive.steady`)
	const list = `document.querySelector("[data-live=r-ov-refusals]")`
	ov.until(t, "the refusal listed", list+`.textContent.includes("/p/first.txt")`)
	ov.eval(t, `document.querySelector("[data-live=r-ov-refusals]").querySelector("li").scrollIntoView({block:"center"}); ""`)
	var box struct{ X, Y float64 }
	b := ov.eval(t, `JSON.stringify((function () { var r = `+list+`.querySelector("li").getBoundingClientRect(); return { X: r.left + 40, Y: r.top + 8 }; })())`)
	s, err := strconv.Unquote(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(s), &box); err != nil {
		t.Fatal(err)
	}
	mouse := func(x, y float64) {
		c.call(t, ov.session, "Input.dispatchMouseEvent", map[string]any{"type": "mouseMoved", "x": x, "y": y})
	}
	mouse(box.X, box.Y)
	ov.until(t, "the pointer on the list", list+`.matches(":hover")`)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, now.Add(time.Second), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/second.txt"`))
	time.Sleep(2500 * time.Millisecond) // the stream's change, and a merge a second later had it moved
	if strings.Contains(ov.eval(t, list+`.textContent`), "/p/second.txt") {
		t.Error("the list moved under the pointer")
	}
	mouse(5, 5)
	ov.until(t, "the list after the pointer left", list+`.textContent.includes("/p/second.txt")`)

	mouse(box.X, box.Y)
	ov.until(t, "the pointer back on the list", list+`.matches(":hover")`)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 9, now.Add(2*time.Second), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/third.txt"`))
	ov.until(t, "the list with the pointer left resting", list+`.textContent.includes("/p/third.txt")`)
}
