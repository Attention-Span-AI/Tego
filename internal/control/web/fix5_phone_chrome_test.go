// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestFix5PhoneRecoveryInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, state := range []string{"missing-ask-root", "missing-run-root", "answered"} {
		for _, width := range []int{360, 1280} {
			for _, theme := range []string{"light", "dark"} {
				t.Run(fmt.Sprintf("%s/%d/%s", state, width, theme), func(t *testing.T) {
					root := twoRequestFixture(t)
					path := "/approvals?run=" + secondRequestRun + "&ask=absent"
					if state == "missing-run-root" {
						path = "/approvals?run=r-bbbbbbbb-0000000000009-absent&ask=absent"
					}
					if state == "answered" {
						appendLine(t, root, secondRequestRun, line(secondRequestRun, "Second agent", 2, time.Now(), "answer", `"ask_id":"ask-B","approved":true,"by":"operator"`))
						path = "/approvals?run=" + secondRequestRun + "&ask=ask-B"
					}
					_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
					if state != "answered" {
						if _, err := ledgerview.Load(root); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(root, 0); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = os.Chmod(root, 0700) })
					}
					tb := sweepTab(t, c, t.Name(), width, 900, theme)
					defer c.closeTarget(t, tb.target)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, path)})
					tb.until(t, "recovery ready", `document.readyState==='complete'&&!!document.querySelector('main h1')&&document.fonts.status==='loaded'`)
					metrics := tb.eval(t, `(()=>{const m=document.querySelector('main'),lead=m.querySelector('.panel');return {mainHeight:Math.round(m.getBoundingClientRect().height),leadHeight:Math.round(lead.getBoundingClientRect().bottom-m.getBoundingClientRect().top),visibleText:m.innerText,visibleRecovery:[...m.querySelectorAll('a.btn')].filter(e=>e.checkVisibility()).map(e=>e.textContent.trim())}})()`)
					if out := os.Getenv("FIX5_SHOTS"); out != "" {
						name := fmt.Sprintf("%s-%d-%s", state, width, theme)
						fix3Shot(t, c, tb, out, name, false)
						if err := os.WriteFile(filepath.Join(out, name+".json"), []byte(metrics), 0600); err != nil {
							t.Fatal(err)
						}
					}
					if os.Getenv("FIX5_CAPTURE_ONLY") == "" && width == 360 {
						if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
							t.Error("phone content widens the page")
						}
						if tb.eval(t, `[...document.querySelectorAll('main a.btn')].filter(e=>e.checkVisibility()).length<=1`) != "true" {
							t.Error("phone exposes supplementary recovery actions")
						}
						if state != "answered" {
							if tb.eval(t, `(/(?:\b(?:open|lstat|stat|read(?:dir)?)\s+\/|events\.jsonl)/.test(document.querySelector('main').innerText))`) == "true" {
								t.Error("technical root diagnostic exposed outside closed details")
							}
							if tb.eval(t, `document.querySelector('main').innerText.includes('Waiting requests are not fully known:')`) == "true" {
								t.Error("request detail repeats the uncertainty explanation")
							}
							if tb.eval(t, `[...document.querySelectorAll('main p.phone-only')].filter(e=>e.checkVisibility()&&e.textContent.includes('at least 2 waiting')).length`) != "1" {
								t.Error("short root uncertainty must appear exactly once")
							}
						}
						tb.eval(t, `[...document.querySelectorAll('main details')].forEach(e=>e.open=true)`)
						if state == "answered" && tb.eval(t, `[...document.querySelectorAll('main a')].some(e=>e.checkVisibility()&&e.textContent==='Next waiting request')`) != "true" {
							t.Error("supplementary action is not recoverable")
						}
					}
					for _, problem := range tb.problems() {
						t.Error(problem)
					}
				})
			}
		}
	}
}
