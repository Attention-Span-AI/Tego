// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFix4PhoneRecoveryInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, state := range []string{"approvals-complete", "approvals-incomplete", "approvals-cold-index", "approvals-history-cold-index", "overview-cold-index", "overview-root-error", "run-cold-index", "connection-error", "run-root-error"} {
		for _, width := range []int{360, 1280} {
			for _, theme := range []string{"light", "dark"} {
				t.Run(fmt.Sprintf("%s/%d/%s", state, width, theme), func(t *testing.T) {
					root := fixture(t)
					path := "/approvals"
					if state == "approvals-incomplete" || state == "run-root-error" || state == "overview-root-error" {
						root = twoRequestFixture(t)
					}
					if state == "approvals-incomplete" {
						makeUnreadableCandidate(t, root)
					}
					if state == "approvals-cold-index" || state == "approvals-history-cold-index" || state == "overview-cold-index" || state == "run-cold-index" {
						holdLock(t, filepath.Join(root, harmRun))
						if err := os.RemoveAll(filepath.Join(root, ".live")); err != nil {
							t.Fatal(err)
						}
					}
					if state == "run-cold-index" || state == "run-root-error" {
						path = "/runs/" + harmRun
					}
					if state == "approvals-history-cold-index" {
						path = "/approvals?tab=history"
					}
					if state == "overview-cold-index" || state == "overview-root-error" {
						path = "/"
					}
					if state == "connection-error" {
						root = filepath.Join(t.TempDir(), "not-a-ledger")
						if err := os.WriteFile(root, nil, 0600); err != nil {
							t.Fatal(err)
						}
						path = "/machine"
					}
					_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
					if state == "run-root-error" || state == "overview-root-error" {
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
					tb.until(t, "recovery page ready", `document.readyState==='complete' && !!document.querySelector('main h1')`)
					tb.until(t, "fonts ready", `document.fonts.status==='loaded'`)
					metrics := tb.eval(t, `(()=>{const m=document.querySelector('main');const lead=[m.querySelector('.run-summary'),m.querySelector('.ap-compact'),m.querySelector('.panel .empty'),m.querySelector('.recovery-page .panel'),m.querySelector('.head'),m.querySelector('.panel')].find(e=>e&&e.checkVisibility());return {mainHeight:Math.round(m.getBoundingClientRect().height),leadHeight:lead?Math.round(lead.getBoundingClientRect().bottom-m.getBoundingClientRect().top):0,leadBottom:lead?Math.round(lead.getBoundingClientRect().bottom+scrollY):0,contentBottom:Math.round(m.getBoundingClientRect().bottom+scrollY),viewportHeight:innerHeight,visibleRecovery:[...document.querySelectorAll('main a.btn')].filter(e=>e.checkVisibility()).map(e=>e.textContent.trim()),visibleText:m.innerText}})()`)
					if out := os.Getenv("FIX4_SHOTS"); out != "" {
						name := fmt.Sprintf("%s-%d-%s", state, width, theme)
						fix3Shot(t, c, tb, out, name, false)
						if err := os.WriteFile(filepath.Join(out, name+".json"), []byte(metrics), 0600); err != nil {
							t.Fatal(err)
						}
					}
					if width == 360 && os.Getenv("FIX4_CAPTURE_ONLY") == "" {
						if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
							t.Error("phone content widens the page")
						}
						if state == "approvals-complete" && tb.eval(t, `[...document.querySelectorAll('main p')].some(e=>e.checkVisibility()&&e.textContent.trim()==='1 waiting')`) == "true" {
							t.Error("redundant complete waiting paragraph")
						}
						if state != "approvals-complete" {
							var m struct{ VisibleRecovery []string }
							if err := json.Unmarshal([]byte(metrics), &m); err != nil {
								t.Fatal(err)
							}
							if len(m.VisibleRecovery) > 1 {
								t.Errorf("phone exposes supplementary recovery controls: %v", m.VisibleRecovery)
							}
							if tb.eval(t, `(/(?:\b(?:open|lstat|stat|read(?:dir)?)\s+\/|events\.jsonl)/.test(document.querySelector('main').innerText))`) == "true" {
								t.Error("technical source path exposed outside disclosure")
							}
						}
						if state != "approvals-complete" {
							if tb.eval(t, `(()=>{const d=document.querySelector('details.count-coverage.phone-only');return !!d&&!d.open})()`) != "true" {
								t.Error("technical recovery must start closed")
							}
							tb.eval(t, `document.querySelector('details.count-coverage.phone-only > summary')?.click()`)
							if tb.eval(t, `[...document.querySelectorAll('details.count-coverage.phone-only a')].some(e=>e.checkVisibility()&&e.textContent.includes('All runs'))`) != "true" {
								t.Error("disclosure did not recover supplementary actions")
							}
							tb.eval(t, `document.querySelector('details.count-coverage.phone-only > summary')?.click()`)
						}
						if (state == "approvals-history-cold-index" || state == "overview-cold-index" || state == "overview-root-error") && tb.eval(t, `(()=>{const s=document.querySelector('main').innerText;return (s.includes('could not tell whether a request is waiting')||s.includes('at least 2 waiting'))&&(s.includes('the live index could not be read')||s.includes('the record folder could not be read'))})()`) != "true" {
							t.Error("phone lost its incomplete waiting explanation")
						}
						if state == "run-cold-index" && tb.eval(t, `[...document.querySelectorAll('main p')].filter(e=>e.checkVisibility()&&e.textContent.includes('could not tell whether a request is waiting')).length`) != "1" {
							t.Error("unknown waiting information must appear once")
						}
					}
					for _, problem := range tb.problems() {
						if (state == "connection-error" || state == "run-root-error") && strings.HasPrefix(problem, "browser network error: Failed to load resource: the server responded with a status of 500") && strings.Contains(problem, strings.Split(a1URL(addr, path), "?")[0]) {
							continue
						}
						t.Error(problem)
					}
				})
			}
		}
	}
}
