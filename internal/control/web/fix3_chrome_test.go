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

func TestLiveWaitingTitleStaysQualifiedInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{360, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, unknown := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/unknown=%v", width, theme, unknown), func(t *testing.T) {
					root := twoRequestFixture(t)
					if unknown {
						for _, r := range []string{harmRun, secondRequestRun} {
							appendLine(t, root, r, line(r, "Agent", 100, time.Now(), "answer", `"ask_id":"ask-7","approved":false`))
							appendLine(t, root, r, line(r, "Agent", 101, time.Now(), "answer", `"ask_id":"ask-B","approved":false`))
						}
					}
					makeUnreadableCandidate(t, root)
					_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
					tb := sweepTab(t, c, t.Name(), width, 900, theme)
					defer c.closeTarget(t, tb.target)
					c.call(t, tb.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": `(()=>{const add=EventSource.prototype.addEventListener;EventSource.prototype.addEventListener=function(kind,fn,...rest){if(kind==='state'){const original=fn;fn=function(e){original.call(this,e);window.fix3StateReceived=true;};}return add.call(this,kind,fn,...rest);};})()`})
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, "/approvals")})
					short, words := "2+", "at least 2 waiting:"
					if unknown {
						short, words = "?", "could not tell whether a request is waiting:"
					}
					tb.until(t, "qualified live title", `document.readyState==='complete' && !!window.tegoLive && document.title.startsWith(`+fmt.Sprintf("%q", "("+short+")")+`)`)
					tb.until(t, "live state applied", `document.body.dataset.conn==='ok' && window.fix3StateReceived===true`)
					if tb.eval(t, `document.documentElement.scrollWidth<=document.documentElement.clientWidth && innerWidth===`+fmt.Sprint(width)) != "true" {
						t.Fatalf("waiting state widens the viewport: %s", tb.eval(t, `JSON.stringify({inner:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,nodes:[...document.querySelectorAll('main *')].filter(e=>e.checkVisibility()&&e.getBoundingClientRect().right>document.documentElement.clientWidth+1).map(e=>({tag:e.tagName,cls:e.className,text:e.textContent.slice(0,100),right:e.getBoundingClientRect().right}))})`))
					}
					if tb.eval(t, `(()=>{const n=document.querySelector('.ap-tabs a .n');return n?.textContent.trim()===`+fmt.Sprintf("%q", short)+` && n.getAttribute('aria-label').includes(`+fmt.Sprintf("%q", words)+`)})()`) != "true" {
						t.Fatal("compact waiting tab disagrees with qualified waiting state")
					}
					// The stream is active here. A raw pending integer would have overwritten the qualified title.
					if tb.eval(t, `document.title.startsWith(`+fmt.Sprintf("%q", "("+short+")")+`)`) != "true" {
						t.Fatal("live title lost qualification")
					}
					if tb.eval(t, `Array.from(document.querySelectorAll('main p,main h2,main h3')).some(e=>e.checkVisibility() && e.textContent.includes(`+fmt.Sprintf("%q", words)+`))`) != "true" {
						t.Fatal("visible waiting sentence disagrees with title")
					}
					if tb.eval(t, `document.querySelector('.nav .count')?.getAttribute('aria-label').includes(`+fmt.Sprintf("%q", words)+`)`) != "true" {
						t.Fatal("spoken badge disagrees with title")
					}
					if out := os.Getenv("FIX3_SHOTS"); out != "" {
						if err := os.MkdirAll(out, 0755); err != nil {
							t.Fatal(err)
						}
						fix3Shot(t, c, tb, out, fmt.Sprintf("waiting-%v-%d-%s", unknown, width, theme), true)
					}
					tb.clean(t, "qualified waiting")
				})
			}
		}
	}
}

func TestApprovalBandActualTabOrderInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{360, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", width, theme), func(t *testing.T) {
				_, addr, _ := liveServer(t, twoRequestFixture(t), 10*time.Second, 30*time.Second)
				tb := sweepTab(t, c, t.Name(), width, 900, theme)
				defer c.closeTarget(t, tb.target)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, "/approvals")})
				tb.until(t, "band and queue", `document.readyState==='complete' && !!document.querySelector('.approval-queue a') && !!document.querySelector('#ask-banner button[value="deny"]')`)
				if tb.eval(t, `(()=>{const q=[...document.querySelectorAll('.approval-queue a[href]')].find(e=>e.checkVisibility()&&e.tabIndex>=0);return ['approve','deny'].every(v=>document.querySelector('#ask-banner button[value="'+v+'"]').compareDocumentPosition(q)&Node.DOCUMENT_POSITION_FOLLOWING)})()`) != "true" {
					t.Fatal("DOM order places the queue before an answer")
				}
				seen := map[string]bool{}
				for i := 0; i < 60; i++ {
					tb.press(t, "Tab")
					active := strings.Trim(tb.eval(t, `(()=>{const e=document.activeElement;if(e.closest('#ask-banner')&&e.matches('button[value]'))return e.value;if(e===[...document.querySelectorAll('.approval-queue a[href]')].find(a=>a.checkVisibility()&&a.tabIndex>=0))return 'queue';return ''})()`), `"`)
					seen[active] = true
					if active == "queue" {
						break
					}
				}
				if !seen["queue"] || !seen["approve"] || !seen["deny"] {
					t.Fatalf("actual Tab order did not reach both answers before the queue: %v", seen)
				}
				if out := os.Getenv("FIX3_SHOTS"); out != "" {
					fix3Shot(t, c, tb, filepath.Join(out, "order"), fmt.Sprintf("band-%d-%s", width, theme), true)
				}
				tb.clean(t, "actual band tab order")
			})
		}
	}
}

// fix3Shot keeps these public checks independent of private page matrix fixtures.
func fix3Shot(t *testing.T, c *cdp, tb *tab, out, name string, full bool) {
	t.Helper()
	if err := os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"format": "png", "captureBeyondViewport": full}
	if full {
		var size struct{ Width, Height float64 }
		if err := json.Unmarshal([]byte(tb.eval(t, `({Width:innerWidth,Height:document.documentElement.scrollHeight})`)), &size); err != nil {
			t.Fatal(err)
		}
		args["clip"] = map[string]any{"x": 0, "y": 0, "width": size.Width, "height": size.Height, "scale": 1}
	}
	var shot struct{ Data []byte }
	if err := json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", args), &shot); err != nil {
		t.Fatal(err)
	}
	if len(shot.Data) == 0 {
		t.Fatal("empty screenshot")
	}
	if err := os.WriteFile(filepath.Join(out, name+".png"), shot.Data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestColdMissingIndexStatesInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{360, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, path := range []string{"/approvals", "/runs/" + harmRun} {
				name := "approvals"
				if strings.HasPrefix(path, "/runs/") {
					name = "run"
				}
				t.Run(fmt.Sprintf("%s/%d/%s", name, width, theme), func(t *testing.T) {
					root := twoRequestFixture(t)
					if err := os.RemoveAll(filepath.Join(root, ".live")); err != nil {
						t.Fatal(err)
					}
					_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
					tb := sweepTab(t, c, t.Name(), width, 900, theme)
					defer c.closeTarget(t, tb.target)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, path)})
					tb.until(t, "cold source uncertainty", `document.readyState==='complete' && document.title.startsWith('(?)') && document.querySelector('main').textContent.includes('could not read the live index')`)
					if tb.eval(t, `document.documentElement.scrollWidth<=document.documentElement.clientWidth && innerWidth===`+fmt.Sprint(width)) != "true" {
						t.Fatal("cold missing-index state widened the viewport")
					}
					if tb.eval(t, `document.querySelector('.nav .count')?.getAttribute('aria-label').includes('could not tell whether a request is waiting:')`) != "true" {
						t.Fatal("cold missing index lost its spoken unknown count")
					}
					if tb.eval(t, `document.querySelector('main').textContent.includes('Nothing waiting') || document.querySelector('main').textContent.includes('This run was lost')`) == "true" {
						t.Fatal("cold missing index became an all-clear or a lost-run claim")
					}
					if name == "run" && tb.eval(t, `document.querySelector('main').textContent.includes('State unknown')`) != "true" {
						t.Fatal("unknown run status was not visible")
					}
					if out := os.Getenv("FIX3_SHOTS"); out != "" {
						fix3Shot(t, c, tb, filepath.Join(out, "cold-index"), fmt.Sprintf("%s-%d-%s", name, width, theme), true)
					}
					if name == "run" {
						tb.eval(t, `document.querySelector('#run-details > summary').click()`)
						tb.until(t, "expanded unknown facts", `document.querySelector('#run-details').open`)
						if tb.eval(t, `(()=>{const facts=[...document.querySelectorAll('#run-details dt')].filter(e=>['Ended','Asks'].includes(e.textContent.trim()));return facts.length===2 && facts.every(e=>{const s=e.nextElementSibling.textContent.toLowerCase();return s.includes('not known')&&s.includes('live index')&&!s.includes('lost')})})()`) != "true" {
							t.Fatal("expanded details guessed the unknown run was lost")
						}
					}
					tb.clean(t, "cold missing index")
				})
			}
		}
	}
}
