// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestExactRequestNavigationInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, js := range []bool{true, false} {
		for _, from := range []string{"/", "/runs/" + secondRequestRun} {
			t.Run(fmt.Sprintf("%s/js=%v", from, js), func(t *testing.T) {
				_, addr, _ := liveServer(t, twoRequestFixture(t), 10*time.Second, 30*time.Second)
				tb := sweepTab(t, c, t.Name(), 1280, 900, "light")
				defer c.closeTarget(t, tb.target)
				c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !js})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, from)})
				tb.until(t, "source", `document.readyState==='complete' && !!document.querySelector('main h1')`)
				selector := `document.querySelector('.wait-row[data-k="` + secondRequestRun + `-ask-B"] a')`
				if from != "/" {
					tb.eval(t, `document.querySelector('#run-details').open=true;''`)
					selector = `document.querySelector('.hl-what[href*="ask-B"]')`
				}
				if tb.eval(t, `!!`+selector) != "true" {
					t.Fatal("no request B link")
				}
				tb.eval(t, selector+`.focus();''`)
				tb.press(t, "Enter")
				tb.until(t, "request B", `location.pathname==='/approvals' && document.readyState==='complete' && !!document.querySelector('.ap-target')`)
				if tb.eval(t, `(()=>{const fs=Array.from(document.querySelectorAll('form[action="/approvals/answer"]'));return location.search.includes('run=`+secondRequestRun+`') && location.search.includes('ask=ask-B') && fs.length>0 && fs.every(f=>f.elements.run.value==='`+secondRequestRun+`' && f.elements.ask.value==='ask-B');})()`) != "true" {
					t.Error("review B exposed a different request's controls")
				}
				tb.clean(t, "exact request navigation")
			})
		}
	}
}

// Synthetic condition combinations enter the actual page templates and CSS.
// Every condition must remain visible alongside the priority headline on phones.
func TestPhoneAttentionCombinationsInChrome(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	c := placeChrome(t)
	for _, width := range []int{360, 390} {
		for mask := 0; mask < 16; mask++ {
			d := overviewData{Total: 1}
			r := runData{Run: &ledgerview.Run{ID: secondRequestRun, Live: true}, Now: time.Now()}
			want := "Nothing needs you"
			if mask&8 != 0 {
				d.Watched = 1
				r.Story.Read = []string{"/secret"}
				want = "Sensitive read recorded"
			}
			if mask&4 != 0 {
				d.Leaked = 1
				r.Story.Kind = ledgerview.VerdictLeak
				r.Story.Exposed = []string{"/secret"}
				want = "Secret leak recorded"
			}
			if mask&2 != 0 {
				d.Chain.Broken = &ledgerview.Chain{Run: secondRequestRun, State: ledgerview.ChainBroken}
				r.Chain = *d.Chain.Broken
				want = "Record needs attention"
			}
			if mask&1 != 0 {
				d.Pending = []ledgerview.Ask{{Run: secondRequestRun, AskID: "ask-B"}}
				r.Run.Pending = d.Pending
				want = "1 request needs you"
			}
			for _, pg := range []struct {
				name, region string
				data         any
			}{{"overview", "r-ov-head", d}, {"run", "r-run-top", r}} {
				if mask == 0 && pg.name == "run" {
					want = "No secret read or unexpected send"
				}
				t.Run(fmt.Sprintf("%s/%d/%d", pg.name, width, mask), func(t *testing.T) {
					var fragment bytes.Buffer
					if err := pages[pg.name].ExecuteTemplate(&fragment, pg.region, page{Data: pg.data}); err != nil {
						t.Fatal(err)
					}
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						if strings.HasPrefix(req.URL.Path, "/static/") {
							http.FileServer(http.FS(assets)).ServeHTTP(w, req)
							return
						}
						fmt.Fprint(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/static/tokens.css"><link rel="stylesheet" href="/static/app.css"><link rel="stylesheet" href="/static/phone.css"><link rel="stylesheet" href="/static/overview.css"><link rel="stylesheet" href="/static/run.css"></head><body><main class="page">`+fragment.String()+`</main></body></html>`)
					}))
					defer srv.Close()
					tb := sweepTab(t, c, t.Name(), width, 844, "light")
					defer c.closeTarget(t, tb.target)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": srv.URL})
					tb.until(t, "rendered", `document.readyState==='complete' && !!document.querySelector('main h1,main .vt')`)
					selector := `document.querySelector('main h1')`
					if pg.name == "run" {
						selector = `document.querySelector('.vt')`
					}
					if tb.eval(t, selector+`.checkVisibility() && `+selector+`.textContent.includes(`+fmt.Sprintf("%q", want)+`)`) != "true" {
						t.Error("phone headline contradicts rendered conditions")
					}
					for _, condition := range []struct {
						bit         int
						kind, words string
					}{{1, "waiting", "1 waiting"}, {2, "broken", "Record needs attention"}, {4, "leak", "leaked secrets"}, {8, "read", "read secrets"}} {
						if mask&condition.bit != 0 && tb.eval(t, `Array.from(document.querySelectorAll('main p[data-attention="`+condition.kind+`"]')).some(e=>e.checkVisibility() && e.textContent.includes(`+fmt.Sprintf("%q", condition.words)+`))`) != "true" {
							t.Errorf("phone hides condition %s", condition.words)
						}
					}
				})
			}
		}
	}
}

func TestPhoneAttentionIncompleteSourcesInChrome(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	c := placeChrome(t)
	for _, width := range []int{360, 390} {
		for _, tc := range incompleteAttentionCases() {
			for _, pg := range incompleteAttentionPages(tc.source, tc.pending) {

				t.Run(fmt.Sprintf("%s/%s/%d", tc.name, pg.name, width), func(t *testing.T) {
					var fragment bytes.Buffer
					if err := pages[pg.name].ExecuteTemplate(&fragment, pg.region, page{chrome: chrome{Numbers: pg.numbers}, Data: pg.data}); err != nil {
						t.Fatal(err)
					}
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						if strings.HasPrefix(req.URL.Path, "/static/") {
							http.FileServer(http.FS(assets)).ServeHTTP(w, req)
							return
						}
						fmt.Fprint(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/static/tokens.css"><link rel="stylesheet" href="/static/app.css"><link rel="stylesheet" href="/static/phone.css"><link rel="stylesheet" href="/static/overview.css"><link rel="stylesheet" href="/static/run.css"><link rel="stylesheet" href="/static/approvals.css"></head><body><main class="page">`+fragment.String()+`</main></body></html>`)
					}))
					defer srv.Close()
					tb := sweepTab(t, c, t.Name(), width, 844, "light")
					defer c.closeTarget(t, tb.target)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": srv.URL})
					tb.until(t, "rendered", `document.readyState==='complete' && !!document.querySelector('main h1,main .vt')`)
					if pg.name == "approvals" && tc.source.forApprovals() == (attentionSource{}) {
						if tb.eval(t, `Array.from(document.querySelectorAll('main h3')).some(e=>e.checkVisibility() && e.textContent.includes('Nothing waiting'))`) != "true" {
							t.Error("unrelated source qualified the waiting headline")
						}
						return
					}
					for _, words := range []string{tc.headline, tc.reason} {
						if tb.eval(t, `Array.from(document.querySelectorAll('main h1,main h2,main h3,main .vt,main p')).some(e=>e.checkVisibility() && e.textContent.includes(`+fmt.Sprintf("%q", words)+`))`) != "true" {
							t.Errorf("phone hides incomplete source fact %s", words)
						}
					}
					if tb.eval(t, `Array.from(document.querySelectorAll('main h1,main h3,main .vt')).some(e=>e.checkVisibility() && /Nothing needs you|Nothing waiting|No secret read or unexpected send recorded/.test(e.textContent))`) != "false" {
						t.Error("phone gives an all-clear with an incomplete source")
					}
				})
			}
		}
	}
}
