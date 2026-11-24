// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The current summary defers the agent to its Event. Test that actual route at
// enlarged text sizes, rather than measuring the retired hidden desktop cell.
func TestShellLogsAgentTextSizeInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, logsRuleTitleFixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	const agent = "support-ticket-triage-worker-for-the-eu-billing-queue"
	for _, large := range []bool{false, true} {
		widths := []int{600, 1280}
		if large {
			widths = []int{768, 861, 1280}
		}
		for _, width := range widths {
			for _, theme := range []string{"light", "dark"} {
				for _, path := range []string{"/logs", "/logs?q=ticket"} {
					t.Run(fmt.Sprintf("text200=%t/%d/%s/%s", large, width, theme, path), func(t *testing.T) {
						tb := sweepTab(t, c, t.Name(), width, 900, theme)
						standard, fixed := 16, 13
						if large {
							standard, fixed = 32, 26
						}
						c.call(t, tb.session, "Page.setFontSizes", map[string]any{"fontSizes": map[string]int{"standard": standard, "fixed": fixed}})
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, path)})
						tb.until(t, "logs and font", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('.lw-agent')`)
						expr := fmt.Sprintf(`(()=>{const label=[...document.querySelectorAll('.lw-agent')].find(e=>e.textContent.trim()===%q),row=label?.closest('tr');return [...(row?.querySelectorAll('a[href]')||[])].find(e=>e.checkVisibility({contentVisibilityAuto:true})&&/\/lines\//.test(e.getAttribute('href')))?.getAttribute('href');})()`, agent)
						var href string
						if err := json.Unmarshal([]byte(tb.eval(t, expr)), &href); err != nil || href == "" {
							t.Fatalf("no visible Event recovery link: %v", err)
						}
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + href})
						tb.until(t, "agent in Event", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('.event-page')`)
						expected := 0.0
						if large && width == 1280 {
							expected = 28
						}
						assertFullTextAtScale(t, tb, `[...document.querySelectorAll('.event-page .kv dt')].find(e=>e.textContent==='Agent')?.nextElementSibling`, agent, expected)
						tb.clean(t, "enlarged Event agent")
					})
				}
			}
		}
	}
}

func assertFullTextAtScale(t *testing.T, tb *tab, element, want string, expectedFont float64) float64 {
	t.Helper()
	raw := tb.eval(t, `(e=>{if(!e)return null;const box=e.getBoundingClientRect(),style=getComputedStyle(e),fragments=[],clips=[];for(const text of e.childNodes)if(text.nodeType===3&&text.textContent.trim()){const r=document.createRange();r.selectNodeContents(text);for(const x of r.getClientRects()){fragments.push(x.toJSON());for(let a=e;a;a=a.parentElement){const s=getComputedStyle(a),b=a.getBoundingClientRect();if((/hidden|clip/.test(s.overflowX)&&(x.left<b.left-1||x.right>b.right+1))||(/hidden|clip/.test(s.overflowY)&&(x.top<b.top-1||x.bottom>b.bottom+1))){clips.push(a.tagName+'.'+a.className);break;}}}}return {text:e.textContent.trim(),font:parseFloat(style.fontSize),width:box.width,fragments:fragments.length,clips,overflow:document.documentElement.scrollWidth>document.documentElement.clientWidth};})(`+element+`)`)
	var m struct {
		Text        string
		Font, Width float64
		Fragments   int
		Clips       []string
		Overflow    bool
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if m.Text != want || m.Width <= 0 || m.Fragments == 0 || len(m.Clips) > 0 || m.Overflow {
		t.Fatalf("full value inaccessible: %s; expected %s", raw, strconv.Quote(want))
	}
	if expectedFont > 0 && math.Abs(m.Font-expectedFont) > .1 {
		t.Errorf("fixture did not enlarge recovered text: %s", raw)
	}
	if tb.eval(t, `getComputedStyle(`+element+`).whiteSpace==='nowrap'&&(`+element+`).scrollWidth>(`+element+`).clientWidth+1`) == "true" {
		t.Error("full value is still shortened")
	}
	t.Logf("recovered %d characters at %.2f px", len(strings.TrimSpace(want)), m.Font)
	return m.Font
}
