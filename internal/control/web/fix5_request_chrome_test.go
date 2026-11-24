// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// requestProbe reads one shared banner (#ask-banner) as a person sees it: the sentence of the width's form (the
// phone sentence at 600 px and under, else the wide one: .ab-h on a page's line banner, .ab-what on Overview), its
// text nodes that are painted and not for assistive technology only, its line boxes up to the end of the target,
// whether Allow once or Deny is visible, and whether Review request is.
const requestProbe = `(()=>{
const vis=e=>!!e&&e.checkVisibility()&&e.getClientRects().length>0;
const root=document.querySelector('#ask-banner');
if(!vis(root))return {banner:false};
const phone=innerWidth<=600;
const s=phone?root.querySelector('.ab-summary'):root.querySelector(root.classList.contains('ab-line')?'.ab-h':'.ab-what');
let text='';const rects=[];
s.setAttribute('data-probe-sentence','');
const w=document.createTreeWalker(s,NodeFilter.SHOW_TEXT);let n;
while(n=w.nextNode()){if(n.parentElement.closest('.sr,.ab-timing'))continue;const r=document.createRange();r.selectNodeContents(n);const rs=[...r.getClientRects()].filter(x=>x.width>0);if(!rs.length)continue;text+=n.data;rects.push(...rs)}
rects.sort((a,b)=>a.top-b.top);let lines=0,bottom=-1e9;for(const r of rects){if(r.top>=bottom-2){lines++;bottom=r.bottom}else bottom=Math.max(bottom,r.bottom)}
const ink=rects.reduce((a,r)=>a+r.width,0),cs=getComputedStyle(s),box=s.clientWidth?s.clientWidth-parseFloat(cs.paddingLeft)-parseFloat(cs.paddingRight):s.getBoundingClientRect().width;
const quick=[...root.querySelectorAll('button[name=decision]')].some(vis);
const words=[...root.querySelectorAll('.ab-note,.ab-what,.ab-h,.ab-summary')].filter(vis).some(e=>e.innerText.includes('Allow once'));
const review=root.querySelector('.ab-review a');
const inside=[...root.querySelectorAll('button,a')].filter(vis).every(e=>{const r=e.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth+1});
return ({banner:true,text,lines,ink,box,quick,words,review:vis(review),reviewHref:review?review.getAttribute('href'):'',reviewLabel:review?review.getAttribute('aria-label'):'',label:phone?s.getAttribute('aria-label'):(s.querySelector('[data-number-exclude="layout.request-full"]')||{}).textContent||'',height:Math.round(root.getBoundingClientRect().height),inside,scroll:document.documentElement.scrollWidth<=innerWidth})})()`

type requestSeen struct {
	Banner                  bool
	Text                    string
	Lines                   int
	Ink, Box                float64
	Quick, Review, Words    bool
	ReviewHref, ReviewLabel string
	Label                   string
	Height                  int
	Inside, Scroll          bool
}

// TestFix5FullRequestInChrome holds the one rule of the request sentence (ADR 0123, "Request sentence forms"): a person
// is never offered Allow once beside a request they cannot read in full there. At 320, 360, 390 and 1280 px in both
// themes, for the sentence just under and just over each bound, the review's 200-character host, a deep path and a
// 4,000-character command: where the width's form is FULL the banners show every character and the quick answers;
// where it is LONG they show the cut sentence with both kept ends and one action, Review request, which opens the
// request's own card with the exact target whole, Allow once and Deny. The FULL form at the bounds takes at most
// four lines at 320 px and two at 1280 px. The waiting row follows the same two forms; the accessible names carry the
// whole sentence. With FIX5_SHOTS it saves each state and its first-screen heights; FIX5_CAPTURE_ONLY skips the
// assertions (the before captures of an older head).
func TestFix5FullRequestInChrome(t *testing.T) {
	c := placeChrome(t)
	capture := os.Getenv("FIX5_CAPTURE_ONLY") != ""
	for _, tc := range requestCases() {
		v := requestOf(ledgerview.Ask{Agent: tc.Agent, Op: tc.Op, Hold: tc.Hold, Target: tc.Target, Run: secondRequestRun, AskID: "long-request"}, nil)
		for _, width := range []int{320, 360, 390, 1280} {
			for _, theme := range []string{"light", "dark"} {
				t.Run(fmt.Sprintf("%s/%d/%s", tc.Name, width, theme), func(t *testing.T) {
					root := t.TempDir()
					id := secondRequestRun
					if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), nil, 0600); err != nil {
						t.Fatal(err)
					}
					at := time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC)
					appendLine(t, root, id, line(id, tc.Agent, 0, at, "run_start", `"tier":"landlock","command":["sh"]`))
					extra, err := json.Marshal(map[string]any{"ask_id": "long-request", "op": tc.Op, "hold": tc.Hold, "target": tc.Target})
					if err != nil {
						t.Fatal(err)
					}
					appendLine(t, root, id, line(id, tc.Agent, 1, at.Add(time.Second), "ask", string(extra[1:len(extra)-1])))
					markLive(t, root, id)
					_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
					height := map[int]int{320: 640, 360: 780, 390: 844, 1280: 900}[width]
					tb := sweepTab(t, c, t.Name(), width, height, theme)
					defer c.closeTarget(t, tb.target)
					phone := width <= 600
					form := v.Wide
					if phone {
						form = v.Phone
					}
					wantTarget, wantAgent := tc.Target, tc.Agent
					if form.Long {
						wantTarget, wantAgent = form.Target, form.Agent
					}
					// see checks one banner against the width's form; the core is that Allow once is never visible beside
					// a cut sentence.
					see := func(page string) {
						var s requestSeen
						if err := json.Unmarshal([]byte(tb.eval(t, requestProbe)), &s); err != nil {
							t.Fatal(err)
						}
						if !s.Banner {
							t.Errorf("%s: no visible request banner", page)
							return
						}
						t.Logf("%s: the sentence is painted in %v", page, platformFonts(t, tb, "[data-probe-sentence]"))
						if s.Quick && strings.Contains(s.Text, "…") {
							t.Errorf("%s: Allow once is offered beside a cut request: %q", page, s.Text)
						}
						if s.Words && !s.Quick {
							t.Errorf("%s: the banner explains Allow once where it offers none", page)
						}
						if s.Quick == form.Long || s.Review != form.Long {
							t.Errorf("%s: LONG %v but quick answers %v and Review request %v", page, form.Long, s.Quick, s.Review)
						}
						if !strings.Contains(s.Text, wantTarget) || strings.Contains(s.Text, "…") != form.Long {
							t.Errorf("%s: the %s form does not show %q: %q", page, map[bool]string{true: "LONG", false: "FULL"}[form.Long], wantTarget, s.Text)
						}
						if !strings.Contains(s.Text, wantAgent) && !(page == "overview" && !phone) {
							t.Errorf("%s: the sentence does not name %q: %q", page, wantAgent, s.Text)
						}
						if form.Long && (!strings.HasPrefix(wantTarget, tc.Head) || !strings.HasSuffix(wantTarget, tc.Tail)) {
							t.Errorf("%s: the cut target lost a kept end: %q", page, wantTarget)
						}
						// In any font: the lines of the sentence are bounded by its measured text width over its box's width, and one
						// more for the word that does not end where a line does (a runaway wrap, a column a character wide, fails
						// whatever the font).
						if s.Box < 1 || s.Ink < 1 {
							t.Errorf("%s: the sentence's measured width is %.1f in a box of %.1f", page, s.Ink, s.Box)
						} else if need := int(math.Ceil(s.Ink/s.Box)) + 1; s.Lines > need {
							t.Errorf("%s: the sentence takes %d lines, but its text %.0f px wide in a box %.0f px wide needs at most %d", page, s.Lines, s.Ink, s.Box, need)
						}
						// The design's own bound (ADR 0123: four lines at 320 px, two at 1280 px) was measured in Noto Sans, so it is
						// asserted where the page was painted in Noto Sans, and only reported anywhere else.
						if limit := map[bool]int{true: 4, false: 2}[phone]; s.Lines > limit && (width == 320 || width == 1280) {
							if fonts := platformFonts(t, tb, "[data-probe-sentence]"); inFont(fonts, "Noto Sans") {
								t.Errorf("%s: the sentence takes %d lines in Noto Sans, more than %d", page, s.Lines, limit)
							} else {
								t.Logf("%s: the sentence takes %d lines, over the design's %d, in %v, not the Noto Sans it was measured in: not asserted", page, s.Lines, limit, fonts)
							}
						}
						if (phone || form.Long) && s.Label != v.Full {
							t.Errorf("%s: the accessible sentence is not whole: %q", page, s.Label)
						}
						if form.Long && (s.ReviewLabel != "Review request: "+v.Full || s.ReviewHref != approvalURL(id, "long-request")+"#long-request") {
							t.Errorf("%s: Review request does not name the whole request or its card: %q %q", page, s.ReviewLabel, s.ReviewHref)
						}
						if !s.Inside || !s.Scroll {
							t.Errorf("%s: a banner action leaves the viewport or the page scrolls sideways", page)
						}
					}
					shot := func(page, lead string) {
						out := os.Getenv("FIX5_SHOTS")
						if out == "" {
							return
						}
						name := fmt.Sprintf("request-%s-%s%d-%s", tc.Name, page, width, theme)
						fix3Shot(t, c, tb, out, name, false)
						metrics := tb.eval(t, fmt.Sprintf(`(()=>{const m=document.querySelector('main'),b=document.querySelector('#ask-banner'),lead=[...document.querySelectorAll(%q)].find(e=>e.checkVisibility());return JSON.stringify({mainHeight:Math.round(m.getBoundingClientRect().height),leadHeight:lead?Math.round(lead.getBoundingClientRect().bottom-m.getBoundingClientRect().top):0,bannerHeight:b&&b.checkVisibility()?Math.round(b.getBoundingClientRect().height):0,visibleText:m.innerText.slice(0,1500)})})()`, lead))
						var raw string
						if err := json.Unmarshal([]byte(metrics), &raw); err != nil {
							raw = metrics
						}
						if err := os.WriteFile(filepath.Join(out, name+".json"), []byte(raw), 0600); err != nil {
							t.Fatal(err)
						}
					}

					c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, "/approvals")})
					tb.until(t, "request ready", `document.readyState==='complete'&&!!document.querySelector('.ap-compact')&&document.fonts.status==='loaded'`)
					shot("", ".ap-compact, .ap-detail .ask")
					if !capture {
						if phone {
							see("approvals")
						} else if tb.eval(t, fmt.Sprintf(`(()=>{const c=document.querySelector('.ap-detail .ask'),b=c&&c.querySelector('.ut-box');return !!b&&b.textContent===%s&&b.checkVisibility()&&[...c.querySelectorAll('button[name=decision]')].some(e=>e.checkVisibility())})()`, jsString(tc.Target))) != "true" {
							t.Error("approvals: the wide card does not show the exact target whole beside its answers")
						}
						row := tb.eval(t, `(()=>{const q=document.querySelector('.approval-queue .phone-who');let text='';const rects=[];const w=document.createTreeWalker(q,NodeFilter.SHOW_TEXT);let n;while(n=w.nextNode()){if(n.parentElement.closest('.sr'))continue;const r=document.createRange();r.selectNodeContents(n);const rs=[...r.getClientRects()].filter(x=>x.width>0);if(rs.length){text+=n.data;rects.push(...rs)}}const sr=q.querySelector('.sr');return ({text,sr:sr?sr.textContent:'',inside:rects.every(x=>x.left>=0&&x.right<=innerWidth+1),ellipsis:getComputedStyle(q).textOverflow})})()`)
						var seenRow struct {
							Text, Sr, Ellipsis string
							Inside             bool
						}
						if err := json.Unmarshal([]byte(row), &seenRow); err != nil {
							t.Fatal(err)
						}
						if !strings.Contains(seenRow.Text, wantAgent+" wants to "+askVerb(tc.Op, "", tc.Hold)+" "+wantTarget) || strings.Contains(seenRow.Text, "…") != form.Long || (form.Long && seenRow.Sr != v.Full) || !seenRow.Inside || seenRow.Ellipsis == "ellipsis" {
							t.Errorf("approvals: the waiting row does not follow the %v form: %+v", form.Long, seenRow)
						}
						if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
							t.Error("approvals: the page scrolls sideways")
						}
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, "/")})
					tb.until(t, "overview request ready", `document.readyState==='complete'&&!!document.querySelector('#ask-banner')&&document.fonts.status==='loaded'`)
					shot("overview-", "#ask-banner")
					if !capture {
						see("overview")
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, "/runs")})
					tb.until(t, "runs request ready", `document.readyState==='complete'&&!!document.querySelector('#ask-banner')&&document.fonts.status==='loaded'`)
					shot("runs-", "#ask-banner")
					if capture {
						return
					}
					see("runs")
					// The request's own card: FULL whatever its length, with its answers, reached by Review request where
					// the banner is LONG.
					if form.Long {
						tb.eval(t, `document.querySelector('#ask-banner .ab-review a').click();''`)
					} else {
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, approvalURL(id, "long-request")) + "#long-request"})
					}
					tb.until(t, "request card", `document.readyState==='complete'&&location.hash==='#long-request'&&!!document.querySelector('#long-request .ut-box')`)
					// On a phone the exact target's box is capped at 8.5rem and scrolls inside itself (approvals.css), so "whole"
					// is: every character is in the box, and the box either fits it or scrolls to its last line within the cap.
					if tb.eval(t, fmt.Sprintf(`(()=>{const c=document.querySelector('#long-request'),b=c.querySelector('.ut-box'),q=c.querySelector('.ask-q');return b.textContent===%s&&b.checkVisibility()&&b.scrollWidth<=b.clientWidth+1&&(b.scrollHeight<=b.clientHeight+1||(['auto','scroll'].includes(getComputedStyle(b).overflowY)&&b.clientHeight<=parseFloat(getComputedStyle(document.documentElement).fontSize)*8.5+1&&(()=>{b.scrollTop=b.scrollHeight;return b.scrollTop+b.clientHeight>=b.scrollHeight-1})()))&&q.textContent.includes(%s)&&[...c.querySelectorAll('button[name=decision]')].filter(e=>e.checkVisibility()).length>=2&&document.documentElement.scrollWidth<=innerWidth&&!document.querySelector('.ap-compact')})()`, jsString(tc.Target), jsString(tc.Agent))) != "true" {
						t.Error("the request's card does not show the whole request beside Allow once and Deny")
					}
					if strings.Contains(tc.Target, "two  spaces") && tb.eval(t, `(()=>{const e=document.querySelector('#long-request .ut-box'),w=document.createTreeWalker(e,NodeFilter.SHOW_TEXT);let n;while(n=w.nextNode()){const i=n.data.indexOf('two  spaces');if(i<0)continue;return [i+3,i+4].every(p=>{const r=document.createRange();r.setStart(n,p);r.setEnd(n,p+1);return r.getBoundingClientRect().width>0})}return false})()`) != "true" {
						t.Error("the request's card collapses the command's whitespace")
					}
					for _, problem := range tb.problems() {
						t.Error(problem)
					}
				})
			}
		}
	}
}
