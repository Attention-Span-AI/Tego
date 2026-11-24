// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// The matrix uses the real templates, authenticated HTTP server and CSP. It also
// records legacy interior findings separately so page packages have an honest baseline.
func TestPhoneShellMatrixInChrome(t *testing.T) {
	root := fixture(t)
	// Replace the unresolved old ask with a real destination and a long agent name.
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":false`))
	appendLine(t, root, harmRun, line(harmRun, strings.Repeat("Mira", 15), 8, now, "ask", `"ask_id":"phone-ask","hold":"net","op":"connect","target":"registry.npmjs.org"`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	var records []map[string]any
	for _, width := range []int{320, 360, 390, 430, 768, 1280} {
		height := map[int]int{320: 640, 360: 780, 390: 844, 430: 932, 768: 1024, 1280: 900}[width]
		for _, theme := range []string{"light", "dark"} {
			for _, pg := range []struct{ name, path string }{{"overview", "/"}, {"runs", "/runs"}, {"run", "/runs/" + harmRun}, {"approvals", "/approvals"}, {"logs", "/logs"}} {
				t.Run(fmt.Sprintf("%s/%d/%s", pg.name, width, theme), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, height, theme)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + pg.path + "?t=tok123"})
					tb.until(t, "page and fonts", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('main') && !!window.tegoLive`)
					c.call(t, tb.session, "Runtime.evaluate", map[string]any{"expression": "new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))", "awaitPromise": true})
					raw := tb.eval(t, phoneMeasure)
					var encoded string
					if err := json.Unmarshal([]byte(raw), &encoded); err != nil {
						t.Fatal(err)
					}
					var record map[string]any
					if err := json.Unmarshal([]byte(encoded), &record); err != nil {
						t.Fatal(err)
					}
					record["page"], record["width"], record["theme"] = pg.name, width, theme
					records = append(records, record)
					t.Log(encoded)
					if tb.eval(t, `JSON.parse(`+phoneMeasure+`).paletteFailures.length===0`) != "true" {
						t.Error("computed palette contrast failed")
					}
					if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
						t.Error("document scrolls sideways")
						t.Log(tb.eval(t, `(()=>{const before=document.documentElement.scrollWidth,old=Array.from(document.adoptedStyleSheets),s=new CSSStyleSheet();s.replaceSync('.page{overflow-wrap:anywhere}');document.adoptedStyleSheets=[...old,s];const after=document.documentElement.scrollWidth;document.adoptedStyleSheets=old;return {before,after,restored:document.documentElement.scrollWidth};})()`))
					}
					if width <= 600 {
						if tb.eval(t, fmt.Sprintf(`document.documentElement.scrollWidth<=%d && innerWidth===%d`, width, width)) != "true" {
							t.Error("phone layout viewport exceeds the device width")
						}
						for label, expr := range map[string]string{
							"bottom navigation":     `(()=>{const n=document.querySelector('nav.side.phone-nav'),r=n?.getBoundingClientRect();return !!r && getComputedStyle(n).position==='fixed' && Math.abs(r.bottom-innerHeight)<1 && Math.abs(r.height-64)<1 && n.querySelectorAll(':scope > .lr > .nav > li').length>=5;})()`,
							"five destinations":     `Array.from(document.querySelectorAll('nav.side > .lr > .nav > li')).filter(e=>e.getBoundingClientRect().width>0).map(e=>e.querySelector('.lbl')?.textContent).join(',')==='Overview,Runs,Approvals,Logs,More'`,
							"quiet topbar":          `(()=>{const h=document.querySelector('.topbar');return h.getBoundingClientRect().height===56 && getComputedStyle(h).position==='static' && !!h.querySelector('.page-name') && !Array.from(h.querySelectorAll('input,select,.toplink,.live')).some(e=>e.getBoundingClientRect().width>0);})()`,
							"reserved space":        `parseFloat(getComputedStyle(document.querySelector('.page')).paddingBottom)>=80 && parseFloat(getComputedStyle(document.documentElement).scrollPaddingBottom)>=96`,
							"shared targets":        `JSON.parse(` + phoneMeasure + `).shellSmall.length===0`,
							"direct shell clipping": `JSON.parse(` + phoneMeasure + `).shellClips.length===0 && JSON.parse(` + phoneMeasure + `).shellRangeClips.length===0`,
							"shell type":            `JSON.parse(` + phoneMeasure + `).shellSmallText.length===0`,
						} {
							if tb.eval(t, expr) != "true" {
								t.Errorf("%s failed", label)
							}
						}
						// A quarter of the screen, or (ADR 0123, request sentence forms) a FULL sentence of at most four
						// 24-px lines with one 44-px action row: 175 px, 27% of a 320 by 640 phone.
						if pg.name != "approvals" && pg.name != "run" {
							if tb.eval(t, `(()=>{const e=document.getElementById('ask-banner'),h=e.getBoundingClientRect().height;return (h/innerHeight<=0.25 || (e.querySelector('.ab-summary').getBoundingClientRect().height<=97 && h<=175)) && Array.from(e.querySelectorAll('.ab-row')).filter(x=>x.getBoundingClientRect().height>0).length===1 && e.querySelector('.ab-summary')?.getAttribute('aria-label').includes('registry.npmjs.org');})()`) != "true" {
								t.Error("request band is crowded or omits its destination")
							}
						}
						if pg.name == "runs" {
							if tb.eval(t, `(()=>{const rows=Array.from(document.querySelectorAll('.runs-panel .phone-row'));return rows.length===2 && rows.every(e=>e.tagName==='A' && e.getBoundingClientRect().height>=80 && e.querySelector('.phone-who') && e.querySelector('.phone-when') && e.querySelectorAll('.b').length===1 && e.querySelectorAll('a,button').length===0);})()`) != "true" {
								t.Error("Runs lacks single-target three-fact rows")
							}
							if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
								t.Error("Runs scrolls sideways")
							}
						}
					}
					if out := os.Getenv("PHONE_SHOTS"); out != "" {
						if err := os.MkdirAll(out, 0755); err != nil {
							t.Fatal(err)
						}
						var shot struct{ Data string }
						_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": false}), &shot)
						b, err := base64.StdEncoding.DecodeString(shot.Data)
						if err != nil {
							t.Fatal(err)
						}
						if err = os.WriteFile(filepath.Join(out, fmt.Sprintf("%s-%d-%s.png", pg.name, width, theme)), b, 0644); err != nil {
							t.Fatal(err)
						}
					}
					tb.clean(t, "phone shell")
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
	if out := os.Getenv("PHONE_SHOTS"); out != "" {
		b, _ := json.MarshalIndent(records, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "measurements.json"), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// Inspect every constructed element directly; an unrelated scrollable ancestor
// cannot disable these tests. Intentional name/sentence ellipses link to full detail.
const phoneMeasure = `JSON.stringify((()=>{
 const visible=e=>{if(!e.checkVisibility({visibilityProperty:true,contentVisibilityAuto:true}))return false;for(let a=e;a;a=a.parentElement){const r=a.getBoundingClientRect(),s=getComputedStyle(a);if(s.display==='none'||s.visibility==='hidden'||((r.width<=2||r.height<=2)&&(s.overflow!=='visible'||s.clipPath!=='none')))return false;}const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>2&&r.height>2&&s.visibility!=='hidden'&&!e.closest('[popover]:not(:popover-open)')&&!e.closest('dialog:not([open])');};
 const desc=e=>e.tagName+'.'+e.className;
 const shell=e=>!!e.closest('.topbar,nav.side,#ask-banner,.runs-panel,.runs-head,.head-more,.head-details,.filter-sheet,.filter-fallback,.phone-filter-control,.more-page,.more-tools');
 const all=Array.from(document.querySelectorAll('body *')).filter(visible);
 const targets=all.filter(e=>e.matches('a[href],button,input:not([type=hidden]),select,textarea,summary'));
 const small=targets.filter(e=>{const r=e.getBoundingClientRect();return r.width<43.9||r.height<43.9;});
 const text=all.filter(e=>!e.closest('svg')&&Array.from(e.childNodes).some(n=>n.nodeType===3&&n.textContent.trim()));
 const smallText=text.filter(e=>parseFloat(getComputedStyle(e).fontSize)<13);
 const clips=all.filter(e=>{const s=getComputedStyle(e);return shell(e)&&!e.matches('.sr,.skip')&&!e.closest('.sr')&&s.textOverflow!=='ellipsis'&&((/hidden|clip/.test(s.overflowX)&&e.scrollWidth>e.clientWidth+1)||(/hidden|clip/.test(s.overflowY)&&e.scrollHeight>e.clientHeight+1));});
 // Measure text fragments through every clipping ancestor. A sibling scroll region
 // never excuses a clip here. Only the two specified ellipses have detail recovery.
 const ranges=[];
 for(const e of text.filter(shell)) {
  if(e.closest('.sr,.skip,thead') || e.matches('option')) continue;
  for(const n of e.childNodes) {
   if(n.nodeType!==3 || !n.textContent.trim()) continue;
   const range=document.createRange();range.selectNodeContents(n);
   for(const r of range.getClientRects()) {
    for(let a=e;a;a=a.parentElement) {
     const s=getComputedStyle(a),b=a.getBoundingClientRect();
     if(a.matches('.phone-who')&&a.closest('a.phone-row[href]') || a.matches('.ab-name')&&a.closest('#ask-banner').querySelector('.ab-act a[href]') || a.matches('.ab-short-target')&&getComputedStyle(a).textOverflow==='ellipsis'&&a.closest('#ask-banner')?.querySelector('.ab-act a[href]')?.getAttribute('aria-label')?.includes(a.closest('.ab-summary')?.getAttribute('aria-label'))) break;
     if((/hidden|clip/.test(s.overflowX)&&(r.left<b.left-1||r.right>b.right+1)) || (/hidden|clip/.test(s.overflowY)&&(r.top<b.top-1||r.bottom>b.bottom+1))) {ranges.push({element:desc(e),ancestor:desc(a),text:n.textContent.trim()});break;}
    }
   }
  }
 }
 const root=getComputedStyle(document.documentElement);
 const rgb=k=>{const s=root.getPropertyValue('--'+(k.startsWith('ch-')?k:'c-'+k)).trim();const n=parseInt(s.slice(1),16);return [(n>>16)&255,(n>>8)&255,n&255].map(v=>{v/=255;return v<=0.04045?v/12.92:Math.pow((v+0.055)/1.055,2.4);});};
 const lum=k=>{const a=rgb(k);return a[0]*.2126+a[1]*.7152+a[2]*.0722;};
 const palettePairs=[["text", "bg", 4.5], ["text", "surface", 4.5], ["text", "raised", 4.5], ["control", "raised", 3.0], ["control", "surface", 3.0], ["control", "ask-soft", 3.0], ["on-brand", "brand", 4.5], ["on-primary", "primary", 4.5], ["on-primary", "primary-hover", 4.5], ["on-ask", "ask", 4.5], ["ask-text", "ask-soft", 4.5], ["ask", "ask-soft", 3.0], ["refused", "refused-soft", 4.5], ["on-through", "through", 4.5], ["allowed", "raised", 4.5], ["passed", "raised", 4.5], ["info", "raised", 4.5], ["ch-stop", "surface", 3.0], ["ch-through", "surface", 3.0], ["ch-ink", "surface", 3.0], ["ch-allowed", "surface", 3.0], ["text", "select", 4.5], ["control", "bg", 3.0], ["focus", "raised", 3.0], ["text", "ask-soft", 4.5], ["on-ask-bar", "ask-bar", 4.5]].map(([fg,bg,min])=>{const a=lum(fg),b=lum(bg);return {fg,bg,min,ratio:(Math.max(a,b)+.05)/(Math.min(a,b)+.05),foreground:root.getPropertyValue('--'+(fg.startsWith('ch-')?fg:'c-'+fg)).trim(),background:root.getPropertyValue('--c-'+bg).trim()};});
 const paletteFailures=palettePairs.filter(p=>!Number.isFinite(p.ratio)||p.ratio<p.min);
 const b=document.getElementById('ask-banner');
 return {palettePairs,paletteFailures,scrollWidth:document.documentElement.scrollWidth,innerWidth,bandPx:b?.getBoundingClientRect().height||0,bandPercent:b?100*b.getBoundingClientRect().height/innerHeight:0,small:small.map(desc),smallText:smallText.map(desc),shellSmall:small.filter(shell).map(desc),shellSmallText:smallText.filter(shell).map(desc),shellClips:clips.map(desc),shellRangeClips:ranges};
})())`

// Native navigation and the GET fallback remain usable without any scripts.
// The enhanced sheet uses the browser's focus containment and Escape behavior.
func TestPhoneNavigationAndFilterInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 360, 390, 430} {
		for _, theme := range []string{"light", "dark"} {
			for _, js := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/js=%t", width, theme, js), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 780, theme)
					c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !js})
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
					tb.until(t, "Runs loaded", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('.phone-row')`)
					if js {
						tb.until(t, "enhancement", `!!window.tegoLive?.steady`)
					}
					if tb.eval(t, `(()=>{const n=document.querySelector('nav.phone-nav');return n.getAttribute('aria-label')==='Main' && n.querySelector('a[aria-current=page]').getAttribute('href')==='/runs' && n.querySelector('a[href="/approvals"] .count').textContent.includes('waiting') && n.querySelector('.phone-more').getAttribute('href')==='/more';})()`) != "true" {
						t.Error("navigation semantics or fallback changed")
					}
					// Walk every control, checking actual focus geometry against the bottom bar.
					tb.eval(t, `document.querySelector('.skip').focus(); ''`)
					for i := 0; i < 24; i++ {
						tb.press(t, "Tab")
						if tb.eval(t, `(()=>{const e=document.activeElement,r=e.getBoundingClientRect(),bar=document.querySelector('nav.phone-nav').getBoundingClientRect();return e===document.body || !!e.closest('nav.phone-nav') || (r.top>=0 && r.bottom<=bar.top+1);})()`) != "true" {
							t.Errorf("Tab %d focus is under navigation: %s", i, tb.eval(t, `document.activeElement.outerHTML`))
							break
						}
					}
					tb.eval(t, `document.querySelector('[data-filter-open]').focus(); ''`)
					tb.press(t, "Enter")
					if js {
						tb.until(t, "modal open", `document.querySelector('dialog.filter-sheet')?.open`)
						for i := 0; i < 14; i++ {
							tb.press(t, "Tab")
							if tb.eval(t, `!!document.activeElement.closest('dialog.filter-sheet')`) != "true" {
								t.Errorf("modal focus escaped: %s", tb.eval(t, `document.activeElement.outerHTML`))
							}
						}
						if tb.eval(t, `(()=>{const d=document.querySelector('dialog.filter-sheet'),r=d.getBoundingClientRect();return r.width<=innerWidth && r.height<=innerHeight*.85+1 && getComputedStyle(d).overscrollBehavior==='contain';})()`) != "true" {
							t.Error("sheet exceeds phone or loses scroll containment")
						}
						if tb.eval(t, `JSON.parse(`+phoneMeasure+`).shellSmall.length===0 && JSON.parse(`+phoneMeasure+`).shellSmallText.length===0 && JSON.parse(`+phoneMeasure+`).shellRangeClips.length===0`) != "true" {
							t.Error("Filter has small targets, type or clipped text")
						}
						tb.press(t, "Escape")
						tb.until(t, "focus returned", `!document.querySelector('dialog.filter-sheet').open && document.activeElement.matches('[data-filter-open]')`)
						// GET results are server-filtered, and a no-result state can be cleared.
						tb.press(t, "Enter")
						tb.eval(t, `document.querySelector('dialog input[name=q]').value='no-such-agent'; document.querySelector('dialog button[type=submit]').click(); ''`)
						tb.until(t, "filtered URL and empty state", `location.search.includes('q=no-such-agent') && document.querySelector('.empty')?.textContent.includes('Clear filters') && document.getElementById('nav-say')?.textContent.includes('0 runs')`)
					} else {
						tb.until(t, "native filter page", `location.search.includes('filters=1') && !!document.querySelector('.filter-fallback')`)
						if tb.eval(t, `document.querySelector('.filter-fallback form').method==='get'`) != "true" {
							t.Error("filter fallback is not GET")
						}
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/more"})
					tb.until(t, "More loaded", `document.readyState==='complete' && !!document.querySelector('.more-page')`)
					if js {
						tb.until(t, "theme in More", `document.getElementById('phone-theme').contains(document.getElementById('theme')) && !document.getElementById('theme-w').hidden`)
					}
					if tb.eval(t, `document.querySelector('.phone-more').getAttribute('aria-current')==='page' && document.querySelector('.more-page a[href="/glossary"]')!==null`) != "true" {
						t.Error("More is not current or help is missing")
					}
					if tb.eval(t, `JSON.parse(`+phoneMeasure+`).shellSmall.length===0 && JSON.parse(`+phoneMeasure+`).shellSmallText.length===0 && JSON.parse(`+phoneMeasure+`).shellRangeClips.length===0`) != "true" {
						t.Error("More has small targets, type or clipped text")
					}
					tb.clean(t, "phone navigation and Filter")
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}

func TestPhoneShortHeightAndSystemModesInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 360, 390, 430} {
		tb := sweepTab(t, c, fmt.Sprint(width), width, 400, "dark")
		c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "forced-colors", "value": "active"}, {"name": "prefers-reduced-motion", "value": "reduce"}}})
		c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
		tb.until(t, "system modes", `document.readyState==='complete' && !!document.querySelector('.phone-row')`)
		if tb.eval(t, `getComputedStyle(document.querySelector('nav.phone-nav')).position==='static' && getComputedStyle(document.querySelector('nav.phone-nav')).order==='2' && getComputedStyle(document.querySelector('.btn')).transitionDuration==='0s' && getComputedStyle(document.querySelector('.b-running')).forcedColorAdjust==='auto'`) != "true" {
			t.Error("short height, reduced motion or system colors regressed")
		}
		tb.clean(t, "short height and system modes")
		c.closeTarget(t, tb.target)
	}
}

func TestPhoneLongRowsAndManyWaitingInChrome(t *testing.T) {
	root := fixture(t)
	now := time.Now()
	name := strings.Repeat("Mira", 15)
	const longID = "r-bbbbbbbb-0000000000003-phone1"
	if err := os.MkdirAll(filepath.Join(root, longID), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, longID, "events.jsonl"), []byte(line(longID, name, 0, now, "run_start", `"tier":"landlock","command":["sh"]`)+line(longID, name, 1, now.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`)), 0644); err != nil {
		t.Fatal(err)
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":false`))
	// The banner's FULL sentence (ADR 0123, request sentence forms) takes at most four 24-px lines; with its one action
	// row the banner stays within 175 px at 320 px.
	for i := 0; i < 12; i++ {
		appendLine(t, root, harmRun, line(harmRun, name, 8+i, now.Add(time.Duration(i)*time.Second), "ask", fmt.Sprintf(`"ask_id":"many-%d","hold":"net","op":"connect","target":"[2001:db8::1]:443"`, i)))
	}
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 360, 390, 430} {
		for _, theme := range []string{"light", "dark"} {
			tb := sweepTab(t, c, fmt.Sprintf("%d/%s", width, theme), width, 640, theme)
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
			tb.until(t, "long row and queue", `document.readyState==='complete' && document.fonts.status==='loaded' && !!window.tegoLive?.steady`)
			if tb.eval(t, fmt.Sprintf(`(()=>{const row=document.querySelector('.phone-row[href="/runs/%s"]'),who=row.querySelector('.phone-who'),band=document.getElementById('ask-banner');return who.textContent.length===60 && who.scrollWidth>who.clientWidth && getComputedStyle(who).textOverflow==='ellipsis' && row.getBoundingClientRect().height>=80 && document.querySelector('.nav .count').textContent.includes('12') && band.querySelector('a').getAttribute('aria-label').includes('12 waiting') && band.querySelector('.ab-summary').getBoundingClientRect().height<=97 && band.getBoundingClientRect().height<=175 && band.querySelector('.ab-summary').getAttribute('aria-label').includes('[2001:db8::1]:443') && Array.from(band.querySelectorAll('.ab-row')).filter(e=>e.getBoundingClientRect().height>0).length===1;})()`, longID)) != "true" {
				t.Error("long name or many-waiting presentation failed")
			}
			if tb.eval(t, fmt.Sprintf(`document.documentElement.scrollWidth<=%d && innerWidth===%d`, width, width)) != "true" {
				t.Error("many requests scroll sideways")
			}
			tb.eval(t, fmt.Sprintf(`document.querySelector('.phone-row[href="/runs/%s"]').click(); ''`, longID))
			tb.until(t, "full name recovery", `document.readyState==='complete' && document.querySelector('main h1')?.textContent.includes('MiraMiraMira')`)
			if tb.eval(t, fmt.Sprintf(`document.querySelector('main h1').textContent.includes(%q)`, name)) != "true" {
				t.Error("detail lost the selected full name")
			}
			tb.clean(t, "long row and many requests")
			c.closeTarget(t, tb.target)
		}
	}
}

// A live row's relative time must advance without waiting for a new ledger line.
func TestPhoneRunsClockInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	tb := sweepTab(t, c, "row-clock", 320, 640, "light")
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
	tb.until(t, "Runs clocks", `document.readyState==='complete' && !!window.tegoLive?.steady && !!document.querySelector('.phone-when')`)
	if tb.eval(t, `(()=>{const e=document.querySelector('.phone-when');return e.hasAttribute('data-started') && e.hasAttribute('data-ck');})()`) != "true" {
		t.Fatal("phone age has no live clock source")
	}
	tb.eval(t, `var e=document.querySelector('.phone-when');e.dataset.started=new Date(Date.now()-120000).toISOString();window.tegoLive.after();''`)
	if tb.eval(t, `document.querySelector('.phone-when').textContent==='2 minutes ago'`) != "true" {
		t.Error("relative start time did not advance")
	}
	tb.clean(t, "row clock")
	c.closeTarget(t, tb.target)
}

func TestPhoneSafeAreaAndClippingProbeInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	tb := sweepTab(t, c, "safe-area", 390, 844, "dark")
	c.call(t, tb.session, "Emulation.setSafeAreaInsetsOverride", map[string]any{"insets": map[string]any{"bottom": 24}})
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
	tb.until(t, "safe-area page", `document.readyState==='complete' && document.fonts.status==='loaded' && !!window.tegoLive?.steady`)
	if tb.eval(t, `(()=>{const n=document.querySelector('nav.phone-nav'),p=document.querySelector('.page');return n.getBoundingClientRect().height===88 && parseFloat(getComputedStyle(p).paddingBottom)===104 && parseFloat(getComputedStyle(document.documentElement).scrollPaddingBottom)===120;})()`) != "true" {
		t.Error("safe inset is not reserved by navigation, content and focus padding")
	}
	// Add a separate scroller and a known clip to the real Runs DOM. The direct
	// fragment probe must still find the clip and must not alter the page to pass.
	tb.eval(t, `const s=document.createElement('div'),bad=document.createElement('div');s.style.cssText='width:20px;overflow:auto';s.textContent='a'.repeat(100);document.body.appendChild(s);bad.style.cssText='width:4px;height:4px;overflow:hidden';bad.textContent='direct clipping probe';document.querySelector('.runs-panel').appendChild(bad);''`)
	if tb.eval(t, `JSON.parse(`+phoneMeasure+`).shellRangeClips.some(e=>e.text==='direct clipping probe')`) != "true" {
		t.Error("direct clipping probe was cleared by a sibling scroller")
	}
	c.closeTarget(t, tb.target)
}

// Keep the empty first run usable with the same native navigation and font floor.
func TestPhoneEmptyRunsInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, t.TempDir(), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 360, 390, 430} {
		for _, theme := range []string{"light", "dark"} {
			tb := sweepTab(t, c, fmt.Sprintf("empty/%d/%s", width, theme), width, 640, theme)
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
			tb.until(t, "empty Runs", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('.empty')`)
			if tb.eval(t, `(()=>{const m=JSON.parse(`+phoneMeasure+`);return document.documentElement.scrollWidth<=innerWidth && m.shellSmall.length===0 && m.smallText.length===0 && m.shellRangeClips.length===0 && !document.querySelector('.phone-row');})()`) != "true" {
				t.Error("empty Runs loses geometry, type or controls")
				t.Log(tb.eval(t, phoneMeasure))
			}
			tb.clean(t, "empty Runs")
			c.closeTarget(t, tb.target)
		}
	}
}

// Small print pages must retain the desktop cells when the phone row is removed.
func TestPhonePrintInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	tb := sweepTab(t, c, "phone-print", 390, 844, "dark")
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
	tb.until(t, "Runs", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('.phone-row')`)
	c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"media": "print", "features": []map[string]string{{"name": "prefers-color-scheme", "value": "dark"}}})
	if tb.eval(t, `getComputedStyle(document.body).backgroundColor==='rgb(251, 250, 248)' && getComputedStyle(document.querySelector('nav.phone-nav')).display==='none' && document.querySelector('.runs-panel td.lead').getBoundingClientRect().height>0 && document.querySelector('.phone-run-cell').getBoundingClientRect().height===0`) != "true" {
		t.Error("phone print hides the run or keeps phone chrome")
	}
	c.closeTarget(t, tb.target)
}

func TestPhoneHeadActionsInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 390, 768, 1280} {
		for _, js := range []bool{false, true} {
			tb := sweepTab(t, c, fmt.Sprintf("actions/%d/%t", width, js), width, 844, "light")
			c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !js})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + harmRun + "?t=tok123"})
			tb.until(t, "run actions", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('.head-more')`)
			if width <= 600 {
				if tb.eval(t, `!document.querySelector('.head-more').open && document.querySelector('.head-more summary').getBoundingClientRect().height>=44 && !document.querySelector('.head-actions').checkVisibility({contentVisibilityAuto:true})`) != "true" {
					t.Error("phone actions start crowded or lose their native disclosure")
				}
				tb.eval(t, `document.querySelector('.head-more summary').focus();''`)
				tb.press(t, "Enter")
				tb.until(t, "actions open", `document.querySelector('.head-more').open`)
				tb.eval(t, `document.querySelector('.run-facts summary').focus();''`)
				tb.press(t, "Enter")
				tb.until(t, "full run metadata", `document.querySelector('.run-facts').open && document.querySelector('.run-facts').textContent.includes('r-aaaaaaaa-0000000000002-harmxx')`)
				if tb.eval(t, `Array.from(document.querySelectorAll('.run-facts a')).every(e=>e.getBoundingClientRect().height>=44)`) != "true" {
					t.Error("run metadata has a small target")
				}
			}
			if tb.eval(t, `(()=>{const a=document.querySelector('a[href$="/stop"]'),r=a.getBoundingClientRect();return r.width>=44 && r.height>=(innerWidth<=600?44:24);})()`) != "true" {
				t.Error("Stop run is unreachable")
			}
			var ax struct {
				Nodes []struct {
					Ignored bool
					Role    struct{ Value string }
					Name    struct{ Value string }
				}
			}
			if err := json.Unmarshal(c.call(t, tb.session, "Accessibility.getFullAXTree", map[string]any{}), &ax); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, n := range ax.Nodes {
				found = found || (!n.Ignored && n.Role.Value == "link" && strings.Contains(n.Name.Value, "Stop run"))
			}
			if !found {
				t.Error("Stop run is absent from the accessibility tree")
			}
			tb.clean(t, "head actions")
			c.closeTarget(t, tb.target)
		}
	}
}

func TestPhoneThemeResizeInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	tb := sweepTab(t, c, "theme-resize", 390, 844, "light")
	c.call(t, tb.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": `Object.defineProperty(window,'localStorage',{value:{getItem(){return null},setItem(){throw new Error('unavailable')},removeItem(){throw new Error('unavailable')}}});`})
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/more?t=tok123"})
	tb.until(t, "theme on More", `document.readyState==='complete' && document.querySelector('#phone-theme #theme') && !document.getElementById('theme-w').hidden`)
	tb.eval(t, `const s=document.getElementById('theme');s.value='dark';s.dispatchEvent(new Event('change'));''`)
	for _, width := range []int{768, 390} {
		c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 844, "deviceScaleFactor": 1, "mobile": width < 600})
		selector := ".top-right #theme"
		if width < 600 {
			selector = "#phone-theme #theme"
		}
		tb.until(t, "switch moved", fmt.Sprintf(`!!document.querySelector(%q)`, selector))
		if tb.eval(t, `document.getElementById('theme').value==='dark' && document.documentElement.dataset.theme==='dark' && document.querySelectorAll('#theme').length===1`) != "true" {
			t.Error("moving the single switch reset its current choice")
		}
	}
	tb.clean(t, "theme resize without storage")
	c.closeTarget(t, tb.target)
}

func TestPhoneExactDetailsInChrome(t *testing.T) {
	root := fixture(t)
	now := time.Now()
	name := strings.Repeat("Mira", 15)
	target := "/home/dana/customer-support/" + strings.Repeat("folder/", 12) + strings.Repeat("final", 36) + ".json"
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":false`))
	appendLine(t, root, harmRun, line(harmRun, name, 8, now, "ask", fmt.Sprintf(`"ask_id":"exact-target","hold":"fs","op":"read","target":%q`, target)))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	// The request is LONG on a phone (request_forms.go): the banner shows the sentence cut in the middle with both kept
	// ends (the name's, the leading folders and the file name's end), no quick answers, and Review request, which opens
	// the request's own card with the exact target whole. The bound counts characters (request_forms.go); this name of
	// wide letters takes the one line more at 320 px that the rule allows, so five lines are the limit here.
	v := requestOf(ledgerview.Ask{Agent: name, Op: "read", Hold: "fs", Target: target}, nil)
	if !v.Phone.Long || !strings.HasPrefix(v.Phone.Target, "/home/dana/") || !strings.HasSuffix(v.Phone.Target, "final.json") || !strings.HasPrefix(v.Phone.Agent, "MiraMira") || !strings.HasSuffix(v.Phone.Agent, "Mira") {
		t.Fatalf("the long request's phone form is not LONG with both ends kept: %+v", v.Phone)
	}
	for _, width := range []int{320, 360, 390, 430} {
		for _, theme := range []string{"light", "dark"} {
			tb := sweepTab(t, c, fmt.Sprintf("exact/%d/%s", width, theme), width, 640, theme)
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
			tb.until(t, "long sentence", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('.ab-summary')`)
			if tb.eval(t, fmt.Sprintf(`(()=>{const b=document.getElementById('ask-banner'),e=b.querySelector('.ab-summary'),r=document.createRange();r.selectNodeContents(e);const tops=new Set([...r.getClientRects()].filter(x=>x.width>0).map(x=>Math.round(x.bottom/24)));const review=b.querySelector('.ab-review a');return e.getAttribute('aria-label').includes(%s) && e.querySelector('.ab-name').textContent===%s && e.querySelector('.ab-short-target').textContent===%s && getComputedStyle(e.querySelector('.ab-name')).textOverflow!=='ellipsis' && tops.size<=5 && ![...b.querySelectorAll('button[name=decision]')].some(x=>x.checkVisibility()) && !!review && review.checkVisibility() && review.textContent==='Review request';})()`, jsString(target), jsString(v.Phone.Agent), jsString(v.Phone.Target))) != "true" {
				t.Error("long request lacks its whole accessible target, its cut sentence with both ends, or Review request in place of the quick answers")
			}
			tb.eval(t, `document.querySelector('#ask-banner .ab-review a').click();''`)
			tb.until(t, "exact request destination", `document.readyState==='complete' && location.hash==='#exact-target' && !!document.querySelector('#exact-target .ut-box')`)
			if tb.eval(t, fmt.Sprintf(`(()=>{const e=document.querySelector('#exact-target .ut-box'),q=document.querySelector('#exact-target .ask-q');return e.textContent===%q && q.textContent.includes(%q) && e.scrollWidth<=e.clientWidth+1 && (e.scrollHeight<=e.clientHeight+1 || (getComputedStyle(e).overflowY==='auto' && e.tabIndex===0 && e.clientHeight<=8.5*parseFloat(getComputedStyle(document.documentElement).fontSize)+1)) && document.documentElement.scrollWidth<=innerWidth;})()`, target, name)) != "true" {
				// A phone's exact-target box is capped at 8.5rem on purpose (C120): a long target scrolls inside the box, which is
				// a keyboard stop, so what must hold is the whole text in the box, its lines wrapped (no sideways scroll) and the
				// box either fitting whole or capped and scrollable; the page itself never scrolls sideways.
				t.Errorf("%d/%s: Details loses the exact target, full name, long filename wrapping, or the capped box's scroll and keyboard stop", width, theme)
				t.Log(tb.eval(t, fmt.Sprintf(`(()=>{const e=document.querySelector('#exact-target .ut-box'),q=document.querySelector('#exact-target .ask-q');return {exact:e.textContent===%q,name:q.textContent.includes(%q),sw:e.scrollWidth,cw:e.clientWidth,sh:e.scrollHeight,ch:e.clientHeight,document:document.documentElement.scrollWidth,inner:innerWidth,wide:Array.from(document.querySelectorAll('main *')).filter(e=>e.getBoundingClientRect().right>innerWidth+1).map(e=>({tag:e.tagName,cls:e.className,text:e.textContent.slice(0,70),right:e.getBoundingClientRect().right}))};})()`, target, name)))
			}
			tb.clean(t, "exact Details recovery")
			c.closeTarget(t, tb.target)
		}
	}
}
