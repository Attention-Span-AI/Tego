// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func tourHTTP(t *testing.T, f *guidetest.Fixture) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := f.Machine(t)
	s, err := New(Config{Ledger: f.Ledger, Anchor: f.Anchor, Machine: m, Port: ln.Addr().(*net.TCPAddr).Port, Token: "tok123", EventTick: 20 * time.Millisecond,
		Now: func() time.Time { return guidetest.CheckTime.Add(time.Hour) }, Guide: func(context.Context) guide.Inputs { in := f.Inputs(t); in.Dir = ""; return in }})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s, "http://" + ln.Addr().String()
}

var tourScenes = []struct {
	name, fixture, step string
	checked             bool
}{
	{"check-missing", guidetest.Fresh, "check", false},
	{"check-ready", guidetest.Fresh, "check", true},
	{"check-refused", guidetest.NotReady, "check", true},
	{"check-ssh", guidetest.Outside, "check", true},
	{"pick", guidetest.Fresh, "pick", true},
	{"watch-before", guidetest.Fresh, "watch", true},
	{"watch-running", guidetest.Recording, "watch", true},
	{"recorded", guidetest.HalfDone, "recorded", true},
	{"review", guidetest.HalfDone, "review", true},
	{"review-saved", guidetest.ContractMade, "review", true},
	{"enforce-before", guidetest.ContractMade, "enforce", true},
	{"enforce-ended", guidetest.Finished, "enforce", true},
	{"enforce-broken", guidetest.Tampered, "enforce", true},
	{"enforce-handwritten", guidetest.HandWritten, "enforce", true},
	{"enforce-refusals", "refusals", "enforce", true},
	{"enforce-running", "enforcing", "enforce", true},
	{"recorded-values", "recorded-values", "recorded", true},
	{"check-long-name", "check-long-name", "check", true},
	{"enforce-unknown", "missing-anchor", "enforce", true},
	{"enforce-waiting-request", "pending", "enforce", true},
}

// One browser, one page at a time. Every screenshot is the real authenticated
// page and CSP, not a second render or a static facsimile.
func TestTourMatrixInChrome(t *testing.T) { tourMatrix(t, true) }

func TestTourNoScriptMatrixInChrome(t *testing.T) { tourMatrix(t, false) }

func tourMatrix(t *testing.T, scripts bool) {
	c := placeChrome(t)
	var measurements []json.RawMessage
	for _, scene := range tourScenes {
		t.Run(scene.name, func(t *testing.T) {
			f := tourSceneFixture(t, scene.fixture)
			if scene.checked {
				if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
					t.Fatal(err)
				}
			}
			s, base := tourHTTP(t, f)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			path := tourURL(g, scene.step)
			for _, width := range []int{320, 360, 390, 430, 768, 1100, 1280} {
				for _, theme := range []string{"light", "dark"} {
					t.Run(fmt.Sprintf("%d/%s", width, theme), func(t *testing.T) {
						tb := sweepTab(t, c, t.Name(), width, 780, theme)
						defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
						if !scripts {
							c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": true})
						}
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + path + "&t=tok123"})
						tb.until(t, "guide ready", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('.gf')`)
						tb.eval(t, `window.scrollTo(0,0)`)
						if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
							t.Error("document scrolls sideways")
						}
						raw := tb.eval(t, tourMeasure)
						var enc string
						if err := json.Unmarshal([]byte(raw), &enc); err != nil {
							t.Fatal(err)
						}
						var meta map[string]any
						_ = json.Unmarshal([]byte(enc), &meta)
						meta["scripts"] = scripts
						tagged, _ := json.Marshal(meta)
						measurements = append(measurements, json.RawMessage(tagged))
						var m struct {
							Small, Clips, Contrast, SmallText []string
							Sizes                             []float64
							ActionBottom                      float64
						}
						if err := json.Unmarshal([]byte(enc), &m); err != nil {
							t.Fatal(err)
						}
						if len(m.Clips) > 0 || len(m.Contrast) > 0 {
							t.Errorf("clips %v contrast %v", m.Clips, m.Contrast)
						}
						if width <= 600 {
							if len(m.Small) > 0 || len(m.SmallText) > 0 || len(m.Sizes) > 3 {
								t.Errorf("targets %v text %v sizes %v", m.Small, m.SmallText, m.Sizes)
							}
							if width == 360 && m.ActionBottom > 716 {
								t.Errorf("action below phone fold: %.1f", m.ActionBottom)
							}
						}
						if scene.step == "recorded" || scene.step == "review" {
							if tb.eval(t, `(()=>{const facts=document.querySelector('.gf-facts'), action=document.querySelector('#gf-action');return !!facts && facts.checkVisibility({visibilityProperty:true,contentVisibilityAuto:true}) && facts.querySelectorAll('dt').length===3 && facts.querySelectorAll('dd').length===3 && facts.getBoundingClientRect().bottom<=action.getBoundingClientRect().top})()`) != "true" {
								t.Error("three action facts are not visible before the main action")
							}
						}
						if out := os.Getenv("TOUR_SHOTS"); out != "" {
							if err := os.MkdirAll(out, 0755); err != nil {
								t.Fatal(err)
							}
							var shot struct{ Data string }
							_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": false}), &shot)
							b, err := base64.StdEncoding.DecodeString(shot.Data)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("%s-%d-%s.png", scene.name, width, theme)), b, 0644); err != nil {
								t.Fatal(err)
							}
						}
						// All steps and every source fact are recoverable by a native disclosure.
						if width <= 600 {
							tb.eval(t, `document.querySelector('.gf-history').open=true`)
							if got := tb.eval(t, `document.querySelectorAll('.gf-history .gf-steps li').length`); got != "6" {
								t.Fatal("missing history")
							}
							if tb.eval(t, `JSON.parse(`+tourMeasure+`).small.length===0`) != "true" {
								t.Error("history has a small target")
							}
						}
						// Expand every piece of guide evidence and measure it directly,
						// including long targets and source facts, after the fold shot.
						tb.eval(t, `document.querySelectorAll('.gf details').forEach(e=>e.open=true)`)
						if tb.eval(t, `JSON.parse(`+tourMeasure+`).clips.length===0 && JSON.parse(`+tourMeasure+`).contrast.length===0 && document.documentElement.scrollWidth<=innerWidth`) != "true" {
							t.Error("expanded guide evidence clips or loses contrast")
						}
						var expanded string
						_ = json.Unmarshal([]byte(tb.eval(t, tourMeasure)), &expanded)
						var expandedMeta map[string]any
						_ = json.Unmarshal([]byte(expanded), &expandedMeta)
						expandedMeta["expanded"] = true
						expandedMeta["scripts"] = scripts
						expandedJSON, _ := json.Marshal(expandedMeta)
						measurements = append(measurements, json.RawMessage(expandedJSON))
						if width <= 600 && tb.eval(t, `JSON.parse(`+tourMeasure+`).small.length===0 && JSON.parse(`+tourMeasure+`).smallText.length===0 && JSON.parse(`+tourMeasure+`).sizes.length<=3`) != "true" {
							t.Error("expanded guide evidence has small type or targets")
						}
						tb.clean(t, "guide matrix")
					})
				}
			}
		})
	}
	if out := os.Getenv("TOUR_SHOTS"); out != "" {
		b, _ := json.MarshalIndent(measurements, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "measurements.json"), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// Every scene includes the actual product page. The frame must not leave a
// second top-level heading exposed when desktop disclosures show their content.
func TestTourOneVisibleHeadingInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, scene := range tourScenes {
		t.Run(scene.name, func(t *testing.T) {
			f := tourSceneFixture(t, scene.fixture)
			if scene.checked {
				if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
					t.Fatal(err)
				}
			}
			s, base := tourHTTP(t, f)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			tb := sweepTab(t, c, t.Name(), 1280, 900, "light")
			defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + tourURL(g, scene.step) + "&t=tok123"})
			tb.until(t, "guide headings", `document.readyState==='complete' && !!document.querySelector('.gf')`)
			if got := tb.eval(t, `Array.from(document.querySelectorAll('h1')).filter(e=>e.checkVisibility({visibilityProperty:true,contentVisibilityAuto:true}) && e.getBoundingClientRect().width>0).map(e=>e.textContent.trim())`); !strings.HasPrefix(got, "[") || !singleTourHeading(got) {
				t.Errorf("want one visible H1, got %s", got)
			}
		})
	}
}

func singleTourHeading(raw string) bool {
	var titles []string
	return json.Unmarshal([]byte(raw), &titles) == nil && len(titles) == 1 && titles[0] != ""
}

func TestTourLeaveAndReturnInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{360, 1280} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			f := tourSceneFixture(t, guidetest.HalfDone)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			s, base := tourHTTP(t, f)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			tb := sweepTab(t, c, t.Name(), width, 780, "light")
			defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + tourURL(g, "review") + "&t=tok123"})
			tb.until(t, "review frame", `document.readyState==='complete' && document.querySelector('.gf')?.dataset.step==='review'`)
			tb.eval(t, `document.querySelector('.gf-leave').click()`)
			tb.until(t, "leave removes frame", `document.readyState==='complete' && document.fonts.status==='loaded' && !document.querySelector('.gf') && !new URL(location.href).searchParams.has('guide')`)
			if width <= 600 {
				tb.eval(t, `document.querySelector('a[href="/more"]').click()`)
				tb.until(t, "More destinations", `location.pathname==='/more' && !!document.querySelector('.more-page a[href="/guide"]')`)
				tb.eval(t, `document.querySelector('.more-page a[href="/guide"]').click()`)
			} else {
				if tb.eval(t, `document.querySelector('.toplink[href="/guide"]').checkVisibility()`) != "true" {
					t.Fatal("Guide return link is hidden")
				}
				tb.eval(t, `document.querySelector('.toplink[href="/guide"]').click()`)
			}
			tb.until(t, "Guide returns", `!!document.querySelector('.gf')`)
			tb.clean(t, "leave and return")
		})
	}
}

func TestTourForcedColoursCurrentStepInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{360, 1280} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			f := tourSceneFixture(t, guidetest.HalfDone)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			s, base := tourHTTP(t, f)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			tb := sweepTab(t, c, t.Name(), width, 780, "light")
			defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
			c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "forced-colors", "value": "active"}}})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + tourURL(g, "review") + "&t=tok123"})
			tb.until(t, "forced-colour guide", `document.readyState==='complete' && !!document.querySelector('.gf')`)
			tb.eval(t, `document.querySelector('.gf-history').open=true;(()=>{const s=new CSSStyleSheet();s.replaceSync('.tour-system-colour{color:Highlight;forced-color-adjust:none}');document.adoptedStyleSheets=[...document.adoptedStyleSheets,s];const p=document.createElement('span');p.className='tour-system-colour';p.textContent='system colour';document.body.appendChild(p)})()`)
			border := "borderTopColor"
			if width <= 600 {
				border = "borderLeftColor"
			}
			if tb.eval(t, fmt.Sprintf(`(()=>{const current=document.querySelector('.gf-steps li.now'), others=Array.from(document.querySelectorAll('.gf-steps li:not(.now)')), colour=getComputedStyle(current).%s;return matchMedia('(forced-colors:active)').matches && colour===getComputedStyle(document.querySelector('.tour-system-colour')).color && others.every(e=>getComputedStyle(e).%s!==colour)})()`, border, border)) != "true" {
				t.Fatal("current rail item does not use a distinct system Highlight colour")
			}
		})
	}
}

// Check actual text fragments through their clipping ancestors. Closed native
// disclosures are excluded by checkVisibility; sibling scrollers excuse nothing.
const tourMeasure = `JSON.stringify((()=>{
 const visible=e=>e.checkVisibility({visibilityProperty:true,contentVisibilityAuto:true}) && e.getBoundingClientRect().width>0 && !e.closest('.sr');
 const all=Array.from(document.querySelectorAll('.gf *, .gf-product>summary')).filter(visible),small=[],clips=[],contrast=[],smallText=[],pairs=[],sizes=new Set();
 const label=e=>e.tagName+'.'+e.className;
 const lum=s=>{const a=s.match(/[\d.]+/g).slice(0,3).map(Number).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4});return a[0]*.2126+a[1]*.7152+a[2]*.0722};
 for(const e of all){
  const r=e.getBoundingClientRect(),s=getComputedStyle(e);
  if(e.matches('a[href],button,summary,input:not([type=hidden]),select') && s.visibility!=='hidden' && (r.width<43.9 || r.height<43.9))small.push(label(e)+':'+r.width+'x'+r.height);
  for(const n of e.childNodes){if(n.nodeType!==3||!n.textContent.trim())continue;
   const size=parseFloat(s.fontSize);sizes.add(size);if(size<13)smallText.push(label(e));
   let bg='';for(let a=e;a;a=a.parentElement){let b=getComputedStyle(a).backgroundColor;if(b!=='rgba(0, 0, 0, 0)' && b!=='transparent'){bg=b;break}}
   if(bg){const a=lum(s.color),b=lum(bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);pairs.push({foreground:s.color,background:bg,ratio});if(ratio<(size>=24?3:4.5))contrast.push(label(e)+':'+ratio.toFixed(2));}
   const range=document.createRange();range.selectNodeContents(n);
   for(const box of range.getClientRects()){for(let a=e;a;a=a.parentElement){const z=getComputedStyle(a),b=a.getBoundingClientRect();if((/hidden|clip/.test(z.overflowX)&&(box.left<b.left-1||box.right>b.right+1))||(/hidden|clip/.test(z.overflowY)&&(box.top<b.top-1||box.bottom>b.bottom+1))){clips.push(label(e)+' in '+label(a));break}}}
  }
 }
 return {url:location.pathname+location.search,width:innerWidth,theme:matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light',small,clips,contrast,smallText,pairs,sizes:Array.from(sizes),minimumTarget:Math.min(...all.filter(e=>e.matches('a[href],button,summary,input:not([type=hidden]),select') && getComputedStyle(e).visibility!=='hidden').map(e=>{const r=e.getBoundingClientRect();return Math.min(r.width,r.height)})),actionBottom:document.querySelector('#gf-action').getBoundingClientRect().bottom};
})())`

func TestTourWatchAnnouncesBeforeMovingInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, holdFocus := range []bool{false, true} {
		t.Run(fmt.Sprintf("focus=%t", holdFocus), func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			w, err := ledger.Open(filepath.Join(f.Ledger, cleanRun), record.RunRef{ID: cleanRun, Agent: "my-agent"}, ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Abandon() }()
			if err := ledger.MarkLive(f.Ledger, cleanRun); err != nil {
				t.Fatal(err)
			}
			if err := w.WriteRunStart(record.RunStartPayload{Tier: "observe", Command: []string{"sh"}, Cwd: f.Project}); err != nil {
				t.Fatal(err)
			}
			_, base := tourHTTP(t, f)
			tb := sweepTab(t, c, t.Name(), 360, 780, "light")
			defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + "/guide?step=watch&t=tok123"})
			tb.until(t, "watch running", `document.readyState==='complete' && document.querySelector('.gf')?.dataset.step==='watch' && document.querySelector('#gf-status')?.textContent.includes('This page moves on')`)
			// Capture the actual end announcement and departure in the browser clock.
			// sessionStorage survives the full navigation that the guide performs.
			tb.eval(t, `sessionStorage.removeItem('tour-departure');window.tourAnnouncementAt=0;window.tourHeldSince=performance.now();new MutationObserver(()=>{if(!window.tourAnnouncementAt && document.querySelector('#gf-status')?.textContent.includes('The run ended. Moving to step 4.'))window.tourAnnouncementAt=performance.now()}).observe(document.querySelector('[data-live="r-guide"]'),{subtree:true,childList:true,characterData:true});addEventListener('pagehide',()=>sessionStorage.setItem('tour-departure',JSON.stringify({announced:window.tourAnnouncementAt,elapsed:performance.now()-Math.max(window.tourAnnouncementAt,window.tourReleasedAt||0)})))`)
			if holdFocus {
				tb.eval(t, `window.tourFocus=document.querySelector('.gf-leave');window.tourFocus.focus()`)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			if err := ledger.ClearLive(f.Ledger, cleanRun); err != nil {
				t.Fatal(err)
			}
			if holdFocus {
				// Cross the three-second guide poll and its two-second move window.
				// The identical focused node must survive live updates throughout.
				tb.until(t, "focus hold interval", `!window.tourHeldSince || performance.now()-window.tourHeldSince>=5500`)
				if tb.eval(t, `document.querySelector('.gf')?.dataset.step==='watch' && window.tourFocus===document.activeElement && window.tourFocus.isConnected && !document.querySelector('#gf-status').textContent.includes('The run ended.')`) != "true" {
					t.Fatal("Watch moved or replaced focus while the guide was in use")
				}
				tb.eval(t, `window.tourReleasedAt=performance.now();document.activeElement.blur()`)
			}
			tb.until(t, "end announced or page left", `!!window.tourAnnouncementAt || document.querySelector('.gf')?.dataset.step!=='watch'`)
			if tb.eval(t, `document.querySelector('.gf')?.dataset.step==='watch' && !!window.tourAnnouncementAt && document.querySelector('#gf-status').textContent.includes('The run ended. Moving to step 4.')`) != "true" {
				t.Fatal("Watch left before publishing its end announcement")
			}
			tb.until(t, "announcement reading interval", `document.querySelector('.gf')?.dataset.step!=='watch' || performance.now()-window.tourAnnouncementAt>=1100`)
			if tb.eval(t, `document.querySelector('.gf')?.dataset.step==='watch' && document.querySelector('#gf-status').textContent.includes('The run ended. Moving to step 4.')`) != "true" {
				t.Fatal("end announcement did not remain on Watch for at least one second")
			}
			tb.until(t, "automatically recorded after announcement", `document.querySelector('.gf')?.dataset.step==='recorded'`)
			var timing struct{ Announced, Elapsed float64 }
			var raw string
			if err := json.Unmarshal([]byte(tb.eval(t, `sessionStorage.getItem('tour-departure')`)), &raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(raw), &timing); err != nil {
				t.Fatal(err)
			}
			if timing.Announced <= 0 || timing.Elapsed < 1800 || timing.Elapsed > 6000 {
				t.Fatalf("end announcement departure: %+v; want about two seconds", timing)
			}
			tb.clean(t, "Watch announcement")
		})
	}
}

func TestTourLiveAndNativeInChrome(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(f.Ledger, cleanRun), record.RunRef{ID: cleanRun, Agent: "my-agent"}, ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.MarkLive(f.Ledger, cleanRun); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "observe", Command: []string{"sh"}, Cwd: f.Project}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	_, base := tourHTTP(t, f)
	c := placeChrome(t)
	tb := sweepTab(t, c, t.Name(), 360, 780, "light")
	defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + "/guide?step=watch&t=tok123"})
	tb.until(t, "watch waiting", `document.querySelector('.gf')?.dataset.step==='watch' && !!document.querySelector('#gf-status')?.textContent.includes('This page moves on')`)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ClearLive(f.Ledger, cleanRun); err != nil {
		t.Fatal(err)
	}
	tb.until(t, "automatically recorded", `document.querySelector('.gf')?.dataset.step==='recorded'`)
	// Script-free server navigation offers the same page and an explicit reload.
	c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": true})
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + "/guide?step=enforce"})
	tb.until(t, "native guide", `document.readyState==='complete' && !!document.querySelector('.gf')`)
	if tb.eval(t, `document.querySelector('noscript').textContent.includes('Scripts are off')`) != "true" {
		t.Error("no script-free reload explanation")
	}
	assertTourLandmark(t, tb)
	// Short screens, forced colours, and reduced motion retain a static decision bar.
	c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 320, "height": 256, "deviceScaleFactor": 4, "mobile": true})
	c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "forced-colors", "value": "active"}, {"name": "prefers-reduced-motion", "value": "reduce"}}})
	if tb.eval(t, `getComputedStyle(document.querySelector('.gf-bar')).position==='static' && document.documentElement.scrollWidth<=innerWidth`) != "true" {
		t.Error("short-screen reflow failed")
	}
	if tb.eval(t, `Array.from(document.querySelectorAll('.gf *')).every(e=>{const s=getComputedStyle(e);return s.animationName==='none' && s.transitionDuration.split(',').every(d=>parseFloat(d)===0)})`) != "true" {
		t.Error("reduced motion leaves an animation in the guide")
	}
	// A clipping probe beside an unrelated scroller must still be detected.
	tb.eval(t, `(()=>{window.tourSheets=Array.from(document.adoptedStyleSheets);const s=new CSSStyleSheet();s.replaceSync('.gf-probe{display:block;width:4px;height:4px;overflow:hidden}.gf-scroller{width:40px;height:40px;overflow:auto}');document.adoptedStyleSheets=[...tourSheets,s];for(const cl of ['gf-probe','gf-scroller']){const e=document.createElement('div');e.className=cl;e.textContent='A long value that must not silently disappear';document.querySelector('.gf').appendChild(e);}})()`)
	if tb.eval(t, `JSON.parse(`+tourMeasure+`).clips.length>0`) != "true" {
		t.Error("direct clipping self-test missed a clipped sibling")
	}
	tb.eval(t, `document.querySelectorAll('.gf-probe,.gf-scroller').forEach(e=>e.remove());document.adoptedStyleSheets=tourSheets`)
	tb.eval(t, `document.querySelector('.gf-history').open=true;document.querySelector('.gf-options').open=true;document.querySelector('.gf-history button[value=no]').focus()`)
	tb.press(t, "Enter")
	tb.until(t, "native hide form", `location.pathname==='/' && document.readyState==='complete' && !document.querySelector('.gf-offer')`)
	tb.clean(t, "native guide")
}

func tourSceneFixture(t *testing.T, name string) *guidetest.Fixture {
	t.Helper()
	if name == "check-long-name" {
		f := guidetest.Make(t, guidetest.NotReady)
		f.Probe.FirstFix = "Check the service " + strings.Repeat("agent", 12) + " before it starts."
		return f
	}
	if name == "missing-anchor" {
		f := guidetest.Make(t, guidetest.Finished)
		if err := os.Remove(f.Anchor); err != nil {
			t.Fatal(err)
		}
		return f
	}
	if name == "refusals" || name == "enforcing" || name == "recorded-values" || name == "pending" {
		return tourValues(t, name)
	}
	f := guidetest.Make(t, name)
	if name == guidetest.Recording {
		if err := ledger.MarkLive(f.Ledger, f.Runs[len(f.Runs)-1]); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestTourKeyboardInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, step := range []string{"check", "pick", "watch", "recorded", "review", "enforce"} {
		name := guidetest.HalfDone
		if step == "check" {
			name = guidetest.Outside
		}
		if step == "watch" {
			name = guidetest.Recording
		}
		if step == "enforce" {
			name = guidetest.ContractMade
		}
		f := tourSceneFixture(t, name)
		if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
			t.Fatal(err)
		}
		s, base := tourHTTP(t, f)
		g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
		for _, width := range []int{360, 1280} {
			for _, theme := range []string{"light", "dark"} {
				t.Run(fmt.Sprintf("%s/%d/%s", step, width, theme), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 780, theme)
					defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + tourURL(g, step) + "&t=tok123"})
					tb.until(t, "ready", fmt.Sprintf(`document.readyState==='complete' && document.querySelector('.gf')?.dataset.step===%q`, step))
					assertTourLandmark(t, tb)
					toMain(t, tb, step)
					tabTo(t, tb, "guide instruction and action", "#gf-action", 25)
					if tb.eval(t, fmt.Sprintf(`document.querySelector('.gf')?.dataset.step===%q`, step)) != "true" {
						t.Error("keyboard journey left its teaching step")
					}
					tb.clean(t, "guide keyboard")
				})
			}
		}
	}
}

// Set TOUR_COMPARE to retain a before/after set. Baseline overlays use exactly
// the same fixture and server, omitting the frame that did not exist on the base.
func TestTourComparisonInChrome(t *testing.T) {
	out := os.Getenv("TOUR_COMPARE")
	if out == "" {
		return
	}
	c := placeChrome(t)
	for _, scene := range tourScenes {
		t.Run(scene.name, func(t *testing.T) {
			f := tourSceneFixture(t, scene.fixture)
			if scene.checked {
				if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
					t.Fatal(err)
				}
			}
			s, base := tourHTTP(t, f)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			path := tourURL(g, scene.step)
			if os.Getenv("TOUR_COMPARE_SIDE") == "before" {
				path, _ = tourPath(g, scene.step)
			}
			for _, width := range []int{360, 1280} {
				for _, theme := range []string{"light", "dark"} {
					height := 780
					if width == 1280 {
						height = 900
					}
					func() {
						tb := sweepTab(t, c, t.Name(), width, height, theme)
						defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
						sep := "&"
						if !strings.Contains(path, "?") {
							sep = "?"
						}
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + path + sep + "t=tok123"})
						tb.until(t, "real page", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('main')`)
						if err := os.MkdirAll(out, 0755); err != nil {
							t.Fatal(err)
						}
						var shot struct{ Data []byte }
						_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": false}), &shot)
						if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("%s-%d-%s.png", scene.name, width, theme)), shot.Data, 0644); err != nil {
							t.Fatal(err)
						}
						tb.clean(t, "comparison")
					}()
				}
			}
		})
	}
}

// The decision bar is a named group in the browser accessibility tree.
func assertTourLandmark(t *testing.T, tb *tab) {
	t.Helper()
	var tree struct {
		Nodes []struct {
			Ignored bool
			Role    struct{ Value string }
			Name    struct{ Value string }
		}
	}
	if err := json.Unmarshal(tb.c.call(t, tb.session, "Accessibility.getFullAXTree", map[string]any{}), &tree); err != nil {
		t.Fatal(err)
	}
	for _, n := range tree.Nodes {
		if !n.Ignored && n.Role.Value == "group" && n.Name.Value == "This step" {
			return
		}
	}
	t.Fatal("decision bar is absent from the accessibility tree's named groups")
}

func TestTourReviewBuilderInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, width := range []int{360, 1280} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			f := guidetest.Make(t, guidetest.HalfDone)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			s, base := tourHTTP(t, f)
			s.cfg.Setup = &rules.Service{Ledger: f.Ledger, Home: f.Home, Machine: f.Machine(t), Anchor: f.Anchor, Compile: func(context.Context, rules.CheckContext, []byte) error { return nil }}
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			tb := sweepTab(t, c, t.Name(), width, 780, "light")
			defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + tourURL(g, "review") + "&t=tok123"})
			tb.until(t, "review ready", `document.readyState==='complete' && !!document.querySelector('#gf-action')`)
			tb.eval(t, `document.querySelector('#gf-action').click()`)
			tb.until(t, "real contract form", `document.readyState==='complete' && location.pathname==='/rules/new' && !!document.querySelector('.nw-form') && !!document.querySelector('.builder-page')`)
			if tb.eval(t, `document.querySelector('.builder-edit')?.checkVisibility() || document.querySelector('.nw-form').checkVisibility()`) != "true" {
				t.Fatal("the initial builder has neither a visible editor nor a visible source form")
			}
			openSource := func() {
				t.Helper()
				// A checked draft keeps Name and source collapsed while its editor is visible.
				// Open the source control as a person does before editing those fields.
				tb.eval(t, `(()=>{const source=document.querySelector('details.builder-source');if(!source.open)source.querySelector('summary').click()})()`)
				tb.until(t, "builder source visible", `document.querySelector('.nw-form').checkVisibility()`)
			}
			openSource()
			if tb.eval(t, `document.querySelector('.gf-product').open && document.querySelector('.nw-form').checkVisibility() && document.querySelectorAll('h1').length===1 && new URL(location.href).searchParams.get('guide')==='review' && document.documentElement.scrollWidth<=innerWidth`) != "true" {
				t.Fatal("builder form or guide is hidden")
			}
			if tb.eval(t, `(()=>{const name=document.querySelector('.nw-form input[name=name]'), original=name.value;name.value='invalid name';const rejected=!name.checkValidity();name.value='valid-agent';const accepted=name.checkValidity();name.value=original;return rejected && accepted})()`) != "true" {
				t.Fatal("builder name constraint does not reject invalid names")
			}
			switchModes := func(stage string) {
				t.Helper()
				for _, label := range []string{"From a run", "From presets", "From presets", "From a run"} {
					tb.eval(t, fmt.Sprintf(`(()=>{document.documentElement.dataset.modeLeaving='1';document.addEventListener('tego:enter',()=>delete document.documentElement.dataset.modeLeaving,{once:true});[...document.querySelectorAll('.nw-mode a')].find(a=>a.textContent===%q).click()})()`, label))
					tb.until(t, stage+" "+label, `document.readyState==='complete' && !document.documentElement.dataset.modeLeaving && !!document.querySelector('.nw-form')`)
					if tb.eval(t, `!!document.querySelector('.gf') && new URL(location.href).searchParams.get('guide')==='review'`) != "true" {
						t.Fatalf("%s: %s drops Review", stage, label)
					}
				}
				openSource()
				if tb.eval(t, fmt.Sprintf(`(()=>{document.querySelector('.nw-form input[name=dir]').value=%q;document.querySelector('.nw-form input[name=name]').value='bot';const source=document.querySelector('.nw-form select[name=from]');source.value=%q;return source.value===%q})()`, f.Project, tourFact(g, guide.StepRecord).Run, tourFact(g, guide.StepRecord).Run)) != "true" {
					t.Fatal("the recorded run is absent from the builder source choices")
				}
			}
			switchModes("before preview")
			tb.eval(t, `document.querySelector('.nw-form button[type=submit]').click()`)
			tb.until(t, "preview retains guide", `!document.querySelector('main[aria-busy=true]') && new URL(location.href).searchParams.get('preview')==='1' && !!document.querySelector('.gf') && !!document.querySelector('#builder-save form')`)
			switchModes("before save")
			tb.eval(t, `document.querySelector('.nw-form button[type=submit]').click()`)
			tb.until(t, "preview after mode switching", `new URL(location.href).searchParams.get('preview')==='1' && !!document.querySelector('.gf') && !!document.querySelector('#builder-save form')`)
			tb.eval(t, `document.querySelector('#builder-save form button[type=submit]').click()`)
			tb.until(t, "saved contract retains guide", `new URL(location.href).searchParams.has('created') && document.querySelector('#gf-action')?.textContent==='Enforce its rules'`)
			if tb.eval(t, `new URL(location.href).searchParams.get('guide')==='review' && document.querySelectorAll('h1').length===1`) != "true" {
				t.Error("save dropped guide context or added a heading")
			}
			tb.clean(t, "review builder")
		})
	}
}
