// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const builderRunID = "r-aaaaaaaa-0000000000035-bldr01"

func builderWatchedFixture(t *testing.T, f *rulesFix) {
	t.Helper()
	f.run(t, builderRunID, f.source, rulesSource, time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC), false,
		`"kind":"exec","source":"supervisor","verdict":"allow","path":"/usr/bin/sh","argv":["sh"],"exec_id":"r/10/1"`,
		`"kind":"exec","source":"supervisor","verdict":"allow","path":"/usr/bin/git","argv":["git","status"],"exec_id":"r/11/1"`,
		`"kind":"fs","source":"supervisor","verdict":"allow","op":"open","path":"`+f.proj+`/out/file.txt","flags":65`,
		`"kind":"net","source":"supervisor","verdict":"allow","proto":"tcp","dst":"203.0.113.24:443"`,
		`"kind":"net","source":"supervisor","verdict":"allow","proto":"tcp","dst":"[2001:db8:1234:5678:abcd:ef01:2345:6789]:443"`,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	file := filepath.Join(f.root, builderRunID, "events.jsonl")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `"tier":"landlock"`, `"tier":"observe"`, 1))
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
}

// This matrix runs against the actual authenticated server and CSP. One browser, one page at a time.
func TestBuilderMatrixInChrome(t *testing.T) {
	f := newChangeFix(t)
	builderWatchedFixture(t, f.rulesFix)
	reg := filepath.Join(f.home, ".config", "tego")
	f.svc.Machine.Registry.Value = reg
	// Read-preview layout fixtures start with a prepared registry. First-time
	// preparation is exercised through the guarded native source form separately.
	if err := os.MkdirAll(filepath.Join(reg, "agents"), 0700); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(filepath.Dir(f.proj), "builder-project")
	if err := os.Mkdir(fresh, 0700); err != nil {
		t.Fatal(err)
	}
	longDir := filepath.Join(fresh, "a-project-with-a-long-but-readable-folder-name", "the-nested-output-folder-and-exact-contract-destination")
	if err := os.MkdirAll(longDir, 0700); err != nil {
		t.Fatal(err)
	}
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Rules = f.svc
	s.cfg.Setup = f.svc
	s.cfg.Machine = f.svc.Machine
	ref := f.ref(t, f.source).Ref
	preset := url.Values{"dir": {fresh}, "name": {"builder-demo"}, "preset": {"no-secrets", "no-prod"}, "cmd": {"sh"}, "preview": {"1"}}
	blank := url.Values{"dir": {fresh}, "name": {"builder-demo"}, "mode": {"blank"}, "cmd": {"/bin/sh"}, "preview": {"1"}}
	full := url.Values{"dir": {fresh}, "name": {"builder-demo"}, "preset": {"no-secrets", "no-prod"}, "cmd": {"sh"}, "view": {"full"}, "preview": {"1"}}
	bad := url.Values{"dir": {fresh}, "name": {"Bad Name"}, "preset": {"no-secrets"}, "preview": {"1"}}
	states := []struct {
		name, path string
		open       bool
	}{
		{"new-source", "/rules/new", false},
		{"new-preset-choice", "/rules/new?" + url.Values{"mode": {"presets"}, "preview": {"1"}, "dir": {fresh}, "name": {"choose-preset"}, "to": {"registry"}}.Encode(), false},
		{"new-run-choice", "/rules/new?" + url.Values{"mode": {"run"}, "preview": {"1"}, "dir": {fresh}, "name": {"choose-run"}, "to": {"registry"}}.Encode(), false},
		{"new-run", "/rules/new?mode=run&from=" + builderRunID + "&name=builder-run", false},
		{"new-presets", "/rules/new?" + preset.Encode(), false},
		{"new-blank", "/rules/new?" + blank.Encode(), false},
		{"new-full", "/rules/new?" + full.Encode(), false},
		{"new-save-rejected", "/rules/new?mode=run&from=" + builderRunID + "&name=builder-rejected&view=full", true},
		{"new-problems", "/rules/new?" + bad.Encode(), false},
		{"change-simple", "/rules/change?c=" + ref + "&view=simple", false},
		{"change-full", "/rules/change?c=" + ref + "&raw=1&view=full", true},
		{"new-named-host", "/rules/new?mode=run&from=" + builderRunID + "&name=named-run", false},
		{"new-name-error", "/rules/new?mode=run&from=" + builderRunID + "&name=bad-host", false},
		{"new-compile-error", "/rules/new?" + full.Encode(), true},
		{"change-compile-error", "/rules/change?c=" + ref + "&raw=1&view=full", true},
		{"change-widening", "/rules/change?c=" + ref + "&raw=1&view=full", true},
		{"change-stale", "/rules/change?c=" + ref + "&raw=1&view=full", true},
		{"change-chooser", "/rules/change", false},
		{"new-saved", "/rules/new?" + preset.Encode(), false},
		{"new-fields", "/rules/new?" + full.Encode(), true},
		{"new-source-options", "/rules/new", false},
		{"new-source-host-error", "/rules/new?" + url.Values{"dir": {fresh}, "name": {"source-host-error"}, "mode": {"blank"}, "to": {"registry"}, "cmd": {"/bin/sh"}, "hosts": {"bad host/443"}, "preview": {"1"}}.Encode(), false},
		{"new-wall-error", "/rules/new?mode=run&from=" + builderRunID + "&name=wall-error", false},
		{"new-long-path", "/rules/new?" + url.Values{"dir": {longDir}, "name": {"long-path"}, "mode": {"blank"}, "cmd": {"/bin/sh"}, "preview": {"1"}}.Encode(), false},
		{"new-long-name", "/rules/new?" + url.Values{"dir": {fresh}, "name": {strings.Repeat("n", 60)}, "preset": {"no-secrets"}, "preview": {"1"}}.Encode(), false},
	}
	c := placeChrome(t)
	var records []map[string]any
	captureOnly := os.Getenv("BUILDER_CAPTURE_ONLY") == "1"
	for _, w := range []int{320, 360, 390, 430, 768, 1100, 1280} {
		if os.Getenv("BUILDER_WIDTH") != "" && os.Getenv("BUILDER_WIDTH") != fmt.Sprint(w) {
			continue
		}
		if captureOnly && w != 360 && w != 1280 {
			continue
		}
		for _, theme := range []string{"light", "dark"} {
			for _, st := range states {
				t.Run(fmt.Sprintf("%s/%d/%s", st.name, w, theme), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), w, 780, theme)
					defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
					path := st.path
					if st.name == "new-saved" {
						dir := filepath.Join(filepath.Dir(f.proj), fmt.Sprintf("saved-%d-%s", w, theme))
						if err := os.MkdirAll(dir, 0700); err != nil {
							t.Fatal(err)
						}
						q := url.Values{"dir": {dir}, "name": {fmt.Sprintf("saved-%d-%s", w, theme)}, "preset": {"no-secrets"}, "cmd": {"sh"}, "preview": {"1"}, "to": {"registry"}}
						path = "/rules/new?" + q.Encode()
					}
					sep := "?"
					for _, ch := range path {
						if ch == '?' {
							sep = "&"
							break
						}
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + sep + "t=tok123" + func() string {
						if st.name == "new-full" || st.name == "new-save-rejected" || strings.HasPrefix(st.name, "change-") && st.name != "change-simple" && st.name != "change-chooser" || st.name == "new-compile-error" || st.name == "new-fields" {
							return ""
						}
						return "&view=simple"
					}()})
					tb.until(t, "real builder and fonts", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
					if !captureOnly {
						switch st.name {
						case "new-wall-error":
							tb.eval(t, `document.getElementById("builder-wall").value="nonsense";document.querySelector("#builder-edit button[name=step]").click();''`)
							tb.until(t, "time limit field error", `document.getElementById("builder-wall")?.getAttribute("aria-invalid")==="true"`)
							tb.eval(t, `document.getElementById("builder-wall").scrollIntoView({block:"center"});''`)
						case "new-fields":
							tb.eval(t, `document.querySelector('.builder-glossary').open=true;''`)
						case "new-source-options":
							tb.eval(t, `document.querySelector('.builder-options').open=true;document.querySelector('.lmode-more').open=true;''`)
						case "new-named-host", "new-name-error":
							value := "api.example.com"
							if st.name == "new-name-error" {
								value = "https://bad.example/path"
							}
							quoted, _ := json.Marshal(value)
							tb.eval(t, `document.querySelector('#builder-edit input[name^="host-"]').value=`+string(quoted)+`;document.querySelector('#builder-edit button[name="step"]').click();''`)
							if st.name == "new-name-error" {
								tb.until(t, "host field error", `!!document.querySelector('[id^="builder-host-"][aria-invalid="true"]')`)
							} else {
								tb.until(t, "named host compiled", `document.querySelector('#builder-save textarea[name="text"]')?.value.includes('api.example.com:443')`)
							}
						case "new-compile-error":
							tb.eval(t, `document.querySelector('#builder-text').value='version: 0\nname: builder-demo\ncommand: [sh]\nnet:\n  allow: ["api.example.com:443/path"]\n';document.querySelector('#builder-edit button[name="step"]').click();''`)
							tb.until(t, "new compiler error", `!!document.querySelector('#builder-problems')&&document.getElementById('builder-text')?.getAttribute('aria-invalid')==='true'`)
						case "change-compile-error", "change-widening", "change-stale":
							if st.name == "change-stale" {
								old, err := os.ReadFile(f.source)
								if err != nil {
									t.Fatal(err)
								}
								if err := os.WriteFile(f.source, append(old, []byte("\n# concurrent edit\n")...), 0600); err != nil {
									t.Fatal(err)
								}
								defer func() {
									if err := os.WriteFile(f.source, old, 0600); err != nil {
										t.Error(err)
									}
								}()
							}
							if st.name == "change-compile-error" {
								tb.eval(t, `document.getElementById('yaml-text').value='version: 0\nname: rules-demo\ncommand: [sh]\nnet:\n  allow: ["api.example.com:443/path"]\n';''`)
							} else {
								tb.eval(t, `document.getElementById('yaml-text').value+='\nkeyring: true\n';''`)
							}
							tb.eval(t, `document.querySelector('#builder-edit button[value="check"]').click();''`)
							switch st.name {
							case "change-compile-error":
								tb.until(t, "located compiler error", `!!document.querySelector('.rc-diag')`)
							case "change-stale":
								tb.until(t, "stale draft", `!!document.querySelector('.builder-page')?.innerText.includes('Changed since you opened')`)
							default:
								tb.until(t, "compiled widening", `!!document.querySelector('.builder-page')?.innerText.includes('This will newly allow')`)
								tb.eval(t, `document.getElementById("builder-newlyallows").scrollIntoView({block:"start"});''`)
							}
						}
					}

					if captureOnly && (st.name == "change-compile-error" || st.name == "change-widening" || st.name == "change-stale") {
						if st.name == "change-stale" {
							old, err := os.ReadFile(f.source)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(f.source, append(old, []byte("\n# concurrent edit\n")...), 0600); err != nil {
								t.Fatal(err)
							}
							defer func() {
								if err := os.WriteFile(f.source, old, 0600); err != nil {
									t.Error(err)
								}
							}()
						}
						if st.name == "change-compile-error" {
							tb.eval(t, `document.getElementById('yaml-text').value='version: 0\nname: rules-demo\ncommand: [sh]\nnet:\n  allow: ["api.example.com:443/path"]\n';''`)
						} else {
							tb.eval(t, `document.getElementById('yaml-text').value+='\nkeyring: true\n';''`)
						}
						tb.eval(t, `document.getElementById('yaml-text').closest('form').querySelector('button[value=check]').click();''`)
						if st.name == "change-compile-error" {
							tb.until(t, "base compiler error", `!!document.querySelector('.rc-diag')`)
						} else {
							tb.until(t, "base checked edit", `!!document.querySelector('.rc-free')`)
						}
						if st.name == "change-widening" {
							tb.eval(t, `document.querySelector('.rc-free').scrollIntoView({block:'center'});''`)
						}
					}
					if captureOnly && st.name == "new-source-options" {
						tb.eval(t, `const d=document.querySelector('.lmode-more');if(d)d.open=true;''`)
					}

					if st.name == "new-save-rejected" {
						if !captureOnly {
							tb.eval(t, `document.getElementById('builder-text').value+='\n# retained after refused Save\n';document.querySelector('#builder-edit button[name=step]').click();''`)
							tb.until(t, "checked edited draft", `document.querySelector('#builder-save textarea[name=text]')?.value.includes('retained after refused Save')`)
						}
						path := filepath.Join(reg, "agents", "builder-rejected.yaml")
						if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, []byte("version: 0\nname: builder-rejected\ncommand: [/bin/sh]\n"), 0600); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if err := os.Remove(path); err != nil {
								t.Error(err)
							}
						}()
						tb.eval(t, `document.querySelector('form[action="/rules/new"]:has(input[name=base]) button[type=submit]').click();''`)
						tb.until(t, "save refusal", `!!(document.querySelector('main')?.textContent.includes('Not saved')||document.querySelector('main')?.textContent.includes('already the contract'))`)
						if !captureOnly && tb.eval(t, `document.getElementById('builder-text')?.value.includes('retained after refused Save')`) != "true" {
							t.Error("save refusal lost the draft")
						}
					}

					if st.name == "new-saved" {
						tb.eval(t, `document.querySelector('form[action="/rules/new"]:has(input[name="base"]) button[type="submit"]').click();''`)
						tb.until(t, "saved contract", `document.querySelector('h1')?.textContent.includes('contract saved')||document.querySelector('h1')?.textContent.includes('contract written')`)
					}

					tb.until(t, "settled page enhancements", `document.readyState==='complete'&&document.fonts.status==='loaded'&&typeof window.tegoLive?.steady==='function'`)
					if !captureOnly && st.name == "change-widening" {
						tb.eval(t, `document.getElementById('builder-newlyallows').scrollIntoView({block:'start',behavior:'instant'});''`)
					}
					if !captureOnly && st.name == "new-wall-error" {
						tb.eval(t, `document.getElementById('builder-wall').scrollIntoView({block:'center',behavior:'instant'});''`)
					}
					if !captureOnly && st.name == "new-save-rejected" {
						tb.eval(t, `document.getElementById('builder-problems').scrollIntoView({block:'start',behavior:'instant'});''`)
					}

					c.call(t, tb.session, "Runtime.evaluate", map[string]any{"expression": "new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))", "awaitPromise": true})
					var encoded string
					if err := json.Unmarshal([]byte(tb.eval(t, builderMeasure)), &encoded); err != nil {
						t.Fatal(err)
					}
					var rec map[string]any
					if err := json.Unmarshal([]byte(encoded), &rec); err != nil {
						t.Fatal(err)
					}
					rec["state"], rec["width"], rec["theme"] = st.name, w, theme
					records = append(records, rec)
					t.Log(encoded)
					if !captureOnly {
						if st.name == "new-run-choice" && w <= 600 && tb.eval(t, `(()=>{const e=document.getElementById('builder-run'),r=e.getBoundingClientRect();return e.getAttribute('aria-invalid')==='true'&&document.activeElement===e&&r.top>=0&&r.bottom<=document.querySelector('nav.phone-nav').getBoundingClientRect().top;})()`) != "true" {
							t.Error("run-choice error focus is not visible")
						}
						if st.name == "new-preset-choice" && w <= 600 && tb.eval(t, `(()=>{const e=document.getElementById('builder-presets'),r=e.getBoundingClientRect();return e.getAttribute('aria-invalid')==='true'&&document.activeElement===e&&r.top>=0&&r.bottom<=document.querySelector('nav.phone-nav').getBoundingClientRect().top;})()`) != "true" {
							t.Error("preset-choice error focus is not visible")
						}
						if st.name == "new-source-options" && tb.eval(t, `Array.from(document.querySelectorAll('.lm-table,.lmode-more .tw')).every(e=>e.scrollWidth<=e.clientWidth+1)`) != "true" {
							t.Error("mode comparison scrolls sideways")
						}
						if st.name == "new-long-path" {
							quoted, _ := json.Marshal(longDir)
							if tb.eval(t, `(()=>{const e=document.querySelector('.cli code');return e.textContent.includes(`+string(quoted)+`)&&e.scrollWidth<=e.clientWidth+1&&document.querySelector('.builder-yaml .ut')?.textContent.includes('…');})()`) != "true" {
								t.Error("long path loses its middle ellipsis or exact wrapping command")
							}
						}
						if st.name == "new-run" && tb.eval(t, `document.querySelectorAll('.builder-decision').length>=3`) != "true" {
							t.Error("real watched draft lacks file, command and destination decisions")
							t.Log(tb.eval(t, `document.querySelector('.builder-page').innerText`))
						}
						if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
							t.Error("actual rendered contrast failed")
						}
						if tb.eval(t, `document.documentElement.scrollWidth<=innerWidth`) != "true" {
							t.Error("sideways document scroll")
							t.Log(tb.eval(t, `Array.from(document.querySelectorAll('.page *')).filter(e=>e.getBoundingClientRect().right>innerWidth+1).slice(0,8).map(e=>[e.tagName,e.className,e.scrollWidth,e.clientWidth])`))
						}
						if w <= 600 {
							for _, check := range []string{"smallTargets", "smallText", "clips"} {
								if tb.eval(t, `JSON.parse(`+builderMeasure+`).`+check+`.length===0`) != "true" {
									t.Errorf("%s failed", check)
								}
							}
							if tb.eval(t, `JSON.parse(`+builderMeasure+`).sizes.length<=3`) != "true" {
								t.Error("more than three phone text sizes")
							}
						}
						if tb.eval(t, `(()=>{const d=JSON.parse(`+builderMeasure+`).design;return d.headingFace.includes('Anton')&&d.disclosures.every(e=>e.justify==='flex-start')&&(!d.editor||d.editor.face.includes('monospace')&&d.editor.tab==='2'&&d.editor.ligatures==='none'&&d.editor.wrap==='off'&&d.editor.whiteSpace==='pre');})()`) != "true" {
							t.Error("heading, disclosure or YAML design contract failed")
						}
						if w <= 600 && tb.eval(t, `(()=>{const d=JSON.parse(`+builderMeasure+`).design;return d.phoneBar==='Contracts'&&(!d.choiceWidths||Math.abs(d.choiceWidths[0]-d.choiceWidths[1])<1);})()`) != "true" {
							t.Error("phone title, equal view choices or reachable primary action failed")
						}
						if w <= 600 && (st.name == "new-run" || st.name == "new-presets" || st.name == "new-blank" || st.name == "new-full" || st.name == "change-simple" || st.name == "change-full" || st.name == "new-long-path") && tb.eval(t, `(()=>{const p=JSON.parse(`+builderMeasure+`).design.primary;return p&&p.top>=0&&p.bottom<=716&&p.height>=44;})()`) != "true" {
							t.Error("primary action is not reachable in the first phone viewport")
						}
						if w > 900 && tb.eval(t, `(()=>{const d=JSON.parse(`+builderMeasure+`).design;return (!d.choiceWidths||d.switchWidth<d.choiceWidths.reduce((a,b)=>a+b,0)+20)&&(!d.decision||d.decision.sentenceRight<=d.decision.choiceLeft);})()`) != "true" {
							t.Error("desktop switch or sentence and choice list failed")
						}
						if tb.eval(t, `JSON.parse(`+phoneMeasure+`).paletteFailures.length===0`) != "true" {
							t.Error("computed token contrast")
						}
					}
					if out := os.Getenv("BUILDER_SHOTS"); out != "" && (w == 360 || w == 1280) {
						if err := os.MkdirAll(out, 0755); err != nil {
							t.Fatal(err)
						}
						var shot struct{ Data string }
						if err := json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": false}), &shot); err != nil {
							t.Fatal(err)
						}
						b, err := base64.StdEncoding.DecodeString(shot.Data)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("%s-%d-%s.png", st.name, w, theme)), b, 0644); err != nil {
							t.Fatal(err)
						}
					}
					if st.name == "new-save-rejected" && !captureOnly {
						if tb.eval(t, `performance.getEntriesByType('navigation')[0].responseStatus===409`) != "true" {
							t.Error("save conflict did not return HTTP 409")
						}
						expected := "browser network error: Failed to load resource: the server responded with a status of 409 (Conflict) http://" + addr + "/rules/new"
						for _, p := range tb.problems() {
							if p != expected {
								t.Errorf("builder: %s", p)
							}
						}
					} else {
						tb.clean(t, "builder")
					}
				})
			}
		}
	}
	if out := os.Getenv("BUILDER_SHOTS"); out != "" {
		b, _ := json.MarshalIndent(records, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "measurements.json"), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

const builderMeasure = `JSON.stringify((()=>{
 const visible=e=>e.checkVisibility({visibilityProperty:true})&&e.getBoundingClientRect().width>2&&e.getBoundingClientRect().height>2;
 const scope=document.querySelector('.page');
 const desc=e=>e.tagName+'.'+e.className+' '+e.textContent.trim().slice(0,50);
 const smallTargets=[],smallText=[],clips=[],sizes=new Set(),pairs=new Map();
 const rgba=s=>(s.match(/[\d.]+/g)||[]).map(Number);
 const blend=(a,b)=>a.slice(0,3).map((v,i)=>v*(a[3]??1)+b[i]*(1-(a[3]??1)));
 const lum=a=>a.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4}).reduce((v,n,i)=>v+n*[.2126,.7152,.0722][i],0);
 const contrast=e=>{const chain=[];for(let a=e;a;a=a.parentElement)chain.unshift(a);let bg=[255,255,255];for(const a of chain)bg=blend(rgba(getComputedStyle(a).backgroundColor),bg);const s=getComputedStyle(e),fg=blend(rgba(s.color),bg),l=lum(fg),b=lum(bg),ratio=(Math.max(l,b)+.05)/(Math.min(l,b)+.05),min=parseFloat(s.fontSize)>=24?3:4.5,key=fg.join(',')+'/'+bg.join(',');if(!pairs.has(key)||pairs.get(key).min<min)pairs.set(key,{fg,bg,ratio,min,element:desc(e)});};
 for(const e of scope.querySelectorAll('a,button,input,select,textarea,summary')){
  if(!visible(e)||e.closest('.lr[data-live="r-banner"]'))continue;
  let target=e;if(e.matches('input[type=radio],input[type=checkbox]'))target=e.closest('label')||e;
  const r=target.getBoundingClientRect();if(r.width<43.9||r.height<43.9)smallTargets.push({element:desc(e),w:r.width,h:r.height});
 }
 const walker=document.createTreeWalker(scope,NodeFilter.SHOW_TEXT);
 while(walker.nextNode()){const n=walker.currentNode,e=n.parentElement;if(!n.textContent.trim()||!visible(e)||e.closest('.sr,script,style'))continue;
  const s=getComputedStyle(e);contrast(e);sizes.add(parseFloat(s.fontSize));if(parseFloat(s.fontSize)<13)smallText.push(desc(e));
  const range=document.createRange();range.selectNodeContents(n);
  for(const r of range.getClientRects()){
   for(let a=e;a&&a!==scope;a=a.parentElement){const cs=getComputedStyle(a),ar=a.getBoundingClientRect();if((['hidden','clip'].includes(cs.overflowX)&&(r.left<ar.left-1||r.right>ar.right+1))||(['hidden','clip'].includes(cs.overflowY)&&(r.top<ar.top-1||r.bottom>ar.bottom+1))){clips.push(desc(e));break}}
  }
 }
 const editor=document.querySelector('#builder-text,#yaml-text'), es=editor&&getComputedStyle(editor);
 const seg=document.querySelector('#builder-edit .seg'), choices=seg&&[...seg.querySelectorAll('button')].map(e=>e.getBoundingClientRect().width);
 const row=document.querySelector('.builder-decision'), sentence=row?.querySelector('p'), choice=row?.querySelector('.kd');
 const primary=document.querySelector('.head .btn-primary'), pr=primary?.getBoundingClientRect();
 const design={headingFace:getComputedStyle(document.querySelector('h1')).fontFamily,phoneBar:document.querySelector('.page-name')?.textContent.trim(),editor:es&&{face:es.fontFamily,tab:es.tabSize,ligatures:es.fontVariantLigatures,wrap:editor.wrap,whiteSpace:es.whiteSpace},switchWidth:seg?.getBoundingClientRect().width,choiceWidths:choices,decision:row&&{sentenceLeft:sentence.getBoundingClientRect().left,sentenceRight:sentence.getBoundingClientRect().right,choiceLeft:choice.getBoundingClientRect().left,sentenceTop:sentence.getBoundingClientRect().top,choiceTop:choice.getBoundingClientRect().top},primary:pr&&{top:pr.top,bottom:pr.bottom,height:pr.height,bg:getComputedStyle(primary).backgroundColor,ink:getComputedStyle(primary).color},disclosures:[...document.querySelectorAll('.builder-page summary')].filter(visible).map(e=>({justify:getComputedStyle(e).justifyContent,label:e.textContent.trim().slice(0,40)}))};
 return {design,width:innerWidth,documentWidth:document.documentElement.scrollWidth,smallTargets,smallText,clips,contrastPairs:[...pairs.values()],contrastFailures:[...pairs.values()].filter(p=>p.ratio<p.min-.01),sizes:[...sizes].sort((a,b)=>a-b),firstDecision:document.querySelector('.builder-decision')?.getBoundingClientRect().top,saveLink:document.querySelector('a[href="#builder-save"]')?.getBoundingClientRect().top};
})())`

// Match the editor's line boxes in an unpainted mirror to measure its final glyph.
// The mirror is removed before a browser frame and changes no product behavior.
const builderCaretMeasure = `JSON.stringify((()=>{
 const e=document.querySelector('#builder-text'),s=getComputedStyle(e),p=document.createElement('pre'),c=document.createElement('span'),sh=new CSSStyleSheet();
 sh.replaceSync('.builder-caret-measure{position:fixed;left:0;top:0;visibility:hidden;white-space:pre;overflow-wrap:normal;font-family:'+s.fontFamily+';font-size:'+s.fontSize+';font-weight:'+s.fontWeight+';font-style:'+s.fontStyle+';line-height:'+s.lineHeight+';padding:'+s.padding+';margin:0;border:0}.builder-caret-measure span{font:inherit}');
 document.adoptedStyleSheets=[...document.adoptedStyleSheets,sh];p.className='builder-caret-measure';p.append(document.createTextNode(e.value));c.textContent='\u200b';p.append(c);document.body.append(p);
 const r=p.getBoundingClientRect(),q=c.getBoundingClientRect(),top=q.top-r.top,bottom=q.bottom-r.top,visible=top>=e.scrollTop-1&&bottom<=e.scrollTop+e.clientHeight+1;
 p.remove();document.adoptedStyleSheets=document.adoptedStyleSheets.slice(0,-1);return {top,bottom,visible};
})())`

func TestBuilderEditingAndNativeFallbackInChrome(t *testing.T) {
	f := newChangeFix(t)
	builderWatchedFixture(t, f.rulesFix)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	if err := os.MkdirAll(filepath.Join(f.svc.Machine.Registry.Value, "agents"), 0700); err != nil {
		t.Fatal(err)
	}
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Setup = f.svc
	s.cfg.Rules = f.svc
	s.cfg.Machine = f.svc.Machine
	c := placeChrome(t)
	for _, js := range []bool{true, false} {
		tb := sweepTab(t, c, fmt.Sprint(js), 360, 780, "light")
		c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !js})
		c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/rules/new?mode=run&from=" + builderRunID + "&name=native-" + fmt.Sprint(js) + "&view=simple&t=tok123"})
		tb.until(t, "decisions", `!!document.querySelector('.builder-decision')&&document.readyState==='complete'`)
		if tb.eval(t, `document.querySelector('.builder-decision').getBoundingClientRect().top<650&&document.querySelector('a[href="#builder-save"]').getBoundingClientRect().bottom<716`) != "true" {
			t.Error("phone first viewport loses question, decisions or Save route")
		}
		tb.eval(t, `document.querySelector('.builder-decision input[value="drop"]').click();''`)
		if js {
			if tb.eval(t, `Array.from(document.querySelectorAll('.builder-decision')).every(e=>!!document.getElementById(e.dataset.yamlId))`) != "true" {
				t.Error("decision and YAML line IDs drifted")
			}
			tb.until(t, "compiled preview", `document.getElementById('builder-updates').textContent.includes('Choices checked')`)
		} else {
			tb.eval(t, `document.querySelector('#builder-edit button[name="step"]').click();''`)
			tb.until(t, "native check", `document.readyState==='complete'&&document.querySelector('#builder-save textarea[name="text"]')?.value.includes('write: []')`)
		}
		if tb.eval(t, `document.querySelector('#builder-save textarea[name="text"]').value.includes('write: []')`) != "true" {
			t.Error("Drop was not compiled into candidate")
		}
		tb.eval(t, `document.querySelector('#builder-edit button[value="full"]').click();''`)
		tb.until(t, "Full view", `!!document.querySelector('#builder-text')&&document.readyState==='complete'&&document.fonts.status==='loaded'&&(!window.tegoLive||typeof window.tegoLive.steady==='function')`)
		tb.eval(t, `document.querySelector('#builder-text').focus();''`)
		c.call(t, tb.session, "Input.dispatchKeyEvent", map[string]any{"type": "keyDown", "key": "End", "code": "End", "windowsVirtualKeyCode": 35, "modifiers": 2})
		c.call(t, tb.session, "Input.dispatchKeyEvent", map[string]any{"type": "keyUp", "key": "End", "code": "End", "windowsVirtualKeyCode": 35, "modifiers": 2})
		c.call(t, tb.session, "Input.insertText", map[string]any{"text": "\n# retained through view switches\n"})
		// The final glyph must be inside the native editor's scrollport. Font leading
		// and padding can extend below it, so scrollHeight alone is not a caret bound.
		if tb.eval(t, `(()=>{const e=document.querySelector('#builder-text');return e.value.includes('retained through view switches')&&e.selectionEnd===e.value.length&&e.wrap==='off'&&getComputedStyle(e).whiteSpace==='pre'&&JSON.parse(`+builderCaretMeasure+`).visible;})()`) != "true" {
			t.Errorf("native editor last-line measurement: %s", tb.eval(t, `(()=>{const e=document.querySelector('#builder-text'),s=getComputedStyle(e);return {top:e.scrollTop,height:e.scrollHeight,client:e.clientHeight,width:e.scrollWidth,clientWidth:e.clientWidth,end:e.selectionEnd,length:e.value.length,padding:s.padding,lineHeight:s.lineHeight,wrap:s.whiteSpace,retained:e.value.includes('retained through view switches')};})()`))
		}
		if js {
			top := tb.eval(t, `document.querySelector('#builder-text').scrollTop`)
			tb.eval(t, `document.querySelector('#builder-text').scrollTop=0;''`)
			if tb.eval(t, `JSON.parse(`+builderCaretMeasure+`).visible`) != "false" {
				t.Error("caret measurement missed the final line outside the native scrollport")
			}
			tb.eval(t, `document.querySelector('#builder-text').scrollTop=`+top+`;''`)
		}
		tb.eval(t, `document.querySelector('#builder-edit button[value="simple"]').click();''`)
		tb.until(t, "Simple retained draft", `!document.getElementById('builder-text')&&!!document.querySelector('#builder-edit textarea[name="text"]')?.value.includes('retained through view switches')`)
		tb.eval(t, `document.querySelector('#builder-edit button[value="full"]').click();''`)
		tb.until(t, "Full retained draft", `document.getElementById('builder-text')?.value.includes('retained through view switches')`)
		// Remembered per viewer, while the explicit draft remains in its form.
		tb.eval(t, `document.querySelector('.builder-yaml').open=true;''`)
		if tb.eval(t, `document.documentElement.scrollWidth<=360`) != "true" {
			t.Error("YAML disclosure widens phone")
		}
		if js {
			tb.eval(t, `document.querySelector('.skip').focus();''`)
			for i := 0; i < 28; i++ {
				tb.press(t, "Tab")
				if tb.eval(t, `(()=>{const e=document.activeElement,r=e.getBoundingClientRect(),b=document.querySelector('nav.phone-nav').getBoundingClientRect();return e===document.body||!!e.closest('nav.phone-nav')||(r.top>=0&&r.bottom<=b.top+1&&getComputedStyle(e).outlineStyle!=='none');})()`) != "true" {
					t.Errorf("focus %d hidden, covered or invisible: %s", i, tb.eval(t, `(()=>{const e=document.activeElement,r=e.getBoundingClientRect();return {tag:e.tagName,cls:e.className,top:r.top,bottom:r.bottom,height:r.height,outline:getComputedStyle(e).outlineStyle};})()`))
					break
				}
			}
			c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "forced-colors", "value": "active"}, {"name": "prefers-reduced-motion", "value": "reduce"}}})
			if tb.eval(t, `getComputedStyle(document.querySelector('.kd label')||document.querySelector('#builder-text')).borderStyle!=='none'`) != "true" {
				t.Error("forced colors loses boundary")
			}
		}
		if js {
			tb.eval(t, `(()=>{const sh=new CSSStyleSheet();sh.replaceSync('.builder-probe{width:20px;height:20px;overflow:hidden;white-space:nowrap}.builder-scroller{width:20px;overflow:auto}');document.adoptedStyleSheets=[...document.adoptedStyleSheets,sh];const p=document.createElement('div');p.className='builder-probe';p.textContent='This deliberately clipped text must fail';const q=document.createElement('div');q.className='builder-scroller';q.textContent='A separate scroller cannot excuse the clip';document.querySelector('.builder-page').append(p,q);return '';})()`)
			if tb.eval(t, `JSON.parse(`+builderMeasure+`).clips.length>0`) != "true" {
				t.Error("direct clipping probe missed intentional clip")
			}
			tb.eval(t, `document.querySelector('.builder-probe').remove();document.querySelector('.builder-scroller').remove();document.adoptedStyleSheets=document.adoptedStyleSheets.slice(0,-1);''`)
		}
		tb.clean(t, "editing")
		c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
	}
}

// Error fields must stay connected to their messages after the preview enhancement and native navigation.
func TestBuilderErrorFocusInChrome(t *testing.T) {
	f := newChangeFix(t)
	builderWatchedFixture(t, f.rulesFix)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	if err := os.MkdirAll(filepath.Join(f.svc.Machine.Registry.Value, "agents"), 0700); err != nil {
		t.Fatal(err)
	}
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Setup, s.cfg.Rules, s.cfg.Machine = f.svc, f.svc, f.svc.Machine
	c := placeChrome(t)
	for _, kind := range []string{"auto-field", "native-focus", "save-exit"} {
		t.Run(kind, func(t *testing.T) {
			tb := sweepTab(t, c, kind, 360, 780, "light")
			defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/rules/new?mode=run&from=" + builderRunID + "&name=focus-" + kind + "&view=simple&t=tok123"})
			tb.until(t, "ready before editing", `document.readyState==='complete'&&typeof window.tegoLive?.steady==='function'`)
			switch kind {
			case "auto-field":
				tb.eval(t, `const e=document.querySelector('#builder-edit input[name^="host-"]');e.value='https://bad.example/path';e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));''`)
				tb.until(t, "auto preview error", `!!document.getElementById('builder-problems')&&document.getElementById('builder-updates').textContent.includes('Fix the problems')`)
				if tb.eval(t, `(()=>{const e=document.querySelector('#builder-edit input[name^="host-"]');return e.getAttribute('aria-invalid')==='true'&&document.getElementById(e.getAttribute('aria-describedby')).textContent.includes('host name');})()`) != "true" {
					t.Error("live validation did not reach the field and its message")
				}
				if tb.eval(t, `!!document.querySelector('#builder-save button')`) == "true" {
					t.Error("invalid auto preview kept Save")
				}
			case "native-focus":
				tb.eval(t, `document.getElementById('builder-wall').value='nonsense';document.querySelector('#builder-edit button[name=step]').click();''`)
				tb.until(t, "invalid time limit", `document.getElementById('builder-wall')?.getAttribute('aria-invalid')==='true'&&document.readyState==='complete'&&typeof window.tegoLive?.steady==='function'`)
				if tb.eval(t, `(()=>{const e=document.getElementById('builder-wall'),r=e.getBoundingClientRect();return document.activeElement===e&&r.top>=0&&r.bottom<=document.querySelector('nav.phone-nav').getBoundingClientRect().top;})()`) != "true" {
					t.Fatalf("error focus is hidden: %s", tb.eval(t, `(()=>{const e=document.getElementById('builder-wall'),r=e.getBoundingClientRect();return {active:document.activeElement.id,top:r.top,bottom:r.bottom,scrollY};})()`))
				}
			default:
				tb.eval(t, `document.querySelector('.builder-decision input[value=drop]').click();''`)
				tb.until(t, "checked choice before Save", `document.querySelector('#builder-save textarea[name=text]')?.value.includes('write: []')`)
				// Observe the unload warning a real Save would cause, then stop navigation in the test only.
				tb.eval(t, `document.addEventListener('submit',function testSave(e){if(!e.target.closest('#builder-save'))return;const u=new Event('beforeunload',{cancelable:true});window.dispatchEvent(u);window.builderSaveWarned=u.defaultPrevented;e.preventDefault();document.removeEventListener('submit',testSave);});document.querySelector('#builder-save form').requestSubmit(document.querySelector('#builder-save form button'));''`)
				if tb.eval(t, `window.builderSaveWarned===false`) != "true" {
					t.Error("Save asks to abandon the draft it is saving")
				}
			}
		})
	}
}
