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

// C125: the Several changes at once form and its preview in a real browser, at 1280 and 390 px, light and dark: the
// form opens with its first four rows (the rest under More rows), three typed rows reach one preview that lists every
// edit in words and carries all three to Save, and neither page scrolls sideways or has a control under 24 by 24 px at
// 390 px. TEGO_CHROME_SHOTS saves each window.
func TestSeveralChangesInChrome(t *testing.T) {
	f := newChangeFix(t)
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Rules, s.cfg.Setup, s.cfg.Machine = f.svc, f.svc, f.svc.Machine
	ref := f.ref(t, f.source).Ref
	c := placeChrome(t)
	shot := func(t *testing.T, tb *tab, name string) {
		dir := os.Getenv("TEGO_CHROME_SHOTS")
		if dir == "" {
			return
		}
		time.Sleep(150 * time.Millisecond)
		var r struct{ Data []byte }
		_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
		if err := os.WriteFile(filepath.Join(dir, name+".png"), r.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range []int{1280, 390} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/rules/change?c=" + ref + "&t=tok123"})
				tb.until(t, "the form", `document.readyState==='complete'&&!!document.getElementById('several')`)
				// Open "Change individual rules" and the several form, and fill three of the rows.
				tb.eval(t, `(function(){for(var d=document.getElementById('several');d;d=d.parentElement&&d.parentElement.closest('details'))d.open=true;
					var fill=function(n,op,key,v){document.getElementById('sev-op-'+n).value=op;document.getElementById('sev-key-'+n).value=key;document.getElementById('sev-v-'+n).value=v};
					fill(1,'add','fs.write','./more/');fill(2,'add','exec.allow','`+anyProgram+`');fill(3,'remove','exec.allow','git');return ''})()`)
				if got := tb.eval(t, `[...document.querySelectorAll('#several .rc-sev-row')].filter(function(r){return r.checkVisibility()}).length`); got != "4" {
					t.Errorf("rows shown before More rows: %s, want 4", got)
				}
				tb.eval(t, `document.getElementById('several').scrollIntoView({block:'start'});''`)
				if w == 390 {
					if v := tb.eval(t, smallControls); v != `""` {
						t.Errorf("controls under 24 by 24 px: %s", v)
					}
				}
				shot(t, tb, fmt.Sprintf("c125-form-%d-%s", w, theme))
				tb.eval(t, `document.querySelector('#several button[type=submit]').click();''`)
				tb.until(t, "the preview", `document.readyState==='complete'&&location.pathname==='/rules/change/preview'`)
				body := tb.eval(t, `document.body.innerText`)
				for _, want := range []string{"Check the change", "./more/", "Cannot run git"} {
					if !strings.Contains(body, want) {
						t.Errorf("the preview lacks %q", want)
					}
				}
				if got := tb.eval(t, `document.querySelectorAll('form.rc-confirm input[name=op]').length`); got != "3" {
					t.Errorf("the Save form carries %s edits, want 3", got)
				}
				if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
					t.Errorf("rendered contrast failed on the preview")
				}
				pageChecks(t, tb, "several preview", w, "", "")
				shot(t, tb, fmt.Sprintf("c125-preview-%d-%s", w, theme))
			})
		}
	}
}
