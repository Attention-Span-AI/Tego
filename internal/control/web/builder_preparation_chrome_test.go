// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the native source submit as well as Save. The HTML preview must
// replace the document instead of becoming an inline action response.
func TestBuilderRegistryPreparationAndSaveInChrome(t *testing.T) {
	c := placeChrome(t)
	for _, js := range []bool{true, false} {
		t.Run(fmt.Sprintf("scripts=%t", js), func(t *testing.T) {
			f := newChangeFix(t)
			reg := filepath.Join(f.home, ".config", "tego")
			f.svc.Machine.Registry.Value = reg
			s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
			s.cfg.Setup, s.cfg.Rules, s.cfg.Machine = f.svc, f.svc, f.svc.Machine
			name := fmt.Sprintf("prepared-%t", js)
			q := url.Values{"mode": {"blank"}, "dir": {f.proj}, "name": {name}, "to": {"registry"}, "cmd": {"/bin/sh"}, "preview": {"1"}, "t": {"tok123"}}
			tb := sweepTab(t, c, t.Name(), 390, 844, "light")
			defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
			c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !js})
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/rules/new?" + q.Encode()})
			tb.until(t, "unprepared source form", `document.readyState==='complete' && !!document.getElementById('builder-source')`)
			if js {
				tb.until(t, "page scripts ready", `typeof window.tegoLive?.steady==='function'`)
			}
			if tb.eval(t, `!document.querySelector('#builder-save form')`) != "true" {
				t.Fatal("read-only preview offered Save before preparing its destination")
			}
			if _, err := os.Lstat(reg); !os.IsNotExist(err) {
				t.Fatalf("GET prepared registry directories: %v", err)
			}
			if tb.eval(t, `(()=>{const f=document.getElementById('builder-source');return f.method==='post' && f.action===location.origin+'/rules/new' && !!f.elements.csrf.value && f.elements.builder.value==='1' && f.elements.step.value==='source' && f.querySelector('[name=to]:checked')?.value==='registry';})()`) != "true" {
				t.Fatal("rendered source form lost its guarded same-origin POST fields")
			}
			tb.eval(t, `window.builderPreparationDocument=true;const d=document.querySelector('.builder-source');if(!d.open)d.querySelector('summary').click();document.querySelector('#builder-source button[type=submit]').focus();''`)
			tb.press(t, "Enter")
			tb.until(t, "native Preview returned a saveable page", `document.readyState==='complete' && location.search==='' && !window.builderPreparationDocument && !!document.querySelector('#builder-save form [name=base]')`)
			if st, err := os.Stat(filepath.Join(reg, "agents")); err != nil || !st.IsDir() {
				t.Fatalf("guarded source POST did not prepare the destination: %v", err)
			}
			if tb.eval(t, `(()=>{const f=document.querySelector('#builder-save form');return f.method==='post' && f.action===location.origin+'/rules/new' && !!f.elements.csrf.value && !!f.elements.base.value && !!f.elements.draft.value && f.elements.step.value==='save' && f.elements.to.value==='registry';})()`) != "true" {
				t.Fatal("rendered Save lost its guarded destination or review fields")
			}
			var reviewed string
			if err := json.Unmarshal([]byte(tb.eval(t, `document.querySelector('#builder-save textarea[name=text]').value`)), &reviewed); err != nil {
				t.Fatal(err)
			}
			tb.eval(t, `document.querySelector('#builder-save button[type=submit]').focus();''`)
			tb.press(t, "Enter")
			tb.until(t, "native Save completed", `document.readyState==='complete' && document.querySelector('h1')?.textContent.includes('contract saved')`)
			saved, err := os.ReadFile(filepath.Join(reg, "agents", name+".yaml"))
			if err != nil || string(saved) != reviewed {
				t.Fatalf("Save did not publish the reviewed contract: %v", err)
			}
			tb.clean(t, "guarded source Preview and Save")
		})
	}
}
