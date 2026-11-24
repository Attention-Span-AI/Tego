// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// The rule editor's pages that changed, in a real browser at 390 and 1280 px, light and dark: the preview that says
// what the next run is and gives the line that restarts it, the Edit YAML diagnostic that names a profile, its file and
// its line, and the 503 page that names its cause. Each must not scroll sideways, must show its words, and breaks no
// control under 24 by 24 px at 390 px. TEGO_CHROME_SHOTS saves each window.
func TestRuleEditorPagesInChrome(t *testing.T) {
	f := newChangeFix(t)
	if err := os.MkdirAll(filepath.Join(f.proj, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	profiles := filepath.Join(t.TempDir(), "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(profiles, "base.yaml")
	if err := os.WriteFile(profile, []byte("version: 0\nname: base\nfs:\n  write: []\nbogus_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.svc.Machine.Profiles.Value = profiles
	builderWatchedFixture(t, f.rulesFix)
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Rules, s.cfg.Setup, s.cfg.Machine = f.svc, f.svc, f.svc.Machine
	ref := f.ref(t, f.source).Ref
	c := placeChrome(t)
	type state struct {
		name, path string
		before     func(t *testing.T, tb *tab)
		want       []string
		pre        func() // runs before the page is opened
	}
	plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: f.source, Agent: "demo", Base: "b2", Direction: "narrows",
		Summary: "fs.ask_read += ./docs/", Diff: "--- agent.yaml\n+  ask_read: [./docs/]\n",
		Sentences: []rules.Sentence{{Before: "May read ./docs/", After: "Asks you before it reads ./docs/", Direction: "narrows"}},
		Now:       []rules.NowOption{{Run: rulesRunB, Change: "fs.ask_read += ./docs/", Why: "an ask cannot be added live: the run asks from its next run"}}}
	states := []state{
		{"preview-next-run", "/rules/change/preview?" + url.Values{"c": {"00112233aabbccdd"}, "op": {"add"}, "key": {"fs.ask_read"}, "v": {"./docs/"}}.Encode(), nil,
			[]string{"Narrows", "keeps the rules it started with", "tego run " + f.source}, func() { s.cfg.Rules = &fakeChange{plan: plan} }},
		{"raw-profile-diagnostic", "/rules/change?c=" + ref + "&raw=1&view=full", func(t *testing.T, tb *tab) {
			tb.eval(t, `document.getElementById('yaml-text').value='version: 0\nname: rules-demo\ncommand: [sh]\nextends: base\n';''`)
			tb.eval(t, `document.querySelector('#builder-edit button[value="check"]').click();''`)
			tb.until(t, "located profile diagnostic", `!!document.querySelector('.rc-diags .rc-where')`)
		}, []string{"Profile base", profile, "line 5"}, nil},
		{"unavailable-503", "/rules/change?c=" + ref, func(t *testing.T, tb *tab) {
			s.cfg.Rules = &unavailableSaveService{Service: f.svc, err: contracts.CheckUnavailable(context.DeadlineExceeded), phase: "raw-catalogue"}
			tb.eval(t, `location.reload();''`)
			tb.until(t, "the 503 page", `document.readyState==='complete'&&document.body.innerText.includes('could not finish')`)
		}, []string{"The check did not finish: the location does not answer"}, nil},
	}
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, st := range states {
				t.Run(fmt.Sprintf("%s/%d/%s", st.name, w, theme), func(t *testing.T) {
					s.cfg.Rules = f.svc
					if st.pre != nil {
						st.pre()
					}
					tb := sweepTab(t, c, t.Name(), w, 900, theme)
					defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
					sep := "&"
					if !strings.Contains(st.path, "?") {
						sep = "?"
					}
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + st.path + sep + "t=tok123"})
					tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
					if st.before != nil {
						st.before(t, tb)
					}
					body := tb.eval(t, `document.body.innerText`)
					for _, want := range st.want {
						if !strings.Contains(body, want) {
							t.Errorf("%s lacks %q in %q", st.name, want, body)
						}
					}
					if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
						t.Errorf("%s: rendered contrast failed", st.name)
					}
					if st.name == "unavailable-503" {
						// The 503 is the page under test: the browser's own line for it is the one problem allowed.
						expected := "browser network error: Failed to load resource: the server responded with a status of 503 (Service Unavailable) http://" + addr + st.path
						for _, p := range tb.problems() {
							if p != expected {
								t.Errorf("%s: %s", st.name, p)
							}
						}
						if v := tb.eval(t, `(function () { var d = document.documentElement; return d.scrollWidth > d.clientWidth ? "wide" : ""; })()`); v != `""` {
							t.Errorf("%s scrolls sideways", st.name)
						}
						if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
							var r struct{ Data []byte }
							_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
							_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("b3-%s-%d-%s.png", st.name, w, theme)), r.Data, 0o600)
						}
						return
					}
					pageChecks(t, tb, st.name, w, fmt.Sprintf("b3-%s-%d-%s", st.name, w, theme), "")
				})
			}
		}
	}
}
