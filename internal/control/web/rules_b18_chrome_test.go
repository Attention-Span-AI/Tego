// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// The pages that changed, in a real browser at 390 and 1280 px, light and dark: the rule families a change moves (the
// preview and the free editor's check), the other spelling of a rules file and the pages of its runs, what a file edited
// outside Tego says now against what the run ran, and the folder and ignore lines of a new contract. Each must show its
// words, not scroll sideways and not break the contrast or the small-control checks. TEGO_CHROME_SHOTS saves each window.
func TestB18PagesInChrome(t *testing.T) {
	f := newChangeFix(t)
	link := filepath.Join(filepath.Dir(f.proj), "proj-link")
	if err := os.Symlink(f.proj, link); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-90 * time.Minute).UTC().Truncate(time.Millisecond)
	f.run(t, "r-aaaaaaaa-0000000000034-linked", filepath.Join(link, "agent.yaml"), rulesSource, t0, false,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	for i := range maxChooserRuns {
		f.run(t, fmt.Sprintf("r-aaaaaaaa-%013d-later", 100+i), f.source, rulesSource, t0.Add(time.Duration(i+1)*time.Second), false,
			`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	}
	if err := os.WriteFile(f.source, []byte(strings.Replace(rulesSource, "  allow: [sh, git]\n", "  allow: [sh]\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(f.source, old, old); err != nil {
		t.Fatal(err)
	}
	settled := filepath.Join(filepath.Dir(f.proj), "settled-proj")
	for _, d := range []string{"src", filepath.Join(".tego", "tmp")} {
		if err := os.MkdirAll(filepath.Join(settled, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Rules, s.cfg.Setup, s.cfg.Machine = f.svc, f.svc, f.svc.Machine
	ref := f.ref(t, f.source).Ref
	c := placeChrome(t)
	long := "Files it may change: the next run may do more than before (" + strings.Repeat("/home/someone/projects/a-very-long-folder-name/", 3) + "x; /srv/data/y; /srv/data/z; and more, listed under This will newly allow)"
	plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: f.source, Agent: "demo", Base: "b2", Direction: "mixed", NeedsAck: true, Ack: "ack1",
		Summary: "exec.allow += cat status", Diff: "--- agent.yaml\n+  allow: [sh, cat status]\n",
		Sentences: []rules.Sentence{{Before: "Cannot run cat status", After: "May run cat status", Direction: "mixed"}},
		Families: []rules.FamilyChange{
			{Family: "filesystem", Direction: "widens", Words: long},
			{Family: "program arguments", Direction: "mixed", Words: "The arguments a program may run with: changed, and Tego cannot tell whether the next run may do more"},
			{Family: "destinations", Direction: "narrows", Words: "Places it may connect to: the next run may do less than before"}}}
	type state struct {
		name, path string
		before     func(t *testing.T, tb *tab)
		want       []string
		pre        func()
	}
	states := []state{
		{"preview-families", "/rules/change/preview?" + url.Values{"c": {"00112233aabbccdd"}, "op": {"add"}, "key": {"exec.allow"}, "v": {"cat status"}}.Encode(), nil,
			[]string{"What the compiled contract changes", "Tego cannot tell whether the next run may do more", "Places it may connect to: the next run may do less than before"},
			func() { s.cfg.Rules = &fakeChange{plan: plan} }},
		{"raw-check-families", "/rules/change?c=" + ref + "&raw=1&view=full", func(t *testing.T, tb *tab) {
			tb.eval(t, `(function(){var e=document.getElementById('yaml-text');e.value=e.value.replace('allow: [sh]','allow: [sh, git, cat]');return ''})()`)
			tb.eval(t, `document.querySelector('#builder-edit button[value="check"]').click();''`)
			tb.until(t, "the families", `!!document.querySelector('.rc-fam-list')`)
		}, []string{"It compiles", "What the compiled contract changes", "Programs it may run: the next run may do more than before"}, nil},
		{"alias-and-pages", "/rules?c=" + ref, nil,
			[]string{"This file is also recorded as ", "Runs of every spelling are listed here together.", "Older runs"}, nil},
		{"outside-edit-comparison", "/rules?run=" + rulesRunA, nil,
			[]string{"What the file says now, compared with what this run ran", "Programs it may run: the next run may do less than before"},
			func() {
				s.cfg.Rules = &compareStub{RuleService: f.svc, got: rules.SourceComparison{Direction: "mixed", Families: []rules.FamilyChange{
					{Family: "programs", Direction: "narrows", Words: "Programs it may run: the next run may do less than before"},
					{Family: "filesystem", Direction: "widens", Words: long}}}}
			}},
		{"new-folders-and-ignore", "/rules/new?" + url.Values{"dir": {settled}, "preset": {"repo-only-writes"}, "writes": {"src/"}, "cmd": {"sh"}, "preview": {"1"}}.Encode(), nil,
			[]string{"Every folder it writes to is already there.", "Add to .gitignore: .tego/tmp/"}, nil},
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
					if st.name != "preview-families" {
						tb.eval(t, `(document.querySelectorAll('details').forEach(d => d.open = true), '')`)
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
					pageChecks(t, tb, st.name, w, fmt.Sprintf("b18-%s-%d-%s", st.name, w, theme), "")
				})
			}
		}
	}
}
