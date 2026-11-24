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
)

// This batch's pages in a real browser at 390 and 1280 px, light and dark: the Rules page of a rules file whose runs started in
// two places (the launch note, the profiles note, the command-word and exec.args rows, the MCP rows and the hook row),
// and the line page that lists the rule change made from it. Each must show its words, scroll nowhere sideways and break
// no control under 24 by 24 px at 390 px. TEGO_CHROME_SHOTS saves each window.
func TestB14PagesInChrome(t *testing.T) {
	f := newRulesFix(t)
	const b14Source = `version: 0
name: b14-demo
command: [sh]
net:
  allow: ["127.0.0.1:1"]
exec:
  allow: [sh, "git status", "git diff"]
mcp:
  - name: files
    command: [cat, notes.txt]
  - name: search
    url: http://127.0.0.1:9000/mcp
`
	src := f.proj + "/b14.yaml"
	t0 := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	f.startExtra = `,"profiles":[{"name":"base/mini","source":"builtin","sha256":"aa"}],"runtime_grants":["exec.harness-hook[/opt/tego/bin/tego]"]`
	f.runAt(t, "r-aaaaaaaa-0000000000041-b14aaa", src, b14Source, t0, false, f.proj, "landlock",
		`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","status"],"exec_id":"x/10/2","path":"/usr/bin/git","command_rule":"git status","command_list":"allow"`,
		`"kind":"exec","source":"seccomp","rule":"exec.args[git]","verdict":"refused","authority":"rule","reason":"exec-not-allowed","attribution":{"confidence":"unattributed","method":"none"},"argv":["git","log"],"exec_id":"x/10/3","path":"/usr/bin/git","command_rule":"git","command_list":"unlisted"`,
		`"kind":"exec","source":"seccomp","rule":"exec.harness-hook[/opt/tego/bin/tego]","verdict":"allow","authority":"rule","argv":["/opt/tego/bin/tego","hook"],"exec_id":"x/10/4","path":"/opt/tego/bin/tego"`,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	f.runAt(t, "r-aaaaaaaa-0000000000042-b14bbb", src, b14Source, t0.Add(time.Hour), false, f.proj+"/elsewhere", "cgroup",
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	ref := f.svcRef(t, src)
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Machine = f.s.cfg.Machine
	c := placeChrome(t)
	// The phone's Rules page keeps each group to one line ("Program access: Allowed"), so the rows' sentences are the wide
	// layout's; the notes, in the contract disclosure, are on both.
	type state struct {
		name, path string
		want, wide []string
	}
	states := []state{
		{"rules-contract", "/rules?c=" + ref, []string{
			"This rules file started runs in more than one place", "started in " + f.proj + "/elsewhere at tier cgroup",
			"The run merged the profiles base/mini (built into tego)"}, []string{
			"Cannot run git with any other words than the commands allowed above", "MCP server files", "its MCP server search",
			"Can run tego's hook command"}},
		{"rules-run", "/rules?run=r-aaaaaaaa-0000000000041-b14aaa", nil, []string{"Can run git status", "1 hit"}},
	}
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, st := range states {
				t.Run(fmt.Sprintf("%s/%d/%s", st.name, w, theme), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), w, 900, theme)
					defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + st.path + "&t=tok123"})
					tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
					// The notes sit in the disclosure that holds the contract's details; open it to read them.
					tb.eval(t, `document.querySelectorAll('details').forEach(function (d) { d.open = true; }), ""`)
					body := tb.eval(t, `document.body.innerText`)
					if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
						_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("b14-%s-%d-%s.txt", st.name, w, theme)), []byte(body), 0o600)
					}
					want := st.want
					if w >= 1280 {
						want = append(want, st.wide...)
					}
					for _, want := range want {
						if !strings.Contains(body, want) {
							t.Errorf("%s lacks %q in %q", st.name, want, body)
						}
					}
					if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
						t.Errorf("%s: rendered contrast failed", st.name)
					}
					pageChecks(t, tb, st.name, w, fmt.Sprintf("b14-%s-%d-%s", st.name, w, theme), ".rules-default")
				})
			}
		}
	}
}

// TestB14EventPageInChrome: the line page that lists the rule change made from its line, the same windows.
func TestB14EventPageInChrome(t *testing.T) {
	saved, line, _ := savedWithBlock(t)
	s, addr, _ := liveServer(t, saved.cfg.Ledger, 10*time.Second, 30*time.Second)
	s.cfg.Rules, s.cfg.Machine = saved.cfg.Rules, saved.cfg.Machine
	c := placeChrome(t)
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("event/%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + line + "?t=tok123&" + url.Values{}.Encode()})
				tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
				body := tb.eval(t, `document.body.innerText`)
				for _, want := range []string{"Rules changed from this line", "Cannot run git", "History"} {
					if !strings.Contains(body, want) {
						t.Errorf("event page lacks %q in %q", want, body)
					}
				}
				if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
					t.Error("rendered contrast failed")
				}
				pageChecks(t, tb, "event", w, fmt.Sprintf("b14-event-%d-%s", w, theme), "#h-chg")
			})
		}
	}
}
