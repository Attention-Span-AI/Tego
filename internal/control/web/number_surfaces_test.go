// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/agents"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"golang.org/x/net/html"
)

// Every standalone page must have an explicit fixture. This list is checked against
// the server's page catalog, so a new page cannot silently escape the delivered walk.
func numberSurfaceFixtures(t *testing.T) []numberFixture {
	t.Helper()
	root := numberLedger(t)
	s := newServer(t, root)
	c := login(t, s)
	var out []numberFixture
	paths := map[string]string{
		"overview": "/", "runs": "/runs", "run": "/runs/" + numRichRun,
		"logs": "/logs", "approvals": "/approvals", "detections": "/detections", "hours": "/refusals",
		"rules": "/rules", "machine": "/machine", "compare": "/compare", "glossary": "/glossary", "more": "/more", "severity": "/severity",
		"investigate": "/runs/" + numRichRun + "/investigate/3", "stop": "/runs/" + numRichRun + "/stop",
		"event":       "/runs/" + numRichRun + "/lines/7",
		"mcp-preview": "/mcp/preview?run=" + harmRun + "&server=files&tool=delete_file&decision=allow",
	}
	for name, path := range paths {
		out = append(out, numberFixture{"surface/" + name, getRaw(t, s, c, path)})
	}
	contract := getRaw(t, s, c, "/rules?run="+numRichRun)
	selected := ""
	walk(parseHTML(t, "contract source", contract), func(n *html.Node) {
		if href, ok := attr(n, "href"); ok && selected == "" {
			u, e := url.Parse(href)
			if e == nil && u.Query().Get("rule") != "" {
				selected = href
			}
		}
	})
	if selected == "" {
		t.Fatal("contract fixture has no selected-rule link")
	}
	out = append(out, numberFixture{"surface/selected-rule", getRaw(t, s, c, selected)})
	routes := newServer(t, routesFixture(t))
	rc := login(t, routes)
	out = append(out, numberFixture{"surface/model-routes-preview", getRaw(t, routes, rc, "/routes/preview?run="+harmRun+"&endpoint=api.anthropic.com%3A443&route=local")})

	ds, dc, _, dp := detailServer(t)
	ep := filepath.Join(ds.cfg.Ledger, detailRun, "events.jsonl")
	raw, err := os.ReadFile(ep)
	if err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(dp, strings.Repeat("nested/", 10), "secret.txt")
	raw = bytes.ReplaceAll(raw, []byte(filepath.Join(dp, "a", "b", "secret.txt")), []byte(deep))
	if err := os.WriteFile(ep, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/runs/" + detailRun + "/lines/1", "/runs/" + detailRun + "/lines/1?a=block", "/runs/" + detailRun + "/lines/4", "regions:/runs/" + detailRun + "/lines/1?a=block", "/logs?q=203.0.113.9"} {
		out = append(out, numberFixture{"surface/action/" + path, inventoryResponse(t, ds, dc, path)})
	}
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	emit := func(name string, data any) {
		t.Helper()
		var b bytes.Buffer
		l := map[string]*liveRegion{}
		for _, n := range regionsOf(name) {
			l[n] = &liveRegion{Name: n}
		}
		if err := pages[name].ExecuteTemplate(&b, "content", page{L: l, Data: data}); err != nil {
			t.Fatal(err)
		}
		out = append(out, numberFixture{"surface/" + name, b.String()})
	}
	av := richAgentsView()
	emit("agents", agentsData{V: av, Recorded: 1, Seen: 2, Rows: []agentRow{agentRowOf(av.Rows[0]), agentRowOf(av.Rows[1]), agentRowOf(av.Rows[2])}})
	for _, r := range av.Rows {
		one := agentRowOf(r)
		emit("agents", agentsData{V: av, One: &one})
	}
	emit("agents", agentsData{V: agents.View{ScanStatus: "unreadable", ScanNotice: "The saved scan could not be read.", Empty: "No current agent evidence can be shown."}})
	run := &ledgerview.Run{ID: numRichRun, Agent: "Counter", Live: true, Start: time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)}
	emit("rule", ruleGone{Line: "/runs/" + numRichRun + "/lines/7"})
	emit("livefence", liftData{Run: run, Kind: "net", Value: "api.example.com:443", What: "connect to api.example.com:443", When: "for 1 hour", CLI: "tego lift " + numRichRun + " net api.example.com:443 --for 1h"})
	emit("error", errorData{Heading: "Not found", Text: "No run at this address."})
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	f.withSetup(t)
	out = append(out, numberFixture{"surface/rules-source", getRaw(t, f.s, f.c, "/rules?c="+ref.Ref)}, numberFixture{"surface/rules-list", getRaw(t, f.s, f.c, "/rules")})
	out = append(out, numberFixture{"surface/rules-change", getRaw(t, f.s, f.c, "/rules/change?c="+ref.Ref)})
	out = append(out, numberFixture{"surface/rules-new", getRaw(t, f.s, f.c, "/rules/new?mode=run")}, numberFixture{"surface/rules-new-presets", getRaw(t, f.s, f.c, "/rules/new")})
	q := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}}
	out = append(out, numberFixture{"surface/rules-preview", getRaw(t, f.s, f.c, "/rules/change/preview?"+q.Encode())})
	emit("approvals", approvalsData{Now: run.Start, Answered: &answered{Run: run.ID, Agent: numRichAgent, Target: "example.com:443", Op: "connect", Word: "Allowed after 4 s"}})
	emit("approvals", approvalsData{Now: run.Start, Lost: []ledgerview.Ask{{Run: run.ID, Agent: numRichAgent, AskID: "lost-1", Seq: 7, TS: run.Start, Op: "connect", Target: "example.com:443"}}})
	emit("rules-change", changeData{Contracts: []rules.ContractRef{{Agent: numRichAgent, Path: "/work/agent12.yaml", Ref: "selected", Runs: 3}}})
	emit("rules-saved", savedData{Contract: "/work/agent.yaml", Agent: "Counter", Applied: &rules.Applied{Plan: &rules.ChangePlan{Agent: "Counter", Summary: "Remove git", Direction: "narrows", Sentences: []rules.Sentence{{Before: "May run git", After: "Cannot run git"}}, Diff: "- git\n"}}, Headline: "Saved"})
	empty := newServer(t, t.TempDir())
	ec := login(t, empty)
	empty.cfg.Setup = f.s.cfg.Setup
	out = append(out, numberFixture{"surface/new-empty-source", getRaw(t, empty, ec, "/rules/new?mode=run")})
	return out
}

func TestNumberInventoryPageCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range numberSurfaceFixtures(t) {
		seen[strings.TrimPrefix(f.name, "surface/")] = true
	}
	// Private page layers append their own fixtures through numberWalkLayers.
	for _, name := range pageNames {
		if !seen[name] {
			t.Errorf("page %s has no delivered-markup inventory fixture", name)
		}
	}
}
