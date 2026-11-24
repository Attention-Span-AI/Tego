// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"slices"
	"strings"
	"testing"
)

// mcpContract has a stdio MCP server, an HTTP one under a net: section, and a relayed stdio one.
const mcpContract = `version: 0
name: mcpdemo
command: [bash, agent.sh]
net:
  allow: ["127.0.0.1:1"]
exec:
  allow: [bash]
mcp:
  - name: files
    command: [cat, notes.txt]
  - name: search
    url: http://127.0.0.1:9000/mcp
  - name: ledger
    command: [grep, x]
    tools:
      allow: [read]
`

// TestMCPServersAreRulesInForce (C154): an mcp: entry grants the agent rights implicitly (a stdio server's command may
// be run, an HTTP server's address may be reached), so the view lists each as a rule, with the line a run's events
// carry for it, and says which are held to the relay's tool rules, which are not listed here.
func TestMCPServersAreRulesInForce(t *testing.T) {
	f := newFixture(t)
	rt := f.compile(t, mcpContract, nil)
	compiled := Of(rt, "landlock", "")
	declared, err := Declared([]byte(mcpContract), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]*View{"compiled": &compiled, "declared": &declared} {
		files := findRule(t, v, "mcp", "files")
		if files.Group != GroupPrograms || files.Effect != EffectAllow || !strings.Contains(files.Sentence, "MCP server files") ||
			files.RuleKey != "exec[cat]" {
			t.Errorf("%s: the stdio server's row is %+v, want a program allow named exec[cat]", name, files)
		}
		ledger := findRule(t, v, "mcp", "ledger")
		if !strings.Contains(ledger.Sentence, "MCP relay") || ledger.Group != GroupPrograms {
			t.Errorf("%s: the relayed server's row says %q, want the relay named", name, ledger.Sentence)
		}
		search := findRule(t, v, "mcp", "search")
		if search.Group != GroupNetwork || !strings.Contains(search.Sentence, "http://127.0.0.1:9000/mcp") {
			t.Errorf("%s: the HTTP server's row is %+v, want a network row naming its URL", name, search)
		}
		note := false
		for _, n := range v.Notes {
			note = note || strings.Contains(n, "relay") && strings.Contains(n, "not listed")
		}
		if !note {
			t.Errorf("%s: no note says the relay's tool rules are not listed: %q", name, v.Notes)
		}
	}
	// Compiled, the HTTP server's row carries the net rule its URL derived, so its lines count there.
	if search := findRule(t, &compiled, "mcp", "search"); search.RuleKey != "mcp[search]" {
		t.Errorf("the HTTP server's rule key is %q, want mcp[search], the name of the net rule its URL derived", search.RuleKey)
	}
	compiled.Count(slices.Values([]string{"exec[cat]", "mcp[search]", "mcp[search]"}))
	if r := findRule(t, &compiled, "mcp", "search"); r.Hits != 2 {
		t.Errorf("the HTTP server's row has %d hits, want 2", r.Hits)
	}
	if r := findRule(t, &compiled, "mcp", "files"); r.Hits != 1 {
		t.Errorf("the stdio server's row has %d hits, want its program's 1", r.Hits)
	}
}

// TestPrivilegedDeclarationsAreListed (C154): exec.privileged is accepted by the schema and refused by this build, so
// a view read from the file's text lists each entry as a declaration that grants nothing and says the file does not
// compile; it never reads as a file with fewer rules.
func TestPrivilegedDeclarationsAreListed(t *testing.T) {
	text := "version: 0\nname: priv\ncommand: [bash]\nexec:\n  allow: [bash]\n  privileged: [\"apt install\"]\n"
	d, err := Declared([]byte(text), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := findRule(t, &d, "exec.privileged", "apt install")
	if r.Group != GroupPrograms || r.Effect != EffectNote || r.State != StateNone || r.Source.Line != 6 ||
		!strings.Contains(r.Sentence, "does not support") {
		t.Errorf("the privileged declaration is %+v, want a programs note on line 6 that says it is not supported", r)
	}
}
