// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

// TestMCPRelayedURLDerivesNoNetRule: an HTTP server behind Tego's relay (tools:) derives no net rule for its URL
// (ADR 0126 §4), so the agent's only route to it is the relay; an unrelayed one beside it still derives its rule.
func TestMCPRelayedURLDerivesNoNetRule(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load(`version: 0
name: t
command: ["python"]
fs:
  write: ["./out/"]
mcp:
  - name: search
    url: "https://mcp.internal/mcp"
    tools: {deny: [delete]}
  - name: local
    url: "http://127.0.0.1:3001/mcp"
net:
  allow: ["api.anthropic.com:443"]
`))
	if hasCode(ds, CodeSchema) || hasCode(ds, CodeContradiction) {
		t.Fatalf("diagnostics: %s", render(ds))
	}
	for _, r := range rt.Net {
		if r.MCP == "search" {
			t.Fatalf("the relayed server derived %+v", r)
		}
	}
	if len(rt.Net) != 2 || rt.Net[1].MCP != "local" {
		t.Fatalf("net rules %+v, want the declared one and local's", rt.Net)
	}
}

// TestMCPRelayWarnings: a relayed stdio server under an exec.allow list is told to admit the tego binary, and a
// relayed url server with no net: section is told it can be reached around the relay.
func TestMCPRelayWarnings(t *testing.T) {
	f := newFixture(t)
	_, ds := f.compile(f.load(`version: 0
name: t
command: ["python"]
fs:
  write: ["./out/"]
exec:
  allow: ["python"]
mcp:
  - name: files
    command: ["python"]
    tools: {}
  - name: web
    url: "http://127.0.0.1:3001/mcp"
    tools: {}
`))
	out := render(ds)
	if !strings.Contains(out, "`tego mcp relay`, which exec.allow must admit") {
		t.Errorf("no exec.allow warning for the relayed stdio server:\n%s", out)
	}
	if !strings.Contains(out, "with no net: section every destination is admitted") {
		t.Errorf("no net: warning for the relayed url server:\n%s", out)
	}
}
