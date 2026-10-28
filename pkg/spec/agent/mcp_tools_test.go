// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"strings"
	"testing"
)

const toolsContract = `version: 0
name: t
command: ["python"]
mcp:
  - name: files
    command: ["python3", "/opt/fake-mcp/server.py"]
    tools:
%s`

// TestMCPToolsAccepted: the three lists load as written, and the server is relayed.
func TestMCPToolsAccepted(t *testing.T) {
	c, ds := loadDiags(t, strings.Replace(toolsContract, "%s",
		"      allow: [read_file, list_dir, \"ns:tool/x\"]\n      deny: [delete_file]\n      ask: [write_file]\nask: {timeout: 2m}\n", 1))
	if c == nil {
		t.Fatalf("refused: %s", render(ds))
	}
	tl := c.MCP[0].Tools
	if tl == nil || !slices.Equal(tl.Allow, []string{"read_file", "list_dir", "ns:tool/x"}) || !slices.Equal(tl.Deny, []string{"delete_file"}) ||
		!slices.Equal(tl.Ask, []string{"write_file"}) || !c.MCP[0].Relayed() {
		t.Fatalf("tools = %+v", tl)
	}
	if !MCPToolNameOK("read_file") || MCPToolNameOK("a b") || MCPToolNameOK(strings.Repeat("x", 129)) {
		t.Fatal("MCPToolNameOK")
	}
}

// TestMCPToolsRefused: a bad name, a name in two lists, an ask list without an ask: section, an unknown key.
func TestMCPToolsRefused(t *testing.T) {
	for _, tc := range []struct{ name, tools, words string }{
		{"bad name", "      deny: [\"rm -rf\"]\n", "is not a tool name"},
		{"two lists", "      allow: [x]\n      deny: [x]\n", "is in tools.allow and tools.deny"},
		{"ask without broker", "      ask: [write_file]\n", "add ask: {timeout: 2m}"},
		{"unknown key", "      maybe: [x]\n", "maybe"},
		{"not a list", "      deny: x\n", "deny"},
		// A key with no value read as absent: the relay off, or every tool allowed where `allow: []` allows none (R1).
		{"null tools", "", "write `tools: {}`"},
		{"null allow", "      allow:\n", "write `allow: []`"},
		{"null deny", "      deny:\n", "write `deny: []`"},
		{"null ask", "      ask:\n", "write `ask: []`"},
		{"tilde allow", "      allow: ~\n", "write `allow: []`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds := loadDiags(t, strings.Replace(toolsContract, "%s", tc.tools, 1))
			if c != nil {
				t.Fatalf("loaded: %s", render(ds))
			}
			if !hasCode(ds, CodeSchema) || !strings.Contains(render(ds), tc.words) {
				t.Errorf("want [schema] %q, got:\n%s", tc.words, render(ds))
			}
		})
	}
}

// TestMCPToolsRefusedUnderObserve: a relayed server needs an enforcing tier.
func TestMCPToolsRefusedUnderObserve(t *testing.T) {
	f := newFixture(t)
	c := f.load(`version: 0
name: t
command: ["python"]
mcp:
  - name: postgres
    command: ["mcp-postgres"]
    tools: {deny: [drop_table]}
`)
	_, ds, _ := Compile(c, f.machine, f.opts(WithObserve())...)
	if !strings.Contains(render(ds), "around the relay") {
		t.Errorf("no observe refusal: %s", render(ds))
	}
	_, ds = f.compile(c)
	if strings.Contains(render(ds), "around the relay") {
		t.Errorf("refused at an enforcing tier: %s", render(ds))
	}
}
