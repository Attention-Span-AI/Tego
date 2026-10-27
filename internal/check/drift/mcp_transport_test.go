// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mixedTable declares a stdio server, two HTTPS servers and a plain http:// one (agent-contract.md R16a).
func mixedTable() *agent.RuleTable {
	return &agent.RuleTable{Contract: &agent.Contract{
		Name: "tester",
		MCP: []agent.MCPServer{{Name: "fs", Command: []string{"mcp-fs"}}, {Name: "search", URL: "https://mcp.internal/mcp"},
			{Name: "wiki", URL: "https://wiki.internal/mcp"}, {Name: "local", URL: "http://127.0.0.1:3001/mcp"}},
	}}
}

func httpMCPEvent(t *testing.T, name, tool string) *record.Event {
	t.Helper()
	e := mcpEvent(t, name)
	e.Source, e.Verdict = record.SourceSSL, record.VerdictObserved
	if err := e.SetPayload(record.MCPPayload{Name: name, Transport: "http", Tool: tool}); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestMCPProducerCoversItsTransport (limits-check-doctor-cli.md R15, amended 2026-10-19): a producer observes the
// servers of its own transport only. The exec producer sees a stdio server start and never an HTTP server's
// connection, so under parsers mcp=exec an idle HTTP server is unobservable, not unused; the HTTP reader (mcp/1)
// covers HTTPS servers; an mcp line of one transport proves that transport's producer ran. A plain http:// server's
// exchanges pass no TLS library, so no producer covers it (capture-derive R41): it is unobservable under every one.
func TestMCPProducerCoversItsTransport(t *testing.T) {
	for _, c := range []struct {
		name          string
		parsers       map[string]string
		body          func() []*record.Event
		unused, blind []string
	}{
		{"exec only", map[string]string{"mcp": "exec"}, nil, []string{"mcp[fs]"}, []string{"mcp[local]", "mcp[search]", "mcp[wiki]"}},
		{"http only", map[string]string{"mcp": "mcp/1"}, nil, []string{"mcp[search]", "mcp[wiki]"}, []string{"mcp[fs]", "mcp[local]"}},
		{"both", map[string]string{"mcp": "exec+mcp/1"}, nil, []string{"mcp[fs]", "mcp[search]", "mcp[wiki]"}, []string{"mcp[local]"}},
		{"legacy version", map[string]string{"mcp": "1"}, nil, []string{"mcp[fs]"}, []string{"mcp[local]", "mcp[search]", "mcp[wiki]"}},
		{"an http line proves the http producer", nil,
			func() []*record.Event { return []*record.Event{httpMCPEvent(t, "search", "q")} },
			[]string{"mcp[wiki]"}, []string{"mcp[fs]", "mcp[local]"}},
		{"a stdio line proves the exec producer only", nil,
			func() []*record.Event { return []*record.Event{mcpEvent(t, "fs")} },
			nil, []string{"mcp[local]", "mcp[search]", "mcp[wiki]"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var body []*record.Event
			if c.body != nil {
				body = c.body()
			}
			rep := mcpRunWith(t, mixedTable(), c.parsers, body...)
			if !slices.Equal(rep.UnusedMCP, c.unused) || !slices.Equal(rep.UnobservableMCP, c.blind) {
				t.Fatalf("unused %v unobservable %v, want %v and %v", rep.UnusedMCP, rep.UnobservableMCP, c.unused, c.blind)
			}
		})
	}
}

// TestDerivedNetRuleIsNoAuthorsEntry: the net rule an HTTP server's url derives (agent-contract R16a, NetRule.MCP) is
// the server's, reported idle under mcp alone; it is never listed as a net entry the author declared and never used.
func TestDerivedNetRuleIsNoAuthorsEntry(t *testing.T) {
	rt := &agent.RuleTable{
		Contract: &agent.Contract{Name: "tester", MCP: []agent.MCPServer{{Name: "search", URL: "https://mcp.internal/mcp"}}},
		Net: []agent.NetRule{
			{Raw: "api.example:443", Host: "api.example", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow},
			{Raw: "tcp://mcp.internal:443", Host: "mcp.internal", Port: 443, Proto: agent.ProtoTCP, Verdict: agent.VerdictAllow, MCP: "search"},
		},
	}
	rep := mcpRunWith(t, rt, map[string]string{"mcp": "mcp/1"})
	if !slices.Equal(rep.UnusedMCP, []string{"mcp[search]"}) {
		t.Fatalf("unused mcp %v", rep.UnusedMCP)
	}
	if !slices.Equal(rep.Undone, []string{"net[api.example:443]"}) {
		t.Fatalf("net undone %v, want the author's entry alone", rep.Undone)
	}
}
