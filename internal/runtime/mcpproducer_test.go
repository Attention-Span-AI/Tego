// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"maps"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestRunParsersNamesTheMCPProducer is limits-check-doctor-cli.md R15's producer half: run_start.parsers
// carries "mcp" naming exactly the producers that could have recorded a declared server — "exec" for a stdio
// server's start when a notify loop answers this run's execve, "mcp/1" for an HTTP server's exchanges when the
// uprobe source is the run's capture (capture-derive.md R41) — and neither under a record mode that drops allowed
// actions. Without a producer of a server's transport, drift reads that server with no mcp event as not observable
// and never as unused, so a run the producer did watch could never report an unused server.
func TestRunParsersNamesTheMCPProducer(t *testing.T) {
	build := map[string]string{"anthropic": "1", "openai": "1"}
	cases := []struct {
		name    string
		sup     bool
		record  agent.RecordMode
		capture agent.CaptureMode
		wantMCP string
	}{
		{"the supervisor records allowed execs", true, "", agent.CaptureForwarder, "exec"},
		{"record: summary", true, agent.RecordSummary, agent.CaptureOff, "exec"},
		{"record: off drops the allowed exec the event rides on", true, agent.RecordOff, agent.CaptureUprobe, ""},
		{"no notify loop: nothing sees the exec", false, "", agent.CaptureForwarder, ""},
		{"uprobe capture reads HTTP servers", true, "", agent.CaptureUprobe, "exec+mcp/1"},
		{"uprobe capture alone", false, agent.RecordSummary, agent.CaptureUprobe, "mcp/1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &runner{rt: &agent.RuleTable{Record: tc.record}}
			r.deps.Build.Parsers = build
			if tc.sup {
				r.sup = &supervisor.Loop{}
			}
			got := r.runParsers(string(tc.capture))
			if v := got["mcp"]; v != tc.wantMCP {
				t.Fatalf("parsers = %v, want mcp %q", got, tc.wantMCP)
			}
			delete(got, "mcp")
			if !maps.Equal(got, build) {
				t.Fatalf("the build's parsers were not carried over: %v", got)
			}
		})
	}
	if _, ok := build["mcp"]; ok {
		t.Fatal("runParsers wrote into the build's own map")
	}
	if got := (&runner{rt: &agent.RuleTable{}}).runParsers(""); got == nil || len(got) != 0 {
		t.Fatalf("a build without parsers: %v, want an empty map, never nil", got)
	}
}
