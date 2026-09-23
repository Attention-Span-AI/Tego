// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"maps"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/derive/mcp"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// MCPProducerExec names, in run_start.parsers["mcp"], the producer of a stdio server's start: an allowed exec of a
// declared mcp[].command is recorded as that server's start (supervisor.emitMCP). It names how the events are
// derived rather than a protocol parser's version.
const MCPProducerExec = "exec"

// runParsers is run_start.parsers: the body parsers this build links, plus "mcp" naming the run's MCP producers,
// "+"-joined (limits-check-doctor-cli.md R15): MCPProducerExec when the supervisor answers this run's execve
// notifications — every tier that installs the tier-1 seccomp filter, tier 2 included — and mcp.Version when the
// uprobe source is the run's capture (capture names it), which reads the declared HTTP MCP servers' exchanges
// (capture-derive.md R41). Either needs a record mode that keeps allowed actions: record: off drops an allowed
// exec, and the mcp event riding on it, and under it the uprobe source captures nothing. drift reads a declared
// server with no mcp event as unused only when a producer of its transport is named, so the key says exactly what
// could have written one.
func (r *runner) runParsers(capture string) map[string]string {
	out := make(map[string]string, len(r.deps.Build.Parsers)+1)
	maps.Copy(out, r.deps.Build.Parsers)
	if r.rt == nil || r.rt.Record == agent.RecordOff {
		return out
	}
	var producers []string
	if r.sup != nil {
		producers = append(producers, MCPProducerExec)
	}
	if capture == string(agent.CaptureUprobe) {
		producers = append(producers, mcp.Version)
	}
	if len(producers) > 0 {
		out["mcp"] = strings.Join(producers, "+")
	}
	return out
}
