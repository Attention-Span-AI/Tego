// SPDX-License-Identifier: Apache-2.0

// Package mcprelay is Tego's MCP relay (ADR 0126 §4): the launcher-side service that stands between a run's agent
// and each MCP server the contract puts behind it (an mcp[] entry with a tools: key). It decides every tools/call
// (allow, ask a person on the run's broker, or deny with a clean JSON-RPC error), hides denied tools from tools/list,
// records every decision as an mcp line (source proxy), and reads the run's live switches (internal/mcptools) so a
// person can change a tool's rule while the run goes on, both ways.
//
// A stdio server is reached through Tego's own shim (`tego mcp relay`), which the agent's MCP client runs in place
// of the declared command: the shim connects to this service's control listener, is admitted only when its peer is
// the launcher's own tego image inside the run's cgroup with the declared argv, starts the server over sockets only it
// holds, and forwards nothing the service did not say to. What the service says to forward is a client line in one wire
// form (wireLine), never the agent's bytes, so a server that ends lines where the relay does not still reads the
// message that was decided. The supervisor's gate (Relayed) refuses a start of the
// declared server whose parent is not such a shim, still the process admitted and holding no TCP socket but the admitted
// one, so the agent can neither go around the relay nor start the server under a relay of its own. The decisions are made
// here, outside the run, from the contract and an overlay the agent cannot write; the decision itself is
// pkg/policy/mcptool's.
//
// The service is a source.LoopbackSource the run lists in Deps.Extra: neither a capture nor an observe source. Its
// listener's port is admitted to the run through Endpoints, and Vars gives the agent TEGO_MCP_RELAY and
// TEGO_MCP_CONFIG (a Claude Code mcpServers file naming the shim for each relayed server).
//
// Imports: the standard library, internal/platform/proc, internal/runtime/source, internal/runtime/ask, internal/runtime/derive/mcp,
// internal/mcptools, pkg/policy/mcptool, pkg/spec/record, golang.org/x/sys/unix.
// Must not import: internal/check, internal/control, internal/runtime (the run imports this), internal/cli.
package mcprelay
