// SPDX-License-Identifier: Apache-2.0

// Package mcpact is the dashboard's MCP tools service (ADR 0126 §6): what the MCP tools page shows of a run's MCP
// servers, and the live per-tool switches it changes. State reads the run's contract copy (its mcp[] entries and
// their tools lists), the run's overlay and tools-seen file (internal/mcptools) and its ledger (the relay's mcp lines
// and the broker's mcp_tool asks), and decides each tool through pkg/policy/mcptool, the relay's own core, so the
// page shows the decision the relay makes. Plan previews a switch and, for one that loosens, returns the
// acknowledgement Set needs: an HMAC under this process's random key, domain tego-mcp-ack-v1, over the run, server,
// tool, decision and the sha256 of the overlay file it was shown against, so a stale or forged preview is refused.
// A tightening needs none. A loosening, and a reset that loosens, is refused to a caller inside a run.
//
// The web package parses forms, renders and calls this; it never opens the overlay itself.
//
// Imports: the standard library, gopkg.in/yaml.v3, internal/mcptools, internal/ledger, internal/runlock,
// internal/control/runact (SelfGoverned), pkg/policy/mcptool, pkg/spec/record.
// Must not import: internal/runtime, internal/policy, internal/cli (control-links-no-engine).
package mcpact
