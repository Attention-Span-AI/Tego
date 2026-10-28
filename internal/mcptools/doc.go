// SPDX-License-Identifier: Apache-2.0

// Package mcptools is the run's live MCP tool overlay and its tools-seen file (ADR 0126 §4): the two files a person
// (through `tego mcp` or the dashboard's MCP tools page) and the run's MCP relay share. The overlay,
// <ledger_root>/<run>/mcp-tools.json, holds per-tool Allow / Ask / Deny switches that win over the contract's
// mcp[].tools for the rest of the run; the relay polls it (Stat) and decides every tools/call with what it read.
// The seen file, <ledger_root>/<run>/mcp-seen.json, is the relay's list of the tools each server offered in a
// tools/list result, so the page can show a switch for a tool nobody has called yet.
//
// Both files live in the run's directory under the ledger root, which the agent cannot write (R6a, R10): a change
// is a person's, never the agent's. Writes are a read-modify-write under a lock file with an atomic rename (the
// internal/liveblock pattern, copied rather than imported, so this leaf links neither binary's other packages).
//
// Imports: the standard library, golang.org/x/sys/unix and internal/platform/sys (descriptor leases, ADR 0023).
// Must not import: internal/runtime, internal/control, internal/liveblock, pkg/spec.
package mcptools
