// SPDX-License-Identifier: Apache-2.0

// Package mcptool is the pure decision core of per-tool MCP rules (ADR 0126 §4): given a server's contract lists
// (mcp[].tools allow / deny / ask) and the live switch a person put in force, it says whether one tools/call is
// allowed, held for a person, or denied, and names the rule that decided. It also filters a tools/list result
// (denied tools hidden, asked ones kept) and builds the JSON-RPC error a refused call is answered with.
//
// Exact tool names only: no globs, no patterns, no model. The relay (internal/runtime/mcprelay), the CLI and the
// dashboard's service decide through this one package, so the page shows the decision the relay makes.
//
// It lives in pkg/policy rather than internal/check because the engine (internal/runtime) may not import the read
// side, and both sides need it (ADR 0126 §6's fallback, recorded in its implementation note).
//
// Imports: the standard library only (encoding/json, strconv).
// Must not import: os, time, sync, internal/*, pkg/spec (it takes plain string lists).
package mcptool
