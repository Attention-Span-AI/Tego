// SPDX-License-Identifier: Apache-2.0

// Package mcp reads the Model Context Protocol's JSON-RPC 2.0 messages a client sends its server — E31, MCP
// derivation (docs/FEATURES.md; docs/p0/capture-derive.md R41) — and says which of them are a session's start
// (initialize) and which a tool call (tools/call, with the tool's name). It reads both transports the protocol
// defines: stdio, newline-delimited messages on the server's standard input (Stdio), and HTTP, one message or a
// batch in a POST body (ReadHTTPRequest), which serves the streamable transport and the older HTTP+SSE one alike,
// since both carry the client's messages in POST bodies.
//
// Only the client's direction is read: a tool call is a client request, and what the server answered says nothing
// about whether the call was made. The reading is the one every server's JSON parser agrees on (JavaScript's
// JSON.parse, Python's json.loads, Go's encoding/json, serde): where they could differ — a key the reader uses
// spelled in another case or twice, a request with no id, a tool name that is not a non-empty string — the message
// is unreadable, so a call named here is the call any server reads, and one it cannot name is counted.
//
// Every input is untrusted bytes from the governed run: nothing here panics, every buffer is bounded, and a message
// that cannot be read is counted, never guessed at.
//
// Imports: standard library
// Must not import: other providers
package mcp
