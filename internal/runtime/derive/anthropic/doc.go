// SPDX-License-Identifier: Apache-2.0

// Package anthropic parses Anthropic Messages API requests and responses, streaming and not: tool_use
// blocks, usage, model, stop_reason, message id, and the parser_version every ssl_response carries.
//
// Imports: standard library, internal/runtime/derive (the Message, Facts and Parser contract)
// Must not import: other providers
//
// The docs/p0/capture-derive.md §1 import line for this package reads "standard library", written when
// the Message type was expected to live in capture/httpstream; the same §1 forbids derive from importing
// capture at all, so the contract the parsers implement lives in the parent derive package and this
// package depends on it alone.
package anthropic
