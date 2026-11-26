// SPDX-License-Identifier: Apache-2.0

// Package openai reads the token usage of OpenAI-style model answers, so a limits.tokens or limits.cost_usd budget
// can count them (ADR 0037, amended 2026-11-26): the Chat Completions API (POST /v1/chat/completions, whole or streamed) and the
// Responses API (POST /v1/responses, whole or streamed). It reads usage, the model and the response id, and nothing
// else: the tool calls of an answer are not decisions this parser derives, so a limits.repeats budget does not count
// them.
//
// It is dispatched to by the declared provider, models[] provider "openai" (or the declared host of such an entry),
// never by sniffing a body (R25): Tego counts what a contract says is an OpenAI-style endpoint. It never changes a
// request: a streamed chat completion carries usage only when the client asked the API for it, and one that ends
// without it is an answer whose spend cannot be read, which ends a run with a token or cost budget exactly as an
// unreadable answer of any provider does (ADR 0037).
//
// Imports: standard library, internal/runtime/derive (the Message, Facts and Parser contract), pkg/spec/record
// Must not import: other providers
package openai
