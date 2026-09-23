// SPDX-License-Identifier: Apache-2.0

// Package openaicodex is a placeholder with no code in this build: it is where I4, the Codex CLI adapter (P2, docs/FEATURES.md) will
// live, kept so the place docs/REPO-LAYOUT.md gives it and the import rules below are fixed before the code
// arrives. When built, it adapts the OpenAI Codex CLI: forwarder routing for its rustls client, enforce-only fallback.
//
// Imports: pkg/spec/**, golang.org/x/sys/unix and the standard library only
// Must not import: internal/runtime, internal/ledger, internal/check, internal/serve, internal/cli,
// internal/bpf, internal/policy/decide, github.com/cilium/ebpf (depguard adapters-never-import-engine)
package openaicodex
