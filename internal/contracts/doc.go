// SPDX-License-Identifier: Apache-2.0

// Package contracts builds a read-only catalog above the registry and ledger
// view. It compiles today's sources offline, without selecting or preparing a
// backend, changing a contract, or adding a rule.
//
// Its bounded helper transport also serves private operations registered by the
// linked control binary, including its existing guarded changes. Operation names
// select only linked handlers; they never select an executable or grant authority.
//
// Imports: internal/registry, internal/ledger/runstart, internal/check/compiledview,
// internal/platform/sys, internal/platform/proc, internal/runscope (a helper request with no caller marker is
// classified by this process's own run membership), internal/rulefile, internal/profilesrc, internal/contractsrc,
// pkg/spec, golang.org/x/sys/unix and the standard library.
// Must not import: internal/runtime, internal/policy, internal/bpf, internal/cli.
// The engine must never import this package.
package contracts
