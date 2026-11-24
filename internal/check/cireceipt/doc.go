// SPDX-License-Identifier: Apache-2.0

// Package cireceipt checks retained CI evidence against independently supplied
// expectations and release checksums (ADR 0143). It freezes bounded regular files
// before checking them and never executes evidence. Cryptographic bundle checks
// belong to the consumer-supplied BundleVerifier; without one acceptance is blocked.
//
// Imports: standard library, internal/check/receipt, internal/ledger,
// internal/platform/proc, pkg/spec/identity, pkg/spec/record, pkg/spec/runstatus.
// Must not import: internal/runtime, internal/cli, internal/control.
package cireceipt
