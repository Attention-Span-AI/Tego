// SPDX-License-Identifier: Apache-2.0

// Package contractsrc selects the general contract for read-only inspection.
// It does not compile, launch, edit or write run records (ADR 0153 slice 1).
//
// Imports: internal/profilesrc, pkg/spec and the standard library.
// Must not import: internal/runtime, internal/control, internal/contracts,
// internal/registry, internal/cli, internal/policy or internal/bpf.
package contractsrc
