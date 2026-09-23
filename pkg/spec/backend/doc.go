// SPDX-License-Identifier: Apache-2.0

// Package backend holds the enforcement-backend vocabulary of Tego (spec/backend/CAPABILITIES.md,
// docs/p0/identity-config.md §2.3, §5): the closed Tier enum with its rank comparisons and parser, capture names,
// the Capability rows of the capability matrix, Set (the
// capabilities one run had) with its deterministic Report, the static matrix mirrored
// cell-for-cell from CAPABILITIES.md, and Select — the pure ceiling/pin/probe algorithm that
// picks the tier a run uses.
//
// The package holds no live state and never probes the kernel: internal/doctor supplies the probe
// as a value, internal/runtime/enforce turns the selected Tier into a Backend. Matrix and
// MatrixDetail return fresh values, so a caller can never mutate the shared table.
//
// Imports: standard library only.
// Must not import: any other pkg/spec/* package, anything under internal/.
package backend
