// SPDX-License-Identifier: Apache-2.0

// Package admission owns the named checks shared by adoption preparation and final
// migration admission (ADR 0144). Callers assemble one table in preparation stages;
// final admission repeats every entry classified as rechecked.
//
// Imports: standard library only.
// Must not import: internal/cli, internal/runtime, pkg/spec, or enforcement backends.
package admission
