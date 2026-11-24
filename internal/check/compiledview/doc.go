// SPDX-License-Identifier: Apache-2.0

// Package compiledview projects a compiled contract into grouped plain sentences
// and source positions. Its declaration data also lets the dashboard reuse the
// renderer for a source that no longer compiles. It does no I/O and makes no
// changes to the contract, compiled table or enforcement.
//
// Imports: internal/check/livestatus (state type only), pkg/spec, pkg/policy/gate,
// pkg/policy/execmatch and its rows, yaml.v3 and the standard library.
// Must not import: internal/control, internal/runtime, internal/policy, internal/cli,
// os, syscall.
package compiledview
