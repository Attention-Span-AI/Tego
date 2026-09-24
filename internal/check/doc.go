// SPDX-License-Identifier: Apache-2.0

// Package check is the read-side facade over one or more ledgers: opens runs, indexes events, and exposes the views used by the CLI and serve.
//
// Imports: internal/check/*, internal/ledger, pkg/spec
// Must not import: internal/runtime
package check
