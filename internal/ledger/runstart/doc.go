// SPDX-License-Identifier: Apache-2.0

// Package runstart reads the bounded run-start metadata used by contract discovery
// and projects the same fields for the dashboard. It reads only the first record
// of each run, with the ledger repository's guarded readers, and retains no raw
// payload, action history or blobs. It makes no chain-verification claim.
//
// Imports: internal/ledger, pkg/spec/record and the standard library.
// Must not import: internal/control, internal/check, internal/runtime, internal/cli.
package runstart
