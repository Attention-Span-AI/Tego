// SPDX-License-Identifier: Apache-2.0

// Package result reads and renders untrusted, bounded scan snapshots. Saved
// observations never establish enforcement or supply executable command text.
// Imports: standard library, x/sys/unix, platform/sys, shellword, spec/identity.
// Must not import: collection, catalog, watcher, sig, runtime, ledger, guide or CLI.
package result
