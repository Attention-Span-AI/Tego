// SPDX-License-Identifier: Apache-2.0

// Package chaincheck is the chain check of one run's record as a pure function of bytes: spec/record/v1/CHAIN.md.
// It reads a run's events.jsonl, framed into lines (ScanLines), and the run's line in chain.log (AnchorHeads),
// and says whether the chain of those record bytes matches, does not match (an error wrapping ErrUnverified, with
// its reason code from Reason), or cannot be checked. It checks integrity: each line's digest (R2), the seq and
// prev links (I3, I4), the run each line names, run_start first and only first, nothing after run_end, the torn
// tail rule (E6, E8), and the anchored head (record-ledger.md §4). With validation on it also holds each line of
// this version to its schema at the run's revision (record.Event.ValidateAt), as `tego events --verify` does.
//
// Walk is the check one line at a time, for a caller that streams a file (internal/ledger's Reader.Verify, the
// Binder and the Follower share its LineCheck); Check is the whole check over bytes held in memory, the function
// the Rust twin (rust/tego-record) is held equal to by the shared vectors and test/rustdiff. Neither opens a file,
// reads a clock, takes a lock or waits: what needs the host (opening the ledger without following a link, probing
// the run lock, waiting for a launcher inside Close) stays in internal/ledger, which hands this package the facts.
//
// Imports: the standard library's pure packages, pkg/spec/record, pkg/spec/identity.
// Must not import: os, syscall, golang.org/x/sys, time, sync, anything under internal/ (depguard
// chaincheck-is-pure).
package chaincheck
