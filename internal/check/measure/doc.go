// SPDX-License-Identifier: Apache-2.0

// Package measure computes per-run metrics: steps, refused, asked, answered, wait seconds, replanned/retried/aborted, tokens in and out, cache, estimated cost, idle max, repeats.
//
// ComputeAt streams one run's ledger and returns a Report: steps, refused, tokens in and out, cache
// read and write, estimated cost, wall, idle max and repeats (R18-R23), and the resource peaks the
// run's run_end recorded, each unknown where it recorded none (R-res), rendered as an aligned table
// or as one JSON object (R31). The ask columns of P0-DESIGN — asked, answered, wait, replanned — are not in
// this table; the receipt (internal/check/receipt) reports a run's asks.
//
// Everything comes from the ledger: the report is identical for a finished run, a still-growing one
// and one whose writer died mid-line, and it never consults a live limits.Watcher. The token and
// cost formulas are deliberately reimplemented here rather than shared with the engine (C1); only
// the price lookup crosses, through the Prices interface this package defines and internal/cli
// fills with the engine's table.
//
// Imports: internal/check/resources, internal/ledger, pkg/spec
// Must not import: internal/runtime
package measure
