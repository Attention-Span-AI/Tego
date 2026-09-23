// SPDX-License-Identifier: Apache-2.0

// Package limits enforces per-run budgets from the record: tokens, estimated cost, wall time, stall_after, repeat detection; triggers stop through cgroup.
//
// Watcher is the whole subsystem (docs/p0/limits-check-doctor-cli.md §2, R1-R6). Observe — or the
// equivalent Stage, which the facade's pipeline composes — accumulates tokens and estimated cost
// from every ssl_response and the repeat streak from every tool-calling decision; Run is the one
// goroutine, ticking at 1 Hz over the monotonic clock for the two ceilings no event announces: wall
// time and the stall gap. The first ceiling crossed trips exactly once (I1): one limit event
// through the Sink it was given, the OnBreach callback that tells the facade this run's terminal
// reason is limit, and one cgroup.kill. It never writes run_end and never decides an exit code —
// the facade owns both, and maps reason=limit to exit 124.
//
// PriceTable is spec/config/v0's prices file, loaded here rather than in internal/check/measure
// because a live run needs it and the engine may not import the read side: measure takes a Prices
// interface that *PriceTable satisfies, and internal/cli hands one over. The file is
//
//	version: 1
//	updated: 2026-09-22
//	models:
//	  <exact ssl_response.model>:
//	    input_per_mtok: 3.00
//	    output_per_mtok: 15.00
//	    cache_read_per_mtok: 0.30
//	    cache_write_per_mtok: 3.75
//
// and a missing, unreadable or wrong-version table is a warning and no cost estimate, unless the
// contract declares a cost_usd budget: nothing could count it, so the run is refused before
// run_start, [budget-unmetered] (E15, R32). Every rendered cost carries the literal "est." (GAPS.md C17).
//
// Imports: internal/ledger (Usage, the one token decode measure shares, limits-check-doctor-cli.md
// §4), internal/runtime/cgroup, pkg/spec
// Must not import: cilium/ebpf
package limits
