// SPDX-License-Identifier: Apache-2.0

// Package livestatus says, in one word and one sentence, what a live block (internal/liveblock) does to a run right
// now: in force, waiting for the run to read it, recorded only, partly in force, or ended. Every view that shows a
// live block (the run page's Block now panel, the Rules page's live group, `tego block`) takes its
// claim from Status (StatusAt for a block with a time limit), so no surface says "blocked" while the agent goes on doing what the block names.
//
// The facts come from the run's own record: run_start's tier (observe: a tego watch run, whose supervisor turns
// every refusal into a recorded line and lets the action go on), run_start's fs_reads and reads_notified (whether
// the supervisor sees each read open, so a path block can refuse a read), run_start's record_minor (whether its
// launcher knows read and write blocks) and decision_plane (whether the kernel decides file changes without asking the
// supervisor), run_end, and the launcher's confirming gap
// lines (what=enforce, why live-block-added or live-block-removed, carrying the overlay serial it put in force).
// FromStart and FromStartJSON read run_start; the caller finds the confirmed serial in the gap lines.
//
// A block with a time limit (ADR 0125) is judged by StatusAt at an instant the caller passes: dormant while it is
// unblocked for a while, expired once its limit passed.
//
// Nothing here does I/O, reads a clock or starts a goroutine.
//
// Imports: pkg/spec/record, pkg/spec/backend, the standard library.
// Must not import: internal/runtime, internal/control, internal/liveblock, os, syscall.
package livestatus
