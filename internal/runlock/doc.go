// SPDX-License-Identifier: Apache-2.0

// Package runlock reads a run's lock from outside the run: whether a live launcher holds <ledger_root>/<run>/lock
// (ProbeLock), who the lock line says it is (LockInfo), and a pidfd on that launcher once it is proved to hold the
// lock (OpenStopTargetFor, the R22 lock-holder proofs). It moved out of internal/runtime unchanged
// (ADR 0100 (7)), so that the engine's clients — `tego stop`, `tego ask`, the ask client and
// tego-control — reach a run's lock without linking the engine; it never imports internal/runtime (a go list test
// holds that). The launcher's own side, writing the line through the descriptor it holds the flock on, stays in
// internal/runtime.
//
// Errors keep the "runtime:" prefix they carried before the move, since `tego stop` and `tego ask` print them.
package runlock
