// SPDX-License-Identifier: Apache-2.0

// Package status derives the run state machine from a ledger and its lock: running, waiting on
// model, waiting on tool, stalled, done, lost, plus the current step and last decision
// (docs/p0/limits-check-doctor-cli.md §5 R7-R12, P0-DESIGN.md §5).
//
// Derive answers for one run the caller has already probed, DeriveAll for every run under a ledger
// root. The checks run in one fixed order and the first match wins: an unheld lock decides between
// done and lost before anything else is read, so a run whose teardown is slow never reads as done
// too early and a crashed launcher's run never reads as done at all. "Live" is the lock and nothing
// else — never a pid, never a state file — and LockHeld is this package's own non-blocking probe of
// it, because the read side never imports internal/runtime.
//
// The snapshot also carries the run's gap events, grouped (the gap line, R34): what the record could not
// see qualifies the state and never decides it. It carries the resource peaks run_end recorded too (R-res),
// read and never measured, since the run's cgroup is gone by the time anyone asks.
//
// Nothing here writes: a lost run stays lost until the runtime's own sweep ends it.
//
// Imports: internal/check/gaps, internal/check/resources, internal/ledger, pkg/spec
// Must not import: internal/runtime
package status
