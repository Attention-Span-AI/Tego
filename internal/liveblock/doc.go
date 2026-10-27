// SPDX-License-Identifier: Apache-2.0

// Package liveblock is a running run's live blocks: the overlay a person adds to while the agent runs (`tego block`,
// the dashboard's Block now), which the run's supervisor refuses on top of the contract. It holds the overlay file's
// format and its one writer (Update, under a lock file, by an atomic rename in the run directory), the engine's
// reader (Read, Signature), and the compiled form the supervisor matches at decision time (Set).
//
// Live blocks only tighten. An entry refuses what it names; removing it removes only what it added, so nothing a
// contract refuses is ever allowed by this package. At tier landlock a running process's Landlock domain can be made
// stricter only by the process itself, so a live block is enforced where Tego's supervisor already decides: an exec
// (exec), a connect or an addressed send (net), and the file opens and changes the run's seccomp filter hands the
// supervisor: all of them under a path (path), only the reads (read) or only the changes (write), Kind.Access.
// docs/OPERATIONS.md ("Live blocks") lists what that leaves out.
//
// The overlay lives in the run's directory under the ledger root, which the agent cannot write (the ledger's own
// trust boundary): <ledger_root>/<run>/live-block.json. Both binaries import this package (the engine's launcher
// reads, `tego block` and tego-control write), so it links neither of them: it is a leaf.
//
// A block or an unblock may carry a time limit (ADR 0125 decision 4, clock.go): it ends by itself at that instant,
// judged on the wall clock and on CLOCK_BOOTTIME, so a clock step never lengthens a loosening or shortens a
// narrowing. An Adjustable run's overlay also carries lift and restore requests for its fence entries (lift.go); a
// lift is MAC'ed under the run's own key, and the launcher alone decides what takes effect. Encode writes the lowest
// version that holds the content, so an overlay with neither is byte for byte the version 1 file.
//
// Imports: the standard library, golang.org/x/sys/unix, internal/platform/sys and pkg/policy/thishost only.
// Must not import: internal/runtime, internal/control, internal/ledger, internal/policy, pkg/spec.
package liveblock
