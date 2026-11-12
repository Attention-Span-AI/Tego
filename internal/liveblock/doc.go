// SPDX-License-Identifier: Apache-2.0

// Package liveblock is a running run's live controls: the overlay a person changes while the agent runs (`tego block`,
// `tego pause`, `tego lift` and their dashboard twins), which the run's launcher reads and its supervisor enforces on
// top of the contract. It holds the overlay file's format and its one writer (Update, under a lock file, by an atomic
// rename in the run directory), the engine's reader (Read, Signature), and the compiled form the supervisor matches
// at decision time (Set).
//
// Live blocks only tighten. An entry refuses what it names; removing it removes only what it added, so nothing a
// contract refuses is ever allowed by this package. At tier landlock a running process's Landlock domain can be made
// stricter only by the process itself, so a live block is enforced where Tego's supervisor already decides: an exec
// (exec), a connect or an addressed send (net), and the file opens and changes the run's seccomp filter hands the
// supervisor: all of them under a path (path), only the reads (read) or only the changes (write), Kind.Access. An
// absolute exec value is matched by the identity of the file it leads to as well as by name, so it refuses that file
// under every name it has (ReachOf and OtherNames say which, for the writers' words); a block the rules editor derives
// from an exec.allow entry removed matches by link instead (Entry.Match, MatchLink): it refuses what the running
// contract grants under that entry, the file and the path the entry resolved to when the run started, by any name
// that reaches it there (Grant), and the whole file only where the contract holds no such entry. SameFileNote says,
// for a reader, when a refusal came through another name of the blocked file. A path, read or write value written
// through a link is resolved once, when it is added (RealPath, AddReal), and refuses where it led too (Entry.Real).
// docs/OPERATIONS.md ("Live blocks") lists what that leaves out.
//
// The overlay also carries the run's pause and resume (OpPause, OpResume, Overlay.Paused), which the launcher applies
// to the run's cgroup. A block or an unblock may carry a time limit (ADR 0125 decision 4, clock.go): it ends by itself
// at that instant, judged on the wall clock and on CLOCK_BOOTTIME, so a clock step never lengthens a loosening or
// shortens a narrowing. An Adjustable run's overlay also carries lift and restore requests for its fence entries
// (lift.go); a lift is MAC'ed under the run's own key, and the launcher alone decides what takes effect. Encode writes
// the lowest version that holds the content, so an overlay with neither is byte for byte the version 1 file. A
// launcher marks in the run directory what it reads beyond version 1 (MarkControl: a pause; MarkReal: a real path;
// MarkLink: a block that matches by link), and a writer asks those only of a run so marked.
//
// Every writer makes the same checks before it writes and says the same words (check.go: Target, CheckBlock,
// CheckFence, CheckLoosening, LiftKey, BlockWord), so `tego block` and the dashboard's Block now never answer one change
// two ways: a run that has ended is refused a block and its removal alike, and its overlay is left as it was. The MCP
// tool switches and the model routes, whose overlays are not this package's, refuse a Locked run's loosening through
// CheckLoosening in the same words.
//
// The overlay lives in the run's directory under the ledger root, which the agent cannot write (the ledger's own
// trust boundary): <ledger_root>/<run>/live-block.json. Both binaries import this package (the engine's launcher
// reads, `tego block` and tego-control write), so it links neither of them: it is a leaf.
//
// Imports: the standard library, golang.org/x/sys/unix, internal/platform/sys and pkg/policy/thishost only.
// Must not import: internal/runtime, internal/control, internal/ledger, internal/policy, pkg/spec.
package liveblock
