// SPDX-License-Identifier: Apache-2.0

// Package runtime is the engine facade: Run(ctx, rt, cmd, deps) wires launch, enforce, supervisor,
// observe, capture, limits and the ledger writer into one supervised run (docs/p0/runtime-launch.md
// §4, P0-DESIGN.md §4.1).
//
// Run owns one sequence and one shutdown order. It mints the run id, creates the run directory
// under the ledger root (never inside a declared write entry, so the agent cannot rewrite its own
// record), opens the ledger — which takes the run lock — creates the run cgroup and writes its
// limits, has the selected backend prepare the tier's kernel objects, sets PR_SET_CHILD_SUBREAPER,
// starts the child stage with clone3(CLONE_PIDFD|CLONE_INTO_CGROUP), takes the seccomp listener over
// pidfd_getfd, starts the notification loop and every source, writes run_start, and only then
// releases the child with the ack byte. From there events flow through one bounded queue into the
// pipeline of P0-DESIGN §4.1 step 4 — stampRule, attribute, redact, splitBlobs, Append — and the run
// ends when the cgroup empties, a signal arrives, or the kernel reports an OOM or a refused fork.
// Shutdown always runs in full: cancel, join the workers, drain the queue, run_end, detach the
// backend, remove the cgroup, release the lock (R8, R18).
//
// The lifecycle files carry the rest of §5: runlock.go the lock file's advisory content, the stop
// marker and the pid-reuse-safe stop target (R22); sweep.go the orphan pass that run, stop and gc
// share, which needs no coordination beyond the kernel's per-run flock (R12, R20); group.go the
// worker set every goroutine belongs to.
//
// Errors surface exactly once: a failure before run_start returns an error, which is always exit
// 125, and everything after run_start becomes Result.Reason and a run_end line (R2). Tier selection
// and machine-config trust are internal/cli's, decided before Run is called.
//
// Imports: internal/runtime/*, internal/ledger, internal/platform, pkg/spec
// Must not import: internal/check, internal/serve, internal/cli
package runtime
