// SPDX-License-Identifier: Apache-2.0

// Package cgroup is the cgroup v2 manager of a run (docs/p0/runtime-launch.md §2, §4, §5): it finds
// the subtree this process may write (the systemd user delegation under
// /sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service for an unprivileged launcher, the
// cgroup2 mount root for a privileged one), creates tego.slice/tego-<agent>.slice/run-<id>.scope
// with the cpu, memory and pids controllers enabled on the way down, hands out the O_DIRECTORY fd a
// launcher passes to clone3(CLONE_INTO_CGROUP), writes the resource files (cpu.max, cpu.weight,
// memory.max, memory.high, pids.max), kills the whole subtree through cgroup.kill, waits for
// cgroup.events to report populated 0 (inotify with a polling fallback), reads the oom_kill and
// pids max counters, and removes the scope bottom-up with the EBUSY retry of §6 case 9.
//
// Two things about that root are spec, not accident. A privileged launcher's subtree sits directly
// under the cgroup2 mount point, which systemd's delegation contract forbids on a systemd host; §6
// case 38 records the cost and why P0 pays it, and §11 holds the decision about doing it the
// sanctioned way. An unprivileged launcher's subtree is derived from /proc/self/cgroup, whose path
// is relative to the reading process's cgroup namespace, so Detect only trusts the cgroup2 mount
// once it has shown it holds the cgroup that file names (§6 case 39) rather than splicing a
// namespace-relative name onto a fixed mount. That verdict covers the canonical
// user@<uid>.service and a privileged launcher's mount root too: a mount that is not this process's
// tree is not this process's tree by whichever path it is reached, or by whom, so a mount Detect
// cannot show to be this process's tree — a "../" path and an unreadable /proc/self/cgroup
// included — is refused, not tried. Every refusal is a *DetectError carrying the one fix for its
// cause as a field.
//
// FS is the one implementation of Manager; Detect picks the root for the invoking uid and NewAt
// takes an explicit root (tests use a temporary directory, which also exercises the missing-
// controller path because a plain mkdir creates no control files). The package never decides a
// limit: it writes what it is given (§2 "Validation") and reports a missing controller as a
// *MissingControllerError naming the delegation fix (case 31) instead of silently dropping it.
//
// Every blocking method takes a context; every fd the package opens is owned by exactly one Cgroup
// value and closed by Remove (or by the caller via Cgroup.Close when Remove is deferred to a sweep).
// A Cgroup is passed and stored by value, so that ownership is shared by every copy rather than held
// by one of them: the first Close through any copy closes the fd, later ones are no-ops, and a copy
// whose fd is gone resolves control files through Path instead of a descriptor number the process may
// have reused.
//
// The package also starts processes, and only one kind: tego's detached helpers (the build's linger
// timer, its ring trimmer, a library's probe removal, a run's reaper). StartHelper and StartHelperExec
// start one without waiting for it, in HelperScope (helpers.scope under tego.slice at the cgroup2 mount
// root, which no unit owns, so the helper outlives the launcher's cgroup) when this process is root and
// can make and enter it, and in this process's own cgroup otherwise, with HelperEnvUnplaced in the
// helper's environment naming why. Every start goes through proc.Start, the one process start of
// ADR 0021 (3), so it is refused (proc.ErrArmed) while this process is armed.
//
// Imports: standard library, golang.org/x/sys/unix, internal/platform/proc, pkg/spec/agent,
// pkg/spec/identity.
// Must not import: anything above internal/runtime.
package cgroup
