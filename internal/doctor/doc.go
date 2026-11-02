// SPDX-License-Identifier: Apache-2.0

// Package doctor checks the machine and reports in plain sentences
// (docs/p0/limits-check-doctor-cli.md §5 R27). It runs the nine probes in their fixed order —
// D1 kernel version by uname(2) against the per-mechanism minimums of docs/ARCHITECTURE.md §14,
// D2 BTF by opening and parsing /sys/kernel/btf/vmlinux and finding in it, by name, every kernel type and
// member the embedded objects read through CO-RE, D3 cgroup v2 delegation by statfs magic plus a
// writable delegated subtree, a scratch mkdir+rmdir, an access(W_OK) on that scratch cgroup's
// cgroup.kill, and cpu, memory and pids enabled in the subtree's cgroup.subtree_control,
// D4 the Landlock ABI from the raw landlock_create_ruleset(NULL, 0, VERSION) syscall,
// D5 a real seccomp NEW_LISTENER filter on a throwaway locked thread, never the main thread, answered with
// SECCOMP_IOCTL_NOTIF_ADDFD and SECCOMP_ADDFD_FLAG_SEND (made again on a new thread, up to five times, when a
// signal made the kernel take the notification back), plus Yama's ptrace_scope, which decides
// whether the supervisor that filter feeds may read the agent at all,
// D6 the active LSM list through lsm_list_modules(2) then securityfs then the kernel log, with a
// counting BPF LSM program behind it when root because activation is silent (§10), D7 a fresh load
// and link into doctor's own fds, at every tier-2 hook, of the embedded program that runs
// there (a minimal stand-in, said so, where this binary has none), then the decision plane's mode probe,
// one row per decide.bpf.c hook per mode, exercised in a scratch cgroup (plane.go, planeprobe.go;
// docs/p0/enforce-plane.md R21), then capture's uprobe_ssl programs
// at the system libssl, which gate no tier, and D8 fanotify's permission marks
// and a FAN_DENY that must refuse the probe's own open — then derives the highest reachable tier, what each tier above it is
// missing, and the one line that would fix it, built from the machine's own values.
//
// Every probe answers with a Result (OK false plus a one-line fix), never a Go error: a missing
// capability is an answer, not a failure (§4 doctor.Run). A probe that needs privilege it lacks says
// "requires root to test", never "unsupported" (§6 E18), and mark themselves Skipped so a reader can tell
// a machine that cannot do something from a probe that was not allowed to find out; OK stays false either
// way, because neither has established the capability a tier needs. Nothing survives a call: no pin (I7), no
// cgroup, no fanotify mark, no plane probe child, and no thread still carrying D5's filter or the no_new_privs set for it. D5's
// thread is never the main thread, which Go parks for good rather than end, and D5 returns only once that
// thread has ended, or fails when it has not ended within its timeout (seccomp.go).
//
// Report.Probe is the backend.Probe that internal/runtime/enforce turns into a run's backend; this
// package never constructs one itself. `tego doctor` gets its report from Run, which runs every check
// afresh. `tego run` gets its report from ForRun, which runs only the checks of the tiers its selection can
// reach (Reach), and which at reach cgroup, as root, reads D7's tier-2 rows and D8's answer from, and keeps
// them in, one root-owned file per build and per set of process privileges under /run/tego (runcache.go),
// coordinating a concurrent miss through an empty lock file per key under /run/tego/doctor-probe-flights
// (runcache_flight.go) — the only things a call can leave behind, and never a kernel object. The plane's known answers are kept in the
// same directory by a run's plane probe alone; Run never reads or writes them.
//
// What the probes establish is capability, never soundness. A kernel with a fixed hole in a
// mechanism Tego enforces with — CVE-2026-46150 in fanotify's permission path is the worked
// example — passes every probe here and still lets an open through, and no userspace code can
// close that; the limitation is recorded in docs/p0/limits-check-doctor-cli.md R27 D8 rather than
// turned into a kernel-version check, which would fail every distribution that backports.
//
// Imports: standard library, golang.org/x/{sys/unix,net/bpf}, github.com/cilium/ebpf (D7's own
// program loads), internal/bpf (the embedded objects D7 loads, and bpf_hash for the run-probe cache's key),
// internal/platform/proc (every plane-probe process start), internal/platform/startphase (the run-probe phase
// timings), internal/platform/sys, internal/policy/decide (the known answers' plane rows),
// internal/runtime/cgroup, internal/runtime/enforce (Buildable and Select), internal/runtime/enforce/cgroup
// (UnixConnectSupported, and the known answers' ProbeRows), internal/shellword (the binary's path in the
// `sudo <path> doctor` fix line), pkg/spec/{agent,backend,config,identity}.
// Must not import: internal/check.
package doctor
