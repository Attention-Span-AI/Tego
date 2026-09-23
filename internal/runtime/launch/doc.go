// SPDX-License-Identifier: Apache-2.0

// Package launch starts the agent's main process under enforcement and drives its lifetime
// (docs/p0/runtime-launch.md §4–§6, ARCHITECTURE.md §5–§6, ADR 0006 as amended).
//
// The child stage, ChildMain, is what `tego __child` runs: on one locked OS thread it reads a framed
// ChildSpec from fd 3, applies the working directory, drops capabilities and restores
// PR_SET_DUMPABLE=1, arms PR_SET_PDEATHSIG after the last credential change and re-checks getppid, sets
// no_new_privs, calls landlock_restrict_self on the inherited ruleset fd, installs the seccomp filter with
// NEW_LISTENER, writes the listener's fd number to fd 4 as one int32, blocks for the ack byte on fd 3 and
// execve's the command with the spec's environment. A privileged run swaps the order (R4). Setup failures
// go back over the same pipe as a negative code naming the step and errno; an execve failure is reported the
// same way right before the stage exits 126 or 127.
//
// Launcher.Start creates that child through os/exec with SysProcAttr{UseCgroupFD, CgroupFD, PidFD} — one
// clone3(CLONE_PIDFD|CLONE_INTO_CGROUP), so the child is inside the run cgroup from its first instruction —
// on a goroutine kept locked to its OS thread for the child's lifetime, because PR_SET_PDEATHSIG watches the
// forking thread. Two anonymous pipes carry the protocol (R6); the ruleset fd travels as an inherited fd.
// Child.WaitNotifyFD reads the fd number and pidfd_getfd's the listener into a fresh descriptor the agent
// never holds (invariant 4); Child.Ack releases the child once the supervisor's NOTIF_RECV is in flight
// (R5, R7); Child.Wait reaps through waitid(P_PIDFD) and learns whether the execve happened; Child.Kill is
// the R13 abort. Nothing here decides verdicts, writes the ledger or touches the cgroup filesystem.
//
// SignalHandler applies the §6 rules: SIGTERM/SIGHUP/SIGUSR1/SIGUSR2 are forwarded always, SIGINT/SIGQUIT
// only when stdin is not a terminal; SIGINT/SIGTERM/SIGHUP start stop_grace; a second SIGINT within two
// seconds or the timer's expiry writes cgroup.kill through a Killer. Ended maps the wait status and the
// handler's Outcome to the run_end reason and the exit code of tego run per RUN-IDENTITY.md. A launcher
// whose handle owns a listener the host waits on (tier 2's fanotify group) ignores the job-control stops
// SIGTSTP, SIGTTIN and SIGTTOU (HoldJobControl), and its child stage resets them to the default before it
// execs the agent, so Ctrl-Z stops the agent and never the launcher (enforce-cgroup-observe.md E40).
//
// Imports: internal/runtime/enforce/api, internal/runtime/deputy, internal/platform/{proc,sys}, pkg/spec/identity
// Must not import: internal/check, internal/serve, internal/cli, internal/runtime/enforce or any backend under it,
// internal/runtime/cgroup, internal/bpf, cilium/ebpf, pkg/spec/{agent,config} (ADR 0031 (a); TestLaunchLinksNoBackend)
package launch
