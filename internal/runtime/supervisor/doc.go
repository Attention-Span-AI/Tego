// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

// Package supervisor runs the seccomp user-notification loop for a run: it drains the notify fd taken from
// the child stage, dispatches each notification by (arch, nr), reads the target's arguments under
// SECCOMP_IOCTL_NOTIF_ID_VALID, decides connects (host:port and unix matching, then the real connect(2) on a
// pidfd_getfd duplicate of the target's socket — a unix one made as the task, on the socket its path
// resolves to), checks datagram destinations, records write-opens, execs
// (and the start of a declared MCP server an exec is), deletes, renames, mkdirs and symlinks, refuses the
// mount family a Landlock domain refuses (recorded as landlock-topology) and a watch (inotify_add_watch,
// fanotify_mark, dnotify's fcntl F_NOTIFY) of a deny_read target, which no Landlock or decision-plane hook sees
// (R36), and answers every
// notification exactly once with CONTINUE, an errno or a relayed result (docs/p0/supervisor.md §4, §5 R1-R36).
//
// It is authoritative for connects, and for the mount family, whose answer is the domain's own EPERM.
// Write-opens, execs and the other mutating operations are enforced by Landlock on the continued syscall;
// the events this package emits for them carry source: seccomp and an advisory verdict. A contract with no
// net: or no exec: section restricts nothing through those rules (SEMANTICS §1), and the verdicts here say
// so, exactly as decide.Evaluate and the Landlock builder read the same sections — with the one exception
// SEMANTICS §1 makes: under capture: forwarder a models[] endpoint stays refused (modelGuard, R7), the one
// lookup this package makes being its host name's. Human approval
// (SECCOMP_IOCTL_NOTIF_ADDFD, hold modes) is the ask package, P1.
//
// A run's live blocks (Options.LiveBlocks, internal/liveblock) are refused here on top of the contract, since this
// loop is where tier landlock decides at run time: an exec, a connect or send, and a notified fs action that a block
// names is refused by this loop itself, never continued (liveblock.go).
// A relay's private stage may receive a process-bound runtime grant for an otherwise unlisted command vector:
// Options.MCPStage authenticates the exact fresh-socket child and pins its pidfd. Explicit refusals still hold;
// this adds no general exec pattern (ADR 0126).
//
// An --observe run (Policy.Observe, R30) makes it authoritative for nothing: every refusal it would have
// answered is answered CONTINUE, and every action event is recorded verdict observed against the entry it
// matched, with no reason.
//
// The package builds on amd64 and arm64 only: its dispatch table is a compile-time per-architecture syscall
// table, so an architecture it has no table for fails the build instead of running an inert loop (R26).
//
// Imports: golang.org/x/sys/unix, internal/platform/{sys,dns,proc}, internal/liveblock, pkg/spec/{agent,identity,record},
// standard library
// Must not import: internal/ledger, internal/check, internal/serve, internal/runtime/observe,
// internal/runtime/capture/*, internal/runtime/derive/*, internal/runtime/enforce/*, cilium/ebpf
package supervisor
