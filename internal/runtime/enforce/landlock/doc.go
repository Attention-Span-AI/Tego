// SPDX-License-Identifier: Apache-2.0

// Package landlock is the unprivileged enforcement tier (tier 1): it turns a compiled agent.RuleTable
// into a Landlock ruleset built from O_PATH fds the launcher holds for the run, and into the
// classic-BPF seccomp program the child installs with NEW_LISTENER so the supervisor sees write-opens,
// execs, connects, datagram sends, deletes, renames, mkdirs, symlinks and the mount family the domain
// refuses (docs/p0/enforce-landlock.md).
//
// What it builds: the ABI is probed once (R1) and every requested right is masked by the degrade table (R2);
// write entries carry the full read+write+create+remove set; deny_read entries compile as sibling enumeration
// from the target's parent to "/" — ancestors get READ_DIR only, siblings the read set, a target nested inside
// another is dropped, a level inside a target through a bind mount of the whole target is skipped with every
// level beneath it, and a target's rights stay 0 and an ancestor's READ_DIR whatever else names its inode (a
// write entry or a declared grant on that inode fails the build) — and an entry under a writable parent is
// left out and reported through the handle's capability set (R3, R4, E29, E32, I5, I11); exec grants cover
// every resolved binary, its PT_INTERP loader read live and confined to a regular file the contract does not
// govern, every #! interpreter checked fail-closed against the resolved grants (a basename covers only env's
// argument when it has no slash), the agent command and MCP commands (R5, E29); TCP port rules are a per-port
// backstop behind the supervisor's connect-on-duplicate (R6), UDP joins at ABI 10 (R22) and unix: paths at ABI
// 9 (R21), and a contract with no net: section handles no net right at all, RESOLVE_UNIX included; signal and
// abstract-socket scopes are declared at ABI 6 (R7); the run directory, contract file, /sys/fs/cgroup and
// /sys/fs/bpf are held for identity only and denied by omission (R8), which is why the write side is handled
// even with no fs: section (I4).
//
// The filter guards the arch and the x32 bit first (ENOSYS), answers ENOSYS to io_uring_*, openat2, clone3
// and open_by_handle_at (R10), and notifies the syscalls the supervisor records or decides (R9–R16); under a
// net: section socket(2) and socketpair(2) pass an allowlist and every other triple is notified (ADR 0018),
// and every filter notifies the namespace-creating unshare/clone and every setns (E24). The remaining arms
// refuse outright, because each decision is scalar and race-free in the filter, and an errno return holds
// where a notification would not: under an observe run, whose supervisor continues every notification
// (supervisor R30), and with no supervisor left to answer (a notification with no handler is answered
// ENOSYS, ADR 0018 (3)). They are, in every filter, the terminal-injection ioctls (EPERM) and
// socket(_, _, IPPROTO_MPTCP) (EPROTONOSUPPORT) — invisible to Landlock's net hooks, so R6's bind denial would
// not reach it (E30); and, per run, the memfd_create arm (EACCES without MFD_NOEXEC_SEAL, or ENOSYS on a kernel
// without it, SEMANTICS §4), the root-tier arm at tiers 2 and 3 (EPERM on bpf and module or kexec loading, ADR 0033),
// pidfd_send_signal (ENOSYS) in the signal-scope arm installed below ABI 6 beside its notified kill family
// (R7), and, below ABI 3 only, truncate(2) and an O_RDONLY|O_TRUNC open (EPERM), which no Landlock right of
// that era can deny and the supervisor's record-only open handler would continue (R2, E31). The
// process-scope arm only notifies. An observe run's filter (BuildFilter) carries the guards, the R10 ENOSYS
// set, the notified syscalls and the ioctl and MPTCP refusals, and none of the per-run arms.
//
// What it does not do: install anything (the child stage applies the ruleset itself, through
// sys.RestrictSelf on its locked thread; the filter is handed back as []bpf.RawInstruction), run the notify loop, write the ledger or
// decide rule semantics — the table arrives validated from pkg/spec/agent.Compile. The package exposes
// concrete *Backend and *Handle types and its own Run value; internal/runtime/enforce adapts them to
// its Backend/Handle interfaces, so the import direction is always enforce → landlock.
//
// Every Landlock syscall goes through an unexported seam so the rule construction is unit-tested
// against a fake kernel; the integration tests (-tags integration, uid 1000, ABI ≥ 2) apply real
// rulesets and filters in a helper subprocess.
//
// Imports: golang.org/x/sys/unix, golang.org/x/net/bpf, pkg/spec/{agent,backend}; a build with -tags tegotesthooks
// adds pkg/spec/config, for filter_testhook.go's AT_SECURE guard.
// Must not import: internal/runtime/enforce (a cycle), github.com/cilium/ebpf, internal/ledger, internal/check.
package landlock
