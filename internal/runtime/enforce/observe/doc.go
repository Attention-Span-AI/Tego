// SPDX-License-Identifier: Apache-2.0

// Package observe is the record-only backend used by learn mode and CI (P0-DESIGN §2.6): Prepare returns a
// handle with no Landlock ruleset and tier 1's seccomp filter, Capabilities is the empty observe column of
// the matrix, and Verdict is observed. The filter is what makes the run recordable: it notifies execve and
// execveat; every open, openat and creat with a write flag (every one under record: full); unlink, unlinkat
// and, on x86-64, rmdir; the rename, mkdir, symlink, link and mknod families; connect; sendto with an address;
// every sendmsg and sendmmsg; and the kernel keyring's add_key, request_key and keyctl. The runtime reads
// Verdict to run the supervisor record-only, so each of those is continued and recorded with verdict
// observed instead of being decided (docs/p0/supervisor.md R30) — a keyring syscall, which record v1 has no
// action kind for, as gap what=record why=keyring-<syscall> once per binary (or process, R31) and syscall (R32). What
// the filter does not notify is not recorded: truncate, chmod, chown, setxattr, a unix socket bound to
// a path, and a read-open outside record: full, among others. Without a filter nothing notifies and nothing
// is recorded, so Prepare refuses to build a handle without one (ErrNoFilter).
//
// The filter is tier 1's own, errno arms included, so R30's "nothing is refused" covers the answers the
// supervisor chooses, not the ones the kernel returns from the filter before any notification. The arch and
// x32 guards answer ENOSYS to every syscall of a non-native or x32 process, so a 32-bit or x32 binary cannot
// run under --observe. io_uring_*, openat2 and open_by_handle_at get ENOSYS (enforce-landlock R10), so no
// open or connect reaches the kernel through a syscall number the supervisor has no entry for. The
// terminal-injection ioctls get EPERM and socket(IPPROTO_MPTCP) gets EPROTONOSUPPORT. Keeping these arms is
// parity as well as completeness: tiers 1 and 2 install this same filter, and an observe run's record is what
// drift compares with a contract and what learn mode (P1) will draft one from, so the agent must meet the
// same syscall surface here that it will meet when that contract is enforced. The truncation arms of
// enforce-landlock R2, which stand in for Landlock below ABI 3, are left out: they refuse an fs action
// outright, and this run enforces nothing.
//
// The filter is installed with NEW_LISTENER, and the kernel allows one listener per filter chain
// (docs/p0/supervisor.md R20), so an --observe run nested inside a run that already has one (tier 1, tier 2
// or another --observe run) fails at startup with EBUSY (launch.ErrChildSeccomp).
//
// It is never chosen by enforce.Select; enforce.Observe hands it out for an explicit --observe, with the
// filter builder injected, because backends never import each other.
//
// Imports: pkg/spec/{agent,backend,record}, golang.org/x/net/bpf (the filter's instruction type).
// Must not import: github.com/cilium/ebpf, internal/runtime/enforce/landlock.
package observe
