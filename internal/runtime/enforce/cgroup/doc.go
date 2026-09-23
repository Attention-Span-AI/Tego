// SPDX-License-Identifier: Apache-2.0

// Package cgroup is the tier-2 enforcement backend: the eight CGROUP_SOCK_ADDR programs that decide a run's
// network destinations and unix socket names in-kernel per cgroup (the two unix ones on 6.7+), the two
// cgroup-lifecycle programs that materialize the run's own descendant cgroups, and the fanotify listener that
// refuses reads of denied paths and execs of unlisted binaries with a reason (docs/p0/enforce-cgroup-observe.md).
//
// What it builds. Prepare validates the ring-buffer size the machine config asks for (R16), takes a shared
// build lock, allocates the run's dense host-wide run_idx slot (R12), loads and pins the objects under
// /sys/fs/bpf/tego/<bpf_hash>/ (or opens them from there when another launcher of the build left them whole), compiles the RuleTable's net entries into the exact and CIDR verdict maps
// (R3) and its unix: and fs entries into the unix name trie (R7), together with port-53 rows for the run's
// resolver endpoints, which the supervisor admits whatever the contract says (R5), creates the fanotify group,
// and hands back a Handle. Arm, the one arming point after the child stage's execve (ADR 0021 (2)), inserts the
// run's cgroup into the run set with descendants=1, scans cgroupfs for children that already exist, and marks
// for fanotify each distinct mount a deny_read or exec entry is on (one mark per mount statx names, so a bind
// mount gets its own, asking only for the permission events a rule there can refuse); its first mark arms the
// process, which then starts no process until the marks are gone (internal/platform/proc.Start, ADR 0021 (3)). Attach adds
// one bpf_link per program to the run's cgroup and writes the run into that cgroup's tego_net_owners
// storage, which is where the deciding programs read which run they enforce — never from the cgroup of
// whoever calls connect(2), which for a connect the seccomp supervisor relays is the supervisor's (R1). A
// link-based cgroup attachment is inherently multi, and the kernel ANDs the programs' return codes, so two
// coexisting builds never block each other. A contract with no net: section gets no rows and no network
// program, because it denies nothing (R1). RefreshNet moves a host entry's rows to the addresses a TTL
// refresh resolved (E7). Detach removes this run's links, then its rows, then its slot,
// and unpins only when it is the last launcher out, leaving the kernel to finish detaching the host-wide links.
//
// What it does not do. It does not own the approval broker or decide approval policy; scoped one-shot network
// grants support the supervisor's approved TCP completion. It does not reimplement tier 1 or tier 3, import another
// backend, read or write the ledger, or run the eBPF recorder — the ring buffer and the lost counter are
// created and pinned here, and internal/runtime/observe drains them. Tier 1's Landlock ruleset and
// seccomp filter are still installed for a tier-2 run; this package composes them through the Inherit seam of
// Options rather than importing enforce/landlock, which backends never do.
//
// What is enforced where. fanotify's FAN_OPEN_PERM carries no access mode, so it cannot tell a read open from
// a write open, and this package's listener decides no write: the inherited Landlock ruleset refuses one outside
// every write entry, by inode. Beneath a deny_read nested in a write entry, which Landlock's union grants, the
// seccomp supervisor refuses a write-open, a create and every other mutation by the root walk with EACCES before
// the kernel acts, at tier cgroup with no plane mode (supervisor fallbackMutation, supervisor R15's 2026-10-17
// amendment, ADR 0021 (5)); where a decision plane mode runs, the plane decides them. fanotify adds what
// Landlock cannot express precisely: deny_read paths under a writable parent, and exec of a binary outside the allow-list,
// each refused with the reason the ledger records. The kernel names the opened file by its canonical path, so
// every entry is matched as compiled and with its symlinks followed; a contract with no exec: section refuses
// no exec, as Landlock and the supervisor do not; and the launcher binary, which the child stage execs as the
// run's first exec, is never asked about, because that exec comes before Arm places any mark (R8); every exec
// the group sees in the run is the agent's, tego's binary included. Delete, rename and mkdir are decided as
// writes are, by Landlock, the supervisor's fallback refusal or the plane; this package's trace_proc only
// records them (R9).
//
// Testability. Everything that needs no kernel is separable and unit-tested: the RuleTable to map-row
// compilation, the reason-code table, the cross-process slot allocator, the build-lock protocol, the pin
// layout, /proc parsing, and the fanotify decision itself. The kernel-touching halves are behind
// //go:build integration and skip with a reason when the process may not load BPF or open a fanotify group;
// bpf/README.md carries the manual procedure for a machine where you do have root.
//
// Wiring. internal/runtime/enforce holds the cgroupBackend adapter (adapters.go, select.go), because the import
// direction is enforce → backend: it fills Options.Inherit with the tier-1 handle, which keeps a tier-2 run
// installing tier 1's ruleset and filter without either backend importing the other, and it completes
// Options.Events from the run's RunRef so this package's refusals and gaps reach the run's ledger. It also
// copies RunRef's Resolvers, the list the runtime hands the supervisor's resolver set, and StageExe; and the
// runtime's DNS worker calls RefreshNet after a TTL refresh that moved a host's addresses (R5, E7).
//
// Imports: github.com/cilium/ebpf (+link), golang.org/x/sys/unix, golang.org/x/net/bpf (the seccomp program
// type only), internal/bpf, internal/platform/proc (the stat parser), pkg/spec/{agent,backend,config,identity,
// record}. Must not import:
// internal/runtime/enforce (a cycle), enforce/landlock, enforce/bpflsm, internal/check, internal/serve,
// internal/ledger.
package cgroup
