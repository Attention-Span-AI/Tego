// SPDX-License-Identifier: Apache-2.0

// Package enforce declares the enforcement Backend and Handle interfaces where they are consumed
// (P0-DESIGN §2.6, docs/p0/enforce-landlock.md §2/§4) and selects the backend a run uses.
//
// A Backend turns a compiled agent.RuleTable into kernel objects for one run (Prepare, before
// clone3) and reports its Tier and static Capabilities; a Handle carries what the child stage and
// the supervisor consume — the Landlock ruleset fd, the classic-BPF seccomp program, Attach/Detach for
// the cgroup-keyed tiers — and releases it with Close. A handle that can narrow the run's matrix (a
// deny_read left unenforced) also implements Reporter.
//
// The RunRef a Prepare is given also carries the run's event sink, because a tier whose own producers
// raise events — tier 2's fanotify listener, which refuses opens and execs and reports the gaps of
// docs/p0/enforce-cgroup-observe.md §7 — reaches the ledger through nothing else. Tier 1 needs none:
// its seccomp supervisor is its own producer and writes to the run's queue directly. It carries two
// things only tier 2 reads as well: the run's resolver endpoints, the same list the supervisor's
// port-53 exception is built from, which tier 2's kernel rows must admit too (enforce-cgroup-observe
// §5 R5); and the binary the child stage execs, which tier 2 execs again for its detached helpers. A handle
// that implements Armer is armed after the child stage's exec and before the ack (ADR 0021 (2)). A handle whose kernel rows hold a host entry's addresses also implements NetRefresher, which
// the runtime's DNS worker calls when a TTL refresh moved any (§6 E7).
//
// Select applies the ceiling/pin/probe algorithm of pkg/spec/backend (identity-config.md §5 R17,
// R18) to the machine config, the contract's tier: pin and the machine probe, filters out tiers this
// binary cannot construct (Buildable, the same answer internal/doctor folds into the tiers it reports),
// probes the Landlock ABI once and threads it into the landlock backend (R19), and returns diagnostics
// in the shared file:line: message [code] form; a nil Backend with an error diagnostic is exit 125
// [tier-unavailable]. Observe returns the record-only backend for an explicit --observe run; it is never
// selected.
//
// Imports: pkg/spec/{agent,backend,config,identity,record}, internal/runtime/enforce/{api,landlock,cgroup,observe},
// internal/bpf (whether this build embeds the tier-2 objects).
// Must not import: internal/check, internal/serve, internal/doctor (which imports this package).
package enforce
