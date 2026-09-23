// SPDX-License-Identifier: Apache-2.0

// Command noop is the overhead benchmark's second control (docs/BENCHMARKS.md): it does nothing at
// all past process start. Where test/workloads/build/cpu isolates "no syscalls of interest" on a
// workload with real duration, this isolates the other half of the question: a run's fixed
// per-invocation cost (cgroup creation, the Landlock ruleset, the seccomp filter install, opening
// the ledger) on a workload with no duration to amortize it into. Bare-vs-enforced on this binary
// is, by construction, that fixed cost and nothing else; the harness reuses it as the fixed-cost
// term it subtracts from every other workload's bare-vs-enforced delta to get a marginal,
// per-syscall cost instead of one percentage that conflates the two (docs/BENCHMARKS.md's
// "fixed vs. marginal" table).
package main

func main() {}
