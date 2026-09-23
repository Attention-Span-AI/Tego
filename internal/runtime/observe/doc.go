// SPDX-License-Identifier: Apache-2.0

// Package observe is the kernel record (docs/p0/enforce-cgroup-observe.md §2.4, §5 R8-R13): it
// drains the ring buffer the tracing programs write to. Each run has its own ring at its slot, opened by slot
// from the run's run-set row, and its recorder is the only reader of it; the run_idx and gen check on a
// sample is a guard, and concurrent runs of one build are supported (§2 "Run scope (as built)"). It decodes every sample through
// internal/bpf's record types (the layouts checked against bpf/include/events.h), enriches it from a
// /proc-backed process cache, stamps the declared entry and the verdict the compiled contract implies,
// aggregates ordinary reads per (exec id, rule) and emits record.Event values. It also hands every
// exec, open and exit to the run's process hooks, which is what drives uprobe capture's attaches.
//
// Recorder is a source.Source: one goroutine owns the ring buffer, the process cache and the
// aggregation table for the life of a run, so none of them needs a lock. The reader is injectable,
// which is what lets the whole path — decode, cache, rule stamping, aggregation, gap accounting — be
// tested against synthetic samples with no kernel at all; in production it is the pinned ring buffer
// of one bpf_hash build. Nothing here decides: the kernel's refusals arrive already decided (R5) and
// everything else is recorded, never enforced. Nothing here writes the ledger either — every event
// crosses internal/runtime's buffered queue (§1).
//
// Imports: internal/bpf, internal/platform/proc, internal/policy/decide, internal/runtime,
// internal/runtime/source (the Source contract),
// internal/runtime/supervisor, pkg/spec/agent, pkg/spec/backend, pkg/spec/identity, pkg/spec/record,
// github.com/cilium/ebpf, golang.org/x/sys/unix
// Must not import: internal/check
package observe
