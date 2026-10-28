// SPDX-License-Identifier: Apache-2.0

// Package inforce says what a contract lets an agent do, as short plain sentences in fixed groups: "Rules in force",
// the view the dashboard's Rules page and `tego rules` both show .
//
// Of builds the View from a compiled agent.RuleTable at the tier a run was given, so each rule says whether that run
// enforces it (the table's Unenforced marks, its held reads and its best-effort cells, ADR 0041 D1), in one word as
// Rule.State: enforced, best_effort, not_enforced or none. exec.ask is reserved (every match is refused, ADR 0044),
// so its entries are listed as refusals among the programs, never as questions. Declared builds
// it from a contract's text alone, the fallback when the contract no longer compiles: the same groups and sentences,
// with no enforcement claim. Every rule carries its contract key, its declared entry, the ledger rule key its events
// carry (agent.FSRule.RuleName and the others), where it was declared (file and line, or "built in"), and whether the
// dashboard may edit it. (*View).Count adds each rule's hits from a run's ledger lines; Words is the one plain label
// for a ledger rule key, the vocabulary the dashboard's event pages use.
//
// The groups come in one fixed order: read, change, ask, never-read, never-change, programs, network, env, limits,
// live, always-on. The env group names variables and never shows a value: env.set values are often secrets, and a
// page or a JSON answer that printed them would leak them to whoever reads it (TestNoEnvValues). The live group is
// empty here; the caller adds a running run's live blocks with (*View).AddLiveStatus, each with its state now
// (internal/check/livestatus), or (*View).AddLive, which claims one in force.
//
// Nothing here does I/O, reads a clock or starts a goroutine: the caller hands it a table, a contract's bytes or the
// rule keys of a run's events.
//
// Imports: internal/check/livestatus, pkg/spec/agent, pkg/spec/backend, pkg/spec/record, gopkg.in/yaml.v3, the standard library.
// Must not import: internal/runtime, internal/policy, internal/control, os, syscall.
package inforce
