// SPDX-License-Identifier: Apache-2.0

// Package inforce says what a contract lets an agent do, as short plain sentences in fixed groups: "Rules in force",
// the view the dashboard's Rules page and `tego rules` both show .
//
// Of builds the View from a compiled agent.RuleTable at the tier a run was given, so each rule says whether that run
// enforces it (the table's Unenforced marks, its held reads and its best-effort cells, ADR 0041 D1, and at tier
// landlock, under every net: section, the datagrams the agent's own call sends after the supervisor's check, supervisor
// R13b), in one word as Rule.State: enforced, best_effort, not_enforced or none; Rule.ByKernel marks the rules the
// operating system enforces in full, and Group.Open a default that leaves the agent wide open, so a view marks either
// by the flag and never by the sentence's words. exec.ask is reserved (every match is refused, ADR 0044), so its
// entries are listed as refusals among the programs, never as questions. Its limits are the table's, each clamped to
// the machine config's ceilings: a limit a ceiling lowers says both values, and one only a ceiling sets is listed from
// the machine config. net.http's and net.ingress's entries are network rules; the gate's scored rules are listed where
// each one's score alone puts an action it matches (among the refusals of its kind, or the questions; a command's
// always among the programs, since tego never asks before one runs), with a note on how the scores add up. Declared
// builds it from a contract's text alone, the fallback when the contract no longer compiles: the same groups and
// sentences, with no enforcement claim. Every rule carries its contract key, its declared entry, the ledger rule key
// its events carry (agent.FSRule.RuleName and the others; none for a rule no ledger line names), where it was declared
// (file and line, or "built in"), and whether the dashboard may edit it. A program entry of a compiled table is named
// after the rule of the file it resolved to, as a run's lines name it, and covers that file's other rules, the helper
// images compile granted its tool (git's exec-path git) and a script command's #! interpreter, so entries that name one
// file share its hits (execNames; internal/control/rulesview's TestIntegrationRuleKeysAreARunsKeys holds the keys of
// the Rules page's view to a real run's ledger). (*View).Count adds each rule's hits from a run's ledger lines, and
// (*View).CountDefault each line no rule named to the default of the group that decided it (an exec line the programs',
// a net line the network's: Group.DefaultKind); Words is the one plain label for a
// ledger rule key, the vocabulary the dashboard's event pages use.
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
// Imports: internal/check/livestatus, pkg/policy/gate (the gate's predicates, which the table holds), pkg/spec/agent,
// pkg/spec/backend, pkg/spec/record, pkg/policy/execmatch and its rows (an exec entry's words and tool, read as compile
// reads them), gopkg.in/yaml.v3, the standard library.
// Must not import: internal/runtime, internal/policy, internal/control, os, syscall.
package inforce
