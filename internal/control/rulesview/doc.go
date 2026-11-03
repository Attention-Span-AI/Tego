// SPDX-License-Identifier: Apache-2.0

// Package rulesview is the dashboard's Rules page model: for one run, the contract the run kept in its directory
// (contract.yaml, the canonical merged contract whose sha256 is run_start's contract_hash) and what that contract
// compiles to today, printed by agent.PrintRuleTable as `tego compile` prints it (Load), and the same contract as
// Rules in force (InForce,).
//
// It recompiles the copy as `tego drift` does: with its extends sealed when the copy's hash is the run's (the copy is
// self-contained), against the run's own working directory and run-command grant from run_start, offline (no name
// is resolved), at the tier the run recorded. It reads files read-only and writes nothing.
//
// InForce is internal/check/inforce's view of that compile, plus what only this side can read: each rule's hits
// from one pass over the run's ledger (kind and rule read from each line's common fields, so a 55k-line run takes
// tens of milliseconds; for a run the read model holds, the hits and run_start are kept per run version,
// inforce_cache.go), the run's live blocks (liveblock.Read, read-only; an ended run's refuse nothing and are listed
// apart from the live group, InForceView.EndedLive, and an overlay that cannot be read is said in words), positions
// in the run's rules file when that file still loads to the run's contract_hash and in the run's copy otherwise, and
// Pending: the rules file changed after the run started, from the rule-change journal (internal/rulefile's doc.go
// has its format) or a later modification time, or, with neither, it loads to other rules than the run ran (Differs,
// undated). RuleSource is the line page's lookup of the rule a line names in that view (its sentence, file, line and
// enforcement), the view kept per run until its copy, live blocks or rules file change, so a page view compiles
// nothing; RuleWords is a rule key in inforce's words, the one label the dashboard gives a line's rule. Learn (Least
// privilege) and Drift (Unused permissions) keep each run's result while the run, its copy, the chain anchor, the
// machine config and PATH are the same (cache.go, on ledgerview.Results). ContractsFromRuns lists the rules files a
// ledger snapshot's runs named, the only files the dashboard offers to change, each marked when nothing is at its
// path now. Contract.Shown is the copy and its compile table with every env.set value hidden (RedactEnvText, line for
// line), the only form a page shows them in. EditableEnv is that form of a rules file for the dashboard's YAML editor,
// and RestoreEnv puts the hidden values back into a free edit of it, refusing any other change to env.set (SetsEnv
// decides env.set on a parse, not on the word "set"). All four read a text as the compiler does, as one YAML document:
// a text with a second document is held back whole, never read only to its first.
//
// Shortcut: a copy whose hash is not the run's is compiled with no profiles at all (an
// extends then fails to load), where drift resolves today's profiles; the compile names the run's tier as the only
// tier this build has, so an auto contract shows the table of the tier the run got.
//
// Imports: the standard library, internal/check/drift, internal/check/inforce, internal/check/learn,
// internal/check/livestatus, internal/control/ledgerview, internal/ledger, internal/liveblock, internal/nextrun,
// internal/rulefile, pkg/policy/execmatch, pkg/spec/agent, pkg/spec/backend, pkg/spec/config, pkg/spec/record,
// gopkg.in/yaml.v3.
// Must not import: the engine (internal/runtime, internal/policy, internal/bpf, internal/cli).
package rulesview
