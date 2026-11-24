// SPDX-License-Identifier: Apache-2.0

// Package agentid projects recorded runs and reported program observations into
// separate rows. It makes no filesystem, process or network reads. Callers
// supply bounded, validated observations and checked record snapshots.
//
// The selection rule is one row per named recorded run. All ticks on that row
// describe only that run, with its id and start time in the view model. A newer
// run never supplies facts to an older run, even if their commands are equal.
// Unchecked, broken and cannot-verify records stop at recorded, not checked,
// with the verification reason and next step. Contract and enforcing claims
// require that same run's affirmative record check. Verified additionally
// requires an ended enforcing run. A contract association needs the explicit
// run_start.contract_source.path and a successful current compile for that
// exact run's context; a different run's compile cannot supply the fact.
//
// A scan retains no argument vector (ADR 0145). It never joins a recorded row,
// changes a recorded row, or receives any tick. Equal absolute program
// paths, exact folders and known uids permit words saying the observation may
// be the same program; those words explicitly cannot identify a run or its
// workload. This also applies to interpreters. Paths are never cleaned,
// resolved through today's PATH, matched by basename or followed through a
// rename. Different spellings have a cannot-tell explanation and a next step.
// Observations with the same complete observed program identity may share an
// observation row. Arguments are omitted from JSON and display commands.
//
// Remembering observations and excluding observations inside a Tego run are
// the caller's responsibilities. The list means what scans have seen, never
// proof that nothing else runs. A same-user process outside Tego can write
// saved observations and remembered discoveries; these never establish ticks
// about a recorded run. Protection from governed writes is a caller boundary,
// not an assurance made by this pure resolver.
//
// Imports: standard library only.
// Must not import: scan collection, ledger, registry, guide, control, CLI,
// runtime, policy or any package that performs actions.
package agentid
