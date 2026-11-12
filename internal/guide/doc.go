// SPDX-License-Identifier: Apache-2.0

// Package guide works out which step of Tego's six a machine is on and the one step that comes next, from facts
// already on disk (ADR 0142). `tego setup` (internal/cli) prints the object Compute returns;
// the dashboard's Overview (internal/control/web) renders the same object, in the same words (State.Words), so the two
// surfaces never disagree about a step (TestParityFixtures, guidetest.Fixtures, and the dashboard's
// TestOverviewGuideParityWithSetup). Neither ticks a step from a click. Next.Built marks the one command Compute built,
// the only one a surface offers to copy.
//
// The steps, at machine level, each with its state, the fact that decided it and where that fact was read:
//
//   - install: always done; the build's own version and commit.
//   - check: a stored check of this boot and this build (check.json under ~/.tego/state, written by `tego setup`
//     alone from doctor's own probes; StoreCheck) says a tier runs from the place it was made. A check of another
//     boot or another build is never used.
//   - find: a run is recorded. Nothing here looks for agents yet (the scan is a later slice).
//   - record: a run that enforced nothing (tier observe: `tego watch`, `--observe`) has ended, and its record checks
//     out now against its chain anchor (ledger.VerifyRunDir).
//   - contract: a contract in the project or the user registry (internal/registry) compiles now (internal/nextrun),
//     with no tier named for an auto contract that no run used, so it resolves to the machine's ceiling.
//   - enforce: a run under a contract has ended, and its record checks out now against its chain anchor, the check
//     `tego receipt --verify` makes (ledger.VerifyRunDir).
//
// Steps record, contract and enforce are read from the hash-chained record and the registries, never from a file
// tego setup writes: check.json decides the check step, and which of a few fixed commands a next step names (the one
// that opens a shell in the user manager's cgroup, tego doctor or tego setup), never any part of one. A fixed list
// of rules, checked in order, gives the next step (next.go); there is no score and no model. A source that cannot be read gives the state "not-known", a null fact and one line in
// NotKnown, never a default. A next step's command is built from fixed words and values this package checked: a run
// id (ledger.IsRunID), an agent name (registry.IsName) and one recorded value, the working folder of a recorded run
// whose record checks out against the chain anchor, written with shellword.Quote only when every character of it
// prints as itself, and the invoking user's uid and name from the passwd entry (config.LookupPasswd), quoted, in the
// scope command OpenScope writes for a person who started tego as that user through sudo or su, which it tells from
// /proc (the login uid and the ancestors' owners), never from the environment. A run tego learn is pointed at checks out too. A process that can also write the chain anchor
// can still choose that folder (GAPS C9, C62). Any other text read from a file or the record is a fact, never part
// of a command.
//
// Imports: the standard library, golang.org/x/sys/unix and internal/platform/sys (check.json is opened beneath ~/.tego
// without following a link, through owned descriptors), internal/check/learn (whether the learn step names
// --allow-host, SuggestHosts), internal/ledger, internal/nextrun, internal/registry, internal/runscope,
// internal/shellword, pkg/spec/{backend,config,record}.
// Must not import: internal/cli, internal/control, internal/doctor, internal/runtime, internal/policy, internal/bpf,
// github.com/cilium/ebpf, github.com/landlock-lsm/go-landlock. tego-control links this package and may not link the
// engine (ADR 0100 (1a)); the probes run in internal/cli, which hands their answer in as Inputs.Fresh, and the
// dashboard never runs them: its own process is in another cgroup than the person's shell.
package guide
