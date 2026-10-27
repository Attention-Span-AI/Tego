// SPDX-License-Identifier: Apache-2.0

// Package setup composes the agent.yaml `tego init --preset` writes (ADR 0068): the presets a
// contract extends (pkg/spec/presets), the folders --write and the project's markers name, and the hosts
// --allow-host names, each host group expanded into concrete host:port entries. The contract stays the single
// readable truth: init never writes a group or a marker as contract syntax, only the entries they stand for, each
// with a comment saying why it is there.
//
// # The API
//
// This is the stable entry a caller other than `tego init` uses too, such as a dashboard page that sets up a new
// agent from a form. Each call is safe to repeat; only Apply and Create write.
//
//   - Options is the form: Presets, Writes, Hosts, Command, Name, Dir (absolute), Home.
//   - Draft(Options, CheckEnv) (*Result, error) composes and compiles offline, creating nothing: Result.Contract is
//     the agent.yaml bytes, Result.Diagnostics what compile found (labelled Dir/agent.yaml) and Result.OK says none
//     is an error. A mistake in the options is a *UsageError (IsUsage) whose text names the fix and the known
//     values; a contract that does not compile is a Result with OK false, never an error.
//   - Apply(*Result, dir, CheckEnv) makes Result.MakeDirs, the folders the contract names that do not exist yet
//     (Create), and compiles again with them in place, since compile skips the rest of an entry's checks while its
//     folder is missing; when that compile refuses, Apply removes what it made and returns ok false. Write
//     Result.Contract to Dir/agent.yaml (ContractFile) after an ok Apply, and add Result.Ignore to the .gitignore.
//   - Compose(Options) is Draft without the compile; Check(bytes, dir, CheckEnv) compiles any contract bytes as the
//     agent.yaml in dir, offline.
//   - KnownPresets and ParsePresets name and read the presets; presets.HostGroups names the @groups.
//
// CheckEnv carries the machine the compile runs against (the machine config, the profile source, compile options
// such as agent.WithPATH): the caller supplies it, so this package reads no machine config. `tego init` passes what
// `tego compile` uses, so a contract init writes compiles as compile compiles it.
//
// Imports: the standard library, pkg/spec/agent, pkg/spec/config, pkg/spec/presets.
// Must not import: the engine (internal/runtime, internal/policy/decide, internal/bpf, internal/ledger,
// internal/check, internal/cli; depguard setup-never-imports-engine).
package setup
