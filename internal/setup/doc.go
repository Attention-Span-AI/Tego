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
// agent from a form. Each call is safe to repeat; only Apply, Create and Remove write.
//
//   - Options is the form: Presets, Writes, Hosts, Command, Name, Dir (absolute, its symlinks resolved), Home.
//   - Draft(Options, CheckEnv) (*Result, error) composes and compiles offline, creating nothing: Result.Contract is
//     the agent.yaml bytes, Result.Diagnostics what compile found (labelled Dir/agent.yaml) and Result.OK says none
//     is an error. A mistake in the options is a *UsageError (IsUsage) whose text names the fix and the known
//     values; a contract that does not compile is a Result with OK false, never an error.
//   - Apply(*Result, dir, CheckEnv) makes Result.MakeDirs, the folders the contract names that do not exist yet
//     (Create), and compiles again with them in place, since compile skips the rest of an entry's checks while its
//     folder is missing; when that compile refuses, Apply removes what it made and returns ok false. Write
//     Result.Contract to Dir/agent.yaml (ContractFile) after an ok Apply, and add Result.Ignore to the .gitignore.
//     Create opens dir once with no symlink followed and makes each folder beneath it with mkdirat, a component at a
//     time (openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS, or openat O_NOFOLLOW where openat2 is refused, as inside a
//     tego run): a symbolic link on the way, in dir's own path or under it, is refused with an error naming it, so a
//     link swapped in after the caller checked dir never leads a folder out of the project. Remove(made, dir) takes
//     away what Create made, as a caller whose own write failed after it does: only while empty, with unlinkat
//     AT_REMOVEDIR beneath dir reached the same way, so it never unlinks a file or removes through a link; Apply's
//     own cleanup is Remove's.
//   - Compose(Options) is Draft without the compile; Check(bytes, dir, CheckEnv) compiles any contract bytes as the
//     agent.yaml in dir, offline.
//   - KnownPresets and ParsePresets name and read the presets; presets.HostGroups names the @groups.
//
// CheckEnv carries the machine the compile runs against (the machine config, the profile source, compile options
// such as agent.WithPATH): the caller supplies it, so this package reads no machine config. `tego init` passes what
// `tego compile` uses, so a contract init writes compiles as compile compiles it.
//
// Imports: the standard library, golang.org/x/sys/unix and internal/platform/sys (the owned descriptors Create makes
// the folders through), pkg/spec/agent, pkg/spec/config, pkg/spec/presets.
// Must not import: the engine (internal/runtime, internal/policy/decide, internal/bpf, internal/ledger,
// internal/check, internal/cli; depguard setup-never-imports-engine).
package setup
