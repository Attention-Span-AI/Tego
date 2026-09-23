// SPDX-License-Identifier: Apache-2.0

// Package identity holds the run identity contract of Tego (spec/identity/RUN-IDENTITY.md,
// docs/p0/identity-config.md): the run, agent and exec id formats, the identity+propagation
// environment set and its precedence over a contract's env.pass/deny/set, the launcher identity,
// labels and role run_start records (ADR 0073), the run-directory and cgroup path conventions,
// the closed set of exit codes of `tego run`, the signal-forwarding table, and the
// `file:line[:col]: message [code]` message format.
//
// The package is pure: it opens no file, holds no state and never blocks. NewRunID consumes an
// already-hashed machine id (HostID hashes bytes the caller read); Env.Apply is a total function
// over a KEY=VALUE slice; LauncherOf reads only the uids, environment and lookups it is handed;
// ExitCode is the single place a run's end reason becomes a process exit status. Cgroup and run-directory helpers only format path strings.
//
// Imports: standard library only.
// Must not import: any other pkg/spec/* package, anything under internal/.
package identity
