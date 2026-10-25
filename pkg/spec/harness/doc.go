// SPDX-License-Identifier: Apache-2.0

// Package harness is the vocabulary of the harness provisioning point (ADR 0062, docs/p0/agent-contract.md R27):
// the contract key harness: (Name, Detect, Resolve), what the launcher tells a provisioner about one run (Run), and
// what a provisioner returns (Provision: a new argv, TEGO_ environment additions, files by name, and the hook the
// harness will exec). A provisioner returns bytes and names; the launcher (internal/runtime) creates every file, by
// directory descriptor, so the guarantees (the files read-only to the agent, hook-state the one place it may write)
// are held by the one process that owns the run's runtime directory. Implementations live in internal/adapters/*.
//
// Imports: standard library only.
// Must not import: any other pkg/spec/* package, anything under internal/.
package harness
