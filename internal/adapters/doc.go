// SPDX-License-Identifier: Apache-2.0

// Package adapters is Layer 3's registry of harness provisioners (docs/FEATURES.md I2, E41; agent-contract.md R27;
// ADR 0062): For names the provisioner of each harness this build can provision, and the harness adapters live in
// its subdirectories (claudecode, openaicodex). A provisioner returns bytes and names (pkg/spec/harness.Provision);
// the launcher (internal/runtime) makes every file, so an adapter writes nothing of the run's and never modifies agent
// code. internal/cli connects For to the launcher. In this build claude-code has a provisioner (claudecode.Provisioner,
// a per-run settings file passed with --settings) and no other harness has one.
//
// Imports: pkg/spec/** (the reason file through pkg/spec/reason, ADR 0061), golang.org/x/sys/unix and the
// standard library only
// Must not import: internal/runtime, internal/ledger, internal/check, internal/serve, internal/cli, internal/bpf,
// internal/policy/decide, github.com/cilium/ebpf (depguard adapters-never-import-engine, .golangci.yml).
package adapters
