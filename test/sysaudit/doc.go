// SPDX-License-Identifier: Apache-2.0

// Package sysaudit holds the syscall-audited tests: each runs a pure function of pkg/spec in a copy of the
// test binary traced with ptrace (internal/testutil.SysTrace, no privilege) and asserts on every syscall it
// made. identity-config.md I10 (config.Load opens its layer files and nothing else) and agent-contract.md I6
// (Compile makes no mutating syscall) are checked here, outside pkg/spec, whose import fence keeps its own
// tests from importing internal/testutil. The package has no code of its own; the binary never imports it.
package sysaudit
