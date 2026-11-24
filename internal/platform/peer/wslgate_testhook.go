// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package peer

import "sync/atomic"

// wslRule is the switch of a binary built with -tags tegotesthooks: whether the rule's proof may answer Outside on
// a WSL machine. It starts off, which is not an ordinary build's state (an ordinary build has it on, wslgate.go): a
// test build exists to hold the state before the switch as well, and its binaries set it from TEGO_TEST_WSL_RULE.
var wslRule atomic.Bool

func wslRuleOn() bool { return wslRule.Load() }

// SetWSLRuleForTest turns the rule's use on WSL on or off in a binary built with -tags tegotesthooks. It was the
// guest proof's way to run on WSL before the rule was on for everyone; it stays so that a test can show both states
// (a binary with the switch off holds as the ordinary build did before the rule was switched on), and its builds set
// it from TEGO_TEST_WSL_RULE (internal/cli and internal/control/cli, never under AT_SECURE). A product build does not
// contain this file.
func SetWSLRuleForTest(on bool) { wslRule.Store(on) }

// nestedRule is the second switch of a binary built with -tags tegotesthooks: whether the rule's proof may answer
// Outside outside WSL in a cgroup namespace that is not the kernel's first one. It starts off, as in an ordinary
// build.
var nestedRule atomic.Bool

func nestedRuleOn() bool { return nestedRule.Load() }

// SetNestedRuleForTest turns the rule's use outside WSL beyond the first cgroup namespace on or off in a binary
// built with -tags tegotesthooks, for the guest rows that measure it there (TEGO_TEST_NESTED_RULE in internal/cli and
// internal/control/cli, never under AT_SECURE). A product build does not contain this file.
func SetNestedRuleForTest(on bool) { nestedRule.Store(on) }
