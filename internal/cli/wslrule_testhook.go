// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"os"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestWSLRule sets the run-membership rule's use on WSL in a binary built with -tags tegotesthooks: on for exactly
// "on", off otherwise. A product build has the rule on where WSL shows two marks (internal/platform/peer's wslgate.go,
// ADR 0100) and answers "unknown, wsl-launcher-unproven" on one; a test build starts off, which is the state of a build
// from before the rule was switched on, so that a test can show both, and the proof's builds set this. A product build
// does not contain this file and has no such variable (internal/platform/peer's
// TestOrdinaryBuildCannotTurnTheWSLRuleOn); a test build ignores the variable under AT_SECURE, like every TEGO_TEST_
// variable, and when AT_SECURE cannot be read.
const EnvTestWSLRule = "TEGO_TEST_WSL_RULE"

// EnvTestNestedRule is the second switch of a binary built with -tags tegotesthooks, on for the exact value "on":
// outside WSL, in a cgroup namespace that is not the kernel's first one (a container, a nested system), an ordinary
// build answers "unknown, system-unproven" where every fact of the rule holds, because no guest has measured the
// rule there (ADR 0100, amended 2026-11-19); the guest rows that measure it set this. The same limits hold as for
// EnvTestWSLRule.
const EnvTestNestedRule = "TEGO_TEST_NESTED_RULE"

func init() {
	peer.SetWSLRuleForTest(testWSLRule(os.Getenv(EnvTestWSLRule), config.DetectSecureExec))
	peer.SetNestedRuleForTest(testWSLRule(os.Getenv(EnvTestNestedRule), config.DetectSecureExec))
}

// testWSLRule is whether a test build whose switch variable (EnvTestWSLRule, EnvTestNestedRule) holds v turns it on.
func testWSLRule(v string, secureExec func() (bool, error)) bool {
	if secure, err := secureExec(); err != nil || secure {
		return false
	}
	return v == "on"
}
