// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestChainAnchor names the chain anchor of a binary built with -tags tegotesthooks. The tests that
// drive tego as a subprocess (internal/runtime's TestIntegrationCLI*, test/e2e) build it that way and
// point it into their own scratch directory: the product anchors in the invoking user's
// ~/.tego/chain.log, which no setting redirects, so without this every test run would append to the
// developer's own anchor, and fail wherever that home is not writable. A product build does not
// contain this file, so the variable means nothing to it; and even a test build ignores it under
// AT_SECURE, where no environment variable may choose a path the capability-bearing launcher writes
// (identity-config.md R21), should such a build ever be given file capabilities.
//
// A test build fails closed on it. With the variable unset (or empty) it names no anchor at all, so every
// command that anchors (`run`, `watch`, `events --verify`) refuses with ErrTestAnchorUnset instead of falling
// back to the product's ~/.tego/chain.log: a harness that forgot the variable, or took its environment
// before it was set, fails the test it belongs to rather than appending test runs to the developer's own
// anchor, where nothing says afterwards which lines are theirs (2026-10-06: 61 lines of runs whose ledgers
// were temporary directories). Only the AT_SECURE case keeps the product's anchor, as above.
const EnvTestChainAnchor = "TEGO_TEST_CHAIN_ANCHOR"

// ErrTestAnchorUnset is what a binary built with tegotesthooks answers when asked for its chain anchor and
// EnvTestChainAnchor is not set.
var ErrTestAnchorUnset = errors.New("this binary is built with tegotesthooks and " + EnvTestChainAnchor +
	" is not set: a test build never anchors in the invoking user's own ~/.tego/chain.log; set it to a file in the test's own directory")

func init() {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	anchorPath = testAnchorResolver(os.Getenv(EnvTestChainAnchor))
}

// testAnchorResolver is the anchor resolver of a test build whose EnvTestChainAnchor holds p: the file p, or,
// for an empty p, none.
func testAnchorResolver(p string) func(*config.Machine) (string, error) {
	if p == "" {
		return func(*config.Machine) (string, error) { return "", ErrTestAnchorUnset }
	}
	return func(*config.Machine) (string, error) { return p, nil }
}
