// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestOwnLogHome names the home a binary built with -tags tegotesthooks keeps its own log under
// (<home>/.tego/tego.log). The tests that drive tego as a subprocess (internal/runtime's
// TestIntegrationCLI* and budget tests) point it into their own scratch directory, as they do the chain
// anchor with EnvTestChainAnchor: the product logs to the invoking user's ~/.tego/tego.log, which no
// setting redirects, so without this every run of those tests appended to the developer's own log.
// A product build does not contain this file, and a test build ignores the variable
// under AT_SECURE, for the reason anchor_testhook.go gives.
//
// A test build fails closed on it too: with the variable unset it has no home to keep a log in, so it keeps
// none (the log is best effort, and a missing one costs a diagnostic, never a run), rather than writing the
// developer's own ~/.tego/tego.log.
const EnvTestOwnLogHome = "TEGO_TEST_OWN_LOG_HOME"

func init() {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	ownLogHomeOf = testOwnLogHome(os.Getenv(EnvTestOwnLogHome))
}

// testOwnLogHome is the own-log home resolver of a test build whose EnvTestOwnLogHome holds home: that home, or,
// for an empty one, none.
func testOwnLogHome(home string) func(int) string {
	return func(int) string { return home }
}
