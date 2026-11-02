// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package runtime

import (
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestLiveAnyTier makes a launcher built with -tags tegotesthooks start an Adjustable run at any tier its other
// start checks allow, tier landlock included, which a product launcher refuses (ADR 0125 decision 7): an isolated run
// without root can then exercise the live fence. Every other start check (run directory, supervisor, no dropped
// notification, held reads) stays.
const EnvTestLiveAnyTier = "TEGO_TEST_LIVE_ANY_TIER"

// liveAnyTier is EnvTestLiveAnyTier set to 1, never under AT_SECURE, where no environment variable may steer the
// capability-bearing binary (identity-config.md R21).
func liveAnyTier() bool {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return false
	}
	return os.Getenv(EnvTestLiveAnyTier) == "1"
}
