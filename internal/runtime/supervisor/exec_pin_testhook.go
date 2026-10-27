// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks && (amd64 || arm64)

package supervisor

import (
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestExecPinSkip makes a binary built with -tags tegotesthooks write no pin for an exec whose image's basename
// is its value, and continue that exec (ADR 0048 P2's K6 unpinned cell: the plane refuses it, pin-missing).
const EnvTestExecPinSkip = "TEGO_TEST_EXEC_PIN_SKIP"

func init() {
	// Never under AT_SECURE, where no environment variable may steer the capability-bearing binary
	// (identity-config.md R21).
	skip := os.Getenv(EnvTestExecPinSkip)
	if secure, err := config.DetectSecureExec(); err != nil || secure || skip == "" {
		return
	}
	pinSkipTestHook = func(image string) bool { return image == skip }
}
