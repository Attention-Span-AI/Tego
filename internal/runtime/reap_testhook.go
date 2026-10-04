// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package runtime

import (
	"os"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestReapHold names a file a reaper of a binary built with -tags tegotesthooks waits for, once its launcher
// is gone and before it acts: a root test holds the reaper to see what a dead launcher's run keeps meanwhile.
const EnvTestReapHold = "TEGO_TEST_REAP_HOLD"

// EnvTestReapStartFail makes such a binary's launcher fail the reaper's start (ADR 0020 (4)).
const EnvTestReapStartFail = "TEGO_TEST_REAP_START_FAIL"

func init() {
	// Never under AT_SECURE, where no environment variable may steer the capability-bearing binary
	// (identity-config.md R21).
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	hold, fail := os.Getenv(EnvTestReapHold), os.Getenv(EnvTestReapStartFail) != ""
	reapStartFails = func() bool { return fail }
	if hold == "" {
		return
	}
	reapTestEnv = func() []string { return []string{EnvTestReapHold + "=" + hold} }
	reapHold = func() {
		for {
			if _, err := os.Lstat(hold); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
