// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package observe

import (
	"os"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestExecPinKillErr makes a binary built with -tags tegotesthooks treat every kill sample of a pinned run as one
// whose bpf_send_signal failed with this errno (a positive number; the sample carries its negation), so ADR 0048 P2's
// K6 kill-failed cell can reach the failure path: refused with kill_failed and detected_bypass, the gap
// exec-pin-kill-failed, run_end's kill_failed and the pidfd backstop.
const EnvTestExecPinKillErr = "TEGO_TEST_EXEC_PIN_KILL_ERR"

func init() {
	// Never under AT_SECURE, where no environment variable may steer the capability-bearing binary
	// (identity-config.md R21).
	v := os.Getenv(EnvTestExecPinKillErr)
	if secure, err := config.DetectSecureExec(); err != nil || secure || v == "" {
		return
	}
	if errno, err := strconv.ParseInt(v, 10, 32); err == nil && errno > 0 {
		pinKillErrTestHook = -int32(errno)
	}
}
