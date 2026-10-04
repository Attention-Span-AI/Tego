// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cgroup

import (
	"os"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestPlaneFillReuse makes a binary built with -tags tegotesthooks reuse the first descriptor number its plane
// fill holds: after the plan is made and before the fill runs, another file is dup3'd over it, as a descriptor
// closed and taken by another open would be (enforce-plane §7, R16).
const EnvTestPlaneFillReuse = "TEGO_TEST_PLANE_FILL_REUSE"

func init() {
	// Never under AT_SECURE, where no environment variable may steer the capability-bearing binary
	// (identity-config.md R21).
	if secure, err := config.DetectSecureExec(); err != nil || secure || os.Getenv(EnvTestPlaneFillReuse) == "" {
		return
	}
	planeFillTestHook = func(fds []int) {
		if len(fds) == 0 {
			return
		}
		other, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return
		}
		_ = unix.Dup3(other, fds[0], unix.O_CLOEXEC)
		_ = unix.Close(other)
	}
}
