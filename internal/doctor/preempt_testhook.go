// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package doctor

import (
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestPlanePreempt names the variable that, set to "waive" in the environment of a binary built with -tags
// tegotesthooks, waives fmod_ret mode's preemption precondition (fmodRetPreemptRefusal): the mode is probed, and
// selected where it passes, on a kernel that preempts kernel code, and its line in doctor says the precondition was
// waived. CI's root-suites job sets it on GitHub's runners, whose 7.0 kernels offer only full and lazy preemption and
// bpf in no LSM list, so that the root suites keep exercising the plane's decisions in fmod_ret mode there; a run of
// such a build can still meet a skipped program, whose hook then proceeds undecided, which is why a product build
// refuses the mode there. A product build does not contain this file; a test build ignores it under AT_SECURE, like
// every TEGO_TEST_ variable.
const EnvTestPlanePreempt = envTestPlanePreempt

func init() {
	if os.Getenv(EnvTestPlanePreempt) != "waive" {
		return
	}
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	planePreemptWaived = true
}
