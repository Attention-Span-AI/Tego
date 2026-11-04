// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import "sync"

// The test builds' waiver of fmod_ret mode's preemption precondition (TEGO_TEST_PLANE_PREEMPT=waive, ADR 0024 (16)),
// seen from the plane tests. A product build refuses fmod_ret mode on a kernel not shown never to preempt kernel
// code, because there the BPF trampoline skips a plane program on a CPU where a preempted task is still inside it,
// and the hook goes on undecided. CI's root suites set the waiver on GitHub's runners, whose 7.0 kernels preempt
// (x86_64: lazy; arm64: full), so that fmod_ret mode's decisions are still tested there. A run under it can meet that
// skip, which no fix in the plane can prevent: it is the kernel's, and the reason the product refuses the mode.
//
// One cell is held differently: TestPlaneSeqcountStress, the one run of the plane's directory walk on a CPU that
// reorders loads, measures the walk under the waiver (no path the chain never had, enough named, marked walks under
// the churn) and counts its wrong allows without holding them, since no count of the kernel's skips over a run can
// tell a skip-made wrong allow from a plane fault (2026-11-03). Its wrong allows are held with no tolerance wherever
// the mode is admitted without the waiver, and every other plane test holds them so under the waiver too.

// planeWaivedModes holds the plane modes planeModesHere found selected under their own pin only because the waiver
// admitted them (doctor's plane env preempt_waived).
var planeWaivedModes sync.Map

// planeModeWaived reports whether planeModesHere found mode admitted here by the waiver alone.
func planeModeWaived(mode string) bool {
	_, ok := planeWaivedModes.Load(mode)
	return ok
}
