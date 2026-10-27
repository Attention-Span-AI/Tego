// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestIntegrationPlaneBuildMemlockIsBpftoolsSum is TestIntegrationBuildMemlockIsBpftoolsSum for a build with the
// decision plane this kernel runs (lsm where bpf is an active LSM, else fmod_ret): the objects pinned under the plane
// directory and those the build's programs share with it are each counted once, and the sum equals bpftool's.
func TestIntegrationPlaneBuildMemlockIsBpftoolsSum(t *testing.T) {
	requireRealPrepare(t)
	mode, build := hostPlane(t)
	checkBuildMemlock(t, "memlockplane", PlaneSetup{Mode: mode, Build: build},
		func(b *Backend, rt *agent.RuleTable, run *Run) {
			rt.Contract = &agent.Contract{}
			rows, err := decide.CompilePlane(rt)
			if err != nil {
				t.Fatal(err)
			}
			b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
			run.CgroupMount, run.PlaneRows = "/sys/fs/cgroup", rows
		})
}
