// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package doctor

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestIntegrationPlaneExecPinCell is ADR 0048 (7)'s plane.exec_pin on a real kernel, as root in the KVM guest on both
// boots: in each mode the boot passes, the exec pin cell runs once the known answers matched, and every one of its
// answers holds (planeexecpin.go), so a run pinned in that mode may claim that the kernel holds its execs. The cell
// leaves no pin, descriptor, cgroup or fixture behind.
func TestIntegrationPlaneExecPinCell(t *testing.T) {
	requirePlaneRoot(t)
	before := leftovers(t)
	uid, _ := config.InvokingUID()
	_, release, _ := probeKernelVersion()
	st, _ := probePlane(true, uid, release, config.PlaneAuto, false)
	passed := 0
	for _, m := range st.Modes {
		t.Logf("mode %s: ok=%v %s; exec pin cell %+v; %s", m.Mode, m.OK, m.Detail, m.ExecPin, strings.Join(m.KnownPhases, ", "))
		if !m.OK {
			continue
		}
		passed++
		if !m.execPinsPass() {
			t.Errorf("mode %s passed, but its exec pin cell did not: %+v", m.Mode, m.ExecPin)
		}
	}
	if passed == 0 {
		if lsm, err := ReadLSMState(); err == nil && !lsm.BPFActive && !fmodRetOffered(t, st) {
			t.Skipf("no plane mode is offered here (bpf is no active LSM, and fmod_ret mode is ruled out: preemption %q "+
				"from %s); TEGO_TEST_PLANE_PREEMPT=waive probes fmod_ret mode", st.Env.Preempt, st.Env.PreemptSource)
		}
		t.Fatalf("no plane mode passed on this boot: %+v", st.Modes)
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("the exec pin cell left state behind: before %v, after %v", before, after)
	}
}
