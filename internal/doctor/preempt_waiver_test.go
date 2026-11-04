// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// The package's own test binary honours TEGO_TEST_PLANE_PREEMPT=waive as a tegotesthooks build does
// (preempt_testhook.go), so that its root tests probe fmod_ret mode on CI's runner, where the root-suites job sets it.
func init() {
	if os.Getenv(envTestPlanePreempt) == "waive" {
		planePreemptWaived = true
	}
}

// fmodRetOffered reports whether this kernel's preemption model, or a waiver, admits fmod_ret mode (ADR 0024 (16)), as
// the probe read it. Where it does not, the mode must have been ruled out before any load with the reason, which is
// what such a kernel is held to.
func fmodRetOffered(t *testing.T, st *PlaneState) bool {
	t.Helper()
	if !preemptsKernelCode(st.Env.Preempt) || st.Env.PreemptWaived {
		return true
	}
	m, _ := st.mode(bpfobj.PlaneFmodRet)
	if m.OK || m.Tested || !strings.Contains(m.Detail, "the BPF trampoline skips an fmod_ret program") {
		t.Errorf("preemption %q (from %s): fmod_ret mode ok=%v tested=%v: %s; want it ruled out before any load, saying why",
			st.Env.Preempt, st.Env.PreemptSource, m.OK, m.Tested, m.Detail)
	}
	return false
}
