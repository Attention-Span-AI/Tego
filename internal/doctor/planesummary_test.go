// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestPlaneSummaryWarnsThatTheFanotifyFallbackDoesNotScale: every open and exec on a marked mount waits on the run's
// listener, so concurrent tier-cgroup runs on the fallback slow each other's opens (the perf suite's conc check,
// enforce-plane §10). The clause says so where the fallback is selected, and only there.
func TestPlaneSummaryWarnsThatTheFanotifyFallbackDoesNotScale(t *testing.T) {
	t.Parallel()
	fallback := planeSummary(&PlaneState{Selected: PlaneFanotify, SelectedWhy: "no plane mode passed the probe"}, false)
	if !strings.Contains(fallback, "does not scale") {
		t.Errorf("the fallback's clause has no scaling note: %q", fallback)
	}
	if lsm := planeSummary(&PlaneState{Selected: "lsm"}, true); strings.Contains(lsm, "does not scale") {
		t.Errorf("an lsm plane's clause carries the fallback's note: %q", lsm)
	}
}

// TestPlaneSummaryBlamesLSMEqualsOnlyWhereBPFIsInactive: tier 2 on fmod_ret says tier 3 needs bpf in lsm= only
// where bpf is not an active LSM. With bpf active, a failed LSM mode probe points at the lsm mode line, and a
// build adopted under the fmod_ret pin (no LSM entry) names the pin: a GRUB edit fixes neither.
func TestPlaneSummaryBlamesLSMEqualsOnlyWhereBPFIsInactive(t *testing.T) {
	t.Parallel()
	fmod := PlaneModeResult{Mode: bpfobj.PlaneFmodRet, OK: true, Tested: true}
	failed := &PlaneState{Selected: string(bpfobj.PlaneFmodRet), Pin: config.PlaneAuto, Source: planeSourceProbed,
		Modes: []PlaneModeResult{{Mode: bpfobj.PlaneLSM, Tested: true, Detail: "3 of 22 hooks failed"}, fmod}}
	pinned := &PlaneState{Selected: string(bpfobj.PlaneFmodRet), Pin: config.PlaneFmodRet, Source: planeSourcePin,
		Modes: []PlaneModeResult{fmod}}
	for _, c := range []struct {
		name      string
		st        *PlaneState
		bpfActive bool
		want      string
	}{
		{"lsm mode failed, bpf active", failed, true, "tier 3 needs LSM mode to pass, see the lsm mode line"},
		{"pin adopted, bpf active", pinned, true, "bpf.plane pins fmod_ret"},
		{"lsm mode failed, bpf inactive", failed, false, "tier 3 needs bpf in lsm="},
		{"pin adopted, bpf inactive", pinned, false, "tier 3 needs bpf in lsm="},
	} {
		got := planeSummary(c.st, c.bpfActive)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q lacks %q", c.name, got, c.want)
		}
		if c.bpfActive && strings.Contains(got, "lsm=") {
			t.Errorf("%s: bpf is active, yet the clause blames lsm=: %q", c.name, got)
		}
	}
}

// TestPlaneSummaryDisclosesExecPinsOff is ADR 0048 (7) in doctor's line: a mode that decides but whose exec pin cell failed
// says pins are off and why; a mode whose cell passed reads as before.
func TestPlaneSummaryDisclosesExecPinsOff(t *testing.T) {
	t.Parallel()
	st := &PlaneState{Selected: string(bpfobj.PlaneLSM), Pin: config.PlaneAuto, Source: planeSourceProbed,
		Modes: []PlaneModeResult{
			{Mode: bpfobj.PlaneLSM, OK: true, Tested: true, ExecPin: &PlaneExecPinCell{OK: true}},
			{Mode: bpfobj.PlaneFmodRet, OK: true, Tested: true, ExecPin: &PlaneExecPinCell{Detail: "answer 3 (covered vector differs): ran, want killed"}},
		}}
	got := planeSummary(st, true)
	if !strings.Contains(got, "lsm mode ok, fmod_ret mode ok (exec pins off: answer 3 (covered vector differs): ran, want killed)") {
		t.Errorf("summary %q", got)
	}
}
