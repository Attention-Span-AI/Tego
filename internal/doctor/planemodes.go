// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// planeDecides reports whether mode result r, the latest of the modes probed in bpfobj.PlaneModes' order, already
// fixes what selectPlane picks under pin, so that the modes after it need no probe for a run to select. It mirrors
// selectPlane's walk exactly: under auto the first mode that passed is selected, whatever the later ones say, and
// under a pinned mode that mode's own pass is selected. A mode that passed only when every hook counted (r.OK,
// planeModeVerdict), the same test selectPlane makes, so the mode a run takes is still selected on a full pass
// alone (ADR 0024 (3)). Under any other pin (fanotify, which only a test build sets), or when r failed, no later
// answer is spared: selection may still read it.
func planeDecides(pin string, r PlaneModeResult) bool {
	if !r.OK {
		return false
	}
	return pin == "" || pin == config.PlaneAuto || pin == string(r.Mode)
}

// planeSkipped is the modes a run's probe left out because the mode probed last decided (planeDecides): those after
// the last mode st holds in bpfobj.PlaneModes' order, and only where that mode fixes what selection takes under st.Pin.
// A state that lacks an earlier mode (an answer adopted from a build pinned to fmod_ret, which holds its one mode)
// was not stopped by any probe: the clause "a mode that bpf.plane takes first passed" is false of it.
func planeSkipped(st *PlaneState) []bpfobj.PlaneMode {
	if st == nil || len(st.Modes) == 0 {
		return nil
	}
	last := st.Modes[len(st.Modes)-1]
	if !planeDecides(st.Pin, last) {
		return nil
	}
	var out []bpfobj.PlaneMode
	after := false
	for _, m := range bpfobj.PlaneModes {
		if after {
			if _, ok := st.mode(m); !ok {
				out = append(out, m)
			}
		}
		if m == last.Mode {
			after = true
		}
	}
	return out
}

// planeProbeEvery is a test's switch to make a run's probe cover every mode as well, for a test that holds each
// mode's own answer on a boot where a run stops after LSM mode. The product never sets it.
var planeProbeEvery bool

// probePlaneModes runs probe for each plane mode in bpfobj.PlaneModes' order, timing each as
// "probe.plane.<mode>.total", and returns their results and rows in that order. A run (keep) stops after the mode
// that selection takes (planeDecides): the later modes' probe costs seconds on a kernel whose tracing links close
// one grace period at a time, and no run of this machine's bpf.plane reads them. Doctor's own scope (keep false)
// probes every mode.
func probePlaneModes(pin string, keep bool,
	probe func(bpfobj.PlaneMode) (PlaneModeResult, []HookResult)) ([]PlaneModeResult, []HookResult) {
	var modes []PlaneModeResult
	var rows []HookResult
	for _, m := range bpfobj.PlaneModes {
		endMode := startphase.Begin(nil, "probe.plane."+string(m)+".total")
		res, modeRows := probe(m)
		endMode()
		modes = append(modes, res)
		rows = append(rows, modeRows...)
		if keep && !planeProbeEvery && planeDecides(pin, res) {
			break
		}
	}
	return modes, rows
}

// probePlaneModesRetried is probePlane's loop: each mode's probe is probePlaneModeTwice around one probe (a mode
// that fails on a row verdict is probed once more, before any later mode is probed), and probePlaneModes decides
// after that whole answer whether a run goes on to the next mode. A mode that did not pass, failed or Faulted, never
// stops the loop, so a Faulted LSM mode is followed by fmod_ret mode's probe.
func probePlaneModesRetried(pin string, keep bool,
	probe func(bpfobj.PlaneMode) (PlaneModeResult, []HookResult)) ([]PlaneModeResult, []HookResult) {
	return probePlaneModes(pin, keep, func(m bpfobj.PlaneMode) (PlaneModeResult, []HookResult) {
		return probePlaneModeTwice(m, func() (PlaneModeResult, []HookResult) { return probe(m) })
	})
}
