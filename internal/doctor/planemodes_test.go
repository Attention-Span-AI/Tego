// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// planeOutcomes is every pass/fail pair a two-mode probe can answer.
var planeOutcomes = []struct {
	name     string
	lsm, fmo bool
}{
	{"both pass", true, true}, {"lsm only", true, false}, {"fmod_ret only", false, true}, {"neither", false, false},
}

// planePins is every bpf.plane value selectPlane reads, "" meaning unset.
var planePins = []string{"", config.PlaneAuto, config.PlaneLSM, config.PlaneFmodRet, PlaneFanotify}

// fakeRunModeProbe answers each mode by ok and records the modes it was asked about.
func fakeRunModeProbe(ok map[bpfobj.PlaneMode]bool, asked *[]bpfobj.PlaneMode) func(bpfobj.PlaneMode) (PlaneModeResult, []HookResult) {
	return func(m bpfobj.PlaneMode) (PlaneModeResult, []HookResult) {
		*asked = append(*asked, m)
		res := PlaneModeResult{Mode: m, Tested: true, OK: ok[m], Detail: "fake " + string(m)}
		return res, []HookResult{{Hook: "row-" + string(m), Plane: m}}
	}
}

// probedPlane is the PlaneState probePlane builds from probePlaneModes' answers under pin.
func probedPlane(pin string, keep bool, ok map[bpfobj.PlaneMode]bool) (*PlaneState, []bpfobj.PlaneMode, []HookResult) {
	var asked []bpfobj.PlaneMode
	modes, rows := probePlaneModes(pin, keep, fakeRunModeProbe(ok, &asked))
	st := &PlaneState{Pin: pin, Source: planeSourceProbed, Modes: modes}
	selectPlane(st)
	return st, asked, rows
}

// TestARunStopsProbingAtTheModeSelectionTakes: under bpf.plane auto or lsm a run whose LSM mode passed every hook
// never probes fmod_ret mode, which on a kernel that closes tracing links one grace period at a time is seconds of
// every cold start; in every other case (LSM failed, a pin naming fmod_ret, the fanotify pin) it probes what it
// did before, and doctor's own scope (keep false) probes both modes always.
func TestARunStopsProbingAtTheModeSelectionTakes(t *testing.T) {
	for _, pin := range planePins {
		for _, o := range planeOutcomes {
			ok := map[bpfobj.PlaneMode]bool{bpfobj.PlaneLSM: o.lsm, bpfobj.PlaneFmodRet: o.fmo}
			t.Run(fmt.Sprintf("pin %q, %s", pin, o.name), func(t *testing.T) {
				all := []bpfobj.PlaneMode{bpfobj.PlaneLSM, bpfobj.PlaneFmodRet}
				_, asked, rows := probedPlane(pin, false, ok)
				if !reflect.DeepEqual(asked, all) || len(rows) != 2 {
					t.Fatalf("doctor's scope probed %v, rows %d; want every mode", asked, len(rows))
				}
				want := all
				if o.lsm && (pin == "" || pin == config.PlaneAuto || pin == config.PlaneLSM) {
					want = all[:1]
				}
				_, asked, rows = probedPlane(pin, true, ok)
				if !reflect.DeepEqual(asked, want) || len(rows) != len(want) {
					t.Errorf("a run probed %v with %d rows, want %v", asked, len(rows), want)
				}
			})
		}
	}
}

// TestStoppingAtTheSelectedModeNeverChangesSelection is ADR 0024 (3)'s guard: a mode is selected only when every
// hook counted, and the probe that leaves a later mode unread selects exactly what the probe of both modes does,
// with the same reason, for every pin and every pass/fail pair of the two modes.
func TestStoppingAtTheSelectedModeNeverChangesSelection(t *testing.T) {
	for _, pin := range planePins {
		for _, o := range planeOutcomes {
			ok := map[bpfobj.PlaneMode]bool{bpfobj.PlaneLSM: o.lsm, bpfobj.PlaneFmodRet: o.fmo}
			full, _, _ := probedPlane(pin, false, ok)
			run, _, _ := probedPlane(pin, true, ok)
			if run.Selected != full.Selected || run.SelectedWhy != full.SelectedWhy {
				t.Errorf("pin %q, %s: a run selects %q (%q), the full probe %q (%q)", pin, o.name,
					run.Selected, run.SelectedWhy, full.Selected, full.SelectedWhy)
			}
			// The selected mode is only ever one whose own result passed.
			if run.Selected != PlaneFanotify {
				if r, found := run.mode(bpfobj.PlaneMode(run.Selected)); !found || !r.OK {
					t.Errorf("pin %q, %s: selected %q without a passing result of its own", pin, o.name, run.Selected)
				}
			}
		}
	}
}

// TestAStateLeftWithoutFmodRetAnswersOnlyWhatItHolds: the answer of a run that stopped after LSM mode is read by a
// later run under auto or lsm and is no answer under a pin naming fmod_ret, which probes (the cache key does not hold
// bpf.plane), and its D7 line says the mode was not probed.
func TestAStateLeftWithoutFmodRetAnswersOnlyWhatItHolds(t *testing.T) {
	st, _, _ := probedPlane(config.PlaneAuto, true,
		map[bpfobj.PlaneMode]bool{bpfobj.PlaneLSM: true, bpfobj.PlaneFmodRet: true})
	if len(st.Modes) != 1 || st.Selected != "lsm" {
		t.Fatalf("state %+v, want LSM mode alone, selected", st)
	}
	for pin, want := range map[string]bool{"": true, config.PlaneAuto: true, config.PlaneLSM: true,
		config.PlaneFmodRet: false} {
		if got := st.answers(pin); got != want {
			t.Errorf("answers(%q) = %v, want %v", pin, got, want)
		}
	}
	if got := planeSkipped(st); !reflect.DeepEqual(got, []bpfobj.PlaneMode{bpfobj.PlaneFmodRet}) {
		t.Errorf("skipped %v, want fmod_ret", got)
	}
	line := planeSummary(st, true)
	if !strings.Contains(line, "lsm mode ok") || !strings.Contains(line, "fmod_ret mode not probed") {
		t.Errorf("the D7 line does not say fmod_ret mode was left unprobed: %s", line)
	}
	if full := planeSummary(passingPlane(config.PlaneAuto), true); strings.Contains(full, "not probed") {
		t.Errorf("a probe of both modes reports one as unprobed: %s", full)
	}
}

// TestAnAnswerAdoptedFromAPinnedBuildDoesNotClaimAnEarlierModeWasSkipped: a run-cache hit on an answer that a build
// pinned to fmod_ret recorded (it holds that one mode; auto picks fmod_ret only after LSM failed) was stopped by no
// probe, so D7 must not say LSM mode was left unprobed because a mode passed first.
func TestAnAnswerAdoptedFromAPinnedBuildDoesNotClaimAnEarlierModeWasSkipped(t *testing.T) {
	for _, pin := range []string{"", config.PlaneAuto, config.PlaneLSM, config.PlaneFmodRet} {
		for _, src := range []string{planeSourceRunCache, planeSourceProbed} {
			st := &PlaneState{Pin: pin, Source: src, Modes: []PlaneModeResult{{Mode: bpfobj.PlaneFmodRet, OK: true}}}
			selectPlane(st)
			if got := planeSkipped(st); len(got) != 0 {
				t.Errorf("pin %q, source %s: skipped %v, want none", pin, src, got)
			}
			if line := planeSummary(st, true); strings.Contains(line, "not probed") {
				t.Errorf("pin %q, source %s: D7 says a mode was not probed: %s", pin, src, line)
			}
		}
	}
	// A failed last mode decides nothing: no clause even where a later mode exists.
	st := &PlaneState{Pin: config.PlaneAuto, Source: planeSourceRunCache, Modes: []PlaneModeResult{{Mode: bpfobj.PlaneLSM}}}
	if got := planeSkipped(st); len(got) != 0 {
		t.Errorf("a failed LSM mode as the last answer: skipped %v, want none", got)
	}
}

// TestACachedAnswerWithoutFmodRetIsProbedAgainForAPinNamingIt drives the run-probe cache through scope.run: the
// first run (auto) probes once and keeps an LSM-only answer; the second (auto) reads it without a probe; a third
// whose bpf.plane pins fmod_ret probes, keeps the answer holding both, and the next auto run reads that.
func TestACachedAnswerWithoutFmodRetIsProbedAgainForAPinNamingIt(t *testing.T) {
	cache, _ := testCache(t)
	var c calls
	chk := passingChecks(&c)
	chk.plane = func(_ bool, _ int, _, pin string, keep bool) (*PlaneState, []HookResult) {
		c.plane++
		st, _, rows := probedPlane(pin, keep, map[bpfobj.PlaneMode]bool{bpfobj.PlaneLSM: true, bpfobj.PlaneFmodRet: true})
		st.Env = passingPlane(pin).Env
		st.Build, st.BuildWhy, st.BuildHash = bpfobj.ObjectPlaneRdonly, "bpf_rdonly_cast is in BTF", "0123abcd4567ef89"
		return st, rows
	}
	run := func(pin string) probeState {
		return scope{reach: backend.TierCgroup, root: true, checks: chk, cache: cache, planePin: pin}.run(context.Background())
	}
	step := func(pin string, wantProbes int, wantSelected string, wantModes int) {
		t.Helper()
		before := c.plane
		st := run(pin)
		if got := c.plane - before; got != wantProbes {
			t.Errorf("pin %q: %d plane probes, want %d", pin, got, wantProbes)
		}
		if st.plane == nil || st.plane.Selected != wantSelected || len(st.plane.Modes) != wantModes {
			t.Errorf("pin %q: plane %+v, want %q selected over %d modes", pin, st.plane, wantSelected, wantModes)
		}
	}
	step(config.PlaneAuto, 1, "lsm", 1)
	if e, _, ok := cache.loadIdentified(testKey()); !ok || e.Plane == nil || len(e.Plane.Modes) != 1 {
		t.Fatalf("the cache kept %+v, want an answer holding LSM mode alone", e.Plane)
	}
	step(config.PlaneAuto, 0, "lsm", 1)
	step(config.PlaneLSM, 0, "lsm", 1)
	step(config.PlaneFmodRet, 1, "fmod_ret", 2)
	step(config.PlaneAuto, 0, "lsm", 2)
}
