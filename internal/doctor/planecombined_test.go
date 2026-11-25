// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The retry (probePlaneModeTwice, ADR 0024 retry amendment) and the run's stop at the mode selection takes
// (probePlaneModes) meet in probePlane: each mode's probe is the retry around one probe, and the loop decides after
// that whole answer. These tests run both with the scripted fake prober the two sets of unit tests use.

// modeAnswerOf is what one probe of mode m finds: its rows, with the first deciding hook's row answered wrongly
// (its inside answer is "passed" where the hook refuses) when wrong is 1, or a second hook's row when wrong is 2, and
// the verdict planeModeVerdict gives them.
func modeAnswerOf(m bpfobj.PlaneMode, wrong int) fakeModeAnswer {
	var rows []HookResult
	for _, r := range passingPlaneRows() {
		if r.Plane == m {
			rows = append(rows, r)
		}
	}
	seen := 0
	for i := range rows {
		if rows[i].Decides {
			seen++
			if seen == wrong {
				rows[i].Inside = planePassed
			}
		}
	}
	return fakeModeAnswer{res: planeModeVerdict(m, rows, planeScope{Inside: 1}, passingKnown()), rows: rows}
}

// combinedProbe is probePlane's loop (probePlaneModesRetried) with the scripted prober of each mode. It returns the state selection works on, the probes each mode got in order, and the rows.
func combinedProbe(pin string, keep bool, script map[bpfobj.PlaneMode][]fakeModeAnswer) (*PlaneState, []bpfobj.PlaneMode, []HookResult) {
	fakes := map[bpfobj.PlaneMode]*fakeModeProbe{}
	for m, a := range script {
		fakes[m] = &fakeModeProbe{answers: a}
	}
	var order []bpfobj.PlaneMode
	modes, rows := probePlaneModesRetried(pin, keep, func(m bpfobj.PlaneMode) (PlaneModeResult, []HookResult) {
		order = append(order, m)
		return fakes[m].probe()
	})
	st := passingPlane(pin)
	st.Modes = modes
	selectPlane(st)
	return st, order, rows
}

func TestPlaneRetryAndRunStopCompose(t *testing.T) {
	const lsm, fmod = bpfobj.PlaneLSM, bpfobj.PlaneFmodRet
	ok := func(m bpfobj.PlaneMode) fakeModeAnswer { return modeAnswerOf(m, 0) }
	bad := func(m bpfobj.PlaneMode) fakeModeAnswer { return modeAnswerOf(m, 1) }
	other := func(m bpfobj.PlaneMode) fakeModeAnswer { return modeAnswerOf(m, 2) }
	for _, a := range []fakeModeAnswer{ok(lsm), bad(lsm), other(lsm), ok(fmod), bad(fmod)} {
		if a.res.Faulted {
			t.Fatalf("a fixture faulted: %+v", a.res)
		}
	}
	if !ok(lsm).res.OK || bad(lsm).res.OK || !ok(fmod).res.OK || bad(fmod).res.OK {
		t.Fatal("the fixtures' verdicts are wrong")
	}

	cases := []struct {
		name   string
		script map[bpfobj.PlaneMode][]fakeModeAnswer
		order  []bpfobj.PlaneMode // the probes a run makes, under auto
		doctor []bpfobj.PlaneMode // the probes doctor makes
		want   string             // selected
		lsmOK  bool
		lsmFlt bool
		fmod   bool // fmod_ret mode is in the answer
		cached bool // the run-probe cache keeps a plane answer
	}{
		{"LSM passes", map[bpfobj.PlaneMode][]fakeModeAnswer{lsm: {ok(lsm)}, fmod: {ok(fmod)}},
			[]bpfobj.PlaneMode{lsm}, []bpfobj.PlaneMode{lsm, fmod}, "lsm", true, false, false, true},
		{"LSM fails twice the same way, fmod_ret passes",
			map[bpfobj.PlaneMode][]fakeModeAnswer{lsm: {bad(lsm), bad(lsm)}, fmod: {ok(fmod)}},
			[]bpfobj.PlaneMode{lsm, lsm, fmod}, []bpfobj.PlaneMode{lsm, lsm, fmod}, "fmod_ret", false, false, true, true},
		{"LSM answers differently, fmod_ret passes",
			map[bpfobj.PlaneMode][]fakeModeAnswer{lsm: {bad(lsm), other(lsm)}, fmod: {ok(fmod)}},
			[]bpfobj.PlaneMode{lsm, lsm, fmod}, []bpfobj.PlaneMode{lsm, lsm, fmod}, "fmod_ret", false, true, true, false},
		{"LSM passes on the second probe: faulted, fmod_ret decides",
			map[bpfobj.PlaneMode][]fakeModeAnswer{lsm: {bad(lsm), ok(lsm)}, fmod: {ok(fmod)}},
			[]bpfobj.PlaneMode{lsm, lsm, fmod}, []bpfobj.PlaneMode{lsm, lsm, fmod}, "fmod_ret", false, true, true, false},
		{"both fail the same way",
			map[bpfobj.PlaneMode][]fakeModeAnswer{lsm: {bad(lsm), bad(lsm)}, fmod: {bad(fmod), bad(fmod)}},
			[]bpfobj.PlaneMode{lsm, lsm, fmod, fmod}, []bpfobj.PlaneMode{lsm, lsm, fmod, fmod}, PlaneFanotify, false, false, true, true},
	}
	for _, tc := range cases {
		st, order, rows := combinedProbe(config.PlaneAuto, true, tc.script)
		if !equalModes(order, tc.order) {
			t.Errorf("%s: a run probed %v, want %v", tc.name, order, tc.order)
		}
		if st.Selected != tc.want {
			t.Errorf("%s: selected %q (%s), want %q", tc.name, st.Selected, st.SelectedWhy, tc.want)
		}
		l, _ := st.mode(lsm)
		if l.OK != tc.lsmOK || l.Faulted != tc.lsmFlt {
			t.Errorf("%s: LSM mode ok %v faulted %v, want %v %v", tc.name, l.OK, l.Faulted, tc.lsmOK, tc.lsmFlt)
		}
		if _, has := st.mode(fmod); has != tc.fmod {
			t.Errorf("%s: fmod_ret mode in the answer %v, want %v", tc.name, has, tc.fmod)
		}
		if tc.lsmFlt && (len(l.Probes) != 2 || l.OK || st.Selected == "lsm") {
			t.Errorf("%s: a faulted LSM mode holds %d probes, ok %v, selected %q", tc.name, len(l.Probes), l.OK, st.Selected)
		}
		if st.faulted() != tc.lsmFlt {
			t.Errorf("%s: the plane is faulted %v, want %v", tc.name, st.faulted(), tc.lsmFlt)
		}
		// What selection took is a mode that passed on its own, never one of a first probe that failed.
		if st.Selected != PlaneFanotify {
			if r, found := st.mode(bpfobj.PlaneMode(st.Selected)); !found || !r.OK || len(r.Probes) != 0 {
				t.Errorf("%s: selected %q without a clean pass of its own", tc.name, st.Selected)
			}
		}
		// Doctor's scope keeps no cache and reports every mode, each with the retry.
		dst, dorder, drows := combinedProbe(config.PlaneAuto, false, tc.script)
		if !equalModes(dorder, tc.doctor) || len(dst.Modes) != 2 || dst.Selected != tc.want {
			t.Errorf("%s: doctor probed %v with %d modes, selected %q; want %v, 2, %q", tc.name, dorder, len(dst.Modes),
				dst.Selected, tc.doctor, tc.want)
		}
		_ = drows

		c, _ := testCache(t)
		k := testKey()
		p, hooks, fan, fs := vouchingAnswer()
		c.record(k, p, hooks, st, rows, fan, fs)
		e, found := c.load(k)
		if !found {
			t.Fatalf("%s: the tier-2 half was not kept", tc.name)
		}
		if (e.Plane != nil) != tc.cached {
			t.Errorf("%s: the cache holds a plane answer %v, want %v", tc.name, e.Plane != nil, tc.cached)
		}
		if e.Plane != nil && len(e.Plane.Modes) != len(st.Modes) {
			t.Errorf("%s: the cache holds %d modes, the probe %d", tc.name, len(e.Plane.Modes), len(st.Modes))
		}
	}
}

// TestPlaneRetryUnderPinsAndStop: the stop never hides a failed pinned mode, and the retry runs before the next mode
// whatever the pin.
func TestPlaneRetryUnderPinsAndStop(t *testing.T) {
	const lsm, fmod = bpfobj.PlaneLSM, bpfobj.PlaneFmodRet
	script := map[bpfobj.PlaneMode][]fakeModeAnswer{
		lsm:  {modeAnswerOf(lsm, 1), modeAnswerOf(lsm, 2)},
		fmod: {modeAnswerOf(fmod, 0)},
	}
	// Pinned to lsm: LSM is Faulted (differing answers), fmod_ret is probed anyway and not selected for a pin on lsm.
	st, order, _ := combinedProbe(config.PlaneLSM, true, script)
	if !equalModes(order, []bpfobj.PlaneMode{lsm, lsm, fmod}) || st.Selected != PlaneFanotify ||
		!strings.Contains(st.SelectedWhy, "pins lsm") {
		t.Errorf("pin lsm: probed %v, selected %q (%s)", order, st.Selected, st.SelectedWhy)
	}
	// Pinned to fmod_ret with LSM passing: LSM is probed once, fmod_ret as well, and fmod_ret is selected.
	pass := map[bpfobj.PlaneMode][]fakeModeAnswer{lsm: {modeAnswerOf(lsm, 0)}, fmod: {modeAnswerOf(fmod, 0)}}
	st, order, _ = combinedProbe(config.PlaneFmodRet, true, pass)
	if !equalModes(order, []bpfobj.PlaneMode{lsm, fmod}) || st.Selected != "fmod_ret" {
		t.Errorf("pin fmod_ret: probed %v, selected %q", order, st.Selected)
	}
	// Pinned to fmod_ret, fmod_ret failing the same way twice: probed twice, nothing selected.
	fail := map[bpfobj.PlaneMode][]fakeModeAnswer{lsm: {modeAnswerOf(lsm, 0)}, fmod: {modeAnswerOf(fmod, 1), modeAnswerOf(fmod, 1)}}
	st, order, _ = combinedProbe(config.PlaneFmodRet, true, fail)
	if !equalModes(order, []bpfobj.PlaneMode{lsm, fmod, fmod}) || st.Selected != PlaneFanotify || st.faulted() {
		t.Errorf("pin fmod_ret failing: probed %v, selected %q, faulted %v", order, st.Selected, st.faulted())
	}
}

func equalModes(a, b []bpfobj.PlaneMode) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
