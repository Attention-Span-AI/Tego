// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// fakeModeProbe answers from a script, one answer per probe, and counts the probes.
type fakeModeProbe struct {
	answers []fakeModeAnswer
	calls   int
}

type fakeModeAnswer struct {
	res  PlaneModeResult
	rows []HookResult
}

func (f *fakeModeProbe) probe() (PlaneModeResult, []HookResult) {
	a := f.answers[min(f.calls, len(f.answers)-1)]
	f.calls++
	// Each probe makes its own rows, as probePlaneMode does.
	return a.res, append([]HookResult(nil), a.rows...)
}

// lsmRows are the LSM mode's rows of a passing machine.
func lsmRows() []HookResult { return passingPlaneRows()[:len(bpfobj.PlaneHooks)] }

// answerOf is what a probe of mode LSM finds when rows are as given and the known answers match.
func answerOf(rows []HookResult) fakeModeAnswer {
	return fakeModeAnswer{res: planeModeVerdict(bpfobj.PlaneLSM, rows, planeScope{Inside: 1}, passingKnown()), rows: rows}
}

// withRow is rows with the key_permission row edited.
func withRow(rows []HookResult, edit func(*HookResult)) []HookResult {
	out := append([]HookResult(nil), rows...)
	for i := range out {
		if strings.HasSuffix(out[i].Hook, "key_permission") {
			edit(&out[i])
		}
	}
	return out
}

// keyInsidePassed is the row of the 2026-11-24 flake: the hook let the key's update by.
func keyInsidePassed(rows []HookResult) []HookResult {
	return withRow(rows, func(r *HookResult) { r.Inside = planePassed })
}

func TestPlaneRetryMatrix(t *testing.T) {
	failed := answerOf(keyInsidePassed(lsmRows()))
	passed := answerOf(lsmRows())
	if !passed.res.OK || failed.res.OK || failed.res.Faulted {
		t.Fatalf("the fixtures are wrong: passed %+v failed %+v", passed.res, failed.res)
	}
	differently := answerOf(withRow(lsmRows(), func(r *HookResult) { r.Inside, r.Outside = planeRefused, planeRefused }))
	loadErr := PlaneModeResult{Mode: bpfobj.PlaneLSM, Tested: true, Detail: "load rdonly lsm: the verifier refused"}
	// A load error that the kernel repeats: no row got to its syscalls.
	unloaded := lsmRows()
	for i := range unloaded {
		unloaded[i].Loaded, unloaded[i].Attached, unloaded[i].Ran, unloaded[i].Inside, unloaded[i].Outside = false, false, false, "", ""
	}
	faulted := PlaneModeResult{Mode: bpfobj.PlaneLSM, Tested: true, Faulted: true, Detail: "fixtures: no space"}
	// Every row is right and a known answer is not: not a row verdict.
	wrongKnown := passingKnown()
	wrongKnown[0].Got = "passed"
	known := fakeModeAnswer{res: planeModeVerdict(bpfobj.PlaneLSM, lsmRows(), planeScope{Inside: 1}, wrongKnown), rows: lsmRows()}
	if known.res.OK || known.res.Faulted {
		t.Fatalf("the known-answer fixture is wrong: %+v", known.res)
	}

	cases := []struct {
		name    string
		answers []fakeModeAnswer
		calls   int
		faulted bool
		ok      bool
		wantRes *PlaneModeResult // the result must be this one exactly, when set
	}{
		{"pass: no retry", []fakeModeAnswer{passed, failed}, 1, false, true, &passed.res},
		{"fail then the same fail: cached failure, one extra probe", []fakeModeAnswer{failed, failed}, 2, false, false, &failed.res},
		{"fail then pass: faulted, never selected on the second", []fakeModeAnswer{failed, passed}, 2, true, false, nil},
		{"fail then other rows: faulted", []fakeModeAnswer{failed, differently}, 2, true, false, nil},
		{"fail then a load error: faulted", []fakeModeAnswer{failed, {res: loadErr, rows: unloaded}}, 2, true, false, nil},
		{"load error: no retry", []fakeModeAnswer{{res: loadErr, rows: unloaded}, passed}, 1, false, false, &loadErr},
		{"faulted: no retry", []fakeModeAnswer{{res: faulted, rows: lsmRows()}, passed}, 1, true, false, &faulted},
		{"a known answer's mismatch: no retry", []fakeModeAnswer{known, passed}, 1, false, false, &known.res},
	}
	for _, tc := range cases {
		f := &fakeModeProbe{answers: tc.answers}
		res, rows := probePlaneModeTwice(bpfobj.PlaneLSM, f.probe)
		if f.calls != tc.calls || res.Faulted != tc.faulted || res.OK != tc.ok {
			t.Errorf("%s: %d probes, faulted %v, ok %v; want %d, %v, %v (%s)", tc.name, f.calls, res.Faulted, res.OK,
				tc.calls, tc.faulted, tc.ok, res.Detail)
		}
		if tc.wantRes != nil && !jsonEqual(res, *tc.wantRes) {
			t.Errorf("%s: the result changed: %+v, want %+v", tc.name, res, *tc.wantRes)
		}
		if len(rows) == 0 {
			t.Errorf("%s: no rows returned", tc.name)
		}
		if tc.faulted && tc.calls == 2 && (len(res.Probes) != 2 || res.OK || res.Fix == "") {
			t.Errorf("%s: probes %d, ok %v, fix %q: want both row sets and a fix", tc.name, len(res.Probes), res.OK, res.Fix)
		}
		if !tc.faulted && len(res.Probes) != 0 {
			t.Errorf("%s: a mode that is not faulted carries %d probe row sets", tc.name, len(res.Probes))
		}
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// TestPlaneRetryFailThenPassIsNotSelectedOrCached: the first probe failed, the second passed: the mode is Faulted, so
// tier selection does not take it (the fmod_ret mode that passed decides), the run-probe cache keeps no plane answer,
// and the output names both probes.
func TestPlaneRetryFailThenPassIsNotSelectedOrCached(t *testing.T) {
	f := &fakeModeProbe{answers: []fakeModeAnswer{answerOf(keyInsidePassed(lsmRows())), answerOf(lsmRows())}}
	res, rows := probePlaneModeTwice(bpfobj.PlaneLSM, f.probe)
	st := passingPlane("")
	st.Modes[0] = res
	selectPlane(st)
	if st.Selected == string(bpfobj.PlaneLSM) || !st.faulted() {
		t.Fatalf("selected %q, faulted %v: a mode whose first probe failed was selected", st.Selected, st.faulted())
	}
	c, path := testCache(t)
	k := testKey()
	p, hooks, fan, fs := vouchingAnswer()
	c.record(k, p, hooks, st, rows, fan, fs)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the faulted plane dropped the tier-2 entry: %v", err)
	}
	if e, ok := c.load(k); !ok || e.Plane != nil || e.PlaneRows != nil {
		t.Errorf("a plane answer holding two different probes was cached (read %v, plane %+v, rows %d)", ok, e.Plane, len(e.PlaneRows))
	}
	for _, want := range []string{"probed twice with different answers", "not used in this run", "nothing is cached",
		"first probe failed", "second probe passed", "lsm/key_permission: first probe: in the scratch cgroup passed",
		"second probe: in the scratch cgroup refused"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("the detail does not say %q: %s", want, res.Detail)
		}
	}
}

// TestPlaneRetryShowsBothProbesInTextAndJSON: doctor's plain text carries the faulted mode's words (the line of the
// tier the mode would have given), and --json carries both probes' rows under the mode.
func TestPlaneRetryShowsBothProbesInTextAndJSON(t *testing.T) {
	f := &fakeModeProbe{answers: []fakeModeAnswer{answerOf(keyInsidePassed(lsmRows())), answerOf(lsmRows())}}
	res, rows := probePlaneModeTwice(bpfobj.PlaneLSM, f.probe)
	rep := state(func(s *probeState) {
		s.plane = passingPlane(config.PlaneAuto)
		s.plane.Modes[0] = res
		selectPlane(s.plane)
		s.hooks = rows
	}).report(nil, "")

	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"probed twice with different answers", "first probe: in the scratch cgroup passed",
		"second probe: in the scratch cgroup refused"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the plain text does not say %q:\n%s", want, text.String())
		}
	}

	var js bytes.Buffer
	if err := writeJSONForTest(&js, rep); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Plane struct {
			Modes []struct {
				Mode    string
				Faulted bool
				Probes  []struct {
					Probe    int
					OK       bool
					Detail   string
					Programs []HookResult
				}
			}
		}
	}
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	m := got.Plane.Modes[0]
	if m.Mode != "lsm" || !m.Faulted || len(m.Probes) != 2 || m.Probes[0].Probe != 1 || m.Probes[1].Probe != 2 ||
		m.Probes[0].OK || !m.Probes[1].OK || len(m.Probes[0].Programs) != len(rows) || len(m.Probes[1].Programs) != len(rows) {
		t.Fatalf("--json does not carry both probes' rows under the mode: %+v", m)
	}
	row := func(rs []HookResult) HookResult {
		for _, r := range rs {
			if strings.HasSuffix(r.Hook, "key_permission") {
				return r
			}
		}
		return HookResult{}
	}
	if row(m.Probes[0].Programs).Inside != planePassed || row(m.Probes[1].Programs).Inside != planeRefused {
		t.Errorf("--json's two key_permission rows are %+v and %+v", row(m.Probes[0].Programs), row(m.Probes[1].Programs))
	}

	notes := rep.PlaneNotes()
	if len(notes) != 1 || !strings.Contains(notes[0], "decision plane, lsm mode: probed twice with different answers") ||
		!strings.Contains(notes[0], "lsm/key_permission") {
		t.Errorf("the log lines are %q", notes)
	}
	if n := passingReport(t).PlaneNotes(); len(n) != 0 {
		t.Errorf("a plane with no retried mode wrote log lines: %q", n)
	}
}

func passingReport(t *testing.T) *Report {
	t.Helper()
	return state(func(s *probeState) { s.plane = passingPlane("") }).report(nil, "")
}

// TestPlaneRetryOnlyRowVerdictsAreRetried: the retry's condition, row by row.
func TestPlaneRetryOnlyRowVerdictsAreRetried(t *testing.T) {
	notAttached := lsmRows()
	notAttached[0].Attached = false
	notRun := withRow(lsmRows(), func(r *HookResult) { r.Ran = false })
	for _, tc := range []struct {
		name string
		res  PlaneModeResult
		rows []HookResult
		want bool
	}{
		{"a wrong answer", answerOf(keyInsidePassed(lsmRows())).res, keyInsidePassed(lsmRows()), true},
		{"a program that never ran", answerOf(notRun).res, notRun, true},
		{"a hook that did not attach", PlaneModeResult{Tested: true}, notAttached, false},
		{"not tested", PlaneModeResult{}, keyInsidePassed(lsmRows()), false},
		{"passed", answerOf(lsmRows()).res, lsmRows(), false},
		{"a fixture's fault", PlaneModeResult{Tested: true, Faulted: true}, keyInsidePassed(lsmRows()), false},
	} {
		if got := planeRowVerdictFailed(tc.res, tc.rows); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
