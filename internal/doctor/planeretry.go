// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"slices"
	"strings"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// A mode whose probe fails on a row's verdict is probed once more (ADR 0024, amendment of 2026-11-24, N131). The
// run-probe cache keeps a failed mode for the whole boot, so one false answer of a probe's syscall, or of a hook,
// would cost the machine the stronger plane until reboot. The rule keeps R21's invariant (a mode is selected only
// when every hook counted) and keeps an intermittently mis-deciding hook visible:
//
//   - the two probes fail the same rows the same way: the failure is real and stays as it was, recorded and cached;
//   - they differ in any row (the second passing included): the mode is Faulted, not selected in this run and not
//     cached, and both row sets are in the answer. A mode whose first probe failed is never selected on the strength
//     of the second.
//
// Only a row verdict is retried. A load or attach error is the kernel's repeated answer (planeProbeFailed), a known
// answer's mismatch is the table's, and a mode that passed or faulted is not probed again.

// planeModeProber is one probe of one mode.
type planeModeProber func() (PlaneModeResult, []HookResult)

// PlaneProbeAnswer is one probe's rows of a mode that was probed twice with differing answers.
type PlaneProbeAnswer struct {
	// Probe is 1 for the first probe, 2 for the second.
	Probe int `json:"probe"`
	// Result is the probe's own verdict for the mode: its detail line and whether it passed.
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Programs are the probe's rows, one per hook of the mode.
	Programs []HookResult `json:"programs"`
}

// probePlaneModeTwice is probe's answer for mode m, probed once more when it failed on a row verdict.
func probePlaneModeTwice(m bpfobj.PlaneMode, probe planeModeProber) (PlaneModeResult, []HookResult) {
	first, firstRows := probe()
	if !planeRowVerdictFailed(first, firstRows) {
		return first, firstRows
	}
	second, secondRows := probe()
	if planeRowVerdictFailed(second, secondRows) && len(planeRowDiff(firstRows, secondRows)) == 0 {
		return first, firstRows // the same rows failed the same way: a failed mode, kept as ever
	}
	return planeUnstable(m, first, firstRows, second, secondRows), firstRows
}

// planeRowVerdictFailed reports whether a mode's probe ran to its end and failed on its rows alone: it was tested,
// is neither OK nor Faulted, every row of it that this kernel has loaded, attached and made its probe syscalls, and a
// row's answer was wrong. A load or attach error leaves rows with no syscalls; a failed scope or known answer
// leaves every row right.
func planeRowVerdictFailed(res PlaneModeResult, rows []HookResult) bool {
	if !res.Tested || res.OK || res.Faulted {
		return false
	}
	failed := false
	for _, r := range rows {
		if r.Absent {
			continue
		}
		if !r.Loaded || !r.Attached || r.Inside == "" {
			return false
		}
		failed = failed || !r.OK()
	}
	return failed
}

// planeRowDiff names the hooks whose rows answered differently in two probes, in the first's order, and a hook only
// one probe has.
func planeRowDiff(a, b []HookResult) []string {
	var diff []string
	seen := map[string]bool{}
	for _, x := range a {
		seen[x.Hook] = true
		i := slices.IndexFunc(b, func(y HookResult) bool { return y.Hook == x.Hook })
		if i < 0 || !samePlaneRow(x, b[i]) {
			diff = append(diff, x.Hook)
		}
	}
	for _, y := range b {
		if !seen[y.Hook] {
			diff = append(diff, y.Hook)
		}
	}
	return diff
}

// samePlaneRow compares what a probe found of one hook: how far it got and each answer, not the wording of a detail.
func samePlaneRow(x, y HookResult) bool {
	return x.Absent == y.Absent && x.Loaded == y.Loaded && x.Attached == y.Attached && x.Ran == y.Ran &&
		x.Inside == y.Inside && x.Outside == y.Outside
}

// planeRowAnswer is one row as the faulted mode's detail words it.
func planeRowAnswer(r HookResult) string {
	if r.Absent {
		return "absent in this kernel"
	}
	if r.Inside == "" {
		return fmt.Sprintf("not exercised (loaded %t, attached %t)", r.Loaded, r.Attached)
	}
	ran := "ran"
	if !r.Ran {
		ran = "did not run"
	}
	return fmt.Sprintf("in the scratch cgroup %s, outside %s, %s", r.Inside, r.Outside, ran)
}

// planeUnstable is the Faulted answer for a mode whose two probes differ: not selected, not cached, both row sets in
// it, and in true words what each probe found.
func planeUnstable(m bpfobj.PlaneMode, first PlaneModeResult, firstRows []HookResult, second PlaneModeResult,
	secondRows []HookResult) PlaneModeResult {
	const showRows = 6
	diff := planeRowDiff(firstRows, secondRows)
	var b strings.Builder
	fmt.Fprintf(&b, "probed twice with different answers, so the mode is not used in this run and nothing is cached: "+
		"the first probe failed (%s); the second probe %s (%s)", first.Detail, planeSecondVerb(second), second.Detail)
	if len(diff) > 0 {
		b.WriteString("; rows that answered differently: ")
		for i, hook := range diff {
			if i == showRows {
				fmt.Fprintf(&b, "; and %d more", len(diff)-showRows)
				break
			}
			if i > 0 {
				b.WriteString("; ")
			}
			f, s := planeRowOf(firstRows, hook), planeRowOf(secondRows, hook)
			fmt.Fprintf(&b, "%s: first probe: %s; second probe: %s", hook, planeRowAnswerOrNone(f), planeRowAnswerOrNone(s))
		}
	}
	return PlaneModeResult{Mode: m, Tested: true, Faulted: true, Detail: b.String(),
		Fix: "a hook that answers differently on two probes of one boot is a tego or kernel fault, not a mode that fails " +
			"the same way each time: nothing is cached, so the next run probes again; report both row sets " +
			"(tego machine check --json, plane.modes[].probes) as a tego bug, or pin bpf.plane to the other mode in " +
			"the machine config",
		Probes: []PlaneProbeAnswer{
			{Probe: 1, OK: first.OK, Detail: first.Detail, Programs: firstRows},
			{Probe: 2, OK: second.OK, Detail: second.Detail, Programs: secondRows}}}
}

func planeSecondVerb(second PlaneModeResult) string {
	switch {
	case second.OK:
		return "passed"
	case second.Faulted:
		return "could not finish"
	}
	return "failed"
}

func planeRowOf(rows []HookResult, hook string) *HookResult {
	if i := slices.IndexFunc(rows, func(r HookResult) bool { return r.Hook == hook }); i >= 0 {
		return &rows[i]
	}
	return nil
}

func planeRowAnswerOrNone(r *HookResult) string {
	if r == nil {
		return "no row"
	}
	return planeRowAnswer(*r)
}

// PlaneNotes are the lines the log keeps of a plane answer: one for each mode that two probes answered differently,
// with the rows that differed, so a hook that decides inconsistently is in the record of the machine and not only
// in the output of the run that met it.
func (r *Report) PlaneNotes() []string {
	if r == nil || r.Plane == nil {
		return nil
	}
	var notes []string
	for _, mode := range r.Plane.Modes {
		if len(mode.Probes) > 0 {
			notes = append(notes, fmt.Sprintf("decision plane, %s mode: %s", mode.Mode, mode.Detail))
		}
	}
	return notes
}
