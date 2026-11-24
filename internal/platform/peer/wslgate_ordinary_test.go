// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package peer

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// TestOrdinaryBuildOnTwoMarkWSL: an ordinary build has the WSL switch on (ADR 0100, amended when it was switched on, from
// the guest rows W-N2-*, W-E4-ALIAS, W-E4-DRIVE and W-E4-WSLG-SOCKETS) and the nested switch off, with nothing a
// caller can set. Where WSL shows two of its marks the gate lets the rule's answer through, in the kernel's first
// cgroup namespace and in the distribution's own, and readiness is not held; where it shows one, every hold stays
// (round 5), in both; outside WSL nothing changed: outside in the first namespace, and the answer before the rule
// (unknown, system-unproven) beyond it. This file is not part of a test build, whose switches start off and which
// TestGateSwitches, TestWSLSwitchNeedsTwoMarks and TestGateInThisBuild hold in both states.
func TestOrdinaryBuildOnTwoMarkWSL(t *testing.T) {
	if !wslRuleOn() || nestedRuleOn() {
		t.Fatalf("an ordinary build's switches: WSL %v, nested %v; want on and off", wslRuleOn(), nestedRuleOn())
	}
	const other = uint64(4026532208)
	for _, c := range []struct {
		name     string
		release  func() (string, error)
		exists   func(string) bool
		marks    int
		holds    bool
		first    runscope.Cause // the gate's answer in the first cgroup namespace, "" for none withheld
		own      runscope.Cause // and in another one
		decision runscope.Cause // what Decide answers when every other fact holds, in another namespace: "" is outside
	}{
		{"WSL: kernel, folder and binfmt entry", wslKernel, wslMarksOf, 3, false, "", "", ""},
		{"WSL: kernel and folder", wslKernel, wslRunMark, 2, false, "", "", ""},
		{"WSL: kernel and binfmt entry", wslKernel, wslBinfmt, 2, false, "", "", ""},
		{"a custom kernel with the folder and the binfmt entry", notWSL, wslMarksOf, 2, false, "", "", ""},
		{"one mark: the kernel alone (interop off)", wslKernel, noMarks, 1, true,
			runscope.CauseWSLLauncherUnproven, runscope.CauseWSLLauncherUnproven, runscope.CauseWSLLauncherUnproven},
		{"one mark: the folder alone", notWSL, wslRunMark, 1, true,
			runscope.CauseWSLLauncherUnproven, runscope.CauseWSLLauncherUnproven, runscope.CauseWSLLauncherUnproven},
		{"one mark: a binfmt entry alone", notWSL, wslBinfmt, 1, true,
			runscope.CauseWSLLauncherUnproven, runscope.CauseWSLLauncherUnproven, runscope.CauseWSLLauncherUnproven},
		{"not WSL", notWSL, noMarks, 0, false, "", runscope.CauseSystemUnproven, runscope.CauseSystemUnproven},
	} {
		h := gateHost(c.release, c.exists)
		if got := h.wslMarks(); got < c.marks || c.marks < 2 && got != c.marks {
			t.Errorf("%s: %d marks; want %d", c.name, got, c.marks)
		}
		if got := h.wslHolds(); got != c.holds {
			t.Errorf("%s: wslHolds (the readiness hold and the gate) = %v; want %v", c.name, got, c.holds)
		}
		for _, w := range []struct {
			first bool
			want  runscope.Cause
		}{{true, c.first}, {false, c.own}} {
			cause, held := h.withheld(w.first)
			if held != (w.want != "") || cause != w.want {
				t.Errorf("%s: withheld(first=%v) = %q, %v; want %q", c.name, w.first, cause, held, w.want)
			}
		}
		v, _ := testProver()
		g := &gated{selfReads: &selfReads{host: h, prover: v}, path: []byte("0::/non-systemd\n"), ino: other}
		a := runscope.Decide(g)
		d := runscope.Describe(a)
		if c.decision == "" && !a.Outside() || c.decision != "" && (d.Verdict != runscope.Unknown || d.Cause != c.decision) {
			t.Errorf("%s: Decide in the distribution's own namespace: %s; want %q (\"\" is outside)", c.name, d, c.decision)
		}
	}
}
