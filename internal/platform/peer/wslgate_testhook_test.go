// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package peer

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// TestGateSwitches: a test build's two switches each lift one hold of the gate and nothing else. The WSL switch lets
// the rule answer outside on WSL in both branches; the nested switch lets it answer outside beyond the first cgroup
// namespace outside WSL. Neither touches the other's machines, and ordinary Linux in the first namespace is outside
// whatever they are. TestGateInThisBuild holds the switches-off state, which is an ordinary build's.
// TestWSLSwitchNeedsTwoMarks holds the asymmetry: the WSL switch relaxes nothing on a machine that shows one mark.
func TestGateSwitches(t *testing.T) {
	const other = uint64(4026532208)
	t.Cleanup(func() { SetWSLRuleForTest(false); SetNestedRuleForTest(false) })
	for _, c := range []struct {
		name        string
		release     func() (string, error)
		ino         uint64
		wsl, nested bool
		cause       runscope.Cause // "" means outside
	}{
		{"WSL, own namespace, WSL switch", wslKernel, other, true, false, ""},
		{"WSL, first namespace, WSL switch", wslKernel, runscope.InitCgroupNS, true, false, ""},
		{"WSL, own namespace, nested switch only", wslKernel, other, false, true, runscope.CauseWSLLauncherUnproven},
		{"WSL, first namespace, nested switch only", wslKernel, runscope.InitCgroupNS, false, true, runscope.CauseWSLLauncherUnproven},
		{"nested, nested switch", notWSL, other, false, true, ""},
		{"nested, WSL switch only", notWSL, other, true, false, runscope.CauseSystemUnproven},
		{"ordinary Linux, both switches", notWSL, runscope.InitCgroupNS, true, true, ""},
	} {

		SetWSLRuleForTest(c.wsl)
		SetNestedRuleForTest(c.nested)
		v, _ := testProver()
		exists := noMarks // WSL is told by two marks: its kernel and its launcher's files
		if r, _ := c.release(); r != "" && r != "6.17.0-41-generic" {
			exists = wslMarksOf
		}
		g := &gated{selfReads: &selfReads{host: gateHost(c.release, exists), prover: v}, path: []byte("0::/non-systemd\n"), ino: c.ino}
		a := runscope.Decide(g)
		d := runscope.Describe(a)
		if c.cause == "" && !a.Outside() || c.cause != "" && (d.Verdict != runscope.Unknown || d.Cause != c.cause) {
			t.Errorf("%s: %s; want %q (\"\" is outside)", c.name, d, c.cause)
		}
	}
}

// TestWSLSwitchNeedsTwoMarks (ADR 0100, amended 2026-11-19, round 5): the detection is asymmetric. With the WSL switch
// on, the rule answers outside on WSL only where two marks show it; one mark (interop off: the kernel release alone;
// or the launcher's folder alone) keeps the answer withheld and keeps readiness held (wslHolds), in the first
// namespace and beyond it. With the switch off any one mark holds as before.
func TestWSLSwitchNeedsTwoMarks(t *testing.T) {
	const other = uint64(4026532208)
	t.Cleanup(func() { SetWSLRuleForTest(false) })
	for _, c := range []struct {
		name    string
		release func() (string, error)
		exists  func(string) bool
		on      bool
		cause   runscope.Cause // "" means outside
	}{
		{"two marks, switch on", wslKernel, wslRunMark, true, ""},
		{"interop off (the release alone), switch on", wslKernel, noMarks, true, runscope.CauseWSLLauncherUnproven},
		{"the launcher's folder alone, switch on", notWSL, wslRunMark, true, runscope.CauseWSLLauncherUnproven},
		{"interop off, switch off", wslKernel, noMarks, false, runscope.CauseWSLLauncherUnproven},
		{"no mark, switch on", notWSL, noMarks, true, ""},
	} {
		SetWSLRuleForTest(c.on)
		host := gateHost(c.release, c.exists)
		for _, ino := range []uint64{runscope.InitCgroupNS, other} {
			if ino == other && c.cause == "" && host.wslMarks() == 0 {
				continue // beyond the first namespace outside WSL the nested switch decides, not this one
			}
			v, _ := testProver()
			g := &gated{selfReads: &selfReads{host: host, prover: v}, path: []byte("0::/non-systemd\n"), ino: ino}
			a := runscope.Decide(g)
			d := runscope.Describe(a)
			if c.cause == "" && !a.Outside() || c.cause != "" && (d.Verdict != runscope.Unknown || d.Cause != c.cause) {
				t.Errorf("%s, namespace %d: %s; want %q (\"\" is outside)", c.name, ino, d, c.cause)
			}
		}
		if got, want := host.wslHolds(), c.cause != ""; got != want {
			t.Errorf("%s: wslHolds = %v; want %v (readiness held exactly where the answer is)", c.name, got, want)
		}
	}
}
