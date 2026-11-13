// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// TestReadLSMRecursionReadsTheKernelsOwnSymbols: the exemption is read from kallsyms, a compiler's copy of the symbol
// counts, a similar name does not, and a table that cannot be read is no exemption.
func TestReadLSMRecursionReadsTheKernelsOwnSymbols(t *testing.T) {
	dir := t.TempDir()
	old := kallsymsPath
	t.Cleanup(func() { kallsymsPath = old })
	for _, c := range []struct {
		name, table string
		exempt      bool
	}{
		{"6.2 and later", "0000000000000000 T bpf_trampoline_link_prog\n0000000000000000 t __bpf_prog_enter_recur\n", true},
		{"an LTO build", "0000000000000000 t __bpf_prog_enter_recur.llvm.1234\n", true},
		{"6.1.53", "0000000000000000 t __bpf_prog_enter\n0000000000000000 t __bpf_prog_enter_sleepable\n", false},
		{"a longer name", "0000000000000000 t __bpf_prog_enter_recursive\n0000000000000000 t x__bpf_prog_enter_recur\n", false},
		{"a module's line", "0000000000000000 t __bpf_prog_enter\t[mod]\n", false},
	} {
		kallsymsPath = filepath.Join(dir, c.name)
		if err := os.WriteFile(kallsymsPath, []byte(c.table), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, src := readLSMRecursion(); got != c.exempt || !strings.Contains(src, kallsymsPath) {
			t.Errorf("%s: exempt %v (%s), want %v", c.name, got, src, c.exempt)
		}
	}
	kallsymsPath = filepath.Join(dir, "missing")
	if got, src := readLSMRecursion(); got || !strings.Contains(src, "could not be read") {
		t.Errorf("an unreadable kallsyms: exempt %v (%s)", got, src)
	}
}

// TestLSMModeOnAKernelThatChecksLSMPrograms is ADR 0148's rule: where the kernel's trampoline still checks LSM programs
// for recursion (before 6.2, and before 6.1.54 in the 6.1 series), LSM mode is held to fmod_ret mode's preemption
// precondition, and the test waiver does not lift it.
func TestLSMModeOnAKernelThatChecksLSMPrograms(t *testing.T) {
	active := LSMState{Modules: []string{"capability", "landlock", "bpf"}, BPFActive: true, Source: LSMSourceSyscall}
	src := kallsymsPath + " does not name " + lsmRecursionSymbol
	for _, m := range []string{preemptFull, preemptLazy, preemptRT, preemptFullOrLazy, ""} {
		env := PlaneEnv{Preempt: m, PreemptSource: debugfsPreemptPath, LSMRecursionSource: src}
		d, fix := modePrecondition(bpfobj.PlaneLSM, env, active)
		if !strings.Contains(d, "still checks LSM programs for recursion") || !strings.Contains(d, src) ||
			!strings.Contains(fix, "6.1.54") || !strings.Contains(fix, "preempt=voluntary") {
			t.Errorf("LSM mode under %q on a checking kernel: %q, fix %q", m, d, fix)
		}
		env.PreemptWaived = true
		if d, _ := modePrecondition(bpfobj.PlaneLSM, env, active); d == "" {
			t.Errorf("the test waiver lifted the LSM rule under %q", m)
		}
		env.PreemptWaived = false
		// fmod_ret's refusal no longer offers LSM mode as the way out on such a kernel.
		if _, fix := modePrecondition(bpfobj.PlaneFmodRet, env, active); strings.Contains(fix, "LSM mode") {
			t.Errorf("fmod_ret's fix offers LSM mode on a kernel that checks LSM programs: %q", fix)
		}
		env.LSMRecursionExempt = true
		if d, _ := modePrecondition(bpfobj.PlaneLSM, env, active); d != "" {
			t.Errorf("LSM mode under %q on an exempt kernel: %q", m, d)
		}
	}
	for _, m := range []string{preemptNone, preemptVoluntary} {
		if d, _ := modePrecondition(bpfobj.PlaneLSM, PlaneEnv{Preempt: m}, active); d != "" {
			t.Errorf("LSM mode under %q on a checking kernel ruled out: %q", m, d)
		}
	}
}

// TestExecPinClaimWithheldWhereTheCheckCanBeSkipped (ADR 0148): a passed exec pin cell is withheld, with the reason in
// words, on a kernel that preempts kernel code or is not shown not to; kept under voluntary or none, and under a test
// build's waiver; a failed or absent cell is left as it is.
func TestExecPinClaimWithheldWhereTheCheckCanBeSkipped(t *testing.T) {
	ok := &PlaneExecPinCell{OK: true, Detail: "passed"}
	for _, m := range []string{preemptFull, preemptLazy, ""} {
		got := execPinWhereSkippable(ok, PlaneEnv{Preempt: m, PreemptSource: debugfsPreemptPath})
		if got.OK || !strings.Contains(got.Detail, "tracepoint program this kernel can skip") ||
			!strings.Contains(got.Detail, "best effort") {
			t.Errorf("under %q: %+v", m, got)
		}
		if got := execPinWhereSkippable(ok, PlaneEnv{Preempt: m, PreemptWaived: true}); got != ok {
			t.Errorf("the waiver withheld the claim under %q", m)
		}
	}
	for _, m := range []string{preemptNone, preemptVoluntary} {
		if got := execPinWhereSkippable(ok, PlaneEnv{Preempt: m}); got != ok {
			t.Errorf("withheld under %q: %+v", m, got)
		}
	}
	failed := &PlaneExecPinCell{OK: false, Detail: "no pins"}
	if execPinWhereSkippable(failed, PlaneEnv{Preempt: preemptLazy}) != failed || execPinWhereSkippable(nil, PlaneEnv{}) != nil {
		t.Error("a failed or absent cell changed")
	}
	// A pinned answer adopted on such a kernel withholds it too.
	st := &PlaneState{Source: planeSourcePin, Modes: []PlaneModeResult{{Mode: bpfobj.PlaneLSM, OK: true, Tested: true, ExecPin: ok}}}
	if !adoptStillAdmitted(st, PlaneEnv{Preempt: preemptLazy, LSMRecursionExempt: true}, LSMState{Source: LSMSourceSyscall}) ||
		st.Modes[0].ExecPin.OK || st.Modes[0].execPinsPass() {
		t.Errorf("an adopted answer under lazy preemption kept the exec pin claim: %+v", st.Modes[0].ExecPin)
	}
}
