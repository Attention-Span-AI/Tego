// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestBPFControlRefusesAMachineThatRefuses holds bpfCheck, bpfControl's decision, to its purpose on a stand-in for
// kernel.unprivileged_bpf_disabled: a 2 is lowered only
// on a disposable host and put back after, a 2 elsewhere fails the fixture naming TEGO_DISPOSABLE_HOST and changes
// nothing, and a refused control map create fails it whatever the value (a 1 cannot be lowered).
func TestBPFControlRefusesAMachineThatRefuses(t *testing.T) {
	refused := Outcome{Errno: 1}
	for _, tc := range []struct {
		name, was, disposable string
		outcome               Outcome
		lowered, called       bool
		fail                  string
	}{
		{"2 on a disposable host, the map made", "2", "kvm", Outcome{OK: true}, true, true, ""},
		{"2 on a disposable host, the map refused", "2", "kvm", refused, true, true, "cannot create a BPF map"},
		{"2 on a developer's machine", "2", "", Outcome{OK: true}, false, false, "TEGO_DISPOSABLE_HOST"},
		{"1, the map refused", "1", "kvm", refused, false, true, "cannot create a BPF map"},
		{"0, the map made", "0", "", Outcome{OK: true}, false, true, ""},
		{"0, the map refused", "0", "", refused, false, true, "cannot create a BPF map"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "unprivileged_bpf_disabled")
			if err := os.WriteFile(path, []byte(tc.was+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			called := false
			restore, err := bpfCheck(path, tc.disposable, func() (Outcome, error) {
				called = true
				if b, _ := os.ReadFile(path); tc.lowered != (strings.TrimSpace(string(b)) == "0" && tc.was != "0") {
					t.Errorf("the control map create ran with the sysctl at %q", b)
				}
				return tc.outcome, nil
			})
			switch {
			case tc.fail == "" && err != nil:
				t.Fatalf("the control failed: %v", err)
			case tc.fail != "" && (err == nil || !strings.Contains(err.Error(), tc.fail)):
				t.Fatalf("the control's error %v, want one naming %q", err, tc.fail)
			case called != tc.called:
				t.Fatalf("the control map create ran: %v, want %v", called, tc.called)
			case (restore != nil) != tc.lowered:
				t.Fatalf("restore %v, want one only where the sysctl was lowered", restore != nil)
			}
			if restore != nil {
				if err := restore(); err != nil {
					t.Fatal(err)
				}
			}
			if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != tc.was {
				t.Fatalf("the sysctl is %q after the control, was %q", b, tc.was)
			}
		})
	}
}

// TestBPFControlHoldsTheLoweringForEveryFixture: two fixtures running side by side share the lowering, and the
// sysctl is put back only when the last of them ends, so neither runs its bpf cell against the machine's 2.
func TestBPFControlHoldsTheLoweringForEveryFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unprivileged_bpf_disabled")
	if err := os.WriteFile(path, []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	made := func() (Outcome, error) { return Outcome{OK: true}, nil }
	first, err := bpfCheck(path, "kvm", made)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	second, err := bpfCheck(path, "kvm", made)
	if err != nil || second == nil {
		t.Fatal(err)
	}
	read := func() string { b, _ := os.ReadFile(path); return strings.TrimSpace(string(b)) }
	if err := first(); err != nil || read() != "0" {
		t.Fatalf("the first fixture's end raised the sysctl to %q under the second's run (%v)", read(), err)
	}
	if err := second(); err != nil || read() != "2" {
		t.Fatalf("the last fixture's end left the sysctl at %q (%v)", read(), err)
	}
}

// TestControlsAskedAndMissing: each kind of cell asks its control, a bpf cell's only under root, and a control that
// did not mark itself passed is missing, which fails the fixture in runFixture (deleting a control's call left every
// test green).
func TestControlsAskedAndMissing(t *testing.T) {
	fx := Fixture{Name: "control", Cells: []Cell{
		{Name: "ptrace-host", Op: OpPtraceAttach, Target: TargetHost},
		{Name: "bpf-map-create", Op: OpBPF},
		{Name: "memfd-exec", Op: OpMemfdExec},
		{Name: "read", Op: OpRead, Path: "w/f"},
	}}
	if got := controlsAsked(&fx, true); !slices.Equal(got, []string{controlHost, controlBPF, controlMemfd}) {
		t.Errorf("under root: %v", got)
	}
	if got := controlsAsked(&fx, false); !slices.Equal(got, []string{controlHost, controlMemfd}) {
		t.Errorf("without root: %v", got)
	}
	if got := controlsAsked(&Fixture{Cells: []Cell{{Name: "read", Op: OpRead}}}, true); len(got) != 0 {
		t.Errorf("a fixture with no such cell: %v", got)
	}
	e := &env{}
	if got := missingControls(e, &fx, true); !slices.Equal(got, []string{controlHost, controlBPF, controlMemfd}) {
		t.Errorf("none ran: missing %v", got)
	}
	e.passed(controlHost)
	e.passed(controlMemfd)
	if got := missingControls(e, &fx, true); !slices.Equal(got, []string{controlBPF}) {
		t.Errorf("the bpf control did not run: missing %v", got)
	}
	e.passed(controlBPF)
	if got := missingControls(e, &fx, true); len(got) != 0 {
		t.Errorf("every control ran: missing %v", got)
	}
}
