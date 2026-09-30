// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// TestPermanentLoadRefusalIsAFailedModeNotAFault: a load the kernel refuses the same way every time (the verifier's
// rejection, a kfunc or program type it lacks, ENOSYS) is a failed mode the run-probe cache keeps for the boot, so a
// run does not load both modes again on every start; a load error whose cause can pass (ENOMEM, EBUSY, a verifier
// error caused by one, an error that is no load's) stays a fault that is never kept.
func TestPermanentLoadRefusalIsAFailedModeNotAFault(t *testing.T) {
	load := func(err error) error {
		// The loader's own wrapping, as LoadAndAssign returns it.
		err = fmt.Errorf("program lsm_file_open: load program: %w", err)
		return &planeLoadError{msg: "load plane_rdonly lsm: " + verifierTail(err), err: err}
	}
	cases := []struct {
		name    string
		err     error
		faulted bool
	}{
		{"verifier rejection", load(&ebpf.VerifierError{Cause: unix.EACCES, Log: []string{"R1 invalid mem access"}}), false},
		{"verifier EINVAL", load(&ebpf.VerifierError{Cause: unix.EINVAL}), false},
		{"missing kfunc", load(fmt.Errorf("kfunc bpf_rdonly_cast: %w", ebpf.ErrNotSupported)), false},
		{"ENOSYS", load(unix.ENOSYS), false},
		{"ENOMEM", load(unix.ENOMEM), true},
		{"verifier error from ENOMEM", load(&ebpf.VerifierError{Cause: unix.ENOMEM}), true},
		{"EBUSY", load(unix.EBUSY), true},
		{"E2BIG", load(&ebpf.VerifierError{Cause: unix.E2BIG}), true},
		{"an unclassified load error", load(errors.New("map plane_counters: something")), true},
		{"a fixtures error", fmt.Errorf("fixtures: %w", unix.ENOSYS), true},
		{"a transient attach", fmt.Errorf("attach x: y (%w)", errAttachTransient), true},
	}
	for _, tc := range cases {
		rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
		for i := range rows {
			rows[i].Detail = ""
		}
		v := planeProbeFailed(bpfobj.PlaneLSM, tc.err, rows)
		if v.OK || !v.Tested || v.Faulted != tc.faulted || v.Fix == "" || v.Detail != tc.err.Error() {
			t.Errorf("%s: %+v, want not OK, tested, Faulted %v, a fix, the error's detail", tc.name, v, tc.faulted)
		}
		if rows[0].Detail != tc.err.Error() {
			t.Errorf("%s: row detail %q", tc.name, rows[0].Detail)
		}
	}

	// A kept refusal is a plane answer the cache reads back.
	c, _ := testCache(t)
	k := testKey()
	p, hooks, fan, fs := vouchingAnswer()
	st := passingPlane("")
	st.Modes[0] = planeProbeFailed(bpfobj.PlaneLSM, cases[0].err, nil)
	c.record(k, p, hooks, st, nil, fan, fs)
	if e, ok := c.load(k); !ok || e.Plane == nil {
		t.Errorf("a verifier rejection's answer was not kept (read %v)", ok)
	}
}
