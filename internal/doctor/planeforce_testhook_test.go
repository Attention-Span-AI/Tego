// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package doctor

import (
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// TestPlaneRowForceForTest: the test build's forced row changes only a passed outside answer of its own hook and
// mode, as often as it was asked to, counts every probe of the hook in every mode, and ends with its restore.
func TestPlaneRowForceForTest(t *testing.T) {
	const hook = "socket_create"
	for _, tc := range []struct {
		name string
		how  PlaneRowForce
		want [3]string // the answers of three probes of the forced mode
	}{
		{"never", PlaneRowForceNever, [3]string{planePassed, planePassed, planePassed}},
		{"first", PlaneRowForceFirst, [3]string{planeRefused, planePassed, planePassed}},
		{"always", PlaneRowForceAlways, [3]string{planeRefused, planeRefused, planeRefused}},
	} {
		calls, restore := PlaneRowForceForTest(bpfobj.PlaneLSM, hook, tc.how)
		for i, want := range tc.want {
			if got := planeTestOutcome(bpfobj.PlaneLSM, hook, planePassed); got != want {
				t.Errorf("%s: probe %d answered %q, want %q", tc.name, i+1, got, want)
			}
		}
		if got := planeTestOutcome(bpfobj.PlaneFmodRet, hook, planePassed); got != planePassed {
			t.Errorf("%s: the other mode answered %q", tc.name, got)
		}
		if got := planeTestOutcome(bpfobj.PlaneLSM, "file_open", planePassed); got != planePassed {
			t.Errorf("%s: another hook answered %q", tc.name, got)
		}
		if got := planeTestOutcome(bpfobj.PlaneLSM, hook, "failed: operation not permitted"); got != "failed: operation not permitted" {
			t.Errorf("%s: a real failure was changed to %q", tc.name, got)
		}
		if calls(bpfobj.PlaneLSM) != 4 || calls(bpfobj.PlaneFmodRet) != 1 {
			t.Errorf("%s: counted %d and %d probes, want 4 (three, and the failure) and 1", tc.name, calls(bpfobj.PlaneLSM), calls(bpfobj.PlaneFmodRet))
		}
		restore()
		if got := planeTestOutcome(bpfobj.PlaneLSM, hook, planePassed); got != planePassed {
			t.Errorf("%s: forced after restore: %q", tc.name, got)
		}
	}
}
