// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestChainFSIsTheChainsReturn is ADR 0016 (1)'s mapping of the LSM chain's return to a line's verdict: 0 is
// allow whatever the model predicts, a Landlock- or listener-shaped refusal the model explains is Tego's refusal
// with the model's reason, and anything else is observed and someone else's. The model is asked only when the
// chain refused.
func TestChainFSIsTheChainsReturn(t *testing.T) {
	refuses := func() (record.Verdict, record.Reason) {
		return record.VerdictRefused, record.ReasonWriteOutsideContract
	}
	allows := func() (record.Verdict, record.Reason) { return record.VerdictAllow, "" }
	cases := []struct {
		name   string
		ret    int32
		model  func() (record.Verdict, record.Reason)
		v      record.Verdict
		reason record.Reason
		other  bool
	}{
		{"allowed, the model disagreeing", 0, refuses, record.VerdictAllow, "", false},
		{"EACCES the model explains", -errnoEACCES, refuses, record.VerdictRefused, record.ReasonWriteOutsideContract, false},
		{"EPERM the model explains (the listener)", -errnoEPERM, refuses, record.VerdictRefused, record.ReasonWriteOutsideContract, false},
		{"EXDEV the model explains (refer)", -errnoEXDEV, refuses, record.VerdictRefused, record.ReasonWriteOutsideContract, false},
		{"EACCES the model does not explain", -errnoEACCES, allows, record.VerdictObserved, "", true},
		{"an errno Tego never refuses with", -2, refuses, record.VerdictObserved, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asked := false
			model := func() (record.Verdict, record.Reason) { asked = true; return tc.model() }
			v, reason, other := ChainFS(tc.ret, model)
			if v != tc.v || reason != tc.reason || other != tc.other {
				t.Fatalf("ChainFS(%d) = %s %q other %v, want %s %q other %v", tc.ret, v, reason, other, tc.v, tc.reason, tc.other)
			}
			if tc.ret == 0 && asked {
				t.Error("the model was asked about an action the chain allowed")
			}
		})
	}
}
