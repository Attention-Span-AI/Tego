// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPlaneExecPolicyFollowsTheMode: the plane's slot flag EXEC_DECIDES is set exactly when the contract restricts
// images, read through RuleTable.ExecUnrestricted (ADR 0048 (1)): a deny-list section sets it for no exec.
func TestPlaneExecPolicyFollowsTheMode(t *testing.T) {
	for _, tc := range []struct {
		exec    *agent.ExecSection
		decides bool
	}{
		{nil, false},
		{&agent.ExecSection{Deny: []string{"git push"}}, false},
		{&agent.ExecSection{Allow: []string{}, Deny: []string{"git push"}}, true},
		{&agent.ExecSection{}, true},
	} {
		s, err := CompilePlane(&agent.RuleTable{Contract: &agent.Contract{Exec: tc.exec}})
		if err != nil {
			t.Fatal(err)
		}
		if s.ExecPolicy != tc.decides {
			t.Errorf("%+v: ExecPolicy %v, want %v", tc.exec, s.ExecPolicy, tc.decides)
		}
	}
}
