// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestCompileReadsTheExecMode: the supervisor reads ADR 0048 (1)'s mode through the contract's methods, so a deny-list
// section is unrestricted here as it is to the Landlock builder, the plane and the fanotify policy.
func TestCompileReadsTheExecMode(t *testing.T) {
	for _, tc := range []struct {
		exec                    *agent.ExecSection
		unrestricted, anonymous bool
	}{
		{nil, true, false},
		{&agent.ExecSection{Deny: []string{"git push"}}, true, false},
		{&agent.ExecSection{Allow: []string{}, Deny: []string{"git push"}}, false, false},
		{&agent.ExecSection{Allow: []string{}, Anonymous: true}, false, true},
	} {
		c := compile(&Policy{Rules: &agent.RuleTable{Contract: &agent.Contract{Exec: tc.exec}, Record: agent.RecordSummary}})
		if c.execUnrestricted != tc.unrestricted || c.execAnonymous != tc.anonymous {
			t.Errorf("%+v: unrestricted %v anonymous %v", tc.exec, c.execUnrestricted, c.execAnonymous)
		}
	}
}
