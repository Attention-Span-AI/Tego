// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestExecOpenFollowsTheMode: the fanotify policy reads ADR 0048 (1)'s mode through RuleTable.ExecUnrestricted, as
// every other enforcer does: a deny-list section refuses no image's exec open, and `allow: []` beside a deny list
// refuses an unlisted one.
func TestExecOpenFollowsTheMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		exec *agent.ExecSection
		open bool
	}{
		{nil, true},
		{&agent.ExecSection{Deny: []string{"git push"}}, true},
		{&agent.ExecSection{Ask: []string{}}, true},
		{&agent.ExecSection{Allow: []string{}, Deny: []string{"git push"}}, false},
		{&agent.ExecSection{}, false},
	} {
		rt := policyTable(nil, nil)
		rt.Contract = &agent.Contract{Exec: tc.exec}
		p := newPolicyWith(rt, "/run.scope", func(string) ([]string, error) { return nil, nil },
			func(string) (mountKey, error) { return mountKey{unique: true, id: 1}, nil })
		if p.execOpen != tc.open {
			t.Errorf("%+v: execOpen %v, want %v", tc.exec, p.execOpen, tc.open)
		}
		if v := p.decideExec("/usr/bin/unlisted"); v.allow != tc.open {
			t.Errorf("%+v: decideExec %+v", tc.exec, v)
		}
	}
}
