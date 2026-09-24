// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// scopedInherited is an inherited tier-1 handle that reports its own capability set, as the Landlock handle
// the composition root supplies does.
type scopedInherited struct {
	fakeInherited
	caps backend.Set
}

func (s scopedInherited) Capabilities() backend.Set { return s.caps }

// TestAbstractScopeComesFromTheInheritedRuleset: tier 2 refuses no abstract unix name itself; the Landlock
// scope in the ruleset it inherits does, from ABI 6 on (enforce-landlock R7). So a run's
// net.unix_abstract_scope is that ruleset's answer: present where the inherited handle has the scope, absent
// below ABI 6 and absent with no inherited ruleset at all, never the static column's.
func TestAbstractScopeComesFromTheInheritedRuleset(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		inherit Inherited
		want    bool
	}{
		{"an inherited ruleset at ABI 6 or above", scopedInherited{fakeInherited{fd: 42}, backend.Set{backend.CapUnixAbstractScope: true}}, true},
		{"an inherited ruleset below ABI 6", scopedInherited{fakeInherited{fd: 42}, backend.Set{backend.CapUnixSockets: true}}, false},
		{"an inherited state that does not say", fakeInherited{fd: 42}, false},
		{"no inherited state", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, func(o *Options) {
				if tc.inherit != nil {
					inh := tc.inherit
					o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) { return inh, nil }
				}
			})
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			defer h.Close()
			if got := h.Capabilities().Has(backend.CapUnixAbstractScope); got != tc.want {
				t.Fatalf("net.unix_abstract_scope = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestExecDenyFollowsTheInheritedRuleset: a contract with exec.anonymous drops tier 1's memfd arm, so the
// inherited handle reports no exec.deny (enforce-landlock R11a), and any readable binary runs from a memfd
// that neither the fanotify listener nor the plane's exec row (PlaneExecAnonAllow) refuses. The run's line
// used to keep the static column's exec.deny there, overstating what the run enforced. An inherited ruleset
// that reports exec.deny, or one that does not say, leaves the column as it was.
func TestExecDenyFollowsTheInheritedRuleset(t *testing.T) {
	t.Parallel()
	execDeny := func(inh Inherited) bool {
		t.Helper()
		f := newFixture(t, func(o *Options) {
			o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) { return inh, nil }
		})
		h, err := f.backend.Prepare(context.Background(), f.table, f.run)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		defer h.Close()
		return h.Capabilities().Has(backend.CapExecDeny)
	}
	with := execDeny(scopedInherited{fakeInherited{fd: 42}, backend.Set{backend.CapExecDeny: true}})
	silent := execDeny(fakeInherited{fd: 42})
	if !with || !silent {
		t.Fatalf("exec.deny with an inherited row that has it = %v, with one that does not say = %v; want both true", with, silent)
	}
	if execDeny(scopedInherited{fakeInherited{fd: 42}, backend.Set{backend.CapUnixSockets: true}}) {
		t.Error("exec.deny = true while the inherited ruleset withholds it (exec.anonymous)")
	}
}
