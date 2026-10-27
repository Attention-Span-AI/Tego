// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// nameTable is a table with the built-in .env pair over scope, as compile makes it.
func nameTable(scope string) *agent.RuleTable {
	scopes := []agent.NameScope{{Canonical: scope, Spelling: scope}}
	return &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordSummary, Contract: &agent.Contract{},
		NameDeny: []agent.NameDenyRule{
			{Literal: ".env", Scopes: scopes, BuiltIn: true},
			{Literal: ".env.", Prefix: true, Scopes: scopes, BuiltIn: true,
				Except: []string{".env.example", ".env.sample", ".env.template", ".env.dist"}},
		}}
}
