// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The core registers itself with pkg/spec/agent, whose deprecated evaluation methods (RuleTable.Evaluate,
// FSDecider, ListenerOpenRefused, ExecReadGrant, and TestTable.Run) delegate here. That package may not import
// this one (ADR 0019, ADR 0031 (1)), so a program that links the core is what makes them answer.
func init() { agent.RegisterDecider(core{}) }

// core is the agent.Decider this package registers: each method is the package function of the same name.
type core struct{}

func (core) Evaluate(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	return Evaluate(rt, a, tier)
}

func (core) FSDecider(rt *agent.RuleTable, path string, read bool) (*agent.FSRule, bool) {
	return FSDecider(rt, path, read)
}

func (core) ListenerOpenRefused(rt *agent.RuleTable, path string) (agent.FSRule, bool) {
	return ListenerOpenRefused(rt, path)
}

func (core) ExecReadGrant(rt *agent.RuleTable, path string) (*agent.ExecRule, bool) {
	return ExecReadGrant(rt, path)
}

func (core) Canonical(rt *agent.RuleTable, path string) string { return Canonical(rt, path) }
