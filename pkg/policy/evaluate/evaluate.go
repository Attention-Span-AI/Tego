// SPDX-License-Identifier: Apache-2.0

// Package evaluate exposes the decision model used by tego compile --test to
// callers outside the Tego module. It delegates to the same core as the CLI;
// importing it also links the core used by agent's legacy evaluation methods.
//
// This is an experimental, version-dependent model of kernel enforcement, not a
// promise that every host kernel will give the predicted answer. Pin the Tego
// module version with the binary whose behavior is being evaluated. The public
// contract types and loading remain in pkg/spec/agent (ADR 0031).
package evaluate

import (
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Evaluate predicts one action's verdict at tier, using the CLI's decision model.
// A nil table or malformed action is refused with agent.InvalidActionRule. The
// action's paths are taken as the kernel's walk would leave them: the model
// follows no symlink of the filesystem, only a link an fs entry declares
// (Canonical), so a path through any other link is answered at its spelling.
// tego compile --test resolves each row through the real filesystem first
// (agent.TestTable.RunResolved).
func Evaluate(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	return decide.Evaluate(rt, a, tier)
}

// FSDecider returns the nearest filesystem rule that decides the given action.
func FSDecider(rt *agent.RuleTable, path string, read bool) (*agent.FSRule, bool) {
	return decide.FSDecider(rt, path, read)
}

// ListenerOpenRefused predicts tier 2's fanotify refusal for an open.
func ListenerOpenRefused(rt *agent.RuleTable, path string) (agent.FSRule, bool) {
	return decide.ListenerOpenRefused(rt, path)
}

// ExecReadGrant returns the exec rule granting a read at tier 1.
func ExecReadGrant(rt *agent.RuleTable, path string) (*agent.ExecRule, bool) {
	return decide.ExecReadGrant(rt, path)
}

// Canonical rewrites a declared symlink prefix using its compiled resolved path.
func Canonical(rt *agent.RuleTable, path string) string { return decide.Canonical(rt, path) }

// Run evaluates every test-table row with the CLI's decision model. Paths are
// interpreted against cwd, as with agent.TestTable.RunBy, and are not resolved
// through the filesystem (Evaluate).
func Run(table *agent.TestTable, rt *agent.RuleTable, cwd string, tiers ...backend.Tier) []agent.TestResult {
	return table.RunBy(decide.Evaluate, rt, cwd, tiers...)
}
