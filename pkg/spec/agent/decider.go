// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Decider is the decision core the evaluation methods of this package delegate to: internal/policy/decide,
// which owns the verdict model of every tier (ADR 0028). The core lives behind the CLI because it changes
// with kernel behaviour, which a public package must not promise (ADR 0028, ADR 0031 (1)); this package
// holds the types, validation and loading, and may not import internal (ADR 0019, .golangci.yml
// spec-is-pure). So the core registers itself here when it is linked (RegisterDecider), rather than being
// imported.
//
// Every method answers for the table it is handed and reads nothing else: no I/O, no clock, no state.
type Decider interface {
	Evaluate(rt *RuleTable, a Action, tier backend.Tier) EvalResult
	FSDecider(rt *RuleTable, path string, read bool) (*FSRule, bool)
	ListenerOpenRefused(rt *RuleTable, path string) (FSRule, bool)
	ExecReadGrant(rt *RuleTable, path string) (*ExecRule, bool)
	Canonical(rt *RuleTable, path string) string
}

// decider is the registered core; nil until internal/policy/decide's init runs.
var decider Decider

// RegisterDecider installs the decision core. internal/policy/decide calls it from its init, once; a second
// registration panics, so no other package can replace the verdicts compile --test reports.
func RegisterDecider(d Decider) {
	if d == nil {
		panic("agent: RegisterDecider(nil)")
	}
	if decider != nil {
		panic("agent: a decision core is already registered")
	}
	decider = d
}

// core is the registered decision core. A program that calls an evaluation method without linking
// a decision core has no verdicts to give. The public compatibility bridge links the
// same core without requiring consumers to import an inaccessible internal package.
func core() Decider {
	if decider == nil {
		panic("agent: no decision core is linked; import github.com/attention-span-ai/tego/pkg/policy/evaluate and use evaluate.Evaluate")
	}
	return decider
}

// Evaluate reports the verdict a compiled table gives a hypothetical action in one tier, as `compile --test`
// uses it (R15): decide.Evaluate, which documents the model of each tier.
//
// It is deprecated for one release, then removed (ADR 0031 (1)): call internal/policy/decide.Evaluate, which
// this shim delegates to. External callers use pkg/policy/evaluate.Evaluate, the opt-in public bridge.
// It carries no "Deprecated:" paragraph yet, which would make staticcheck fail every
// test still calling it; ADR 0031 (c) moves those tests beside the core and adds the marker.
func (rt *RuleTable) Evaluate(a Action, tier backend.Tier) EvalResult {
	return core().Evaluate(rt, a, tier)
}

// FSDecider is the entry whose verdict an fs action on path takes in the nearest-wins walk (decide.FSDecider).
//
// It is deprecated with Evaluate: call pkg/policy/evaluate.FSDecider outside this module.
func (rt *RuleTable) FSDecider(path string, read bool) (*FSRule, bool) {
	return core().FSDecider(rt, path, read)
}

// ListenerOpenRefused is tier 2's fanotify open decision on path (decide.ListenerOpenRefused).
//
// It is deprecated with Evaluate: call pkg/policy/evaluate.ListenerOpenRefused outside this module.
func (rt *RuleTable) ListenerOpenRefused(path string) (FSRule, bool) {
	return core().ListenerOpenRefused(rt, path)
}

// ExecReadGrant is the exec entry through which tier 1 reads path under an enforced deny_read
// (decide.ExecReadGrant).
//
// It is deprecated with Evaluate: call pkg/policy/evaluate.ExecReadGrant outside this module.
func (rt *RuleTable) ExecReadGrant(path string) (*ExecRule, bool) {
	return core().ExecReadGrant(rt, path)
}
