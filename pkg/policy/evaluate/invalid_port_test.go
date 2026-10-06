// SPDX-License-Identifier: Apache-2.0

package evaluate_test

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/evaluate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestInvalidInternetPort checks the public API boundary, where actions bypass
// the YAML test-table parser's port validation.
func TestInvalidInternetPort(t *testing.T) {
	rt := &agent.RuleTable{Contract: &agent.Contract{}}
	want := agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.InvalidActionRule}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM, backend.TierObserve} {
		for _, port := range []int{-1, 65536} {
			t.Run(fmt.Sprintf("%s/%d", tier, port), func(t *testing.T) {
				a := agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.1", Port: port}
				if got := evaluate.Evaluate(rt, a, tier); got != want {
					t.Errorf("public Evaluate = %+v, want %+v", got, want)
				}
				if got := rt.Evaluate(a, tier); got != want {
					t.Errorf("legacy Evaluate = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestInternetPortBoundariesRemainEvaluable(t *testing.T) {
	rt := &agent.RuleTable{Contract: &agent.Contract{}}
	for _, port := range []int{0, 65535} {
		a := agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.1", Port: port}
		if got := evaluate.Evaluate(rt, a, backend.TierLandlock); got.Verdict != agent.VerdictAllow {
			t.Errorf("port %d = %+v, want allow", port, got)
		}
	}
	// Unix actions name no Internet port; that unused field does not invalidate
	// a pathname socket, including the Action.Path shorthand. host_sockets: true
	// leaves a host socket reachable with no net: section (ADR 0070), so the
	// answer is the allow the field must not turn into invalid-action.
	rt = &agent.RuleTable{Contract: &agent.Contract{HostSockets: true}}
	for _, a := range []agent.Action{
		{Kind: agent.ActionNetConnect, Host: "/tmp/example.sock", Port: -1, Proto: agent.ProtoUnix},
		{Kind: agent.ActionNetConnect, Path: "/tmp/example.sock", Port: 65536},
	} {
		if got := evaluate.Evaluate(rt, a, backend.TierLandlock); got.Verdict != agent.VerdictAllow {
			t.Errorf("Unix action %+v = %+v, want allow", a, got)
		}
	}
}
