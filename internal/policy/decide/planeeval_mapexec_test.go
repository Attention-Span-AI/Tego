// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"errors"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestPlaneEvaluatorUnbuildableMapExec: a table with no exec: section that is over the plane's fs cap answers
// map-exec refused as plane-unbuildable too, like every other fs and exec action, not no-exec:-section's allow.
func TestPlaneEvaluatorUnbuildableMapExec(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{}}
	for i := range PlaneRowsMax + 1 {
		p := "/w/" + strconv.Itoa(i)
		rt.FS = append(rt.FS, agent.FSRule{Path: p, Resolved: p, Kind: agent.FSWrite, Access: agent.AccessWriteFile | agent.AccessReadFile})
	}
	if !rt.ExecUnrestricted() {
		t.Fatal("the table has an exec: section")
	}
	pe := NewPlaneEvaluator(rt)
	var capErr *ErrPlaneCap
	if !errors.As(pe.Err(), &capErr) {
		t.Fatalf("over the fs cap: %v, want ErrPlaneCap", pe.Err())
	}
	for _, a := range []agent.Action{{Kind: agent.ActionMapExec, Path: "/w/1"}, {Kind: agent.ActionFSRead, Path: "/w/1"}} {
		if got := pe.Evaluate(a, Env{}); got.Verdict != agent.VerdictRefused || got.Rule != PlaneUnbuildableRule {
			t.Errorf("%+v: %+v, want refused %s", a, got, PlaneUnbuildableRule)
		}
	}
	// A malformed map-exec action is still invalid before the compile error is asked.
	if got, want := pe.Evaluate(agent.Action{Kind: agent.ActionMapExec}, Env{}), invalidAction(); got != want {
		t.Errorf("malformed map-exec: %+v, want %+v", got, want)
	}
}
