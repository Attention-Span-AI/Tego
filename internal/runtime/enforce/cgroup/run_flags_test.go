// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestRunRowListenerResultsRequireExplicitPreparedPlane(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table *agent.RuleTable
		mode  bpf.PlaneMode
		want  uint8
	}{
		{"missing-table", nil, bpf.PlaneLSM, 0},
		{"legacy-plane", &agent.RuleTable{}, bpf.PlaneLSM, 0},
		{"empty-listener-plane", &agent.RuleTable{Listen: []agent.ListenRule{}}, bpf.PlaneLSM, bpf.RunListenerResults},
		{"declared-listener-plane", &agent.RuleTable{Listen: []agent.ListenRule{{Raw: "unix:@service"}}}, bpf.PlaneLSM, bpf.RunListenerResults},
		{"explicit-record-off", &agent.RuleTable{Record: agent.RecordOff, Listen: []agent.ListenRule{}}, bpf.PlaneFmodRet, bpf.RunListenerResults},
		{"listener-without-plane", &agent.RuleTable{Listen: []agent.ListenRule{}}, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handle{slot: 17, gen: 91, table: tc.table, planeMode: tc.mode}
			row := h.runRow()
			if row.Flags != tc.want || row.Pad != [3]uint8{} || row.RunIdx != 17 || row.Gen != 91 || row.Descendants != 1 {
				t.Fatalf("immutable prepared row %+v, want flags%d and original identity", row, tc.want)
			}
		})
	}
}

// TestRunRowActivityFlagFollowsTheStallBudget: the row carries RunActivity exactly when the run's limits bound
// stall_after, in every record mode (limits R4): trace_proc stamps a flagged run's allowed actions under record: off,
// and the TLS probes a flagged run's calls in every mode, so a run with no stall budget pays nothing and one with a
// budget of 0 (the tightest) is stamped. The flag is beside RunListenerResults, never instead of it.
func TestRunRowActivityFlagFollowsTheStallBudget(t *testing.T) {
	bounded := agent.ResolvedLimits{StallAfter: 3 * time.Second, Set: agent.BudgetStallAfter}
	zero := agent.ResolvedLimits{Set: agent.BudgetStallAfter}
	for _, mode := range []agent.RecordMode{agent.RecordOff, agent.RecordSummary, agent.RecordFull} {
		for _, tc := range []struct {
			name  string
			table *agent.RuleTable
			plane bpf.PlaneMode
			want  uint8
		}{
			{"no-table", nil, "", 0},
			{"unbounded", &agent.RuleTable{Record: mode}, "", 0},
			{"other-budget", &agent.RuleTable{Record: mode, Limits: agent.ResolvedLimits{Wall: 5 * time.Second, Set: agent.BudgetWall}}, "", 0},
			{"bounded", &agent.RuleTable{Record: mode, Limits: bounded}, "", bpf.RunActivity},
			{"bounded-at-zero", &agent.RuleTable{Record: mode, Limits: zero}, "", bpf.RunActivity},
			{"bounded-by-value", &agent.RuleTable{Record: mode, Limits: agent.ResolvedLimits{StallAfter: time.Second}}, "", bpf.RunActivity},
			{"bounded-with-listener", &agent.RuleTable{Record: mode, Limits: bounded, Listen: []agent.ListenRule{}}, bpf.PlaneLSM,
				bpf.RunActivity | bpf.RunListenerResults},
		} {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				h := &Handle{slot: 3, gen: 5, table: tc.table, planeMode: tc.plane}
				if row := h.runRow(); row.Flags != tc.want {
					t.Fatalf("flags %#x, want %#x", row.Flags, tc.want)
				}
			})
		}
	}
}
