// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// swapCgroups is a manager whose cgroups report swap areas a memory cap cannot hold them out of.
type swapCgroups struct {
	fakeCgroups
	areas []string
}

func (s *swapCgroups) UncappedSwap(cgroup.Cgroup) []string { return s.areas }

// TestMemoryCapIntoSwapIsALimitsGap is ADR 0038's 2026-09-24 note (runtime-launch.md R10): on a kernel that
// accounts no swap to cgroups, memory.swap.max is absent and SetLimits skips it, so with swap on the agent can
// exceed its memory cap into swap. A run with a memory cap then records one what=limits gap naming it and
// prints one warning; with swap accounted, with no swap, or with no memory cap it records and prints nothing.
func TestMemoryCapIntoSwapIsALimitsGap(t *testing.T) {
	capped := agent.ResolvedLimits{MemoryB: 64 << 20, Set: agent.BudgetMemory}
	for _, tc := range []struct {
		name   string
		areas  []string
		limits agent.ResolvedLimits
		want   bool
	}{
		{"memory cap, swap uncapped", []string{"/dev/zram0"}, capped, true},
		{"memory cap, swap capped or off", nil, capped, false},
		{"no memory cap", []string{"/dev/zram0"}, agent.ResolvedLimits{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warned []string
			r := &runner{
				log:   slog.New(slog.DiscardHandler),
				queue: NewQueue(4),
				rt:    &agent.RuleTable{Contract: &agent.Contract{Name: "swap"}, Limits: tc.limits},
				deps: Deps{Cgroups: &swapCgroups{fakeCgroups{root: t.TempDir()}, tc.areas}, Warn: func(code, s string) {
					if code != WarnSwapUncapped {
						t.Errorf("swap warning code %q, want %s", code, WarnSwapUncapped)
					}
					warned = append(warned, s)
				}},
				agentID: identity.AgentID("swap"),
				id:      identity.RunID("r-00000000-000000000000a-aaaaaa"),
			}
			if err := r.createCgroup(); err != nil {
				t.Fatalf("createCgroup: %v", err)
			}
			r.emitLimitsGap()
			var gaps []record.GapPayload
		drain:
			for {
				select {
				case ev := <-r.queue.C():
					var p record.GapPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					gaps = append(gaps, p)
				default:
					break drain
				}
			}
			if !tc.want {
				if len(gaps) != 0 || len(warned) != 0 {
					t.Errorf("gaps %+v, warnings %q, want none", gaps, warned)
				}
				return
			}
			if len(gaps) != 1 || gaps[0].What != record.GapLimits || gaps[0].Why != GapMemorySwapUncapped {
				t.Errorf("gaps %+v, want one what=limits why=%s", gaps, GapMemorySwapUncapped)
			}
			if len(warned) != 1 || !strings.Contains(warned[0], "/dev/zram0") || !strings.Contains(warned[0], "swap") {
				t.Errorf("warnings %q, want one naming the swap area", warned)
			}
		})
	}
}
