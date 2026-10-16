// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// relaySource is a capture source that relays model traffic and reports it (StreamActivityReporter).
type relaySource struct {
	plainSource
	activity func(uint64)
}

func (s *relaySource) SetStreamActivity(fn func(uint64)) { s.activity = fn }

// TestStreamActivityUnderAStallBudgetInEveryMode is limits R4's relay half at the run: a response the forwarder
// relays for longer than stall_after is the agent waiting on its model, in every record mode, so the run hands the
// relays the watcher's Touch whenever stall_after is bounded (a contract's 0s included, E16), and nothing when it
// is not, where no stall check reads it.
func TestStreamActivityUnderAStallBudgetInEveryMode(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordOff, agent.RecordSummary, agent.RecordFull} {
		for _, bounded := range []bool{true, false} {
			name := string(mode) + "/unbounded"
			lim := agent.ResolvedLimits{}
			if bounded {
				name = string(mode) + "/stall_after=0s"
				lim = agent.ResolvedLimits{Set: agent.BudgetStallAfter}
			}
			t.Run(name, func(t *testing.T) {
				src := &relaySource{plainSource: plainSource{name: "forwarder"}}
				r := newTestRunner(Deps{Capture: []source.Source{src, &plainSource{name: "uprobe"}}})
				r.rt, r.queue = &agent.RuleTable{Record: mode, Limits: lim}, NewQueue(4)
				r.newBudget()
				r.wireStreamActivity()
				if (src.activity != nil) != bounded {
					t.Fatalf("stream activity set %v with stall_after bounded %v under record: %s", src.activity != nil, bounded, mode)
				}
				if src.activity == nil {
					return
				}
				src.activity(uint64(7 * time.Second))
				if got := r.budget.Snapshot().LastEventMonoNS; got != uint64(7*time.Second) {
					t.Errorf("the watcher's last activity is %d, want the relay's %d", got, uint64(7*time.Second))
				}
			})
		}
	}
}
