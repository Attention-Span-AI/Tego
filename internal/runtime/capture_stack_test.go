// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Inject the same mechanism-unavailable cause returned by the capture loader.
// Explicit uprobes must refuse even without a model budget; auto retains its
// existing forwarder selection. No agent is released by this host test.
func TestCaptureReadbackUnavailableAtStart(t *testing.T) {
	const cause = "uprobe: cannot verify capture stack safety: read translated instructions: permission denied"
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		for _, requested := range []agent.CaptureMode{agent.CaptureUprobe, agent.CaptureAuto, ""} {
			rt := &agent.RuleTable{Tier: tier, Capture: agent.CaptureUprobe, Record: agent.RecordFull,
				Contract: &agent.Contract{Capture: requested}}
			sources := []source.Source{&causedInert{plainSource{name: "uprobe"}, cause}}
			if requested != agent.CaptureUprobe {
				sources = append(sources, &plainSource{name: "forwarder"})
			}
			r := &runner{log: slog.New(slog.DiscardHandler), rt: rt, deps: Deps{Capture: sources}}
			err := r.refuseUnmeteredBudget()
			if requested == agent.CaptureUprobe {
				if !errors.Is(err, ErrCaptureUnavailable) || !strings.Contains(err.Error(), cause) {
					t.Fatalf("explicit uprobes started without checked programs: %v", err)
				}
			} else if err != nil || r.captureMode() != string(agent.CaptureForwarder) {
				t.Fatalf("auto selection: mode=%s err=%v", r.captureMode(), err)
			}
		}
	}
}
