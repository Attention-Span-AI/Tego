// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAttributeStageIgnoresTheKernelRecorder is the tier-2 half of attributeStage's own rule. The
// tier's eBPF recorder (enforce.KernelRecorder, wired by startKernelRecord) and Deps.Observe raise
// fs, net and exec events and never an ssl_request, so neither can feed derive.Steps. Deciding on
// every producer instead of the capture list installed derive.Steps on a run with `capture: off`,
// whose states map then stayed empty and stamped `method=time` on every action — the exact false
// claim ("unattributed by time" on a run with no model-turn signal) the method-none branch exists to
// avoid (P0-DESIGN §5).
func TestAttributeStageIgnoresTheKernelRecorder(t *testing.T) {
	t.Run("a tier-2 kernel recorder is not capture", func(t *testing.T) {
		r := newTestRunner(Deps{})
		r.rt = &agent.RuleTable{Capture: agent.CaptureOff}
		r.kernelRecord = &plainSource{name: "observe"}
		if got := r.attributeStage(); got != nil {
			t.Error("derive.Steps was installed for a run with no model traffic to derive from")
		}
		if r.steps != nil {
			t.Error("step tracking was started for a run with no model traffic")
		}
	})

	t.Run("a pre-built Deps.Observe is not capture either", func(t *testing.T) {
		r := newTestRunner(Deps{Observe: &plainSource{name: "observe"}})
		r.rt = &agent.RuleTable{Capture: agent.CaptureOff}
		if got := r.attributeStage(); got != nil {
			t.Error("derive.Steps was installed for a run whose only producer is the tier recorder")
		}
	})

	t.Run("a capture source still installs step derivation", func(t *testing.T) {
		r := newTestRunner(Deps{Capture: []source.Source{&plainSource{name: "forwarder"}}})
		r.rt = &agent.RuleTable{Capture: agent.CaptureForwarder}
		r.kernelRecord = &plainSource{name: "observe"}
		if r.attributeStage() == nil || r.steps == nil {
			t.Fatal("a capturing run did not install step derivation")
		}
	})
}

// TestEmitCaptureGapsIgnoresTheKernelRecorder is the same conflation at the other call site, and the
// worse of the two: a contract that asked for capture, a tier that wired only its kernel recorder and
// no capture source, and therefore no ssl event in the ledger — with the "capture was asked for and
// nothing provides it" gap suppressed because allSources() was not empty. A capture shortfall is
// always a gap event and never a silence (capture-derive.md §8 I4).
func TestEmitCaptureGapsIgnoresTheKernelRecorder(t *testing.T) {
	r := &runner{rt: &agent.RuleTable{Capture: agent.CaptureForwarder}, queue: NewQueue(8)}
	r.kernelRecord = &plainSource{name: "observe"}
	r.emitCaptureGaps()
	r.queue.Close()

	var got []string
	for ev := range r.queue.C() {
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		got = append(got, p.Why)
	}
	if want := []string{"mechanism-unavailable"}; !slices.Equal(got, want) {
		t.Fatalf("gaps %v, want %v", got, want)
	}
}

// TestEmitCaptureGapsFallbackIgnoresTheKernelRecordGap: startKernelRecord's what=record gap sits in
// CaptureGaps, and a capture the contract asked for with no source and no capture gap still gets its
// mechanism-unavailable gap beside it.
func TestEmitCaptureGapsFallbackIgnoresTheKernelRecordGap(t *testing.T) {
	r := &runner{rt: &agent.RuleTable{Capture: agent.CaptureForwarder}, queue: NewQueue(8)}
	r.deps.CaptureGaps = []source.Gap{{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1}}
	r.emitCaptureGaps()
	r.queue.Close()

	var got []string
	for ev := range r.queue.C() {
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		got = append(got, p.What+"/"+p.Why)
	}
	want := []string{"record/" + GapKernelRecordUnavailable, "capture/mechanism-unavailable"}
	if !slices.Equal(got, want) {
		t.Fatalf("gaps %v, want %v", got, want)
	}
}
