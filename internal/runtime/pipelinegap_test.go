// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestPipelineRefusedEventsBecomeAGap is the refused half of P0-DESIGN §2.4's loss accounting. A
// queue-full drop already becomes `gap what=record why=channel-full count=N`; an event a stage or
// Append refused must get the same treatment, or the run's ledger stays intact, complete and verified
// with an action the agent really took simply absent from it — the one loss an audit record cannot
// afford to take silently.
func TestPipelineRefusedEventsBecomeAGap(t *testing.T) {
	// SplitBlobsStage's real failure mode (internal/ledger/blob.go): the blob file cannot be written,
	// so the whole oversized ssl_response is refused before Append.
	failingSplit := func(next ledger.Sink) ledger.Sink {
		return func(ev *record.Event) error {
			if ev.Kind == record.KindSSLResponse {
				return errors.New("blob: no space left on device")
			}
			return next(ev)
		}
	}
	q := NewQueue(8)
	sink := &collectSink{}
	p := newPipeline(q, sink.append, ledger.RedactStage, failingSplit,
		runStamp{PID: 11, TID: 12, Cgroup: 99}, nil, nil, slog.New(slog.DiscardHandler))

	for i := 0; i < 2; i++ {
		ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder}
		if err := ev.SetPayload(record.SSLResponsePayload{Status: 200}); err != nil {
			t.Fatal(err)
		}
		q.Emit(ev)
	}
	p.drain()

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("wrote %d events, want only the gap that reports the two refusals: %+v", len(got), got)
	}
	if got[0].Kind != record.KindGap {
		t.Fatalf("event is %s, want gap", got[0].Kind)
	}
	var gp record.GapPayload
	if err := got[0].DecodePayload(&gp); err != nil {
		t.Fatal(err)
	}
	if gp.What != record.GapRecord || gp.Why != GapStageRefused || gp.Count != 2 {
		t.Fatalf("gap %+v, want record/%s/2", gp, GapStageRefused)
	}
	// The counter resets with the report, so a second drain says nothing (the same contract
	// reportDrops keeps).
	p.drain()
	if sink.count() != 1 {
		t.Fatalf("a second drain wrote %d events, want none", sink.count()-1)
	}
}

// TestPipelineRefusedGapIsSilentWhenNothingFailed keeps the common case quiet: a run whose stages
// refused nothing must not carry a count=0 gap, which would read as a loss that never happened.
func TestPipelineRefusedGapIsSilentWhenNothingFailed(t *testing.T) {
	q := NewQueue(4)
	sink := &collectSink{}
	p := testPipeline(t, q, sink)
	q.Emit(&record.Event{Kind: record.KindFS, Source: record.SourceSeccomp})
	p.drain()
	if sink.count() != 1 {
		t.Fatalf("wrote %d events, want just the one real event", sink.count())
	}
}
