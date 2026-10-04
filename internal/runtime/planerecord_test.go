// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRunStartNamesTheDecisionPlane is enforce-plane R19 and I7 made auditable (record_minor 2): run_start's
// decision_plane is the mode the run's kernel decision plane decided in, fanotify for a tier-2 run on the listener
// (a handle with the plane seam and no mode), and absent for a tier with no plane seam (tier 1).
func TestRunStartNamesTheDecisionPlane(t *testing.T) {
	for _, tc := range []struct {
		name   string
		handle api.Handle
		want   string
	}{
		{"lsm", planeHandle{mode: record.DecisionPlaneLSM}, record.DecisionPlaneLSM},
		{"fmod_ret", planeHandle{mode: record.DecisionPlaneFmodRet, execs: true}, record.DecisionPlaneFmodRet},
		{"the fanotify fallback", planeHandle{}, record.DecisionPlaneFanotify},
		{"tier 1", plainHandle{}, ""},
		{"no handle", nil, ""},
	} {
		r := newTestRunner(Deps{})
		r.handle = tc.handle
		if got := r.decisionPlane(); got != tc.want {
			t.Errorf("%s: decision_plane %q, want %q", tc.name, got, tc.want)
		}
	}
	if record.Minor < record.MinorDecisionPlane {
		t.Errorf("record.Minor %d does not cover decision_plane (%d)", record.Minor, record.MinorDecisionPlane)
	}
}

// countingPlane is a plane handle whose slot counted its fail-closed outcomes (enforce.PlaneCounterReporter).
type countingPlane struct {
	planeHandle
	counts []enforce.PlaneCount
	err    error
}

func (h countingPlane) PlaneCounters() ([]enforce.PlaneCount, error) { return h.counts, h.err }

// TestPlaneCountersBecomeGaps is enforce-plane §2.8's counters half: at run end every non-zero counter of the run's
// slot is one gap what=enforce line, why the counter's name, count its value, decision_plane the mode; a zero
// counter writes nothing, and a slot that cannot be read is one gap with no count, never silence.
func TestPlaneCountersBecomeGaps(t *testing.T) {
	gaps := func(h api.Handle) []record.GapPayload {
		r := newTestRunner(Deps{})
		r.handle = h
		r.queue = NewQueue(8)
		sink := &collectSink{}
		r.pipe = newPipeline(r.queue, sink.append, ledger.RedactStage, passthroughStage,
			runStamp{PID: 1, TID: 1, Cgroup: 2}, nil, nil, slog.New(slog.DiscardHandler))
		r.emitPlaneGaps()
		var out []record.GapPayload
		for _, ev := range sink.all() {
			var g record.GapPayload
			if ev.Kind != record.KindGap || ev.DecodePayload(&g) != nil {
				t.Fatalf("not a gap line: %+v", ev)
			}
			out = append(out, g)
		}
		return out
	}
	lsm := planeHandle{mode: record.DecisionPlaneLSM}
	got := gaps(countingPlane{planeHandle: lsm, counts: []enforce.PlaneCount{
		{Why: record.GapPlaneBound, Count: 3}, {Why: record.GapPlaneMismatch, Count: 1}, {Why: record.GapPlaneNoRows},
	}})
	want := []record.GapPayload{
		{What: record.GapEnforce, Why: record.GapPlaneBound, Count: 3, DecisionPlane: record.DecisionPlaneLSM},
		{What: record.GapEnforce, Why: record.GapPlaneMismatch, Count: 1, DecisionPlane: record.DecisionPlaneLSM},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("gaps %+v, want %+v", got, want)
	}
	got = gaps(countingPlane{planeHandle: lsm, err: errors.New("no map")})
	if len(got) != 1 || got[0].What != record.GapEnforce || got[0].Why != record.GapPlaneCountersUnread ||
		got[0].DecisionPlane != record.DecisionPlaneLSM || got[0].Count != 0 {
		t.Errorf("an unread slot: %+v", got)
	}
	if got := gaps(countingPlane{planeHandle: planeHandle{}, counts: []enforce.PlaneCount{{Why: record.GapPlaneBound, Count: 1}}}); len(got) != 0 {
		t.Errorf("a run with no plane mode wrote %+v", got)
	}
	if got := gaps(lsm); len(got) != 0 {
		t.Errorf("a handle with no counters wrote %+v", got)
	}
}
