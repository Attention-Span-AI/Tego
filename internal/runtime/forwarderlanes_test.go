// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// forwarderTurn is one forwarder line as the forwarder emits it: the peer's pid, no tid, and the
// lane its turn took among the process's turns in flight.
func forwarderTurn(t *testing.T, kind record.Kind, ts time.Time, pid int, lane uint64, pair uint64) *record.Event {
	t.Helper()
	ev := &record.Event{V: record.Version, TS: ts, PID: pid, Lane: lane, Kind: kind, Source: record.SourceForwarder,
		Pair: pair}
	var err error
	if kind == record.KindSSLRequest {
		err = ev.SetPayload(record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages",
			Host: "api.anthropic.com"})
	} else {
		err = ev.SetPayload(record.SSLResponsePayload{Status: 200})
	}
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// execAt is an action of the agent at ts.
func execAt(t *testing.T, ts time.Time) *record.Event {
	t.Helper()
	act := &record.Event{V: record.Version, TS: ts, PID: 777, TID: 778, Kind: record.KindExec,
		Source: record.SourceSeccomp, Rule: "exec.allow[/bin/true]", Verdict: record.VerdictAllow,
		Authority: record.AuthorityRule}
	if err := act.SetPayload(record.ExecPayload{Path: "/bin/true", Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	return act
}

// TestForwarderTurnsKeepTheirOwnThread: through the pipeline, the forwarder left pid and tid
// empty, stampRule filled in the launcher's own, and the attribute stage keyed every turn on that one tid:
// two concurrent model turns of an agent became one thread with one open step, every action while both were in
// flight was attributed "likely" to it where R34 says more than one open step is unattributed, and the ledger
// named tego's own process as the model's caller. The forwarder's lines now carry the peer's pid and a lane
// per turn in flight.
func TestForwarderTurnsKeepTheirOwnThread(t *testing.T) {
	const launcherPID, launcherTID, peer = 11, 12, 500
	sink := &collectSink{}
	steps := derive.NewSteps("api.anthropic.com")
	p := newPipeline(NewQueue(8), sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: launcherPID, TID: launcherTID, Cgroup: 99}, steps.Stage, nil, slog.New(slog.DiscardHandler))

	now := time.Now()
	p.handle(forwarderTurn(t, record.KindSSLRequest, now, peer, 1, 1))
	p.handle(forwarderTurn(t, record.KindSSLRequest, now.Add(time.Millisecond), peer, 2, 2))
	p.handle(execAt(t, now.Add(5*time.Millisecond)))

	evs := sink.all()
	for _, ev := range evs {
		if ev.Source == record.SourceForwarder && (ev.PID != peer || ev.TID == launcherTID) {
			t.Errorf("%s from the forwarder carries pid %d tid %d: the ledger names tego as the model's caller",
				ev.Kind, ev.PID, ev.TID)
		}
	}
	got := evs[len(evs)-1]
	if got.Kind != record.KindExec || got.Attr == nil {
		t.Fatalf("last line %s attr %+v", got.Kind, got.Attr)
	}
	if got.Attr.Confidence != record.ConfidenceUnattributed {
		t.Errorf("an action during two concurrent turns is attributed %s to step %d of thread %s; R34 says unattributed",
			got.Attr.Confidence, got.Attr.Step, got.Attr.Thread)
	}
}

// TestSequentialForwarderTurnsAreOneThread: turns one after another take the same lane whichever connection
// they come on, so a single-threaded agent's actions between its turns stay attributed to its last step, as
// they were when every forwarder line carried the launcher's one tid.
func TestSequentialForwarderTurnsAreOneThread(t *testing.T) {
	sink := &collectSink{}
	steps := derive.NewSteps("api.anthropic.com")
	p := newPipeline(NewQueue(8), sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 11, TID: 12, Cgroup: 99}, steps.Stage, nil, slog.New(slog.DiscardHandler))
	now := time.Now()
	for i := range 2 {
		base := now.Add(time.Duration(i) * time.Second)
		p.handle(forwarderTurn(t, record.KindSSLRequest, base, 500, 1, uint64(2*i+1)))
		p.handle(forwarderTurn(t, record.KindSSLResponse, base.Add(10*time.Millisecond), 500, 1, uint64(2*i+1)))
	}
	p.handle(execAt(t, now.Add(3*time.Second)))
	evs := sink.all()
	got := evs[len(evs)-1]
	if got.Attr == nil || got.Attr.Confidence != record.ConfidenceLikely || got.Attr.Step != 2 {
		t.Errorf("an action after a single thread's second turn is attributed %+v, want likely to step 2", got.Attr)
	}
}
