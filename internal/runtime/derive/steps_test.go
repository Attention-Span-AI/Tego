// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ev builds one event of a kind, from one thread.
func ev(kind record.Kind, tid int, payload any) *record.Event {
	e := &record.Event{
		V: record.Version, TS: time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC),
		Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "retriever",
		PID: 48212, TID: tid, Cgroup: 44821, Kind: kind, Source: record.SourceForwarder,
	}
	if kind.IsAction() {
		e.Source = record.SourceKernel
		e.Rule, e.Verdict, e.Authority = "fs.read[.]", record.VerdictAllow, record.AuthorityRule
		e.Attr = record.Unattributed()
	}
	if payload != nil {
		if err := e.SetPayload(payload); err != nil {
			panic(err)
		}
	}
	return e
}

func sslRequest(tid int, host, retryOf string) *record.Event {
	return ev(record.KindSSLRequest, tid, record.SSLRequestPayload{
		Endpoint: "anthropic", Method: "POST", Path: "/v1/messages", Host: host, RetryOf: retryOf})
}

func sslResponse(tid int) *record.Event {
	return ev(record.KindSSLResponse, tid, record.SSLResponsePayload{Status: 200, ParserVersion: "x"})
}

func action(tid int) *record.Event {
	return ev(record.KindFS, tid, record.FSPayload{Op: record.FSOpen, Path: "/work/proj/a"})
}

// The capture-derive.md R33–R36 table; R34 is its rows for one open step (likely), none and several (never guessed).
func TestStepsByTime(t *testing.T) {
	cases := []struct {
		name string
		// stream is the events in order; the action to check is the last one.
		stream         []*record.Event
		wantStep       int
		wantConfidence string
		wantThread     string
		wantCount      int
	}{
		{
			name:           "no model call yet: nothing to attribute to",
			stream:         []*record.Event{action(48212)},
			wantConfidence: record.ConfidenceUnattributed,
		},
		{
			name:           "inside the one open step",
			stream:         []*record.Event{sslRequest(48212, "api.anthropic.com", ""), action(48212)},
			wantStep:       1,
			wantConfidence: record.ConfidenceLikely,
			wantThread:     "t48212",
			wantCount:      1,
		},
		{
			name: "after the response, while the turn's tools run",
			stream: []*record.Event{sslRequest(48212, "api.anthropic.com", ""), sslResponse(48212),
				action(48212)},
			wantStep: 1, wantConfidence: record.ConfidenceLikely, wantThread: "t48212", wantCount: 1,
		},
		{
			name: "the second turn is step 2",
			stream: []*record.Event{
				sslRequest(48212, "api.anthropic.com", ""), sslResponse(48212),
				sslRequest(48212, "api.anthropic.com", ""), sslResponse(48212), action(48212)},
			wantStep: 2, wantConfidence: record.ConfidenceLikely, wantThread: "t48212", wantCount: 2,
		},
		{
			name: "a retry extends the original step rather than opening one (R23, R33)",
			stream: []*record.Event{
				sslRequest(48212, "api.anthropic.com", ""),
				sslRequest(48212, "api.anthropic.com", "fx-1"),
				action(48212)},
			wantStep: 1, wantConfidence: record.ConfidenceLikely, wantThread: "t48212", wantCount: 1,
		},
		{
			name: "two threads waiting at once is never guessed at (R34)",
			stream: []*record.Event{
				sslRequest(48212, "api.anthropic.com", ""),
				sslRequest(48215, "api.anthropic.com", ""),
				action(48212)},
			wantConfidence: record.ConfidenceUnattributed, wantCount: 2,
		},
		{
			name: "one thread waiting while another's turn is done: the open step wins",
			stream: []*record.Event{
				sslRequest(48212, "api.anthropic.com", ""), sslResponse(48212),
				sslRequest(48215, "api.anthropic.com", ""),
				action(48212)},
			wantStep: 2, wantConfidence: record.ConfidenceLikely, wantThread: "t48215", wantCount: 2,
		},
		{
			name: "two finished turns and nothing open: still not guessed at",
			stream: []*record.Event{
				sslRequest(48212, "api.anthropic.com", ""), sslResponse(48212),
				sslRequest(48215, "api.anthropic.com", ""), sslResponse(48215),
				action(48212)},
			wantConfidence: record.ConfidenceUnattributed, wantCount: 2,
		},
		{
			name:           "a request to a host the contract never declared opens nothing",
			stream:         []*record.Event{sslRequest(48212, "telemetry.example.com", ""), action(48212)},
			wantConfidence: record.ConfidenceUnattributed, wantCount: 0,
		},
		{
			name: "a step is numbered even when the thread that acts is a different one",
			stream: []*record.Event{sslRequest(48212, "api.anthropic.com", ""), sslResponse(48212),
				action(48999)},
			wantStep: 1, wantConfidence: record.ConfidenceLikely, wantThread: "t48212", wantCount: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := derive.NewSteps("api.anthropic.com")
			for _, e := range tc.stream {
				s.Apply(e)
			}
			last := tc.stream[len(tc.stream)-1]
			if last.Attr == nil {
				t.Fatal("the action kept no attribution")
			}
			if last.Attr.Method != record.MethodTime {
				t.Errorf("method = %q, want time", last.Attr.Method)
			}
			if last.Attr.Confidence != tc.wantConfidence {
				t.Errorf("confidence = %q, want %q", last.Attr.Confidence, tc.wantConfidence)
			}
			if last.Attr.Step != tc.wantStep {
				t.Errorf("step = %d, want %d", last.Attr.Step, tc.wantStep)
			}
			if last.Attr.Thread != tc.wantThread {
				t.Errorf("thread = %q, want %q", last.Attr.Thread, tc.wantThread)
			}
			if s.Count() != tc.wantCount {
				t.Errorf("%d steps opened, want %d", s.Count(), tc.wantCount)
			}
			if !last.Attr.Valid() {
				t.Errorf("attribution %+v is not a v1 attribution", last.Attr)
			}
		})
	}
}

// A richer method is never lowered, and the P0 placeholder always is (capture-derive.md R35).
func TestStepsNeverLowersARicherMethod(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(sslRequest(48212, "api.anthropic.com", ""))

	exact := action(48212)
	exact.Attr = &record.Attribution{Thread: "t1", Step: 7, Confidence: record.ConfidenceExact,
		Method: record.MethodToolID}
	s.Apply(exact)
	if exact.Attr.Step != 7 || exact.Attr.Method != record.MethodToolID {
		t.Errorf("a tool_id attribution was overwritten: %+v", exact.Attr)
	}

	placeholder := action(48212)
	placeholder.Attr = record.Unattributed() // {unattributed, none}, what a producer stamps
	s.Apply(placeholder)
	if placeholder.Attr.Method != record.MethodTime || placeholder.Attr.Step != 1 {
		t.Errorf("the none placeholder was not upgraded: %+v", placeholder.Attr)
	}
}

// A decision event with no step of its own is numbered by the turn it came from.
func TestStepsStampsDecisions(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(sslRequest(48212, "api.anthropic.com", ""))
	s.Apply(sslResponse(48212))
	d := ev(record.KindDecision, 48212, record.DecisionPayload{ToolUseID: "t1", Tool: "bash"})
	s.Apply(d)
	var p record.DecisionPayload
	if err := d.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Step != 1 {
		t.Errorf("step = %d, want 1", p.Step)
	}
	if p.Tool != "bash" || p.ToolUseID != "t1" {
		t.Errorf("stamping the step changed the decision: %+v", p)
	}

	// A decision a parser already numbered is left alone.
	fixed := ev(record.KindDecision, 48212, record.DecisionPayload{Step: 9, Tool: "bash"})
	s.Apply(fixed)
	if err := fixed.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Step != 9 {
		t.Errorf("step = %d, want the parser's own 9", p.Step)
	}
}

// The stage shape the pipeline composes, and the state it exposes.
func TestStepsStage(t *testing.T) {
	s := derive.NewSteps()
	var seen []record.Kind
	stage := s.Stage(func(e *record.Event) { seen = append(seen, e.Kind) })
	req := sslRequest(48212, "api.anthropic.com", "")
	act := action(48212)
	stage(req)
	stage(act)
	if len(seen) != 2 || seen[0] != record.KindSSLRequest || seen[1] != record.KindFS {
		t.Errorf("the stage did not pass every event on: %v", seen)
	}
	if act.Attr.Step != 1 {
		t.Errorf("the stage did not attribute: %+v", act.Attr)
	}
	states := s.States()
	st, ok := states["t48212"]
	if !ok || st.Step != 1 || !st.InFlight || st.OpenSince.IsZero() {
		t.Errorf("states = %+v", states)
	}
	states["t48212"] = derive.StepState{Step: 99}
	if s.States()["t48212"].Step != 1 {
		t.Error("States returned the live state, not a copy")
	}
	s.Apply(nil) // must not panic
}

// AttributeByTime is pure — the same states give the same answer, and an empty set is
// unattributed rather than a panic.
func TestAttributeByTimeIsPure(t *testing.T) {
	states := map[string]derive.StepState{"t1": {Step: 3, InFlight: true}}
	a := derive.AttributeByTime(states, action(1))
	b := derive.AttributeByTime(states, action(1))
	if a != b {
		t.Errorf("%+v != %+v", a, b)
	}
	if a.Step != 3 || a.Thread != "t1" || a.Confidence != record.ConfidenceLikely {
		t.Errorf("attribution = %+v", a)
	}
	empty := derive.AttributeByTime(nil, action(1))
	if empty.Confidence != record.ConfidenceUnattributed || empty.Method != record.MethodTime {
		t.Errorf("attribution = %+v", empty)
	}
}

// BenchmarkSteps measures the attribute stage: it runs on every event of every run (§9 Benchmarks).
func BenchmarkSteps(b *testing.B) {
	s := derive.NewSteps("api.anthropic.com")
	req := sslRequest(48212, "api.anthropic.com", "")
	resp := sslResponse(48212)
	act := action(48212)
	b.ReportAllocs()
	for b.Loop() {
		s.Apply(req)
		s.Apply(act)
		s.Apply(resp)
	}
}

// BenchmarkStepsThreads measures the attribute stage in a run whose model traffic came from many threads,
// each of which opened a step: one model turn on one of them, and an action attributed in it, per
// operation. The stage runs on the pipeline's one goroutine, so its cost per event must not grow with the
// threads the run has seen (P8: it copied and scanned every thread's state for every action).
func BenchmarkStepsThreads(b *testing.B) {
	for _, n := range []int{1, 1000, 10000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			s := derive.NewSteps("api.anthropic.com")
			for tid := 1; tid <= n; tid++ {
				s.Apply(sslRequest(tid, "api.anthropic.com", ""))
				s.Apply(sslResponse(tid))
			}
			req, act, resp := sslRequest(1, "api.anthropic.com", ""), action(1), sslResponse(1)
			b.ReportAllocs()
			for b.Loop() {
				s.Apply(req)
				s.Apply(act)
				s.Apply(resp)
			}
		})
	}
}

// A pipelined request never inflates the step count (R33: "opens step N+1 ... if none is
// already open"). steps_test.go's table exercises the retry_of path and the after-response path, but
// never a second, plain (non-retry) request arriving while the first is still outstanding — the branch
// `if st.InFlight { return }` in Steps.open. A client that pipelines two requests on one connection
// before either response lands must still be inside step 1, not step 2: the window R33 describes is
// "until that thread's response arrives," and neither request here has one yet.
func TestStepsPipelinedRequestStaysInOpenStep(t *testing.T) {
	cases := []struct {
		name      string
		requests  int // plain, non-retry ssl_requests sent back to back with no response between
		wantCount int
	}{
		{name: "a second request while the first is outstanding stays in step 1", requests: 2, wantCount: 1},
		{name: "a third pipelined request still stays in step 1", requests: 3, wantCount: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := derive.NewSteps("api.anthropic.com")
			for i := 0; i < tc.requests; i++ {
				s.Apply(sslRequest(48212, "api.anthropic.com", ""))
			}
			act := action(48212)
			s.Apply(act)
			if s.Count() != tc.wantCount {
				t.Errorf("%d requests opened %d steps, want %d (R33: none already open)",
					tc.requests, s.Count(), tc.wantCount)
			}
			if act.Attr.Step != 1 {
				t.Errorf("action attributed to step %d, want 1", act.Attr.Step)
			}
			if act.Attr.Confidence != record.ConfidenceLikely {
				t.Errorf("confidence = %q, want likely", act.Attr.Confidence)
			}
		})
	}
}

// R35 names both P1 methods a time attribution must never touch, tool_id and tid.
// TestStepsNeverLowersARicherMethod (steps_test.go) only ever exercises tool_id; a regression that
// dropped MethodTID from richerThanTime's check would still pass that test while silently overwriting
// every tid-attributed action that also happens to fall inside one open step. Confidence varies too
// (exact, and a tid call that only reached likely): R35 says a richer *method* is never touched, not
// that lower-confidence richer attributions are fair game.
func TestStepsNeverTouchesEitherRicherMethod(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		confidence string
	}{
		{name: "an exact tool_id attribution is preserved", method: record.MethodToolID, confidence: record.ConfidenceExact},
		{name: "an exact tid attribution is preserved", method: record.MethodTID, confidence: record.ConfidenceExact},
		{name: "a merely likely tid attribution is preserved, not just an exact one", method: record.MethodTID, confidence: record.ConfidenceLikely},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := derive.NewSteps("api.anthropic.com")
			// Exactly one open step, so AttributeByTime has an opinion (likely, step 1, t48212) that
			// would visibly differ from what we stamp below — a silent no-op bug would overwrite it.
			s.Apply(sslRequest(48212, "api.anthropic.com", ""))

			act := action(48212)
			want := record.Attribution{Thread: "tool-42", Step: 42, Confidence: tc.confidence, Method: tc.method}
			act.Attr = &want
			s.Apply(act)
			if *act.Attr != want {
				t.Errorf("a %s attribution was touched by time: got %+v, want %+v", tc.method, *act.Attr, want)
			}
		})
	}
}

// A forwarder turn that never got an ssl_response (its upstream leg failed) does not swallow the next turn on
// the same lane: the next non-retry request opens a new step. A retry still extends, and a tid-carrying source
// (uprobe) keeps R33's one open step per thread.
func TestForwarderRequestAfterAnAbandonedTurnOpensAStep(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(sslRequest(0, "api.anthropic.com", ""))
	s.Apply(sslRequest(0, "api.anthropic.com", ""))
	if s.Count() != 2 {
		t.Errorf("forwarder: %d steps, want 2", s.Count())
	}
	s.Apply(sslRequest(0, "api.anthropic.com", "req_1"))
	if s.Count() != 2 {
		t.Errorf("a retry opened a step: %d", s.Count())
	}
	u := derive.NewSteps()
	for range 2 {
		e := sslRequest(7, "api.anthropic.com", "")
		e.Source = record.SourceSSL
		u.Apply(e)
	}
	if u.Count() != 1 {
		t.Errorf("uprobe: %d steps, want 1", u.Count())
	}
}
