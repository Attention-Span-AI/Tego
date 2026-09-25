// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// seqSink assigns seq numbers as the ledger does and keeps what it was handed.
type seqSink struct {
	next   uint64
	events []*record.Event
}

func (s *seqSink) append(ev *record.Event) error {
	ev.Seq = s.next
	s.next++
	s.events = append(s.events, ev)
	return nil
}

func sslEvent(t *testing.T, kind record.Kind, pair uint64) *record.Event {
	t.Helper()
	ev := &record.Event{Kind: kind, Source: record.SourceForwarder, Pair: pair}
	var err error
	if kind == record.KindSSLRequest {
		err = ev.SetPayload(record.SSLRequestPayload{Method: "POST", Path: "/v1/messages", RequestID: "x"})
	} else {
		err = ev.SetPayload(record.SSLResponsePayload{Status: 200, RequestID: "x"})
	}
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestResponseCarriesItsRequestsSeq: an ssl_response gets the seq the ledger gave its ssl_request's line,
// matched by the pair token both carry, whatever came between them; a response whose request line is not
// known omits request_seq instead of naming seq 0, which is run_start.
func TestResponseCarriesItsRequestsSeq(t *testing.T) {
	sink := &seqSink{next: 5}
	p := newPipeline(NewQueue(4), sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 1, TID: 1}, nil, nil, slog.New(slog.DiscardHandler))
	a, b := source.NewPair(), source.NewPair()
	p.handle(sslEvent(t, record.KindSSLRequest, a))                                // seq 5
	p.handle(sslEvent(t, record.KindSSLRequest, b))                                // seq 6
	p.handle(&record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}) // seq 7
	p.handle(sslEvent(t, record.KindSSLResponse, b))                               // answers 6
	p.handle(sslEvent(t, record.KindSSLResponse, a))                               // answers 5
	p.handle(sslEvent(t, record.KindSSLResponse, source.NewPair()))                // its request was never seen

	want := []any{uint64(6), uint64(5), nil}
	var got []any
	for _, ev := range sink.events {
		if ev.Kind != record.KindSSLResponse {
			continue
		}
		var pl record.SSLResponsePayload
		if err := ev.DecodePayload(&pl); err != nil {
			t.Fatal(err)
		}
		if pl.RequestSeq == nil {
			got = append(got, nil)
		} else {
			got = append(got, *pl.RequestSeq)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d responses, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("response %d request_seq = %v, want %v (all: %v)", i, got[i], want[i], got)
		}
	}
}

// TestPendingRequestsAreBounded: requests whose responses never come are forgotten oldest first, so the
// map cannot grow for the length of a run.
func TestPendingRequestsAreBounded(t *testing.T) {
	sink := &seqSink{}
	p := newPipeline(NewQueue(4), sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 1, TID: 1}, nil, nil, slog.New(slog.DiscardHandler))
	for range maxPendingRequests + 10 {
		p.handle(sslEvent(t, record.KindSSLRequest, source.NewPair()))
	}
	if len(p.requests) != maxPendingRequests || len(p.requestOrder) != maxPendingRequests {
		t.Fatalf("%d remembered (%d in order), want at most %d", len(p.requests), len(p.requestOrder), maxPendingRequests)
	}
}

// TestAnsweredRequestsLeaveTheOrder: an answered request leaves requestOrder too, so a request still waiting
// keeps its seq however many exchanges are answered after it.
func TestAnsweredRequestsLeaveTheOrder(t *testing.T) {
	sink := &seqSink{}
	p := newPipeline(NewQueue(4), sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 1, TID: 1}, nil, nil, slog.New(slog.DiscardHandler))
	long := source.NewPair()
	p.handle(sslEvent(t, record.KindSSLRequest, long))
	for range maxPendingRequests + 10 {
		pair := source.NewPair()
		p.handle(sslEvent(t, record.KindSSLRequest, pair))
		p.handle(sslEvent(t, record.KindSSLResponse, pair))
	}
	if len(p.requestOrder) != 1 || len(p.requests) != 1 {
		t.Fatalf("%d in order, %d remembered, want the one waiting", len(p.requestOrder), len(p.requests))
	}
	if _, ok := p.requests[long]; !ok {
		t.Fatal("the request still waiting was forgotten")
	}
}
