// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// panicReader is a parser whose request reader panics, which the Dispatcher must recover as it does a Parse panic.
type panicReader struct{ fakeParser }

func (panicReader) ToolResults(*derive.Message) ([]string, bool) { panic("reader bug") }

// TestReadRequestLabelsWhatARequestSaysAlone is what a capture source stamps on an ssl_request before any answer
// (capture-derive R40, R42): a model host's silent path is side traffic and is not read for results; a model turn
// is read for the tool results its last message reports; a host no parser claims, a turn the parser cannot read,
// and a reader that panics leave tool_results unset, which the attribute stage reads as "not read".
func TestReadRequestLabelsWhatARequestSaysAlone(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()})
	turn := &derive.Message{Method: "POST", Path: "/v1/messages",
		Body: []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_8812"}]}]}`)}
	first := &derive.Message{Method: "POST", Path: "/v1/messages", Body: []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)}
	logging := &derive.Message{Method: "POST", Path: "/api/event_logging/batch", Body: []byte(`{}`)}
	meta := testMeta("anthropic", "api.anthropic.com")

	payload := func(r derive.RequestReading) record.SSLRequestPayload {
		var p record.SSLRequestPayload
		r.Apply(&p)
		return p
	}
	if p := payload(d.ReadRequest(turn, meta)); p.Side || p.ToolResults == nil || !slices.Equal(*p.ToolResults, []string{"toolu_8812"}) {
		t.Fatalf("a turn reporting a result: %+v", p)
	}
	if p := payload(d.ReadRequest(first, meta)); p.Side || p.ToolResults == nil || len(*p.ToolResults) != 0 {
		t.Fatalf("a first turn is read and reports none: %+v", p)
	}
	if p := payload(d.ReadRequest(logging, meta)); !p.Side || p.ToolResults != nil {
		t.Fatalf("telemetry on the model host is side traffic: %+v", p)
	}
	cut := *turn
	cut.Truncated = true
	if p := payload(d.ReadRequest(&cut, meta)); p.Side || p.ToolResults != nil {
		t.Fatalf("a cut turn is not read: %+v", p)
	}
	if p := payload(d.ReadRequest(turn, testMeta("", "pypi.org"))); p.Side || p.ToolResults != nil {
		t.Fatalf("a host no parser claims is not read: %+v", p)
	}
	if p := payload(d.ReadRequest(nil, meta)); p.Side || p.ToolResults != nil {
		t.Fatalf("no request: %+v", p)
	}

	bad := derive.NewDispatcher([]derive.Parser{&panicReader{fakeParser{provider: "anthropic"}}})
	if p := payload(bad.ReadRequest(turn, meta)); p.ToolResults != nil {
		t.Fatalf("a reader that panicked: %+v", p)
	}
}
