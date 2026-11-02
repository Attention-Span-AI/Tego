// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRequestLineCarriesWhatDeriveReadOffIt: the forwarder stamps an ssl_request with what derive reads off the
// request alone (capture-derive R40, R42): a model turn's tool results, an empty list for a turn that reports none,
// and side on the model host's telemetry, before the round trip, so the attribute stage has them when the line
// reaches it.
func TestRequestLineCarriesWhatDeriveReadOffIt(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	for _, c := range []struct {
		path, body string
	}{
		{"/v1/messages", `{"model":"m","max_tokens":9,"messages":[{"role":"user","content":"hi"}]}`},
		{"/v1/messages", `{"model":"m","max_tokens":9,"messages":[{"role":"user","content":"hi"},` +
			`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_8812","name":"db_query","input":{}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_8812","content":"rows"}]}]}`},
		{"/api/event_logging/batch", `{"events":[]}`},
	} {
		resp := h.post(c.path, []byte(c.body), nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	reqs := h.sink.waitFor(t, record.KindSSLRequest, 3)
	first := payloadOf[record.SSLRequestPayload](t, reqs[0])
	if first.Side || first.ToolResults == nil || len(*first.ToolResults) != 0 {
		t.Errorf("first turn: side %v, tool_results %v; want a read turn reporting none", first.Side, first.ToolResults)
	}
	second := payloadOf[record.SSLRequestPayload](t, reqs[1])
	if second.Side || second.ToolResults == nil || !slices.Equal(*second.ToolResults, []string{"toolu_8812"}) {
		t.Errorf("second turn: side %v, tool_results %v; want toolu_8812", second.Side, second.ToolResults)
	}
	logging := payloadOf[record.SSLRequestPayload](t, reqs[2])
	if !logging.Side || logging.ToolResults != nil {
		t.Errorf("telemetry: side %v, tool_results %v; want side traffic, not read", logging.Side, logging.ToolResults)
	}
}
