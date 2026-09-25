// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"testing"
)

// cutStream is an event stream the client or a cap ended after content_block_stop: message_start's placeholder
// output count is all it reported, and the message_delta carrying the real one never came.
const cutStream = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","usage":{"input_tokens":1200,"output_tokens":1}}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}` + "\n\n" +
	"event: content_block_stop\n" +
	`data: {"type":"content_block_stop","index":0}` + "\n\n"

// TestCutStreamChargesMaxTokens: a stream cut before its final message_delta is charged the request's max_tokens as
// output, marked as a bound; with max_tokens unknown the exchange is unmetered.
func TestCutStreamChargesMaxTokens(t *testing.T) {
	cases := []struct {
		name      string
		req       string
		wantOut   int
		bound     bool
		unmetered bool
	}{
		{"max_tokens known", `{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`, 4096, true, false},
		{"max_tokens absent", `{"model":"claude-opus-5","stream":true,"messages":[]}`, 1, false, true},
		{"request unreadable", `{"model":`, 1, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := response([]byte(cutStream), "text/event-stream")
			resp.SSE = true
			facts, err := New().Parse(request([]byte(tc.req)), resp)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if facts.Usage == nil || facts.Usage.Input != 1200 || facts.Usage.Output != tc.wantOut ||
				facts.Usage.OutputBound != tc.bound {
				t.Errorf("usage = %+v, want input 1200, output %d, bound %v", facts.Usage, tc.wantOut, tc.bound)
			}
			if facts.Unmetered != tc.unmetered {
				t.Errorf("Unmetered = %v, want %v", facts.Unmetered, tc.unmetered)
			}
		})
	}
}

// TestWholeStreamIsNotBounded: a stream that carried its message_delta is charged what it reported, never the
// bound.
func TestWholeStreamIsNotBounded(t *testing.T) {
	body := cutStream + "event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}` + "\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	resp := response([]byte(body), "text/event-stream")
	resp.SSE = true
	facts, err := New().Parse(request([]byte(`{"model":"claude-opus-5","max_tokens":4096,"messages":[]}`)), resp)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Usage == nil || facts.Usage.Output != 7 || facts.Usage.OutputBound || facts.Unmetered {
		t.Errorf("facts = %+v usage %+v", facts, facts.Usage)
	}
}
