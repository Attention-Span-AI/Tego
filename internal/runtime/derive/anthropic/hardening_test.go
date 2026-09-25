// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

const citedStream = `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[],"stop_reason":null,"usage":{"input_tokens":150000,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":"","citations":[]}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":{"type":"char_location","cited_text":"x","document_index":0,"document_title":"d","start_char_index":0,"end_char_index":1}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":9000}}

event: message_stop
data: {"type":"message_stop"}

`

// A documented Messages-API stream shape (citations_delta) voids the whole response: no usage reaches
// limits, so a token/cost budget never counts a response the agent can make carry citations at will.
func TestHardeningCitationsDeltaLosesUsage(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{New()})
	res, err := d.Handle(request([]byte(`{"model":"claude-opus-5","messages":[]}`)),
		response([]byte(citedStream), "text/event-stream"), derive.Meta{Provider: "anthropic"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Facts.Usage == nil {
		t.Fatalf("citations_delta stream: usage lost (facts=%+v, events=%d)", res.Facts, len(res.Events))
	}
}

// A stream cut short after message_start (capture cap, capture budget, a client that went away, a mid-stream
// error event) loses the input tokens message_start already reported.
func TestHardeningTruncatedStreamLosesSeedUsage(t *testing.T) {
	body := `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[],"stop_reason":null,"usage":{"input_tokens":150000,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hel`
	d := derive.NewDispatcher([]derive.Parser{New()})
	res, _ := d.Handle(request([]byte(`{"model":"claude-opus-5","messages":[]}`)),
		&derive.Message{Status: 200, Header: map[string][]string{"Content-Type": {"text/event-stream"}}, Body: []byte(body), Truncated: true},
		derive.Meta{Provider: "anthropic"})
	if res.Facts.Usage == nil {
		t.Fatalf("truncated stream: message_start's 150000 input tokens dropped; facts=%+v", res.Facts)
	}
}

// An unknown (future) stream event type voids the response too; Anthropic's versioning policy says new
// event types may be added and clients must ignore them.
func TestHardeningUnknownEventLosesUsage(t *testing.T) {
	body := citedStream[:0] + `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[],"stop_reason":null,"usage":{"input_tokens":10,"output_tokens":1}}}

event: some_future_event
data: {"type":"some_future_event"}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}

event: message_stop
data: {"type":"message_stop"}
`
	d := derive.NewDispatcher([]derive.Parser{New()})
	res, _ := d.Handle(request([]byte(`{"model":"claude-opus-5","messages":[]}`)),
		response([]byte(body), "text/event-stream"), derive.Meta{Provider: "anthropic"})
	if res.Facts.Usage == nil {
		t.Fatalf("unknown event: usage lost")
	}
}

// Spellings of the Messages endpoint that an HTTP front end commonly normalises to /v1/messages parse to no
// usage and no decision at all — not even unparsed — so the exchange is invisible to every budget.
func TestHardeningNonCanonicalMessagesPathSilentlyUnbudgeted(t *testing.T) {
	stream := read(t, "messages-stream.sse")
	for _, p := range []string{"/v1/%6Dessages", "//v1/messages", "/v1//messages", "/v1/./messages", "/x/../v1/messages"} {
		req := request([]byte(`{"model":"claude-opus-5","messages":[]}`))
		req.Path = p
		facts, err := New().Parse(req, response(stream, "text/event-stream"))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if facts.Usage == nil && len(facts.Decisions) == 0 {
			t.Errorf("%s: a full Messages stream derived no usage and no decision (silent)", p)
		}
	}
}
