// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// deltaStream is a realistic response body: message_start, one text block of n small text_delta frames, a
// tool_use block, and the end of the message.
func deltaStream(n int) []byte {
	var b bytes.Buffer
	b.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\",\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n")
	b.WriteString("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
	for range n {
		b.WriteString("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello, world\"}}\n\n")
	}
	b.WriteString("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	b.WriteString("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n")
	b.WriteString("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}\n\n")
	b.WriteString("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n")
	b.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":40}}\n\n")
	b.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return b.Bytes()
}

// TestParseStreamResponseAllocationBoundedByBody: the parser's path over a stream of ordinary text deltas
// allocates a small multiple of the body, keeps no event, and still reads the tool_use input and the usage.
func TestParseStreamResponseAllocationBoundedByBody(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector makes sync.Pool drop items, so TotalAlloc is not bounded by the body")
	}
	body := deltaStream(40000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	resp, err := parseStreamResponse(body, true)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 4*uint64(len(body)) {
		t.Errorf("parseStreamResponse allocated %d KiB for a %d KiB body, want at most %d KiB",
			got>>10, len(body)>>10, 4*len(body)>>10)
	}
	if len(resp.Content) != 2 || resp.Content[1].Name != "bash" ||
		!strings.Contains(string(resp.Content[1].Input), `"cmd"`) || resp.Usage.OutputTokens != 40 || !resp.FinalUsage {
		t.Fatalf("the response lost what a decision reads: %+v", resp)
	}
	if resp.Content[0].Text != "" {
		t.Errorf("the lean reading kept %d bytes of text no decision reads", len(resp.Content[0].Text))
	}
	// ParseStream keeps the text and the events for a caller that wants them.
	full, events, err := ParseStream(deltaStream(3))
	if err != nil || full.Content[0].Text != strings.Repeat("hello, world", 3) || len(events) != 3+8 {
		t.Fatalf("ParseStream: %v, text %q, %d events", err, full.Content[0].Text, len(events))
	}
}
