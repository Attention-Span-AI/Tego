// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"errors"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUsageExtraIsRecorded: the 1-hour cache writes and the per-request server-tool counts
// of a response reach the ledger's usage, whole or streamed, where they were dropped and a cost budget charged the
// one as 5-minute writes and the other nothing.
func TestUsageExtraIsRecorded(t *testing.T) {
	want := record.Usage{Input: 10, Output: 20, CacheWrite: 300, CacheWrite1h: 100,
		ServerTool: map[string]int{"web_search_requests": 3}}

	body := []byte(`{"id":"msg_1","type":"message","model":"m","role":"assistant","content":[],` +
		`"usage":{"input_tokens":10,"output_tokens":20,"cache_creation_input_tokens":300,` +
		`"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":100},` +
		`"server_tool_use":{"web_search_requests":3,"web_fetch_requests":0}}}`)
	resp, err := ParseResponse(200, body)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if got := resp.Usage.Record(); !reflect.DeepEqual(got, want) {
		t.Errorf("whole body: usage %+v, want %+v", got, want)
	}

	stream := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","model":"m","role":"assistant","content":[],` +
		`"usage":{"input_tokens":10,"output_tokens":1,"cache_creation_input_tokens":300,` +
		`"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":100}}}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":20,` +
		`"server_tool_use":{"web_search_requests":3}}}` + "\n\n" +
		"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n")
	sresp, _, err := ParseStream(stream)
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if got := sresp.Usage.Record(); !reflect.DeepEqual(got, want) {
		t.Errorf("stream: usage %+v, want %+v", got, want)
	}
}

// TestUsageExtraNegativeIsASchemaError: a negative count in either object is rejected as one in the four token
// counters is.
func TestUsageExtraNegativeIsASchemaError(t *testing.T) {
	for _, usage := range []string{
		`{"cache_creation":{"ephemeral_1h_input_tokens":-1}}`,
		`{"server_tool_use":{"web_search_requests":-1}}`,
	} {
		body := []byte(`{"id":"msg_1","type":"message","model":"m","content":[],"usage":` + usage + `}`)
		if _, err := ParseResponse(200, body); !errors.Is(err, ErrSchema) {
			t.Errorf("%s: err = %v, want ErrSchema", usage, err)
		}
	}
}
