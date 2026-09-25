// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestScannerReadsUsageExtra: on the wire scanner, the 1-hour cache writes and the
// server-tool counts it reads off every relayed byte reach the merged usage, so a record copy the capture budget
// cut does not lose them.
func TestScannerReadsUsageExtra(t *testing.T) {
	var s anthropic.StreamUsageScanner
	_, _ = s.Write([]byte(`data: {"type":"message_start","message":{"model":"m","usage":{"input_tokens":10,` +
		`"cache_creation_input_tokens":300,"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":100}}}}` + "\n\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":20,"server_tool_use":{"web_search_requests":3}}}` + "\n\n"))
	scanned, model, final := s.Result()
	want := &record.Usage{Input: 10, Output: 20, CacheWrite: 300, CacheWrite1h: 100,
		ServerTool: map[string]int{"web_search_requests": 3}}
	if model != "m" || !final || !reflect.DeepEqual(scanned, want) {
		t.Fatalf("scanned %+v %q %v, want %+v", scanned, model, final, want)
	}
	derived := &record.Usage{Input: 10, Output: 20, CacheWrite: 300,
		ServerTool: map[string]int{"web_fetch_requests": 1}}
	got := mergeUsage(derived, scanned, final)
	if got.CacheWrite1h != 100 || got.ServerTool["web_search_requests"] != 3 || got.ServerTool["web_fetch_requests"] != 1 {
		t.Errorf("merged %+v, want the 1-hour writes and both tools' counts", got)
	}
	if len(derived.ServerTool) != 1 {
		t.Errorf("merge wrote into derive's map: %v", derived.ServerTool)
	}
}
