// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"encoding/json"
	"slices"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRequestLineCarriesWhatDeriveReadOffIt: the uprobe source stamps an ssl_request with what derive reads off the
// request alone as it is captured (capture-derive R40, R42), as the forwarder does: the tool results a model turn
// reports, and side on the model host's telemetry.
func TestRequestLineCarriesWhatDeriveReadOffIt(t *testing.T) {
	post := func(path, body string) []byte {
		return []byte("POST " + path + " HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	}
	turn := `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_8812"}]}]}`
	records := [][]byte{
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, post("/v1/messages", turn), false),
		chunkRecord(41, 100, 101, 0xdef, bpf.SSLWrite, 2_000_000, post("/api/event_logging/batch", `{"events":[]}`), false),
	}
	rules := &agent.RuleTable{Record: agent.RecordSummary, Contract: &agent.Contract{
		Models: []agent.ModelEndpoint{{Provider: anthropic.Provider, Host: "api.anthropic.com"}}}}
	u, sink := newTestUprobe(t, records, Options{Rules: rules,
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	var reqs []record.SSLRequestPayload
	for _, ev := range sink.events() {
		if ev.Kind != record.KindSSLRequest {
			continue
		}
		var p record.SSLRequestPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if ev.TID != 101 || ev.Source != record.SourceSSL {
			t.Errorf("ssl_request from tid %d source %s, want the writing thread 101 and source ssl", ev.TID, ev.Source)
		}
		reqs = append(reqs, p)
	}
	if len(reqs) != 2 {
		t.Fatalf("%d ssl_request lines, want 2", len(reqs))
	}
	if reqs[0].Side || reqs[0].ToolResults == nil || !slices.Equal(*reqs[0].ToolResults, []string{"toolu_8812"}) {
		t.Errorf("model turn: side %v, tool_results %v; want toolu_8812", reqs[0].Side, reqs[0].ToolResults)
	}
	if !reqs[1].Side || reqs[1].ToolResults != nil {
		t.Errorf("telemetry: side %v, tool_results %v; want side traffic, not read", reqs[1].Side, reqs[1].ToolResults)
	}
}
