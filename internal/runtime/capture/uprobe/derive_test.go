// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// messagesReply is a Messages API answer with one tool_use block, the shape kill test 2's stand-in returns.
const messagesReply = `{"id":"msg_01","type":"message","role":"assistant","model":"claude-test",` +
	`"content":[{"type":"tool_use","id":"toolu_01","name":"step","input":{"n":1}}],"stop_reason":"tool_use",` +
	`"usage":{"input_tokens":3,"output_tokens":1}}`

// TestResponsesAreDerived is what kill test 2's uprobe half found in the KVM guest: a tier-2 run capturing
// through uprobes wrote all 20 ssl_request lines and every ssl_response without a parser_version, a model or a
// usage, and no decision, because nothing derived what the uprobe source captured. `limits` counts tokens off
// ssl_response.usage, so such a run's token and cost budgets never moved. The source now runs the same
// dispatch as the forwarder: the response carries the parser's facts and stamp, and its decisions follow it.
func TestResponsesAreDerived(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(messagesReply)) + "\r\n\r\n" + messagesReply
	records := [][]byte{
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLRead, 9_000_000, []byte(resp), false),
	}
	rules := &agent.RuleTable{Record: agent.RecordSummary, Contract: &agent.Contract{
		Models: []agent.ModelEndpoint{{Provider: anthropic.Provider, Host: "api.anthropic.com"}}}}
	u, sink := newTestUprobe(t, records, Options{Rules: rules,
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	evs := sink.events()
	if len(evs) != 3 || evs[0].Kind != record.KindSSLRequest || evs[1].Kind != record.KindSSLResponse ||
		evs[2].Kind != record.KindDecision {
		kinds := make([]record.Kind, 0, len(evs))
		for _, ev := range evs {
			kinds = append(kinds, ev.Kind)
		}
		t.Fatalf("events %v, want ssl_request, ssl_response, decision", kinds)
	}
	var sp record.SSLResponsePayload
	if err := json.Unmarshal(evs[1].Payload, &sp); err != nil {
		t.Fatal(err)
	}
	if sp.ParserVersion != anthropic.ParserVersion || sp.Model != "claude-test" || sp.Usage == nil ||
		sp.Usage.Input != 3 || sp.Usage.Output != 1 || sp.StopReason != "tool_use" {
		t.Errorf("ssl_response %+v (usage %+v), want the parser's facts and stamp", sp, sp.Usage)
	}
	var dp record.DecisionPayload
	if err := json.Unmarshal(evs[2].Payload, &dp); err != nil {
		t.Fatal(err)
	}
	if dp.Tool != "step" || dp.ToolUseID != "toolu_01" || evs[2].PID != 100 || evs[2].Source != record.SourceSSL {
		t.Errorf("decision %+v from pid %d source %s, want tool step from pid 100 source ssl", dp, evs[2].PID,
			evs[2].Source)
	}
}

// TestNoDeriverRecordsUnderived keeps the other side: a source given no Deriver still records the pair, and
// claims no parser it did not run.
func TestNoDeriverRecordsUnderived(t *testing.T) {
	u, sink := newTestUprobe(t, exchangeOf(41, 100, 0), Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	evs := sink.events()
	if len(evs) != 2 {
		t.Fatalf("%d events, want the pair", len(evs))
	}
	var sp record.SSLResponsePayload
	if err := json.Unmarshal(evs[1].Payload, &sp); err != nil {
		t.Fatal(err)
	}
	if sp.ParserVersion != "" {
		t.Errorf("parser_version %q with no parser run", sp.ParserVersion)
	}
}

// mcpCallRequest is a tools/call db_query POSTed to the declared server local, on port 8443 of mcp.internal.
func mcpCallRequest() string {
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"db_query","arguments":{"sql":"select 1"}}}`
	return "POST /mcp HTTP/1.1\r\nHost: mcp.internal:8443\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// runMCP runs the uprobe source over records with the two servers of mcp.internal declared.
func runMCP(t *testing.T, records [][]byte) []*record.Event {
	t.Helper()
	servers := []agent.MCPServer{{Name: "postgres", URL: "https://mcp.internal/mcp"}, {Name: "local", URL: "https://mcp.internal:8443/mcp"}}
	rules := &agent.RuleTable{Record: agent.RecordSummary, Contract: &agent.Contract{MCP: servers}}
	u, sink := newTestUprobe(t, records, Options{Rules: rules,
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()}, derive.WithMCP(servers))})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	return sink.events()
}

// checkMCPCall checks that ev is the mcp line of mcpCallRequest's call, written by the thread that sent it and stamped
// when it was sent, as its ssl_request req is.
func checkMCPCall(t *testing.T, ev, req *record.Event) {
	t.Helper()
	var mp record.MCPPayload
	if ev.Kind != record.KindMCP || json.Unmarshal(ev.Payload, &mp) != nil {
		t.Fatalf("%+v is not an mcp line", ev)
	}
	if mp.Name != "local" || mp.Tool != "db_query" || mp.Transport != "http" || ev.Rule != "mcp[local]" ||
		ev.Verdict != record.VerdictObserved || ev.PID != 100 || ev.TID != 100 || ev.Source != record.SourceSSL {
		t.Fatalf("mcp line %+v %+v", ev, mp)
	}
	if ev.MonoNS != req.MonoNS || !ev.TS.Equal(req.TS) {
		t.Fatalf("mcp line stamped %d %v, want its request's %d %v", ev.MonoNS, ev.TS, req.MonoNS, req.TS)
	}
}

// TestMCPExchangesAreDerived (capture-derive.md R41): an HTTPS exchange with a declared HTTP MCP server derives its
// tools/call as an mcp line when the request is captured, right after its ssl_request, stamped with the request's
// time and the thread that wrote it, though the answer came nine seconds later; the ssl_response carries
// the MCP reader's stamp. The server is told apart from another on its host by the port the Host header names.
func TestMCPExchangesAreDerived(t *testing.T) {
	answer := `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(answer)) + "\r\n\r\n" + answer
	evs := runMCP(t, [][]byte{
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(mcpCallRequest()), false),
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLRead, 9_000_000_000, []byte(resp), false),
	})
	if len(evs) != 3 || evs[0].Kind != record.KindSSLRequest || evs[1].Kind != record.KindMCP || evs[2].Kind != record.KindSSLResponse {
		t.Fatalf("events %+v, want ssl_request, mcp, ssl_response", evs)
	}
	checkMCPCall(t, evs[1], evs[0])
	var sp record.SSLResponsePayload
	if err := json.Unmarshal(evs[2].Payload, &sp); err != nil || sp.ParserVersion != "mcp/1" {
		t.Fatalf("ssl_response %+v, %v", sp, err)
	}
}

// TestUnansweredMCPCallIsRecorded: a tools/call whose answer never comes was still sent, and the server ran it: it
// is recorded whether the capture source stops first or the agent closes the connection before the answer.
func TestUnansweredMCPCallIsRecorded(t *testing.T) {
	for _, c := range []struct {
		name    string
		records [][]byte
	}{
		{"pending at stop", [][]byte{chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(mcpCallRequest()), false)}},
		{"closed before the answer", [][]byte{
			chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(mcpCallRequest()), false),
			closeRecord(41, 100, 100, 0xabc, 2_000_000),
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			evs := runMCP(t, c.records)
			if len(evs) < 2 || evs[0].Kind != record.KindSSLRequest {
				t.Fatalf("events %+v", evs)
			}
			checkMCPCall(t, evs[1], evs[0])
		})
	}
}

// TestRefusedMCPRequestIsUnparsed: a request past R11's pipelining depth is not decoded, so its MCP messages cannot
// be read; it was still sent, so the record says an MCP message went unread (decision: unparsed under the
// server's rule's reader, R29) rather than nothing.
func TestRefusedMCPRequestIsUnparsed(t *testing.T) {
	var records [][]byte
	for i := 0; i < httpstream.DefaultMaxPipeline+1; i++ {
		records = append(records, chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, uint64(1_000_000+i), []byte(mcpCallRequest()), false))
	}
	var calls, unparsed int
	for _, ev := range runMCP(t, records) {
		var p record.DecisionPayload
		switch {
		case ev.Kind == record.KindMCP:
			calls++
		case ev.Kind == record.KindDecision && ev.DecodePayload(&p) == nil && p.Unparsed && p.Why == derive.WhySchema:
			unparsed++
		}
	}
	if calls != httpstream.DefaultMaxPipeline || unparsed != 1 {
		t.Fatalf("%d calls and %d unparsed, want %d calls and the refused request unparsed", calls, unparsed, httpstream.DefaultMaxPipeline)
	}
}

// TestTLSPort: the port a Host names, 443 when it names none, 0 when it names one that is not a port.
func TestTLSPort(t *testing.T) {
	for host, want := range map[string]int{"a": 443, "a:8443": 8443, "[::1]:9": 9, "[::1]": 443, "::1": 443, "a:": 0,
		"a:x": 0, "a:0": 0, "a:70000": 0, "": 443} {
		if got := tlsPort(host); got != want {
			t.Errorf("tlsPort(%q) = %d, want %d", host, got, want)
		}
	}
	// It runs on every derived response: the usual Host, with no port or with one, costs no allocation.
	for _, host := range []string{"api.anthropic.com", "mcp.internal:8443", "[::1]:9"} {
		if n := testing.AllocsPerRun(100, func() { _ = tlsPort(host) }); n != 0 {
			t.Errorf("tlsPort(%q) allocates %v times", host, n)
		}
	}
}
