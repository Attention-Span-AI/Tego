// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive/mcp"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var mcpServers = []agent.MCPServer{
	{Name: "postgres", URL: "https://mcp.internal/mcp"},
	{Name: "local", URL: "https://mcp.internal:8443/mcp"},
	{Name: "fs", Command: []string{"mcp-fs"}},
}

func mcpMeta(port int) Meta {
	return Meta{Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "retriever", PID: 48212, TID: 7, Source: record.SourceSSL,
		TS: time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC), Host: "MCP.internal.", Port: port}
}

// recordedExchanges replays one of derive/mcp's recorded HTTP fixtures (testdata/README.md there) as captured
// request and response pairs.
func recordedExchanges(t *testing.T, name string) [][2]*Message {
	t.Helper()
	f, err := os.Open(filepath.Join("mcp", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][2]*Message
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var x struct {
			Request struct {
				Method, Path, Body string
			}
			Status       int
			ResponseType string `json:"response_type"`
			Response     string
		}
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			t.Fatal(err)
		}
		req := &Message{Method: x.Request.Method, Path: x.Request.Path, Body: []byte(x.Request.Body), Decoded: true}
		resp := &Message{Status: x.Status, Body: []byte(x.Response), Decoded: true, SSE: x.ResponseType == "text/event-stream"}
		out = append(out, [2]*Message{req, resp})
	}
	return out
}

func mcpLines(t *testing.T, events []*record.Event) []record.MCPPayload {
	t.Helper()
	var out []record.MCPPayload
	for _, ev := range events {
		if err := ev.Validate(); err != nil {
			t.Fatalf("an invalid line: %v", err)
		}
		if ev.Kind != record.KindMCP {
			continue
		}
		var p record.MCPPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Rule != "mcp["+p.Name+"]" || ev.Verdict != record.VerdictObserved || ev.Authority != record.AuthorityRule ||
			ev.Source != record.SourceSSL || ev.PID != 48212 {
			t.Fatalf("mcp line %+v", ev)
		}
		out = append(out, p)
	}
	return out
}

// TestDispatcherDerivesMCPToolCalls (capture-derive.md R41): a real client's HTTP exchanges with a declared server,
// both HTTP transports, derive the connection and each tools/call, in wire order, as mcp lines; the ssl_response
// carries parser_version mcp/1; nothing is a decision and nothing is unmetered.
func TestDispatcherDerivesMCPToolCalls(t *testing.T) {
	d := NewDispatcher(nil, WithMCP(mcpServers))
	want := []record.MCPPayload{{Name: "postgres", Transport: "http"}, {Name: "postgres", Transport: "http", Tool: "db_query"},
		{Name: "postgres", Transport: "http", Tool: "echo"}}
	for _, name := range []string{"streamable-sse.jsonl", "streamable-json.jsonl", "http-sse-legacy.jsonl"} {
		var got []record.MCPPayload
		for _, x := range recordedExchanges(t, name) {
			res, err := d.Handle(x[0], x[1], mcpMeta(443))
			if err != nil || res.Facts.ParserVersion != mcp.Version || len(res.Facts.Decisions) != 0 || res.Facts.Unmetered {
				t.Fatalf("%s: %+v, %v", name, res.Facts, err)
			}
			got = append(got, mcpLines(t, res.Events)...)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %+v, want %+v", name, got, want)
		}
	}
}

// TestMCPLinesFallIntoSteps: the derived lines are numbered into the model step they fell in, as every action line
// is (E28a): "mcp call db_query, step 1".
func TestMCPLinesFallIntoSteps(t *testing.T) {
	d := NewDispatcher(nil, WithMCP(mcpServers))
	steps := NewSteps("api.anthropic.com")
	model := mcpMeta(443)
	req := model.event(record.KindSSLRequest)
	req.Pair = 1
	if err := req.SetPayload(record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages", Host: "api.anthropic.com"}); err != nil {
		t.Fatal(err)
	}
	resp := model.event(record.KindSSLResponse)
	resp.Pair = 1
	if err := resp.SetPayload(record.SSLResponsePayload{Status: 200, ParserVersion: "x"}); err != nil {
		t.Fatal(err)
	}
	steps.Apply(req)
	steps.Apply(resp)
	x := recordedExchanges(t, "streamable-json.jsonl")[3] // tools/call db_query
	res, err := d.Handle(x[0], x[1], mcpMeta(443))
	if err != nil || len(res.Events) != 1 {
		t.Fatalf("%+v, %v", res, err)
	}
	steps.Apply(res.Events[0])
	// The call was written by the thread that made the model request, which the uprobe source names by its tid:
	// it is that thread's own action, in its step (R42's tid rule).
	if a := res.Events[0].Attr; a == nil || a.Step != 1 || a.Confidence != record.ConfidenceLikely || a.Method != record.MethodTID {
		t.Fatalf("attribution %+v", a)
	}
}

// TestMCPExchangeBoundaries: which exchanges are a server's, and what an unreadable one derives.
func TestMCPExchangeBoundaries(t *testing.T) {
	d := NewDispatcher(nil, WithMCP(mcpServers))
	call := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`)
	post := func(body []byte) *Message { return &Message{Method: "POST", Path: "/mcp", Body: body, Decoded: true} }
	ok := &Message{Status: 200, Decoded: true}

	// Another port of the host is the other server; no port known, or a port no server declares, is no server's.
	res, _ := d.Handle(post(call), ok, mcpMeta(8443))
	if got := mcpLines(t, res.Events); len(got) != 1 || got[0].Name != "local" || got[0].Tool != "q" {
		t.Fatalf("port 8443: %+v", got)
	}
	for _, port := range []int{0, 9999} {
		res, _ = d.Handle(post(call), ok, mcpMeta(port))
		if res.Facts.ParserVersion != NoParser || len(mcpLines(t, res.Events)) != 0 {
			t.Fatalf("port %d: %+v", port, res)
		}
	}
	// A models[] provider that claimed the exchange keeps it.
	m := mcpMeta(443)
	m.Provider = "anthropic"
	if res, _ = d.Handle(post(call), ok, m); len(mcpLines(t, res.Events)) != 0 {
		t.Fatalf("a provider's exchange read as MCP: %+v", res)
	}
	// Without WithMCP nothing is a server's.
	if res, _ = NewDispatcher(nil).Handle(post(call), ok, mcpMeta(443)); len(mcpLines(t, res.Events)) != 0 {
		t.Fatalf("an undeclared server's exchange read as MCP: %+v", res)
	}

	unparsed := func(res Result, why string) {
		t.Helper()
		var n int
		for _, ev := range res.Events {
			var p record.DecisionPayload
			if ev.Kind == record.KindDecision && ev.DecodePayload(&p) == nil && p.Unparsed && p.Why == why {
				n++
			}
		}
		if n != 1 || res.Facts.ParserVersion != mcp.Version || res.Facts.Unmetered {
			t.Fatalf("want one unparsed why=%s: %+v", why, res)
		}
	}
	res, _ = d.Handle(post([]byte("not json")), ok, mcpMeta(443))
	unparsed(res, WhySchema)
	cut := post(call)
	cut.Truncated = true
	res, _ = d.Handle(cut, ok, mcpMeta(443))
	unparsed(res, WhySchema)
	enc := post(call)
	enc.ContentEncoding, enc.Decoded = "zstd", false
	res, _ = d.Handle(enc, ok, mcpMeta(443))
	unparsed(res, WhyEncoding)
	// A batch with one readable call and one bad member records the call and the unreadable marker.
	res, _ = d.Handle(post([]byte("["+string(call)+",7]")), ok, mcpMeta(443))
	unparsed(res, WhySchema)
	if got := mcpLines(t, res.Events); len(got) != 1 || got[0].Tool != "q" {
		t.Fatalf("half-readable batch: %+v", got)
	}
	// A request whose response never came was still sent.
	res, _ = d.Handle(post(call), nil, mcpMeta(443))
	if got := mcpLines(t, res.Events); len(got) != 1 || res.Events[len(res.Events)-1].Kind != record.KindGap {
		t.Fatalf("unanswered call: %+v", res.Events)
	}
	// A GET (the server's event stream) names nothing.
	if res, _ = d.Handle(&Message{Method: "GET", Path: "/mcp", Decoded: true}, ok, mcpMeta(443)); len(res.Events) != 0 {
		t.Fatalf("a GET derived %+v", res.Events)
	}
}

// TestMCPEventsStdio: on stdio a server's start is its exec's line, so an initialize derives nothing there.
func TestMCPEventsStdio(t *testing.T) {
	evs := MCPEvents("fs", MCPTransportStdio, []mcp.Item{{Kind: mcp.KindInitialize}, {Kind: mcp.KindToolCall, Tool: "read"}}, mcpMeta(0))
	if got := mcpLines(t, evs); !reflect.DeepEqual(got, []record.MCPPayload{{Name: "fs", Transport: "stdio", Tool: "read"}}) {
		t.Fatalf("%+v", got)
	}
}

// TestStdioToolCallsFallIntoSteps: the bytes a real client wrote to a stdio server (derive/mcp's recorded fixture),
// read by mcp.Stdio, derive one mcp line per tools/call, transport stdio, each numbered into the open step by time,
// as the reader will once provisioning relays a server's stdin (capture-derive.md R41).
func TestStdioToolCallsFallIntoSteps(t *testing.T) {
	wire, err := os.ReadFile(filepath.Join("mcp", "testdata", "stdio-client.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var s mcp.Stdio
	r := s.Write(wire)
	if end := s.Close(); r.Malformed+end.Malformed+r.Oversize != 0 {
		t.Fatalf("the recorded stream read with errors: %+v %+v", r, end)
	}
	steps := NewSteps("api.anthropic.com")
	meta := mcpMeta(0)
	req := meta.event(record.KindSSLRequest)
	req.Pair = 1
	if err := req.SetPayload(record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages", Host: "api.anthropic.com"}); err != nil {
		t.Fatal(err)
	}
	steps.Apply(req) // the model turn is still in flight, and the calls fall inside it
	evs := MCPEvents("fs", MCPTransportStdio, r.Items, meta)
	want := []record.MCPPayload{{Name: "fs", Transport: "stdio", Tool: "db_query"}, {Name: "fs", Transport: "stdio", Tool: "echo"}}
	if got := mcpLines(t, evs); !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v, want %+v", got, want)
	}
	for _, ev := range evs {
		steps.Apply(ev)
		if a := ev.Attr; a == nil || a.Step != 1 || a.Confidence != record.ConfidenceLikely {
			t.Fatalf("attribution %+v", a)
		}
	}
}

// TestHandleRequestReadsMCPRequestsAlone: a source that reads a request as it is captured gets a declared server's
// lines from the request alone, with no gap for an answer still to come; any other exchange is left to Handle.
func TestHandleRequestReadsMCPRequestsAlone(t *testing.T) {
	d := NewDispatcher(nil, WithMCP(mcpServers))
	call := &Message{Method: "POST", Path: "/mcp", Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`), Decoded: true}
	res, ok := d.HandleRequest(call, mcpMeta(443))
	if got := mcpLines(t, res.Events); !ok || len(got) != 1 || got[0].Tool != "q" || len(res.Events) != 1 || res.Facts.ParserVersion != mcp.Version {
		t.Fatalf("declared server: ok %v, %+v", ok, res)
	}
	for _, port := range []int{0, 9999} {
		if res, ok := d.HandleRequest(call, mcpMeta(port)); ok || len(res.Events) != 0 {
			t.Fatalf("port %d: ok %v, %+v", port, ok, res)
		}
	}
	if _, ok := d.HandleRequest(nil, mcpMeta(443)); ok {
		t.Fatal("a nil request was handled")
	}
}

// TestMCPReaderPanicIsRecovered: a panic in the MCP reader is recovered in the Dispatcher, as a parser's is (§7's
// failure table): the exchange is one unparsed decision, why=schema, and the panic goes to tego's own log.
func TestMCPReaderPanicIsRecovered(t *testing.T) {
	saved := readMCPRequest
	t.Cleanup(func() { readMCPRequest = saved })
	readMCPRequest = func(string, []byte, bool) (mcp.Result, error) { panic("boom") }
	var log bytes.Buffer
	d := NewDispatcher(nil, WithMCP(mcpServers), WithLogger(slog.New(slog.NewTextHandler(&log, nil))))
	call := &Message{Method: "POST", Path: "/mcp", Body: []byte(`{}`), Decoded: true}
	check := func(res Result) {
		t.Helper()
		var p record.DecisionPayload
		if len(res.Events) == 0 || res.Events[0].Kind != record.KindDecision || res.Events[0].DecodePayload(&p) != nil ||
			!p.Unparsed || p.Why != WhySchema || res.Facts.ParserVersion != mcp.Version {
			t.Fatalf("%+v", res)
		}
	}
	res, ok := d.HandleRequest(call, mcpMeta(443))
	if !ok {
		t.Fatal("not handled")
	}
	check(res)
	res, err := d.Handle(call, &Message{Status: 200, Decoded: true}, mcpMeta(443))
	if err != nil {
		t.Fatal(err)
	}
	check(res)
	if !strings.Contains(log.String(), "boom") || !strings.Contains(log.String(), "MCP reader") {
		t.Fatalf("own log: %q", log.String())
	}
}

// panickingParser is a parser with a bug its fuzz target missed.
type panickingParser struct{}

func (panickingParser) Provider() string                   { return "stub" }
func (panickingParser) Hosts() []string                    { return []string{"stub.example"} }
func (panickingParser) Version() string                    { return "stub/1" }
func (panickingParser) Parse(_, _ *Message) (Facts, error) { panic("parser boom") }

// TestParserPanicIsLogged: a parser's recovered panic, like the MCP reader's, is one unparsed decision and goes to
// tego's own log with its stack (§7's failure table), never the ledger.
func TestParserPanicIsLogged(t *testing.T) {
	var log bytes.Buffer
	d := NewDispatcher([]Parser{panickingParser{}}, WithLogger(slog.New(slog.NewTextHandler(&log, nil))))
	m := mcpMeta(443)
	m.Provider = "stub"
	res, err := d.Handle(&Message{Method: "POST", Path: "/v1/x", Decoded: true}, &Message{Status: 200, Decoded: true}, m)
	var p record.DecisionPayload
	if err != nil || len(res.Events) != 1 || res.Events[0].DecodePayload(&p) != nil || !p.Unparsed || p.Why != WhySchema {
		t.Fatalf("%+v, %v", res, err)
	}
	if !strings.Contains(log.String(), "parser boom") || !strings.Contains(log.String(), "stack=") {
		t.Fatalf("own log: %q", log.String())
	}
	for _, ev := range res.Events {
		if strings.Contains(string(ev.Payload), "boom") {
			t.Fatalf("the panic reached a ledger line: %s", ev.Payload)
		}
	}
}
