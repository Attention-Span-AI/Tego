// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// captured is one item of the 5.2 retriever run's traffic, in the order capture and the kernel record saw it: a
// request or response on a TLS connection, or a kernel action line, with the attribution the action must get.
type captured struct {
	What      string           `json:"what"` // request | response | kernel
	TID       int              `json:"tid"`
	Host      string           `json:"host"`
	Port      int              `json:"port"`
	Method    string           `json:"method"`
	Path      string           `json:"path"`
	Status    int              `json:"status"`
	Body      json.RawMessage  `json:"body"`
	Side      bool             `json:"side"`
	Kind      record.Kind      `json:"kind"`
	Source    record.Source    `json:"source"`
	Rule      string           `json:"rule"`
	Verdict   record.Verdict   `json:"verdict"`
	Authority record.Authority `json:"authority"`
	Reason    record.Reason    `json:"reason"`
	Payload   json.RawMessage  `json:"payload"`
	Want      *struct {
		ToolUseID string `json:"tool_use_id"`
		Step      int    `json:"step"`
		Method    string `json:"method"`
	} `json:"want"`
}

// retrieverMCP is the 5.2 contract's MCP server, the warehouse's HTTP endpoint.
var retrieverMCP = []agent.MCPServer{{Name: "warehouse", URL: "https://mcp.internal:8443/mcp"}}

// replayRetriever replays the retriever run's captured traffic through what a run derives it with: the
// Dispatcher reads each request as the source captures it (side traffic, the tool results it reports, an MCP call)
// and each exchange when its answer is read (decisions), the source writes the lines in that order, and the attribute
// stage folds them with the kernel's action lines. viaForwarder replays the model traffic as the forwarder records
// it (tid 0, the process's lane) instead of the uprobe source (the writing thread's tid). It returns every line,
// encoded as the ledger writes it and decoded back, beside the item that produced it.
func replayRetriever(t *testing.T, viaForwarder bool) ([]*record.Event, []captured) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "retriever-5.2", "traffic.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()}, derive.WithMCP(retrieverMCP))
	steps := derive.NewSteps("api.anthropic.com")
	const pid = 4242
	var (
		out     []*record.Event
		from    []captured
		pending = map[int]*derive.Message{} // tid -> the request awaiting its answer
		metas   = map[int]derive.Meta{}
		pair    uint64
		pairs   = map[int]uint64{}
		clock   = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	)
	emit := func(ev *record.Event, c captured) {
		clock = clock.Add(time.Second)
		ev.V, ev.Run, ev.Agent, ev.TS, ev.MonoNS = record.Version, "r-3f9c2a1b-0dllq06ts7400-k7m2pq", "retriever", clock, uint64(clock.UnixNano())
		steps.Apply(ev)
		line, err := ev.MarshalLine()
		if err != nil {
			t.Fatalf("%s line: %v", ev.Kind, err)
		}
		back, err := record.Decode(line)
		if err != nil {
			t.Fatalf("decode %s: %v", line, err)
		}
		out, from = append(out, back), append(from, c)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var c captured
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			t.Fatalf("traffic line %q: %v", sc.Bytes(), err)
		}
		meta := derive.Meta{Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "retriever", PID: pid, TID: c.TID,
			Source: record.SourceSSL, Host: c.Host, Port: c.Port}
		if c.Host == "api.anthropic.com" {
			meta.Provider = anthropic.Provider
			if viaForwarder {
				meta.Source, meta.TID, meta.Lane = record.SourceForwarder, 0, 1
			}
		}
		switch c.What {
		case "request":
			req := &derive.Message{Method: c.Method, Path: c.Path, Body: c.Body}
			pair++
			pending[c.TID], metas[c.TID], pairs[c.TID] = req, meta, pair
			ev := &record.Event{PID: meta.PID, TID: meta.TID, Lane: meta.Lane, Kind: record.KindSSLRequest, Source: meta.Source, Pair: pair}
			p := record.SSLRequestPayload{Endpoint: meta.Provider, Method: c.Method, Path: c.Path, Host: c.Host, Size: len(c.Body)}
			d.ReadRequest(req, meta).Apply(&p)
			if p.Side != c.Side {
				t.Fatalf("%s %s: side %v, want %v", c.Host, c.Path, p.Side, c.Side)
			}
			if err := ev.SetPayload(p); err != nil {
				t.Fatal(err)
			}
			emit(ev, c)
			if read, ok := d.HandleRequest(req, meta); ok {
				for _, e := range read.Events {
					emit(e, c)
				}
			}
		case "response":
			req, meta := pending[c.TID], metas[c.TID]
			resp := &derive.Message{Status: c.Status, Body: c.Body, Header: map[string][]string{"Content-Type": {"application/json"}}}
			res, err := d.Handle(req, resp, meta)
			if err != nil {
				t.Fatal(err)
			}
			ev := &record.Event{PID: meta.PID, TID: meta.TID, Lane: meta.Lane, Kind: record.KindSSLResponse, Source: meta.Source, Pair: pairs[c.TID]}
			p := record.SSLResponsePayload{Status: c.Status}
			res.Facts.Apply(&p)
			if err := ev.SetPayload(p); err != nil {
				t.Fatal(err)
			}
			emit(ev, c)
			if _, mcp := d.HandleRequest(req, meta); !mcp {
				for _, e := range res.Events {
					emit(e, c)
				}
			}
		case "kernel":
			ev := &record.Event{PID: pid + c.TID, TID: c.TID, Kind: c.Kind, Source: c.Source, Rule: c.Rule,
				Verdict: c.Verdict, Authority: c.Authority, Reason: c.Reason, Attr: record.Unattributed(), Payload: c.Payload}
			if ev.Authority == "" {
				ev.Authority = record.AuthorityRule
			}
			emit(ev, c)
		default:
			t.Fatalf("traffic line of unknown what %q", c.What)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if steps.Count() != 3 {
		t.Errorf("%d steps, want the run's three model turns (its side traffic opens none)", steps.Count())
	}
	return out, from
}

// TestRetrieverRunTiesEachActionToItsReply (capture-derive R42): the retriever run
// replayed from its captured traffic gives each action the reply that asked for it. Step 1's reply asked
// for db_query (toolu_8812): the connection to the warehouse, the MCP call, the gzip the tool ran and the summary it
// wrote are that reply's. Step 2's reply asked for publish_summary (toolu_8813): the approved connection to the queue
// and the refused write to ~/.netrc are that one's. What no window covers falls back to time or tid, with its method
// said; the harness's telemetry on the model host is side traffic and no turn. Replayed as the uprobe source and as
// the forwarder records the model traffic, the replies are the same.
func TestRetrieverRunTiesEachActionToItsReply(t *testing.T) {
	for _, viaForwarder := range []bool{false, true} {
		name := "uprobe"
		if viaForwarder {
			name = "forwarder"
		}
		t.Run(name, func(t *testing.T) {
			lines, from := replayRetriever(t, viaForwarder)
			var checked, toolID, mcpCalls int
			decisions := map[string]int{} // tool_use id -> the step its decision line was numbered into
			for i, ev := range lines {
				c := from[i]
				switch {
				case ev.Kind == record.KindDecision:
					var p record.DecisionPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					if p.ToolUseID != "" {
						decisions[p.ToolUseID] = p.Step
					}
				case ev.Kind == record.KindSSLRequest:
					var p record.SSLRequestPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					if p.Path == "/api/event_logging/batch" && !p.Side {
						t.Errorf("seq %d: the telemetry batch is not labelled side", i)
					}
				case ev.Kind.IsAction():
					if ev.Kind == record.KindMCP {
						mcpCalls++
					}
					if c.Want == nil {
						t.Fatalf("line %d (%s) has no expected attribution in the traffic", i, ev.Kind)
					}
					want := *c.Want
					if viaForwarder && want.Method == record.MethodTID {
						// The forwarder names no thread by its tid: the turn's own thread is a process and a lane.
						want.Method = record.MethodTime
					}
					a := ev.Attr
					if a == nil || a.ToolUseID != want.ToolUseID || a.Step != want.Step || a.Method != want.Method ||
						a.Confidence != record.ConfidenceLikely {
						t.Errorf("%s %s: attribution %+v, want reply %q step %d by %s", ev.Kind, strings.TrimSpace(string(c.Payload)), a,
							want.ToolUseID, want.Step, want.Method)
					}
					if a != nil && a.Method == record.MethodToolID {
						toolID++
						if decisions[a.ToolUseID] != a.Step {
							t.Errorf("%s names %s in step %d, whose decision line is in step %d", ev.Kind, a.ToolUseID, a.Step,
								decisions[a.ToolUseID])
						}
					}
					checked++
				}
			}
			if mcpCalls != 1 || toolID != 6 || checked != 8 {
				t.Errorf("%d actions checked, %d tied to a reply, %d MCP calls; want 8, 6 and 1", checked, toolID, mcpCalls)
			}
		})
	}
}
