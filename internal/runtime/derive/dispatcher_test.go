// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeParser stands in for a provider parser: it returns what the case wants, including a panic.
type fakeParser struct {
	provider string
	hosts    []string
	facts    derive.Facts
	err      error
	panics   bool
}

func (p *fakeParser) Provider() string { return p.provider }
func (p *fakeParser) Hosts() []string  { return p.hosts }
func (p *fakeParser) Version() string  { return p.provider + "-test-1" }
func (p *fakeParser) Parse(_, _ *derive.Message) (derive.Facts, error) {
	if p.panics {
		panic("parser bug")
	}
	return p.facts, p.err
}

// testMeta is the exchange context every case shares.
func testMeta(provider, host string) derive.Meta {
	return derive.Meta{
		Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "retriever",
		PID: 48212, TID: 48212, Cgroup: 44821, Source: record.SourceForwarder,
		TS: time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC), MonoNS: 812_357_500_000,
		Provider: provider, Host: host,
	}
}

func pair() (*derive.Message, *derive.Message) {
	return &derive.Message{Method: "POST", Path: "/v1/messages", Header: http.Header{}, Body: []byte("{}")},
		&derive.Message{Status: 200, Header: http.Header{}, Body: []byte("{}"), Decoded: true}
}

// decisionOf decodes the decision payload of one event.
func decisionOf(t *testing.T, ev *record.Event) record.DecisionPayload {
	t.Helper()
	var p record.DecisionPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	return p
}

// Dispatch is by the declared provider first and the upstream host second, never by the
// body (R25); an exchange nobody claims is one unparsed decision, not a silent drop and not a gap.
func TestDispatchRouting(t *testing.T) {
	a := &fakeParser{provider: "anthropic", hosts: []string{"api.anthropic.com"},
		facts: derive.Facts{Model: "claude-opus-5"}}
	b := &fakeParser{provider: "openai", hosts: []string{"api.openai.com"},
		facts: derive.Facts{Model: "gpt"}}
	d := derive.NewDispatcher([]derive.Parser{a, b})

	cases := []struct {
		name, provider, host, wantModel, wantVersion string
		wantUnparsed                                 bool
	}{
		{name: "by provider", provider: "anthropic", host: "elsewhere", wantModel: "claude-opus-5", wantVersion: "anthropic-test-1"},
		{name: "by provider, case folded", provider: "Anthropic", wantModel: "claude-opus-5", wantVersion: "anthropic-test-1"},
		{name: "by host when no provider", host: "api.openai.com", wantModel: "gpt", wantVersion: "openai-test-1"},
		{name: "by host with a port", host: "api.openai.com:443", wantModel: "gpt", wantVersion: "openai-test-1"},
		{name: "unknown provider", provider: "mistral", host: "api.mistral.ai", wantUnparsed: true, wantVersion: derive.NoParser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, resp := pair()
			got, err := d.Handle(req, resp, testMeta(tc.provider, tc.host))
			if err != nil {
				t.Fatalf("handle: %v", err)
			}
			if got.Facts.ParserVersion != tc.wantVersion {
				t.Errorf("parser_version = %q, want %q", got.Facts.ParserVersion, tc.wantVersion)
			}
			if tc.wantUnparsed {
				if len(got.Events) != 1 {
					t.Fatalf("%d events, want exactly one unparsed decision (R25)", len(got.Events))
				}
				p := decisionOf(t, got.Events[0])
				if !p.Unparsed || p.Why != derive.WhySchema {
					t.Errorf("decision = %+v, want unparsed why=schema", p)
				}
				return
			}
			if got.Facts.Model != tc.wantModel {
				t.Errorf("model = %q, want %q", got.Facts.Model, tc.wantModel)
			}
		})
	}
}

// The first registration wins a contested provider or host — the stated P0 limit for two
// declared models sharing one upstream (capture-derive.md E33 (edge case #33)).
func TestDispatchFirstRegistrationWins(t *testing.T) {
	first := &fakeParser{provider: "anthropic", hosts: []string{"shared.example"}, facts: derive.Facts{Model: "first"}}
	second := &fakeParser{provider: "anthropic", hosts: []string{"shared.example"}, facts: derive.Facts{Model: "second"}}
	d := derive.NewDispatcher([]derive.Parser{first, second})
	req, resp := pair()
	got, err := d.Handle(req, resp, testMeta("", "shared.example"))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got.Facts.Model != "first" {
		t.Errorf("model = %q, want the first registration", got.Facts.Model)
	}
}

// Every runtime condition is an event, never an error. Only a nil request — a caller bug —
// returns one (§4).
func TestHandleNeverErrorsOnContent(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{&fakeParser{provider: "anthropic",
		err: fmt.Errorf("bad body: %w", derive.ErrEncoding)}})
	req, resp := pair()

	got, err := d.Handle(req, resp, testMeta("anthropic", ""))
	if err != nil {
		t.Fatalf("an unreadable body must not be an error: %v", err)
	}
	if p := decisionOf(t, got.Events[0]); !p.Unparsed || p.Why != derive.WhyEncoding {
		t.Errorf("decision = %+v, want unparsed why=encoding", p)
	}

	// A response that never arrived: one gap, no decision (§4, §7).
	got, err = d.Handle(req, nil, testMeta("anthropic", ""))
	if err != nil {
		t.Fatalf("a mid-flight request must not be an error: %v", err)
	}
	if len(got.Events) != 1 || got.Events[0].Kind != record.KindGap {
		t.Fatalf("events = %+v, want one gap", got.Events)
	}
	var gap record.GapPayload
	if err := got.Events[0].DecodePayload(&gap); err != nil {
		t.Fatal(err)
	}
	if gap.What != record.GapCapture || gap.Why != derive.GapMalformed {
		t.Errorf("gap = %+v, want what=capture why=malformed", gap)
	}

	if _, err := d.Handle(nil, resp, testMeta("anthropic", "")); !errors.Is(err, derive.ErrNoRequest) {
		t.Errorf("err = %v, want ErrNoRequest", err)
	}
}

// A parser panic is converted, logged to derive's own log and never reaches the ledger as
// anything but the decision a malformed body produces (§7).
func TestHandleRecoversPanic(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{&fakeParser{provider: "anthropic", panics: true}})
	req, resp := pair()
	got, err := d.Handle(req, resp, testMeta("anthropic", ""))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(got.Events) != 1 {
		t.Fatalf("%d events, want one", len(got.Events))
	}
	if p := decisionOf(t, got.Events[0]); !p.Unparsed || p.Why != derive.WhySchema {
		t.Errorf("decision = %+v, want unparsed why=schema", p)
	}
}

// Facts.Apply fills an ssl_response without clearing what capture already knew, and never
// leaves parser_version empty (capture-derive.md I6, R32).
func TestFactsApply(t *testing.T) {
	usage := record.Usage{Input: 10, Output: 2}
	p := record.SSLResponsePayload{Status: 200, LatencyMS: 42, RequestID: "fx-1", ContentEncoding: "gzip"}
	derive.Facts{Model: "claude-opus-5", ResponseID: "msg_1", StopReason: "tool_use",
		Usage: &usage, ParserVersion: "anthropic-2026-09-4"}.Apply(&p)
	if p.Status != 200 || p.LatencyMS != 42 || p.RequestID != "fx-1" || p.ContentEncoding != "gzip" {
		t.Errorf("payload lost what capture knew: %+v", p)
	}
	if p.Model != "claude-opus-5" || p.ResponseID != "msg_1" || p.StopReason != "tool_use" || p.Usage == nil {
		t.Errorf("payload = %+v", p)
	}
	usage.Input = 999 // the payload holds a copy, not the caller's usage
	if p.Usage.Input != 10 {
		t.Error("Apply aliased the caller's usage")
	}
	var empty record.SSLResponsePayload
	derive.Facts{}.Apply(&empty)
	if empty.ParserVersion != derive.NoParser {
		t.Errorf("parser_version = %q, want it never empty", empty.ParserVersion)
	}
	derive.Facts{}.Apply(nil) // must not panic
}

// The real parser, dispatched by provider, produces the decisions the golden facts froze —
// the dispatcher and the parser agree end to end.
func TestDispatchAnthropic(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()})
	req := &derive.Message{Method: "POST", Path: "/v1/messages", Header: http.Header{},
		Body: []byte(`{"model":"claude-opus-5","messages":[]}`)}
	resp := &derive.Message{Status: 200, Header: http.Header{"Content-Type": {"application/json"}}, Decoded: true,
		Body: []byte(`{"id":"msg_1","type":"message","model":"claude-opus-5","stop_reason":"tool_use",` +
			`"content":[{"type":"tool_use","id":"toolu_1","name":"bash","input":{"command":"ls"}}],` +
			`"usage":{"input_tokens":7,"output_tokens":3}}`)}
	got, err := d.Handle(req, resp, testMeta("anthropic", "api.anthropic.com"))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got.Facts.ParserVersion != anthropic.ParserVersion {
		t.Errorf("parser_version = %q", got.Facts.ParserVersion)
	}
	if len(got.Events) != 1 {
		t.Fatalf("%d events, want one decision", len(got.Events))
	}
	p := decisionOf(t, got.Events[0])
	if p.Tool != "bash" || p.ToolUseID != "toolu_1" || p.Step != 0 || p.Unparsed {
		t.Errorf("decision = %+v", p)
	}
	if p.InputHash != anthropic.InputHash([]byte(`{"command":"ls"}`)) {
		t.Errorf("input_hash = %s", p.InputHash)
	}
}

// A derived event marshals as a v1 line with the common fields the capture source knew —
// derive never invents a pid, a run or a source of its own.
func TestDerivedEventCarriesCommonFields(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{&fakeParser{provider: "anthropic",
		facts: derive.Facts{Decisions: []derive.Decision{{ToolUseID: "t1", Tool: "bash", InputHash: "ab"}}}}})
	req, resp := pair()
	meta := testMeta("anthropic", "api.anthropic.com")
	got, err := d.Handle(req, resp, meta)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	ev := got.Events[0]
	if ev.Run != meta.Run || ev.Agent != meta.Agent || ev.PID != meta.PID || ev.TID != meta.TID ||
		ev.Cgroup != meta.Cgroup || ev.Source != record.SourceForwarder || !ev.TS.Equal(meta.TS) ||
		ev.MonoNS != meta.MonoNS {
		t.Errorf("event = %+v", ev)
	}
	if ev.Attr != nil {
		t.Error("a decision is not an action event and must carry no attribution")
	}
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		t.Fatalf("the derived line is not an object: %v", err)
	}
	if _, ok := fields["tool_use_id"]; !ok {
		t.Errorf("the decision payload was not spliced into the line: %s", line)
	}
}
