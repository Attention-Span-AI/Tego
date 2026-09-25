// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// r3Drain runs one request/response pair through a source whose contract declares api.anthropic.com (or
// declares nothing, when declared is false) and returns what it recorded and what it reported unmetered.
func r3Drain(t *testing.T, requestHead string, declared bool) ([]*record.Event, int64) {
	t.Helper()
	body := `{"model":"claude-test","max_tokens":8,"messages":[]}`
	req := requestHead + "Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) +
		"\r\n\r\n" + body
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(messagesReply)) + "\r\n\r\n" + messagesReply
	records := [][]byte{
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(req), false),
		chunkRecord(41, 100, 100, 0xabc, bpf.SSLRead, 9_000_000, []byte(resp), false),
	}
	rules := &agent.RuleTable{Record: agent.RecordSummary}
	if declared {
		rules.Contract = &agent.Contract{
			Models: []agent.ModelEndpoint{{Provider: anthropic.Provider, Host: "api.anthropic.com"}}}
	}
	u, _ := newTestUprobe(t, records, Options{Rules: rules,
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	return sink.events(), sink.reported()
}

// r3Usage is the usage the pair's ssl_response carries, nil when it carries none.
func r3Usage(t *testing.T, evs []*record.Event) (*record.SSLRequestPayload, *record.SSLResponsePayload) {
	t.Helper()
	var (
		rq *record.SSLRequestPayload
		rs *record.SSLResponsePayload
	)
	for _, ev := range evs {
		switch ev.Kind {
		case record.KindSSLRequest:
			rq = &record.SSLRequestPayload{}
			if err := json.Unmarshal(ev.Payload, rq); err != nil {
				t.Fatal(err)
			}
		case record.KindSSLResponse:
			rs = &record.SSLResponsePayload{}
			if err := json.Unmarshal(ev.Payload, rs); err != nil {
				t.Fatal(err)
			}
		}
	}
	if rq == nil || rs == nil {
		t.Fatalf("no ssl_request/ssl_response pair in %d events", len(evs))
	}
	return rq, rs
}

// An absolute-form request (RFC 9112 §3.2.2) reaches the host its URL names whatever Host says, and the
// path its URL carries. Read by Host and the raw target, "/https:/api.anthropic.com/v1/messages" fell outside
// /v1 and spent nothing, and with Host naming another host no parser was even chosen.
func TestAbsoluteFormIsMetered(t *testing.T) {
	for _, tc := range []struct {
		name, head string
		declared   bool
	}{
		{"host matches", "POST https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n", true},
		{"host differs", "POST https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: telemetry.example\r\n", true},
		{"no host header", "POST https://api.anthropic.com:443/v1/messages?beta=true HTTP/1.1\r\n", true},
		{"undeclared, parser host", "POST https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: x.example\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evs, lost := r3Drain(t, tc.head, tc.declared)
			rq, rs := r3Usage(t, evs)
			if rs.Usage == nil || rs.Usage.Input != 3 || rs.Usage.Output != 1 {
				t.Fatalf("ssl_response usage %+v (parser %q), want input 3 output 1", rs.Usage, rs.ParserVersion)
			}
			if lost != 0 {
				t.Errorf("%d reported unmetered for a metered exchange", lost)
			}
			if tc.declared && rq.Endpoint != anthropic.Provider {
				t.Errorf("ssl_request endpoint %q, want %q", rq.Endpoint, anthropic.Provider)
			}
		})
	}
}

// R3-H1 backstop: a target that is neither origin-form, "*" nor an http(s) URL says nothing capture can
// classify. A successful answer to it is reported unmetered, which ends a budgeted run, never counted free —
// whichever host the Host header names.
func TestUnreadableTargetFailsClosed(t *testing.T) {
	for _, head := range []string{
		"POST api.anthropic.com/v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n",
		"POST api.anthropic.com/v1/messages HTTP/1.1\r\nHost: telemetry.example\r\n",
		"POST ftp://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: telemetry.example\r\n",
		"POST https:///v1/messages HTTP/1.1\r\nHost: telemetry.example\r\n",
	} {
		evs, lost := r3Drain(t, head, true)
		_, rs := r3Usage(t, evs)
		if rs.Usage == nil && lost < 1 {
			t.Errorf("%q: no usage and nothing reported unmetered: an unreadable target was counted free", head)
		}
	}
}

// A fully qualified Host ("api.anthropic.com.") names the declared host; hosts compare without the
// trailing dot (R33). It matched no models[] entry and no parser, so the exchange was dispatched to nothing.
func TestTrailingDotHostIsMetered(t *testing.T) {
	for _, tc := range []struct {
		name, head string
		declared   bool
	}{
		{"declared", "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com.\r\n", true},
		{"declared with port", "POST /v1/messages HTTP/1.1\r\nHost: API.anthropic.com.:443\r\n", true},
		{"parser host", "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com.\r\n", false},
		{"absolute-form", "POST https://api.anthropic.com./v1/messages HTTP/1.1\r\nHost: x.example\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evs, _ := r3Drain(t, tc.head, tc.declared)
			rq, rs := r3Usage(t, evs)
			if rs.Usage == nil || rs.Usage.Input != 3 {
				t.Fatalf("ssl_response usage %+v (parser %q), want input 3", rs.Usage, rs.ParserVersion)
			}
			if tc.declared && rq.Endpoint != anthropic.Provider {
				t.Errorf("ssl_request endpoint %q, want %q", rq.Endpoint, anthropic.Provider)
			}
		})
	}
}
