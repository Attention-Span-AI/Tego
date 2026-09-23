// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// response builds an ssl_response carrying p.
func response(t *testing.T, p record.SSLResponsePayload) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindSSLResponse}
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestUsage is limits-check-doctor-cli.md §4's ledger.Usage: populated exactly for an ssl_response
// that carries a usage object, straight from usage{...}, with a negative count read as 0 so that
// neither the live budget nor measure can underflow on a malformed reply.
func TestUsage(t *testing.T) {
	got, ok := Usage(response(t, record.SSLResponsePayload{
		Model: "m", Usage: &record.Usage{Input: 10, Output: -3, CacheRead: 4, CacheWrite: 2},
	}))
	if !ok || !reflect.DeepEqual(got, TokenUsage{Model: "m", In: 10, Out: 0, CacheRead: 4, CacheWrite: 2}) {
		t.Fatalf("Usage = %+v %v", got, ok)
	}
	// The 1-hour cache writes and the server-tool counts are read too, and a 1-hour count larger than the whole
	// cache-write count raises the whole rather than being lost.
	got, ok = Usage(response(t, record.SSLResponsePayload{
		Model: "m", Usage: &record.Usage{CacheWrite: 2, CacheWrite1h: 5, ServerTool: map[string]int{"web_search_requests": 3}},
	}))
	if want := (TokenUsage{Model: "m", CacheWrite: 5, CacheWrite1h: 5, ServerTool: map[string]int{"web_search_requests": 3}}); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("Usage = %+v %v, want %+v", got, ok, want)
	}
	for name, e := range map[string]*record.Event{
		"no usage object (E14)": response(t, record.SSLResponsePayload{Model: "m"}),
		"not a response":        {Kind: record.KindDecision},
		"undecodable payload":   {Kind: record.KindSSLResponse, Payload: []byte(`{"usage":"lots"}`)},
		"nil":                   nil,
	} {
		if u, ok := Usage(e); ok || !reflect.DeepEqual(u, TokenUsage{}) {
			t.Errorf("%s: Usage = %+v %v, want nothing", name, u, ok)
		}
	}
}
