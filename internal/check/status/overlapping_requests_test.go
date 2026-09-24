// SPDX-License-Identifier: Apache-2.0

package status

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDeriveOverlappingModelRequests pins which half of R10 decides the state when a run has more
// than one model call in flight at once — the case a forwarded agent reaches whenever it issues a
// background call alongside its main completion.
//
// R10 reads "∃ ssl_request with no ssl_response sharing its request_id, newer than the last
// response" (docs/p0/limits-check-doctor-cli.md §5). Both halves qualify the same request, and
// together they are exactly "the newest ssl_* event is a request": a response is always recorded
// after the request it answers, so a request newer than the last response is by construction one
// that has not been answered, and one older than the last response cannot be shown to be still
// outstanding by anything the ledger holds. That equivalence is why Derive decides R10 by order and
// not by an unbounded set of unanswered request_ids.
//
// The difference only shows in the four cases below, and in three of them the order rule is the one
// that gives the honest answer. An id-set reading has no way to retire the id of a request that was
// never answered — the forwarder records no ssl_response when the upstream leg fails
// (internal/runtime/capture/forwarder/listener.go: RoundTrip error ⇒ finish(x, nil), and derive
// emits the response event only when a result exists) — so one failed call would pin the run to
// "waiting model" for every later poll, hiding every tool and every step until R9 finally called it
// stalled. Under the order rule a wrong reading is bounded by the next response instead.
func TestDeriveOverlappingModelRequests(t *testing.T) {
	tests := []struct {
		name  string
		build func(w *ledger.Writer)
		want  State
	}{
		{
			// Both readings agree here, and it is the case that matters most: while the newest
			// ssl_* event is a request the run is waiting on the model, however many calls
			// overlap. A is still outstanding, B is the newest event.
			name: "two calls in flight with no response yet is waiting model",
			build: func(w *ledger.Writer) {
				sslRequest(w, "A")
				sslRequest(w, "B")
			},
			want: WaitingModel,
		},
		{
			// The readings part company here. B answered and asked for a tool, A is outstanding.
			// R10's "newer than the last response" excludes A, so R11 decides: the run is
			// executing the tool B asked for, which is the fact a reader can act on. Reporting
			// "waiting model" off A would hide the running tool for as long as A stays open, and
			// nothing in the ledger ever says whether A is alive or was abandoned.
			name: "an older call still open does not hide the tool the newest response asked for",
			build: func(w *ledger.Writer) {
				sslRequest(w, "A")
				sslRequest(w, "B")
				sslResponse(w, "B")
				appendEvent(w, record.KindDecision, record.DecisionPayload{Step: 1, Tool: "bash", ToolUseID: "t1"})
			},
			want: WaitingTool,
		},
		{
			// The liveness half: an abandoned call must not latch the state. The forwarder writes
			// ssl_request before RoundTrip and no ssl_response at all when the upstream leg fails,
			// so A's id has no closing event and never will; the agent's retry (B) then completes
			// normally. The run is running, and must read that way for the rest of its life.
			name: "a call that was never answered does not latch the state",
			build: func(w *ledger.Writer) {
				sslRequest(w, "A") // upstream failed: no ssl_response will ever carry id A
				sslRequest(w, "B")
				sslResponse(w, "B")
			},
			want: Running,
		},
		{
			// Tier 2 cannot be matched by id at all: the uprobe path reads request_id out of the
			// request's own headers and out of the response's headers separately
			// (internal/runtime/capture/uprobe/events.go, requestIDHeaders), and a provider
			// returns its own id rather than echoing the client's. The two ids of one exchange
			// routinely differ, so an id-set reading would leave every tier-2 request outstanding
			// forever. The order rule reads the same exchange correctly on both tiers.
			name: "a response whose request_id differs from the request's still closes the wait",
			build: func(w *ledger.Writer) {
				sslRequest(w, "client-sent-id")
				sslResponse(w, "req_provider_9")
			},
			want: Running,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := write(t, true, func(w *ledger.Writer) {
				runStart("")(w)
				tc.build(w)
			}, nil)
			if got := derive(t, dir, true, base, time.Hour); got.St != tc.want {
				t.Fatalf("state %q, want %q", got.St, tc.want)
			}
		})
	}
}

// sslRequest appends one ssl_request carrying the id the forwarder stamps on both halves of an
// exchange (internal/runtime/capture/forwarder/event.go).
func sslRequest(w *ledger.Writer, id string) {
	appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{
		Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages", RequestID: id,
	})
}

// sslResponse appends the ssl_response of the exchange with that request_id.
func sslResponse(w *ledger.Writer, id string) {
	appendEvent(w, record.KindSSLResponse, record.SSLResponsePayload{
		Status: 200, RequestID: id, ParserVersion: "1",
	})
}
