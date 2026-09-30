// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// bodyMember is the length of an event's "body" member, decoded, and whether it has one.
func bodyMember(t *testing.T, ev *record.Event) (int, bool) {
	t.Helper()
	var p struct {
		Body *string `json:"body"`
	}
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Body == nil {
		return 0, false
	}
	return len(*p.Body), true
}

// A body cut at MaxBody was recorded as a prefix whose ssl_request and ssl_response lines read as a whole body:
// truncated and wire_size were never set on the forwarder, the only capture at tier 1, while record-ledger §2.2
// says a blob holding only a prefix is marked so, with the body's length on the wire.
func TestABodyCutAtMaxBodyIsMarkedOnItsLines(t *testing.T) {
	const (
		maxBody = 64 << 10
		reqSize = 300 << 10
		resSize = 200 << 10
	)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("r"), resSize))
	}, Options{MaxBody: maxBody})
	resp := h.post("/v1/messages", bytes.Repeat([]byte("q"), reqSize), nil)
	if n, _ := io.Copy(io.Discard, resp.Body); n != resSize {
		t.Fatalf("the client got %d bytes, want %d", n, resSize)
	}
	_ = resp.Body.Close()
	res := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	req := h.sink.of(record.KindSSLRequest)[0]

	rp := payloadOf[record.SSLRequestPayload](t, req)
	if n, ok := bodyMember(t, req); !ok || n >= reqSize {
		t.Fatalf("ssl_request kept %d bytes (a body: %v), want a prefix", n, ok)
	}
	if !rp.Truncated || rp.WireSize != reqSize || rp.Size != reqSize {
		t.Errorf("ssl_request truncated=%v wire_size=%d size=%d, want true and %d: its blob is a prefix",
			rp.Truncated, rp.WireSize, rp.Size, reqSize)
	}
	sp := payloadOf[record.SSLResponsePayload](t, res)
	if n, ok := bodyMember(t, res); !ok || n >= resSize {
		t.Fatalf("ssl_response kept %d bytes (a body: %v), want a prefix", n, ok)
	}
	if !sp.Truncated || sp.WireSize != resSize {
		t.Errorf("ssl_response truncated=%v wire_size=%d, want true and %d: its blob is a prefix",
			sp.Truncated, sp.WireSize, resSize)
	}
}

// A body kept whole carries neither field.
func TestABodyKeptWholeIsNotMarked(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"type":"message"}`))
	}, Options{})
	resp := h.post("/v1/messages", []byte(`{"model":"m"}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	res := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	for _, ev := range []*record.Event{h.sink.of(record.KindSSLRequest)[0], res} {
		if strings.Contains(string(ev.Payload), `"truncated"`) || strings.Contains(string(ev.Payload), `"wire_size"`) {
			t.Errorf("%s of a whole body is marked cut: %s", ev.Kind, ev.Payload)
		}
	}
}

// The event's copy cut by the capture budget is a prefix too, though capture kept the body whole: both lines
// say so. A body that is not recorded at all has no blob to describe, so a cut body then carries neither field.
func TestABodyTheBudgetCutIsMarkedOnItsLines(t *testing.T) {
	body := bytes.Repeat([]byte("b"), 4096)
	const room = 100
	newL := func(bodies bool) *Listener {
		l := &Listener{opts: Options{Bodies: bodies}, budget: newBudget(1<<20, 0), gaps: map[string]int64{}}
		l.budget.take(int(l.budget.limit)-room, int(l.budget.limit)-room)
		return l
	}
	x := &exchange{method: http.MethodPost, body: body, size: int64(len(body))}
	r := &upstreamResult{status: http.StatusOK, body: body, wireSize: int64(len(body))}

	// Each line gets a listener of its own: the request's copy stays counted while it is reachable.
	req := newL(true).requestEvent(x)
	res := newL(true).responseEvent(x, r, derive.Facts{})
	for _, ev := range []*record.Event{req, res} {
		if n, ok := bodyMember(t, ev); !ok || n >= len(body) {
			t.Fatalf("%s kept %d bytes (a body: %v), want the prefix the budget granted", ev.Kind, n, ok)
		}
	}
	if p := payloadOf[record.SSLRequestPayload](t, req); !p.Truncated || p.WireSize != len(body) {
		t.Errorf("ssl_request truncated=%v wire_size=%d, want true and %d", p.Truncated, p.WireSize, len(body))
	}
	if p := payloadOf[record.SSLResponsePayload](t, res); !p.Truncated || p.WireSize != len(body) {
		t.Errorf("ssl_response truncated=%v wire_size=%d, want true and %d", p.Truncated, p.WireSize, len(body))
	}
	runtime.KeepAlive(req)
	runtime.KeepAlive(res)

	l := newL(false)
	x.truncated, r.truncated, r.sizeCut = true, true, true
	for _, ev := range []*record.Event{l.requestEvent(x), l.responseEvent(x, r, derive.Facts{})} {
		if strings.Contains(string(ev.Payload), `"truncated"`) || strings.Contains(string(ev.Payload), `"body"`) {
			t.Errorf("%s without a recorded body is marked cut: %s", ev.Kind, ev.Payload)
		}
	}
}
