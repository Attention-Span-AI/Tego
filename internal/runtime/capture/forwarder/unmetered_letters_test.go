// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// failingTransport fails every round trip with err, as a leg whose dial failed or whose upstream went away does.
type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	return nil, f.err
}

// cutStream is an Anthropic event stream padded past a 16 KiB capture, its usage in the closing message_delta.
func cutStream() string {
	var b strings.Builder
	b.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":150000,\"output_tokens\":1}}}\n\n")
	pad := strings.Repeat("x", 4096)
	for range 64 {
		fmt.Fprintf(&b, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"%s\"}}\n\n", pad)
	}
	b.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":900}}\n\n")
	b.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return b.String()
}

// TestEveryR1LetterOnTheForwarder is limits-check-doctor-cli.md R1's two lists on the forwarder, one row per
// letter the forwarder can meet: every "Reported as unmetered" case is reported to the run, which ends a run
// with a token or cost budget at the first report (runtime.TestUnmeteredSpendEndsABudgetedRun); every "Not
// reported" case is not, and a budgeted run goes on. The letters that belong to the uprobe path alone (f-j, n,
// p, q) are TestEveryR1LetterOnTheUprobePath's; (j) and (r) are the runner's and the watcher's.
func TestEveryR1LetterOnTheForwarder(t *testing.T) {
	const (
		message = `{"id":"msg_1","type":"message","model":"claude-opus-5","content":[],"usage":{"input_tokens":3,"output_tokens":2}}`
		start   = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":20,\"output_tokens\":1}}}\n\n"
		errEv   = "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n"
	)
	answer := func(status int, ctype, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", ctype)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(cutStream()))
	_ = zw.Close()
	gzipped := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz.Bytes())
	}
	msgs := `{"model":"claude-opus-5","max_tokens":8,"messages":[]}`
	for _, row := range []struct {
		letter, name, method, path, body string
		handler                          http.HandlerFunc
		transport                        http.RoundTripper
		maxBody                          int
		reported                         bool
	}{
		// Reported as unmetered.
		{letter: "a", name: "2xx message with no usage", method: "POST", path: "/v1/messages", body: msgs,
			handler: answer(200, "application/json", `{"id":"msg_1","type":"message","model":"claude-opus-5","content":[]}`), reported: true},
		{letter: "a", name: "2xx on a /v1 path the parser reads no usage from", method: "POST", path: "/v1/complete", body: msgs,
			handler: answer(200, "application/json", `{"completion":"x"}`), reported: true},
		{letter: "a", name: "2xx on a batch's results", method: "GET", path: "/v1/messages/batches/msgbatch_1/results",
			handler: answer(200, "application/json", `{}`), reported: true},
		{letter: "a", name: "2xx on /V1/messages", method: "POST", path: "/V1/messages", body: msgs,
			handler: answer(200, "application/json", message), reported: true},
		{letter: "b", name: "message batch created", method: "POST", path: "/v1/messages/batches", body: `{"requests":[]}`,
			handler: answer(200, "application/json", `{"id":"msgbatch_1","type":"message_batch"}`), reported: true},
		{letter: "c", name: "stream cut after message_start, no max_tokens", method: "POST", path: "/v1/messages",
			body:    `{"model":"claude-opus-5","stream":true,"messages":[]}`,
			handler: answer(200, "text/event-stream", start), reported: true},
		{letter: "d", name: "gzip stream cut by size", method: "POST", path: "/v1/messages",
			body: `{"model":"claude-opus-5","stream":true,"max_tokens":8,"messages":[]}`, handler: gzipped,
			maxBody: 16 << 10, reported: true},
		{letter: "e", name: "upstream went away after the request", method: "POST", path: "/v1/messages", body: msgs,
			transport: failingTransport{err: io.ErrUnexpectedEOF}, reported: true},

		// Not reported.
		{letter: "d", name: "identity stream cut by size, usage read by the scanner", method: "POST", path: "/v1/messages",
			body:    `{"model":"claude-opus-5","stream":true,"max_tokens":8,"messages":[]}`,
			handler: answer(200, "text/event-stream", cutStream()), maxBody: 16 << 10},
		{letter: "k", name: "4xx", method: "POST", path: "/v1/messages", body: msgs,
			handler: answer(429, "application/json", `{"type":"error","error":{"type":"rate_limit_error"}}`)},
		{letter: "k", name: "2xx stream whose first event is an error", method: "POST", path: "/v1/messages",
			body: `{"model":"claude-opus-5","stream":true,"messages":[]}`, handler: answer(200, "text/event-stream", errEv)},
		{letter: "l", name: "model listing", method: "GET", path: "/v1/models", handler: answer(200, "application/json", `{"data":[]}`)},
		{letter: "l", name: "token counting unanswered", method: "POST", path: "/v1/messages/count_tokens", body: msgs,
			transport: failingTransport{err: io.ErrUnexpectedEOF}},
		{letter: "l", name: "a batch's cancel", method: "POST", path: "/v1/messages/batches/msgbatch_1/cancel",
			handler: answer(200, "application/json", `{"id":"msgbatch_1","type":"message_batch"}`)},
		{letter: "m", name: "stream cut after message_start, max_tokens known", method: "POST", path: "/v1/messages",
			body:    `{"model":"claude-opus-5","stream":true,"max_tokens":2048,"messages":[]}`,
			handler: answer(200, "text/event-stream", start)},
		{letter: "o", name: "upstream dial failed", method: "POST", path: "/v1/messages", body: msgs,
			transport: failingTransport{err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}},
	} {
		t.Run("("+row.letter+") "+row.name, func(t *testing.T) {
			handler := row.handler
			if handler == nil {
				handler = answer(200, "application/json", message)
			}
			opts := Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()}), Transport: row.transport,
				MaxBody: row.maxBody}
			h := newHarness(t, handler, opts)
			m := meter(h)
			var body io.Reader
			if row.body != "" {
				body = strings.NewReader(row.body)
			}
			req, err := http.NewRequest(row.method, h.listener.BaseURL()+row.path, body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "gzip")
			resp := h.do(req)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			// The exchange is derived once its answer has been relayed, or its failure returned: wait for its
			// ssl_response, or the gap an unanswered one leaves, and then for a report.
			deadline := time.Now().Add(5 * time.Second)
			for len(h.sink.of(record.KindSSLResponse))+len(h.sink.of(record.KindGap)) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			var got []string
			if row.reported {
				got = waitReported(m, 1)
			} else {
				time.Sleep(100 * time.Millisecond)
				got = m.reported()
			}
			switch {
			case row.reported && len(got) == 0:
				t.Fatalf("R1 (%s) is reported as unmetered and so ends a budgeted run; the forwarder reported nothing", row.letter)
			case !row.reported && len(got) != 0:
				t.Fatalf("R1 (%s) is not reported, and a budgeted run would have ended: %q", row.letter, got)
			}
		})
	}
}
