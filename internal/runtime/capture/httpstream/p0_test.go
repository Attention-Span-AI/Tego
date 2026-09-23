// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

// TestMaxBodyTruncatesDecodedBody covers the assembler-level half of R14 and capture-derive.md E24: Options.MaxBody is the one
// caller-supplied override to R14's "no total cap" default ("a positive value marks a body that reaches it
// Truncated instead", assembler.go). Every other body-size test in this package (TestBigBody, TestDecode,
// TestDecodeMaxBody) either leaves MaxBody at its zero default or exercises the bare decode() helper
// directly; none feeds a MaxBody-bounded Options through a real Assembler and checks what Message the
// caller actually receives. That is the path capture wires up in production (conn.go's
// decode(body, msg.ContentEncoding, c.opts.MaxBody)), so it is the one worth pinning.
func TestMaxBodyTruncatesDecodedBody(t *testing.T) {
	const capBytes = 200
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte('a' + i%26) // compresses well but decodes to far more than capBytes
	}
	encoded := gzipBytes(t, payload)
	ws := []wire{req(postRequest(reqBody)),
		respBytes(httpResponse("200 OK", []string{"Content-Encoding: gzip"}, encoded))}
	msgs, gaps, err := run(t, Options{MaxBody: capBytes}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if len(msgs[1].Body) != capBytes {
		t.Fatalf("body = %d bytes, want exactly the %d-byte MaxBody cap (R14)", len(msgs[1].Body), capBytes)
	}
	if !msgs[1].Truncated {
		t.Error("body cut at MaxBody not marked Truncated (R14: \"a positive value marks a body that reaches it Truncated\")")
	}
	// Hitting a caller-configured bound is not a peer malformation: R14 draws MaxBody as this package's
	// own choice, not a framing error, so it must not cost a gap why=malformed.
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none: a MaxBody cut is silent truncation, not a gap", gaps)
	}
}

// TestPipelineOverflowPreservesFIFOOrder covers capture-derive.md E15 (response N pairs to request N, first in first out) and the part of R11 that TestPipelineOverflow (gap on the 9th
// request) and TestGoldenPipeline (no overflow at all) do not: what happens to pairing once the queue is
// full. Pairing a response to the wrong request is a silent data-integrity failure this package must never
// produce: R11 says the connection "otherwise continues," not "otherwise desyncs quietly."
//
// This test previously asserted the opposite policy — that queue() evicts the OLDEST entry, so the first
// response after the overflow paired with request index 1, the next with 2, and so on, and that the
// size-cap gap only appeared at Close. That was the defect: RFC 9112 §9.3 has a server answer a pipelined
// connection in request order, so the head of the FIFO is the next response's partner, and evicting it
// re-pairs every response that follows with a request it did not answer. R11 puts the gap "on that
// request" — the ninth — which is the entry that must give way.
func TestPipelineOverflowPreservesFIFOOrder(t *testing.T) {
	a := NewAssembler(Options{})
	for i := 0; i < 9; i++ {
		msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(fmt.Sprintf(`{"n":%d}`, i)))})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if len(msgs) != 1 {
			t.Fatalf("request %d produced %d messages, want 1: R11 refuses the queue slot, not the message", i, len(msgs))
		}
	}
	// The ninth request is the one refused, and R11 makes that a gap as it happens rather than at
	// Close — a connection that dies later must not be able to swallow it.
	if !hasGap(a.Gaps(), GapSizeCap) {
		t.Errorf("gaps = %v, want a size-cap gap for the request R11's depth-8 queue refused", a.Gaps())
	}
	// Each of the eight requests still queued must pair with the response that actually answers it:
	// index 0 first, in request order.
	for want := 0; want <= 7; want++ {
		respData := httpResponse("200 OK", nil, []byte(fmt.Sprintf(`{"r":%d}`, want)))
		msgs, err := a.Feed(testKey, DirResponse, Chunk{Data: respData})
		if err != nil {
			t.Fatalf("response %d: %v", want, err)
		}
		if len(msgs) != 1 {
			t.Fatalf("response %d produced %d messages, want 1", want, len(msgs))
		}
		if msgs[0].RequestIndex != want {
			t.Fatalf("response paired with request index %d, want %d (R11: FIFO pairing must survive an overflow)",
				msgs[0].RequestIndex, want)
		}
	}
	// The ninth exchange is the one the cap declared lost. Its response has no partner, and I3 forbids
	// handing over a bare response, so it is passed over — never quietly paired with something else.
	// Its loss is the size-cap gap already recorded on its request, so it costs no second gap, and the
	// connection R11 says "otherwise continues" does: a tenth exchange pairs. That is one lost exchange
	// against the eight a head eviction would have mispaired. (It used to be ErrMalformed, which
	// abandoned the connection and every exchange after it.)
	last := httpResponse("200 OK", nil, []byte(`{"r":8}`))
	msgs, err := a.Feed(testKey, DirResponse, Chunk{Data: last})
	if err != nil {
		t.Fatalf("ninth response error = %v, want none: R11's connection otherwise continues", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("ninth response emitted %d messages despite having no request to pair with (I3)", len(msgs))
	}
	if hasGap(a.Gaps(), GapMalformed) {
		t.Errorf("gaps = %v: the refused request's response is its size-cap gap, not a malformed one too", a.Gaps())
	}
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(`{"n":9}`))}); err != nil {
		t.Fatalf("tenth request: %v", err)
	}
	msgs, err = a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(`{"r":9}`))})
	if err != nil || len(msgs) != 1 || msgs[0].RequestIndex != 9 {
		t.Fatalf("tenth response = %v, %v; want it paired with request 9", msgs, err)
	}
}

// TestCloseMidHeaders covers edge case #28 ("Stop() mid-request ... any non-Done connection is Close()d,
// producing gap why=malformed ... rather than a silent half-message") for the one FSM state none of the
// existing close tests reach: a half parked inside the header block itself, before any body framing is even
// decided. TestCloseShortBody and TestCloseAllThenFeed both close a connection mid-*body* (hsBody);
// TestCloseIdleAndTwice closes one that never started a message (hsStart with an empty buffer). The
// hsHeaders branch of conn.go's flush() — "half-read %s at close" — is a distinct fourth path.
//
// No request is ever sent on this connection, deliberately: queuing one would also leave close()'s own
// "requests with no response at close" check non-empty, which raises its own why=malformed gap and would
// mask a broken flush() default case behind a false pass. Parsing a response never requires a queued
// request (pairing is only checked at complete()), so feeding response bytes alone isolates flush()'s
// hsHeaders branch as the one and only possible source of a gap here.
func TestCloseMidHeaders(t *testing.T) {
	a := NewAssembler(Options{})
	// A status line and one complete header line, no terminating blank line: the half is sitting in
	// hsHeaders, msg already allocated, when Close arrives mid-run.
	partial := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(partial)}); err != nil {
		t.Fatalf("partial headers: %v", err)
	}
	msgs := a.Close(testKey)
	if len(msgs) != 0 {
		t.Fatalf("a half-read header block produced a message instead of nothing: %v", msgs)
	}
	if !hasGap(a.Gaps(), GapMalformed) {
		t.Errorf("gaps = %v, want why=malformed (edge case #28: a half-read header block at close is never silent)", a.Gaps())
	}
}

// TestBodilessStatusIgnoresContentLength covers R10's framing decision for 204 and 304: header.go's
// framing() explicitly special-cases them ("A 1xx, 204 or 304 response and any response to HEAD carry no
// body whatever the headers say", RFC 9112 §6.3) but no existing test sends one with a Content-Length that
// lies about a body. TestHeadResponseHasNoBody covers the HEAD half of that same condition only. If a
// 204/304 body length were honoured instead, the next request's own bytes on a keep-alive connection would
// be consumed as this response's phantom body — a framing desync R10 exists specifically to prevent.
func TestBodilessStatusIgnoresContentLength(t *testing.T) {
	cases := []struct{ code, reason string }{
		{"204", "No Content"},
		{"304", "Not Modified"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			liar := fmt.Sprintf("HTTP/1.1 %s %s\r\nContent-Length: 50\r\n\r\n", tc.code, tc.reason)
			ws := []wire{
				req(postRequest(reqBody)),
				resp(liar),
				req(postRequest(reqBody)),
				respBytes(httpResponse("200 OK", nil, []byte(respBody))),
			}
			msgs, gaps, err := run(t, Options{}, 0, true, ws)
			if err != nil {
				t.Fatalf("feed: %v", err)
			}
			if len(msgs) != 4 {
				t.Fatalf("want 2 whole exchanges (4 messages), got %d: no keep-alive desync should follow a %s", len(msgs), tc.code)
			}
			if len(msgs[1].Body) != 0 {
				t.Errorf("%s response carried %d body bytes despite a Content-Length that lies about one (RFC 9112 §6.3, R10)",
					tc.code, len(msgs[1].Body))
			}
			wantStatus, err := strconv.Atoi(tc.code)
			if err != nil {
				t.Fatalf("test case status %q: %v", tc.code, err)
			}
			if msgs[1].Status != wantStatus {
				t.Errorf("status = %d, want %s", msgs[1].Status, tc.code)
			}
			if msgs[3].Status != http.StatusOK || msgs[3].RequestIndex != msgs[2].Index {
				t.Errorf("second exchange desynced after the %s: response=%+v request=%+v", tc.code, msgs[3], msgs[2])
			}
			if len(gaps) != 0 {
				t.Errorf("gaps = %v, want none", gaps)
			}
		})
	}
}
