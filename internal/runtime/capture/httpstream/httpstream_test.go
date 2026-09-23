// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// reqBody is the request body every golden sends: the shape derive/anthropic will later parse.
const reqBody = `{"model":"claude-opus-4","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`

// respBody is the non-streaming response body.
const respBody = `{"id":"msg_01","model":"claude-opus-4","stop_reason":"end_turn",` +
	`"content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":9,"output_tokens":3}}`

// postRequest is the request line and headers of the golden POST.
func postRequest(body string) string {
	return "POST /v1/messages HTTP/1.1\r\n" +
		"Host: api.anthropic.com\r\n" +
		"Content-Type: application/json\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" + body
}

// TestGoldenEncodings covers R15: one golden per content coding, each asserting that the decoded body is
// what reaches derive and that content_encoding still records what the wire used.
func TestGoldenEncodings(t *testing.T) {
	cases := []struct {
		name   string
		coding string
		encode func(*testing.T, []byte) []byte
	}{
		{"identity", "", func(_ *testing.T, b []byte) []byte { return b }},
		{"gzip", "gzip", gzipBytes},
		{"deflate", "deflate", zlibBytes},
		{"br", "br", brotliBytes},
		{"zstd", "zstd", zstdBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := []string{"Content-Type: application/json"}
			if tc.coding != "" {
				headers = append(headers, "Content-Encoding: "+tc.coding)
			}
			encoded := tc.encode(t, []byte(respBody))
			ws := []wire{req(postRequest(reqBody)), respBytes(httpResponse("200 OK", headers, encoded))}
			msgs, gaps, err := run(t, Options{}, 0, true, ws)
			if err != nil {
				t.Fatalf("feed: %v", err)
			}
			if len(msgs) != 2 {
				t.Fatalf("want 2 messages, got %d", len(msgs))
			}
			if got := string(msgs[1].Body); got != respBody {
				t.Errorf("decoded body = %q, want %q", got, respBody)
			}
			checkGolden(t, "encoding-"+tc.name, render(msgs, gaps))

			// The same conversation split byte by byte must produce exactly the same messages: no
			// rule in this package may depend on where a write boundary fell (edge case #17).
			split, splitGaps, err := run(t, Options{}, 1, true, ws)
			if err != nil {
				t.Fatalf("byte-split feed: %v", err)
			}
			if string(render(split, splitGaps)) != string(render(msgs, gaps)) {
				t.Errorf("byte-split reassembly differs from whole-chunk reassembly")
			}
		})
	}
}

// TestGoldenChunked covers a chunked response whose size lines and data are split across writes.
func TestGoldenChunked(t *testing.T) {
	first, second := `{"id":"msg_01","model":"c"`, `,"stop_reason":"end_turn"}`
	body := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" +
		fmt.Sprintf("%x\r\n%s\r\n", len(first), first) +
		fmt.Sprintf("%x;ext=1\r\n%s\r\n", len(second), second) +
		"0\r\nX-Trailer: done\r\n\r\n"
	msgs, gaps, err := run(t, Options{}, 0, true, []wire{req(postRequest(reqBody)), resp(body)})
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	checkGolden(t, "chunked", render(msgs, gaps))
	split, splitGaps, err := run(t, Options{}, 3, true, []wire{req(postRequest(reqBody)), resp(body)})
	if err != nil {
		t.Fatalf("split feed: %v", err)
	}
	if string(render(split, splitGaps)) != string(render(msgs, gaps)) {
		t.Errorf("3-byte-split chunked reassembly differs")
	}
}

// TestGoldenSSE covers capture-derive.md R16 and E19: a streamed text/event-stream response is one Message
// carrying the decoded body intact. The provider parser owns its framing and ignores comments and retry.
func TestGoldenSSE(t *testing.T) {
	frames := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"usage\":{\"input_tokens\":9}}}\n\n",
		": heartbeat\n\n",
		"retry: 3000\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"text\":\"he\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"text\":\"llo\"}}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	ws := []wire{req(postRequest(reqBody)),
		resp("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")}
	for _, f := range frames {
		ws = append(ws, resp(fmt.Sprintf("%x\r\n%s\r\n", len(f), f)))
	}
	ws = append(ws, resp("0\r\n\r\n"))

	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want one request and one response, got %d messages", len(msgs))
	}
	if !msgs[1].SSE {
		t.Error("response not marked SSE")
	}
	if got, want := string(msgs[1].Body), strings.Join(frames, ""); got != want {
		t.Errorf("SSE framing changed: got %q, want %q", got, want)
	}
	checkGolden(t, "sse", render(msgs, gaps))
}

// TestRequestEventStreamKeepsBody covers capture-derive.md R16: a request the agent labels text/event-stream
// keeps its exact body and remains a request rather than a stream response, as the forwarder records it.
func TestRequestEventStreamKeepsBody(t *testing.T) {
	head := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: text/event-stream\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(reqBody)) + reqBody
	ws := []wire{req(head), respBytes(httpResponse("200 OK", []string{"Content-Type: application/json"}, []byte(respBody)))}
	msgs, _, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if msgs[0].SSE {
		t.Error("request marked SSE")
	}
	if got := string(msgs[0].Body); got != reqBody {
		t.Errorf("request body = %q, want %q", got, reqBody)
	}
}

// TestGoldenKeepAlive covers R10: three exchanges on one connection, each paired in order.
func TestGoldenKeepAlive(t *testing.T) {
	var ws []wire
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"n":%d}`, i)
		ws = append(ws, req(postRequest(body)))
		ws = append(ws, respBytes(httpResponse("200 OK", []string{"Content-Type: application/json"},
			[]byte(fmt.Sprintf(`{"reply":%d}`, i)))))
	}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 6 {
		t.Fatalf("want 6 messages, got %d", len(msgs))
	}
	for i := 1; i < len(msgs); i += 2 {
		if msgs[i].RequestIndex != msgs[i-1].Index {
			t.Errorf("response %d paired with request %d, want %d", i, msgs[i].RequestIndex, msgs[i-1].Index)
		}
	}
	checkGolden(t, "keepalive", render(msgs, gaps))
}

// TestGoldenContinue covers capture-derive.md R12 and capture-derive.md E16 (edge case #16): the interim 100 is consumed and never emitted, and a
// server that skips it needs no separate path.
func TestGoldenContinue(t *testing.T) {
	head := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nExpect: 100-continue\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(reqBody))
	ws := []wire{
		req(head),
		resp("HTTP/1.1 100 Continue\r\n\r\n"),
		req(reqBody),
		respBytes(httpResponse("200 OK", []string{"Content-Type: application/json"}, []byte(respBody))),
	}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages (the interim is discarded), got %d", len(msgs))
	}
	if msgs[1].Status != 200 {
		t.Errorf("status = %d, want 200", msgs[1].Status)
	}
	checkGolden(t, "continue", render(msgs, gaps))
}

// TestGoldenPipeline covers R11 at two and at the full depth of eight.
func TestGoldenPipeline(t *testing.T) {
	for _, depth := range []int{2, 8} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			var ws []wire
			for i := 0; i < depth; i++ {
				ws = append(ws, req(postRequest(fmt.Sprintf(`{"n":%d}`, i))))
			}
			for i := 0; i < depth; i++ {
				ws = append(ws, respBytes(httpResponse("200 OK", nil, []byte(fmt.Sprintf(`{"r":%d}`, i)))))
			}
			msgs, gaps, err := run(t, Options{}, 0, true, ws)
			if err != nil {
				t.Fatalf("feed: %v", err)
			}
			if len(gaps) != 0 {
				t.Errorf("depth %d produced gaps %v", depth, gaps)
			}
			checkGolden(t, fmt.Sprintf("pipeline-%d", depth), render(msgs, gaps))
		})
	}
}

// TestPipelineOverflow covers R11's ninth request: one gap why=size-cap, the connection continuing.
func TestPipelineOverflow(t *testing.T) {
	var ws []wire
	for i := 0; i < 9; i++ {
		ws = append(ws, req(postRequest(fmt.Sprintf(`{"n":%d}`, i))))
	}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 9 {
		t.Fatalf("want 9 requests emitted, got %d", len(msgs))
	}
	if !hasGap(gaps, GapSizeCap) {
		t.Errorf("want a size-cap gap, got %v", gaps)
	}
}

// TestMalformed is R18's table, capture-derive.md E21's Content-Length plus Transfer-Encoding row among them: every one of these is a gap and none of them panics or disturbs another
// connection. It doubles as the fuzz corpus seed.
func TestMalformed(t *testing.T) {
	cases := []struct {
		name    string
		wires   []wire
		wantWhy string
		wantErr error
	}{
		{"bad request line", []wire{req("GET\r\nHost: x\r\n\r\n")}, GapMalformed, ErrMalformed},
		{"http/0.9 request", []wire{req("GET /x\r\n\r\n")}, GapMalformed, ErrMalformed},
		{"header without colon", []wire{req("GET / HTTP/1.1\r\nHost api.anthropic.com\r\n\r\n")}, GapMalformed, ErrMalformed},
		{"header name not a token", []wire{req("GET / HTTP/1.1\r\nHo st: x\r\n\r\n")}, GapMalformed, ErrMalformed},
		{"content-length and transfer-encoding", []wire{
			req("POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc")},
			GapMalformed, ErrMalformed},
		{"content-length values disagree", []wire{
			req("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc")}, GapMalformed, ErrMalformed},
		{"negative content-length", []wire{req("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n")}, GapMalformed, ErrMalformed},
		{"bad chunk size", []wire{
			req("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n")}, GapMalformed, ErrMalformed},
		{"chunk data not followed by crlf", []wire{
			req("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX")}, GapMalformed, ErrMalformed},
		{"transfer-encoding not chunked", []wire{
			req("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n")}, GapMalformed, ErrMalformed},
		{"h2 preface", []wire{req("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")}, GapH2, ErrHTTP2},
		{"h2 on the request line", []wire{req("GET / HTTP/2.0\r\n\r\n")}, GapH2, ErrHTTP2},
		{"101 upgrade to h2c", []wire{req(postRequest("x")),
			resp("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n")}, GapH2, ErrHTTP2},
		{"bad status line", []wire{req(postRequest("x")), resp("HTTP/1.1 nine hundred\r\n\r\n")}, GapMalformed, ErrMalformed},
		// A response with no request at all is not here: it is passed over as one counted gap and the
		// connection goes on (resync_test.go). One that arrives while its request is still arriving is.
		{"response while its request is arriving", []wire{
			req("POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\nab"),
			respBytes(httpResponse("200 OK", nil, []byte("hi")))}, GapMalformed, ErrMalformed},
		{"continuation line with nothing to fold into", []wire{
			req("GET / HTTP/1.1\r\n  folded\r\n\r\n")}, GapMalformed, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, gaps, err := run(t, Options{}, 0, true, tc.wires)
			if err == nil {
				t.Fatalf("want an error, got messages %d gaps %v", len(msgs), gaps)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
			if !hasGap(gaps, tc.wantWhy) {
				t.Errorf("gaps = %v, want one %s", gaps, tc.wantWhy)
			}
		})
	}
}

// TestHeaderCaps covers capture-derive.md R13: a header block over either cap gaps the connection once.
func TestHeaderCaps(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		big := "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 2048) + "\r\n\r\n"
		_, gaps, err := run(t, Options{MaxHeaderBytes: 512}, 0, true, []wire{req(big)})
		if !errors.Is(err, ErrSizeCap) {
			t.Fatalf("error = %v, want ErrSizeCap", err)
		}
		if !hasGap(gaps, GapSizeCap) {
			t.Errorf("gaps = %v, want size-cap", gaps)
		}
	})
	t.Run("lines", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("GET / HTTP/1.1\r\n")
		for i := 0; i < 200; i++ {
			fmt.Fprintf(&b, "X-H%d: v\r\n", i)
		}
		b.WriteString("\r\n")
		_, gaps, err := run(t, Options{}, 0, true, []wire{req(b.String())})
		if !errors.Is(err, ErrSizeCap) {
			t.Fatalf("error = %v, want ErrSizeCap", err)
		}
		if !hasGap(gaps, GapSizeCap) {
			t.Errorf("gaps = %v, want size-cap", gaps)
		}
	})
}

// TestConnectionsAreIndependent is R18's "other connections unaffected": a malformed connection gaps and
// its neighbour on the same assembler still completes.
func TestConnectionsAreIndependent(t *testing.T) {
	a := NewAssembler(Options{})
	bad := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	good := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 2}
	if _, err := a.Feed(bad, DirRequest, Chunk{Data: []byte("NOT HTTP AT ALL\r\n\r\n")}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad connection error = %v", err)
	}
	if _, err := a.Feed(good, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatalf("good connection: %v", err)
	}
	msgs, err := a.Feed(good, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(respBody))})
	if err != nil {
		t.Fatalf("good response: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Status != 200 {
		t.Fatalf("good connection did not complete: %v", msgs)
	}
	// A feed on the gapped connection is a no-op, not a second error: one gap per connection (R13/R18).
	if got, err := a.Feed(bad, DirRequest, Chunk{Data: []byte("more junk")}); err != nil || got != nil {
		t.Errorf("feed after gap = %v, %v; want nil, nil", got, err)
	}
	if g := a.Gaps(); len(g) != 1 || g[0].Count != 1 {
		t.Errorf("gaps = %v, want exactly one malformed", g)
	}
}

// TestH2IsDetectedByItsPrefaceAlone pins R17 as built: an h2 connection is known by the
// preface its client writes first, which reassembly checks on the request half, and by nothing else. The
// Assembler had a NoteALPN for the negotiated ALPN that nothing called, so the ALPN half of R17 was claimed and
// never done; it is gone, and R17 states the gap it leaves (a connection whose preface capture missed).
func TestH2IsDetectedByItsPrefaceAlone(t *testing.T) {
	if _, ok := reflect.TypeOf(&Assembler{}).MethodByName("NoteALPN"); ok {
		t.Error("the Assembler takes an ALPN result nothing supplies")
	}
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")}); !errors.Is(err, ErrHTTP2) {
		t.Fatalf("preface error = %v, want ErrHTTP2", err)
	}
	if !hasGap(a.Gaps(), GapH2) {
		t.Errorf("gaps = %v, want h2", a.Gaps())
	}
}

// TestCloseShortBody covers edge case #22: a declared Content-Length the server never finishes flushes
// what arrived, marks it Truncated and gaps once.
func TestCloseShortBody(t *testing.T) {
	ws := []wire{req(postRequest(reqBody)),
		resp("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n" + strings.Repeat("x", 300))}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if !msgs[1].Truncated {
		t.Error("short body not marked Truncated")
	}
	if len(msgs[1].Body) != 300 {
		t.Errorf("body = %d bytes, want the 300 that arrived", len(msgs[1].Body))
	}
	if !hasGap(gaps, GapMalformed) {
		t.Errorf("gaps = %v, want malformed", gaps)
	}
}

// TestCloseDelimitedBody is the HTTP/1.0-style response with neither framing header: the close is the end
// of the message, not a gap.
func TestCloseDelimitedBody(t *testing.T) {
	ws := []wire{req(postRequest(reqBody)), resp("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 2 || string(msgs[1].Body) != "hello" {
		t.Fatalf("messages = %v", msgs)
	}
	if msgs[1].Truncated {
		t.Error("a close-delimited body is complete, not truncated")
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none", gaps)
	}
}

// TestCloseIdleAndTwice covers §4's idempotence and "nothing, if genuinely idle" (edge case #28).
func TestCloseIdleAndTwice(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: nil}); err != nil {
		t.Fatalf("empty feed: %v", err)
	}
	if msgs := a.Close(testKey); msgs != nil {
		t.Errorf("idle close returned %v", msgs)
	}
	if msgs := a.Close(testKey); msgs != nil {
		t.Errorf("second close returned %v", msgs)
	}
	if g := a.Gaps(); len(g) != 0 {
		t.Errorf("idle close gapped: %v", g)
	}
}

// TestCloseAllThenFeed covers the final drain of Stop (edge case #28).
func TestCloseAllThenFeed(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatalf("feed: %v", err)
	}
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nfour")}); err != nil {
		t.Fatalf("feed: %v", err)
	}
	msgs := a.CloseAll()
	if len(msgs) != 1 || !msgs[0].Truncated {
		t.Fatalf("CloseAll = %v, want one truncated response", msgs)
	}
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("x")}); !errors.Is(err, ErrClosed) {
		t.Errorf("feed after CloseAll = %v, want ErrClosed", err)
	}
	if a.Conns() != 0 {
		t.Errorf("Conns = %d after CloseAll", a.Conns())
	}
}

// TestSeqHole covers I2: a producer that numbers its chunks gets a hole reported, not accepted.
func TestSeqHole(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("POST / HTTP/1.1\r\n"), Seq: 1}); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	_, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("Host: x\r\n\r\n"), Seq: 3})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("seq hole error = %v, want ErrMalformed", err)
	}
	if !hasGap(a.Gaps(), GapMalformed) {
		t.Errorf("gaps = %v", a.Gaps())
	}
}

// TestSeqHoleAcrossDirections: the sequence is the connection's, both directions counted
// together, so a response lost whole — the first of its direction, which a per-direction count cannot show —
// is found at the next request, and the connection gaps instead of pairing that request's response with the
// one before it.
func TestSeqHoleAcrossDirections(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(`{"n":0}`)), Seq: 1}); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// The response, seq 2, never reached the reader.
	msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(`{"n":1}`)), Seq: 3})
	if !errors.Is(err, ErrMalformed) || len(msgs) != 0 {
		t.Fatalf("the chunk after a lost one: %d messages, err %v, want ErrMalformed", len(msgs), err)
	}
	msgs, err = a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(`{"r":1}`)), Seq: 4})
	if err != nil || len(msgs) != 0 {
		t.Fatalf("a response on the gapped connection was handed over (I3): %d messages, %v", len(msgs), err)
	}
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1", got)
	}
}

// TestSeqWraps: the producer's count skips 0 when it wraps, and so does the check.
func TestSeqWraps(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("POST / HTTP/1.1\r\n"), Seq: ^uint32(0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("Host: x\r\n\r\n"), Seq: 1}); err != nil {
		t.Fatalf("the count after its wrap: %v", err)
	}
}

// TestChunkTruncationPropagates covers R6: a chunk the kernel cut marks the message it belongs to.
func TestChunkTruncationPropagates(t *testing.T) {
	a := NewAssembler(Options{})
	body := `{"a":1}`
	head := "POST /v1/messages HTTP/1.1\r\nHost: x\r\n" + fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(head), Seq: 1, Truncated: true}); err != nil {
		t.Fatalf("head: %v", err)
	}
	msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(body), Seq: 2})
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(msgs) != 1 || !msgs[0].Truncated {
		t.Fatalf("messages = %v, want one truncated request", msgs)
	}
}

// TestHeadResponseHasNoBody covers RFC 9112 §6.3's HEAD rule: the declared length is not a body.
func TestHeadResponseHasNoBody(t *testing.T) {
	ws := []wire{
		req("HEAD /api/hello HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"),
		resp("HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n"),
		req("GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"),
		respBytes(httpResponse("200 OK", nil, []byte(`{"ok":true}`))),
	}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(msgs) != 4 {
		t.Fatalf("want 4 messages, got %d", len(msgs))
	}
	if len(msgs[1].Body) != 0 {
		t.Errorf("HEAD response carried %d body bytes", len(msgs[1].Body))
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v", gaps)
	}
}

// TestDecodeErrorKeepsPrefix covers R15 and edge case #18: a body cut mid-codeword still contributes what
// decoded, marked Truncated, with one gap why=malformed.
func TestDecodeErrorKeepsPrefix(t *testing.T) {
	var raw strings.Builder
	for i := 0; i < 4096; i++ {
		fmt.Fprintf(&raw, "payload %06d %s\n", i, strconv.FormatUint(uint64(i)*2654435761, 36))
	}
	full := gzipBytes(t, []byte(raw.String()))
	cut := full[:len(full)*3/4]
	ws := []wire{req(postRequest(reqBody)),
		respBytes(httpResponse("200 OK", []string{"Content-Encoding: gzip"}, cut))}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("a body's decode failure is its own gap, not a connection error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want the truncated response emitted, got %d messages", len(msgs))
	}
	if !msgs[1].Truncated {
		t.Error("response not marked Truncated")
	}
	if len(msgs[1].Body) == 0 {
		t.Error("decoded prefix was thrown away")
	}
	if !strings.HasPrefix(string(msgs[1].Body), "payload ") {
		t.Errorf("prefix = %q", clip(msgs[1].Body))
	}
	if !hasGap(gaps, GapMalformed) {
		t.Errorf("gaps = %v", gaps)
	}
}

// TestUnsupportedEncodingIsAGap covers a coding this build cannot decode: the bytes still reach the
// caller, the message is marked Truncated and the gap says so.
func TestUnsupportedEncodingIsAGap(t *testing.T) {
	ws := []wire{req(postRequest(reqBody)),
		respBytes(httpResponse("200 OK", []string{"Content-Encoding: exotic"}, []byte("raw")))}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(msgs) != 2 || string(msgs[1].Body) != "raw" {
		t.Fatalf("messages = %v", msgs)
	}
	if !hasGap(gaps, GapMalformed) {
		t.Errorf("gaps = %v", gaps)
	}
	if SupportedEncoding("exotic") {
		t.Error("SupportedEncoding lied about exotic")
	}
	for _, ok := range []string{"", "identity", "gzip", "deflate", "br", "zstd", "GZIP"} {
		if !SupportedEncoding(ok) {
			t.Errorf("SupportedEncoding(%q) = false", ok)
		}
	}
}

// TestBigBody covers the acceptance line "32 MB body handled": capture-derive.md R14 sets no total cap, so a body far past
// any chunk size reassembles whole.
func TestBigBody(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 32 MiB")
	}
	const size = 32 << 20
	payload := strings.Repeat("0123456789abcdef", size/16)
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(reqBody)), Seq: 1}); err != nil {
		t.Fatalf("request: %v", err)
	}
	head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(head), Seq: 2}); err != nil {
		t.Fatalf("response head: %v", err)
	}
	var msgs []*Message
	// One sequence for both directions (Chunk.Seq): the response head was 2.
	seq := uint32(2)
	for off := 0; off < size; off += 32 << 10 { // one R6-sized chunk at a time
		end := off + 32<<10
		if end > size {
			end = size
		}
		seq++
		got, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(payload[off:end]), Seq: seq})
		if err != nil {
			t.Fatalf("body chunk at %d: %v", off, err)
		}
		msgs = append(msgs, got...)
	}
	if len(msgs) != 1 || len(msgs[0].Body) != size || msgs[0].Truncated {
		t.Fatalf("want one whole %d-byte body, got %d messages", size, len(msgs))
	}
	if len(a.Gaps()) != 0 {
		t.Errorf("gaps = %v", a.Gaps())
	}
}

// TestMessageHelpers covers the small accessors every caller uses.
func TestMessageHelpers(t *testing.T) {
	m := &Message{Body: []byte("abc"), StartNS: 1_000_000, EndNS: 5_000_000, Header: http.Header{}}
	b, err := readAll(m.BodyReader(), 0)
	if err != nil || string(b) != "abc" {
		t.Fatalf("BodyReader = %q, %v", b, err)
	}
	if got := m.LatencyMS(); got != 4 {
		t.Errorf("LatencyMS = %d, want 4", got)
	}
	if got := (&Message{}).LatencyMS(); got != 0 {
		t.Errorf("LatencyMS of an unstamped message = %d", got)
	}
	if got := DirResponse.String(); got != "response" {
		t.Errorf("Direction.String = %q", got)
	}
	if got := (ConnKey{Src: record.SourceForwarder, ConnID: 7}).String(); got != "forwarder/7" {
		t.Errorf("forwarder key = %q", got)
	}
	if got := testKey.String(); !strings.HasPrefix(got, "ssl/") {
		t.Errorf("ssl key = %q", got)
	}
}

// TestMaxConns covers the connection-table bound: past it a new key is one gap, never unbounded growth.
func TestMaxConns(t *testing.T) {
	a := NewAssembler(Options{MaxConns: 2})
	for i := 0; i < 2; i++ {
		k := ConnKey{Src: record.SourceSSL, SSLPtr: uint64(i)}
		if _, err := a.Feed(k, DirRequest, Chunk{Data: []byte("GET / HTTP/1.1\r\n")}); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}
	k := ConnKey{Src: record.SourceSSL, SSLPtr: 99}
	if _, err := a.Feed(k, DirRequest, Chunk{Data: []byte("GET / HTTP/1.1\r\n")}); !errors.Is(err, ErrSizeCap) {
		t.Fatalf("third connection error = %v, want ErrSizeCap", err)
	}
	if !hasGap(a.Gaps(), GapSizeCap) {
		t.Errorf("gaps = %v", a.Gaps())
	}
}

// TestTimestamps checks that a message carries the first and last chunk's clocks (capture-derive.md E25 (edge case #25)).
func TestTimestamps(t *testing.T) {
	a := NewAssembler(Options{})
	ts := time.Unix(1700000000, 0).UTC()
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n"),
		Seq: 1, TS: ts, MonoNS: 1_000_000}); err != nil {
		t.Fatalf("head: %v", err)
	}
	msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("hi"), Seq: 2, TS: ts.Add(time.Second), MonoNS: 8_000_000})
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("messages = %d", len(msgs))
	}
	if !msgs[0].Start.Equal(ts) || msgs[0].StartNS != 1_000_000 || msgs[0].EndNS != 8_000_000 {
		t.Errorf("stamps = %v/%d..%d", msgs[0].Start, msgs[0].StartNS, msgs[0].EndNS)
	}
	if got := msgs[0].LatencyMS(); got != 7 {
		t.Errorf("LatencyMS = %d, want 7", got)
	}
}

// hasGap reports whether a gap with the given reason is present.
func hasGap(gaps []Gap, why string) bool {
	for _, g := range gaps {
		if g.Why == why && g.Count > 0 {
			return true
		}
	}
	return false
}
