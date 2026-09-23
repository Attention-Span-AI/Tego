// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// FuzzFeed drives the whole reassembler over network-controlled bytes: the start line, the header block,
// both body framings and the content-coding decoders (P0-DESIGN §7, §9 "every reader of network-controlled
// bytes gets one").
//
// The property is R18's: no input panics, and whatever comes back is either a message or a gap — never a
// message the assembler cannot describe. The corpus is seeded from the golden conversations, which is why
// the malformed table above doubles as the seed list.
func FuzzFeed(f *testing.F) {
	seeds := []string{
		postRequest(reqBody),
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: {}\n\n: ping\n\n",
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\n\x1f\x8b\x08\x00",
		h2Preface,
		"GET / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
		"GET / HTTP/1.1\r\n  folded\r\n\r\n",
		"\r\n\r\n\r\n",
		"",
	}
	seeds = append(seeds, encodedRequests(f)...)
	for _, s := range seeds {
		f.Add([]byte(s), uint8(0), uint8(7))
		f.Add([]byte(s), uint8(1), uint8(3))
	}
	f.Fuzz(func(t *testing.T, data []byte, dir uint8, split uint8) {
		a := NewAssembler(Options{MaxHeaderBytes: 4096, MaxHeaderLines: 32, MaxPipeline: 4, MaxConns: 4})
		key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
		d := Direction(dir % 2)
		n := int(split) + 1
		var seq uint32
		for off := 0; off < len(data); off += n {
			end := off + n
			if end > len(data) {
				end = len(data)
			}
			seq++
			msgs, err := a.Feed(key, d, Chunk{Data: data[off:end], Seq: seq})
			if err != nil && whyFor(err) == "" {
				t.Fatalf("error with no gap reason: %v", err)
			}
			for _, m := range msgs {
				checkMessageInvariants(t, m)
			}
		}
		for _, m := range a.CloseAll() {
			checkMessageInvariants(t, m)
		}
		for _, g := range a.Gaps() {
			switch g.Why {
			case GapH2, GapMalformed, GapSizeCap:
			default:
				t.Fatalf("gap reason %q is outside the closed set of R37", g.Why)
			}
		}
	})
}

// checkMessageInvariants asserts what every emitted Message must satisfy whatever the input was.
func checkMessageInvariants(t *testing.T, m *Message) {
	t.Helper()
	if m == nil {
		t.Fatal("nil message")
	}
	if m.Header == nil {
		t.Fatal("message with no header map")
	}
	if m.Dir == DirRequest {
		if m.Method == "" || m.Path == "" {
			t.Fatalf("request with no method or target: %+v", m)
		}
		if m.RequestIndex != -1 {
			t.Fatalf("request paired with a request: %+v", m)
		}
		return
	}
	if m.Status < 200 || m.Status > 599 {
		t.Fatalf("response emitted with status %d (interim responses are never emitted)", m.Status)
	}
	if m.RequestIndex < 0 {
		t.Fatalf("response with no request (I3): %+v", m)
	}
}

// FuzzSSEBodyPreserved verifies that HTTP chunk boundaries do not change the decoded event stream (R16).
// Provider framing and accounting validation need the original event names and empty data fields.
func FuzzSSEBodyPreserved(f *testing.F) {
	f.Add([]byte("data: {\"a\":1}\n\n: ping\n\nretry: 100\n\ndata: x\ndata: y\n\n"), uint16(7))
	f.Add([]byte("event: message_delta\ndata:\n\n"), uint16(1))
	f.Add([]byte("data"), uint16(3))
	f.Add([]byte(":\r\n\r"), uint16(2))
	f.Add([]byte(""), uint16(0))
	f.Fuzz(func(t *testing.T, b []byte, split uint16) {
		a := NewAssembler(Options{})
		if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
			t.Fatal(err)
		}
		head := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: %d\r\n\r\n", len(b)))
		msgs, err := a.Feed(testKey, DirResponse, Chunk{Data: head})
		if err != nil {
			t.Fatal(err)
		}
		cut := min(int(split), len(b))
		for _, part := range [][]byte{b[:cut], b[cut:]} {
			got, err := a.Feed(testKey, DirResponse, Chunk{Data: part})
			if err != nil {
				t.Fatal(err)
			}
			msgs = append(msgs, got...)
		}
		if len(msgs) != 1 || !msgs[0].SSE {
			t.Fatalf("SSE response: messages=%d", len(msgs))
		}
		if !msgs[0].Truncated && !bytes.Equal(msgs[0].Body, b) {
			t.Fatalf("HTTP reassembly changed the SSE body (%d bytes to %d)", len(b), len(msgs[0].Body))
		}
	})
}

// FuzzParseStartLine fuzzes the two start-line parsers, the first thing a traced process's bytes reach.
func FuzzParseStartLine(f *testing.F) {
	f.Add("POST /v1/messages HTTP/1.1")
	f.Add("HTTP/1.1 200 OK")
	f.Add("GET / HTTP/2.0")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if rl, err := parseRequestLine([]byte(s)); err == nil && rl.Method == "" {
			t.Fatalf("parsed %q into an empty method", s)
		}
		if sl, err := parseStatusLine([]byte(s)); err == nil && (sl.Status < 100 || sl.Status > 599) {
			t.Fatalf("parsed %q into status %d", s, sl.Status)
		}
	})
}

// FuzzFeedBothHalves drives both halves of one connection in an order the input chooses, which is where
// passing over a response with no request or a request with no head (R18) could pair a response with a
// request it did not answer. Whatever the bytes, a response is only ever handed over paired with a request
// this connection handed over earlier, and in the order the requests came (RFC 9112 §9.3, I3): never with
// one twice, never out of order, never with one it never emitted.
func FuzzFeedBothHalves(f *testing.F) {
	exchange := postRequest(`{"n":0}`) + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
	f.Add([]byte(exchange), []byte{byte(len(postRequest(`{"n":0}`))) << 1, 1 | 40<<1})
	f.Add([]byte(`{"model":"opus"}`+"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), []byte{16 << 1, 1 | 60<<1})
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nGET / HTTP/1.1\r\n\r\nHTTP/1.1 201 Created\r\n\r\n"),
		[]byte{1 | 38<<1, 18 << 1, 1 | 30<<1})
	data, plans := encodedExchanges(f)
	for i := range data {
		f.Add(data[i], plans[i])
	}
	f.Fuzz(func(t *testing.T, data []byte, plan []byte) {
		a := NewAssembler(Options{MaxHeaderBytes: 4096, MaxHeaderLines: 32, MaxPipeline: 4})
		emitted := map[int]bool{}
		last := -1
		check := func(msgs []*Message) {
			for _, m := range msgs {
				checkMessageInvariants(t, m)
				if m.Dir == DirRequest {
					emitted[m.Index] = true
					continue
				}
				if !emitted[m.RequestIndex] {
					t.Fatalf("response paired with request %d, which was never handed over", m.RequestIndex)
				}
				if m.RequestIndex <= last {
					t.Fatalf("response paired with request %d after one paired with %d", m.RequestIndex, last)
				}
				last = m.RequestIndex
			}
		}
		off := 0
		for i := 0; off < len(data); i++ {
			step := byte(2) // with no plan, two bytes at a time on the request half
			if len(plan) > 0 {
				step = plan[i%len(plan)]
			}
			n := int(step>>1) + 1
			end := min(off+n, len(data))
			msgs, _ := a.Feed(testKey, Direction(step&1), Chunk{Data: data[off:end]})
			check(msgs)
			off = end
		}
		check(a.CloseAll())
	})
}
