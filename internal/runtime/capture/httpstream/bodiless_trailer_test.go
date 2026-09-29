// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// A message with no body to decode (HEAD, 204, 304, Content-Length: 0, an empty chunked body) that carries a
// Content-Encoding is not malformed: gzip and brotli fail on empty input, and the connection must live on.
func TestEncodedBodilessMessageKeepsTheConnection(t *testing.T) {
	cases := []struct{ name, head, req string }{
		{"cl0", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", "POST /v1/x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"},
		{"204", "HTTP/1.1 204 No Content\r\n", "POST /v1/x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"},
		{"304", "HTTP/1.1 304 Not Modified\r\n", "GET /v1/x HTTP/1.1\r\nHost: h\r\n\r\n"},
		{"head", "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n", "HEAD /v1/x HTTP/1.1\r\nHost: h\r\n\r\n"},
	}
	for _, enc := range []string{"gzip", "x-gzip", "br", "zstd", "deflate"} {
		for _, c := range cases {
			t.Run(enc+"/"+c.name, func(t *testing.T) {
				ws := []wire{
					req(c.req),
					resp(c.head + "Content-Encoding: " + enc + "\r\n\r\n"),
					req("GET /v1/y HTTP/1.1\r\nHost: h\r\n\r\n"),
					respBytes(httpResponse("200 OK", nil, []byte(`{"ok":true}`))),
				}
				msgs, gaps, err := run(t, Options{}, 0, true, ws)
				if err != nil || len(gaps) != 0 {
					t.Fatalf("err=%v gaps=%v", err, gaps)
				}
				if len(msgs) != 4 {
					t.Fatalf("want 4 messages, got %d", len(msgs))
				}
			})
		}
	}
	t.Run("empty chunked body", func(t *testing.T) {
		ws := []wire{
			req("GET /v1/x HTTP/1.1\r\nHost: h\r\n\r\n"),
			resp("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
			req("GET /v1/y HTTP/1.1\r\nHost: h\r\n\r\n"),
			respBytes(httpResponse("200 OK", nil, []byte(`{}`))),
		}
		msgs, gaps, err := run(t, Options{}, 0, true, ws)
		if err != nil || len(gaps) != 0 || len(msgs) != 4 {
			t.Fatalf("msgs=%d err=%v gaps=%v", len(msgs), err, gaps)
		}
	})
}

// The trailer cap holds when the section reaches it exactly: a further complete line is over it.
func TestTrailerCapHoldsAtExactlyTheCap(t *testing.T) {
	line := "X-A: " + strings.Repeat("a", maxTrailerBytes-len("X-A: ")-2) + "\r\n"
	if len(line) != maxTrailerBytes {
		t.Fatalf("setup: line is %d bytes", len(line))
	}
	a := NewAssembler(Options{})
	feed := func(dir Direction, seq uint32, b []byte) error {
		_, err := a.Feed(testKey, dir, Chunk{Seq: seq, Data: b})
		return err
	}
	if err := feed(DirRequest, 1, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	head := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n" + line
	if err := feed(DirResponse, 2, []byte(head)); err != nil {
		t.Fatalf("a trailer exactly at the cap is within it: %v", err)
	}
	var err error
	for i := uint32(0); i < 4 && err == nil; i++ {
		err = feed(DirResponse, 3+i, bytes.Repeat([]byte("X-B: b\r\n"), 10))
	}
	if err == nil {
		t.Fatal("trailer lines past the cap were accepted")
	}
}

// A transfer coding before chunked is undone like a content coding rather than handed on compressed as the
// content; chunked not last is malformed (RFC 9112 §6.1).
func TestTransferCodingBeforeChunked(t *testing.T) {
	gz := gzipBytes(t, []byte(`{"hello":"world"}`))
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(gz), gz)
	ws := []wire{
		req("GET /v1/x HTTP/1.1\r\nHost: h\r\n\r\n"),
		resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" + body),
	}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil || len(gaps) != 0 || len(msgs) != 2 {
		t.Fatalf("msgs=%d err=%v gaps=%v", len(msgs), err, gaps)
	}
	if string(msgs[1].Body) != `{"hello":"world"}` {
		t.Errorf("body = %q, want the gunzipped content", msgs[1].Body)
	}
	_, _, err = run(t, Options{}, 0, true, []wire{
		req("GET /v1/x HTTP/1.1\r\nHost: h\r\n\r\n"),
		resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"),
	})
	if err == nil {
		t.Error("chunked, gzip was framed as chunked")
	}
}

// FuzzEncodedEmptyBody seeds the empty encoded body.
func FuzzEncodedEmptyBody(f *testing.F) {
	f.Add("gzip")
	f.Add("br")
	f.Fuzz(func(t *testing.T, enc string) {
		if strings.ContainsAny(enc, "\r\n") {
			return
		}
		d := decodeBudgeted(nil, enc, 1<<20, nil)
		_ = d
		c := &conn{opts: &Options{MaxBody: 1 << 20}}
		if _, err := c.decodeBody(nil, &Message{ContentEncoding: enc}); err != nil {
			t.Fatalf("empty body under %q: %v", enc, err)
		}
	})
}
