// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// seedBody is the body every encoded seed carries: a Messages API response, as a provider compresses one.
var seedBody = []byte(`{"id":"msg_01","type":"message","content":[{"type":"text","text":"the quick brown fox, the quick brown fox"}],"usage":{"input_tokens":12,"output_tokens":9}}`)

// seedCodings are the Content-Encoding values of the encoded seeds, each with how its body is made: every
// coding R15 undoes, "deflate" both as RFC 9110 defines it (zlib) and as some servers send it (raw), and a
// stacked list.
var seedCodings = []struct{ header, how string }{
	{"gzip", "gzip"}, {"deflate", "zlib"}, {"deflate", "flate"}, {"br", "br"}, {"zstd", "zstd"}, {"gzip, br", "gzip+br"},
}

// encodeSeed compresses b the way how names.
func encodeSeed(tb testing.TB, how string, b []byte) []byte {
	tb.Helper()
	if how == "gzip+br" {
		return encodeSeed(tb, "br", encodeSeed(tb, "gzip", b))
	}
	var out bytes.Buffer
	var w io.WriteCloser
	var err error
	switch how {
	case "gzip":
		w = gzip.NewWriter(&out)
	case "zlib":
		w = zlib.NewWriter(&out)
	case "flate":
		w, err = flate.NewWriter(&out, flate.BestCompression)
	case "br":
		w = brotli.NewWriter(&out)
	case "zstd":
		w, err = zstd.NewWriter(&out)
	default:
		tb.Fatalf("no encoder %q", how)
	}
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		tb.Fatal(err)
	}
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	return out.Bytes()
}

// encodedRequests are POSTs whose bodies are valid in each seed coding. FuzzFeed's other seeds reached the
// decoders only through a four-byte gzip header, and a response on its own never does: one that answers no
// request is passed over before its body is decoded (conn.complete). So the fuzzer began with no input that
// got past any decoder's first read; from these it mutates inside a real brotli, zstd
// or deflate stream.
func encodedRequests(tb testing.TB) []string {
	tb.Helper()
	var out []string
	for _, c := range seedCodings {
		b := encodeSeed(tb, c.how, seedBody)
		out = append(out, fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n"+
			"Content-Encoding: %s\r\nContent-Length: %d\r\n\r\n%s", c.header, len(b), b))
	}
	z := encodeSeed(tb, "zstd", seedBody)
	return append(out, fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nContent-Encoding: zstd\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"%x\r\n%s\r\n0\r\n\r\n", len(z), z))
}

// encodedExchanges are FuzzFeedBothHalves inputs: a request, then a response whose body is valid in each seed
// coding, with the plan that feeds the request whole on its half and then the response on the other.
func encodedExchanges(tb testing.TB) (data [][]byte, plans [][]byte) {
	tb.Helper()
	req := postRequest(`{"model":"claude-opus-5"}`)
	for _, c := range seedCodings {
		b := encodeSeed(tb, c.how, seedBody)
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: %s\r\nContent-Length: %d\r\n\r\n%s",
			c.header, len(b), b)
		data = append(data, []byte(req+resp))
		plans = append(plans, append(halfPlan(len(req), 0), halfPlan(len(resp), 1)...))
	}
	return data, plans
}

// halfPlan is the FuzzFeedBothHalves plan steps that feed n bytes to one half: step>>1+1 bytes each, at most
// 128 a step.
func halfPlan(n int, half byte) []byte {
	var plan []byte
	for ; n > 0; n -= 128 {
		plan = append(plan, byte(min(n, 128)-1)<<1|half)
	}
	return plan
}

// TestEncodedSeedsReachTheDecoders: every encoded seed comes out of the assembler as a message whose body is
// seedBody decoded whole, so the fuzzers start inside each decoder rather than at its refusal.
func TestEncodedSeedsReachTheDecoders(t *testing.T) {
	for _, s := range encodedRequests(t) {
		a := NewAssembler(Options{MaxHeaderBytes: 4096, MaxHeaderLines: 32, MaxPipeline: 4, MaxConns: 4})
		key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
		msgs, err := a.Feed(key, DirRequest, Chunk{Data: []byte(s), Seq: 1})
		if err != nil || len(msgs) != 1 || !bytes.Equal(msgs[0].Body, seedBody) || msgs[0].Truncated {
			t.Fatalf("request seed %.80q: %d messages, %v", s, len(msgs), err)
		}
	}
	data, plans := encodedExchanges(t)
	for i := range data {
		a := NewAssembler(Options{MaxHeaderBytes: 4096, MaxHeaderLines: 32, MaxPipeline: 4})
		var resp *Message
		off := 0
		for _, step := range plans[i] {
			end := off + int(step>>1) + 1
			msgs, err := a.Feed(testKey, Direction(step&1), Chunk{Data: data[i][off:end]})
			if err != nil {
				t.Fatalf("exchange seed %d: %v", i, err)
			}
			for _, m := range msgs {
				if m.Dir == DirResponse {
					resp = m
				}
			}
			off = end
		}
		if off != len(data[i]) || resp == nil || !bytes.Equal(resp.Body, seedBody) || resp.Truncated {
			t.Fatalf("exchange seed %d (%s): the response did not decode to the seed body", i, seedCodings[i].header)
		}
	}
}
