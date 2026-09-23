// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// BenchmarkFeed measures the budgeted path of §9: one 32 KiB chunk — R6's ceiling — through the state
// machine, which is what the overhead harness compares per tier and record mode.
func BenchmarkFeed(b *testing.B) {
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	chunk := []byte(strings.Repeat("x", 32<<10))
	// Calibration may feed more than 1 GiB. Keep one extra chunk outstanding so every timed Feed
	// stays in this response body, including the final operation, without completing the message.
	if int64(b.N) >= math.MaxInt64/int64(len(chunk)) {
		b.Fatal("benchmark body length exceeds int64")
	}
	head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", (int64(b.N)+1)*int64(len(chunk)))
	a := NewAssembler(Options{})
	if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		b.Fatal(err)
	}
	if _, err := a.Feed(key, DirResponse, Chunk{Data: []byte(head)}); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Feed(key, DirResponse, Chunk{Data: chunk}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFeedExchange measures a whole small request/response pair on a fresh connection: the shape a
// keep-alive agent session repeats thousands of times.
func BenchmarkFeedExchange(b *testing.B) {
	request := []byte(postRequest(reqBody))
	response := httpResponse("200 OK", []string{"Content-Type: application/json"}, []byte(respBody))
	a := NewAssembler(Options{})
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Feed(key, DirRequest, Chunk{Data: request}); err != nil {
			b.Fatal(err)
		}
		if _, err := a.Feed(key, DirResponse, Chunk{Data: response}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkChunked measures the chunked decoder, the framing every streamed model response uses.
func BenchmarkChunked(b *testing.B) {
	payload := strings.Repeat("y", 4096)
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(payload), payload)
	head := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	request := []byte(postRequest(reqBody))
	a := NewAssembler(Options{})
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Feed(key, DirRequest, Chunk{Data: request}); err != nil {
			b.Fatal(err)
		}
		if _, err := a.Feed(key, DirResponse, Chunk{Data: []byte(head + body)}); err != nil {
			b.Fatal(err)
		}
	}
}
