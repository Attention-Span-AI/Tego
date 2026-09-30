// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// WireBytes is the body's length on the wire, so bytes the kernel dropped (Chunk.Skipped) count.
func TestWireBytesCountsBytesSteppedOverAsAHole(t *testing.T) {
	a := NewAssembler(Options{})
	head := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 10\r\n\r\n"
	msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(head + "ab"), Skipped: 8})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("feed: %v, %d messages", err, len(msgs))
	}
	if !msgs[0].Truncated || msgs[0].WireBytes != 10 {
		t.Errorf("truncated=%v WireBytes=%d, want a cut body of 10 wire bytes", msgs[0].Truncated, msgs[0].WireBytes)
	}
}

// A refused connection is one gap, however many chunks it sends.
func TestFullTableGapIsCountedOncePerRefusedKey(t *testing.T) {
	a := NewAssembler(Options{MaxConns: 1})
	busy := ConnKey{Src: record.SourceSSL, SSLPtr: 1}
	if _, err := a.Feed(busy, DirRequest, Chunk{Data: []byte("GET / HTTP/1.1\r\n")}); err != nil {
		t.Fatal(err)
	}
	other := ConnKey{Src: record.SourceSSL, SSLPtr: 2}
	for i := 0; i < 5; i++ {
		if _, err := a.Feed(other, DirResponse, Chunk{Data: []byte("HTTP/1.1 200 OK\r\n")}); !errors.Is(err, ErrSizeCap) {
			t.Fatalf("chunk %d: %v, want ErrSizeCap", i, err)
		}
	}
	for _, g := range a.Gaps() {
		if g.Why == GapSizeCap && g.Count != 1 {
			t.Errorf("size-cap count = %d for one refused connection, want 1", g.Count)
		}
	}
}
