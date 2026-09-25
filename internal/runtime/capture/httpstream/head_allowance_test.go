// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A full budget (bodies in flight on other connections) truncates bodies; it must not gap a keep-alive
// connection (Feed's error, which drops the connection) over a few bytes of a start line split across two
// feeds. Each half's first headAllowance bytes of buffer are uncharged.
func TestHeadSplitUnderFullBudget(t *testing.T) {
	a := NewAssembler(Options{MaxBody: 1 << 20, MaxBytes: 3 << 20})
	b := a.Budget()
	got := b.Take(b.Limit()) // other connections' bodies hold the whole budget
	defer b.Give(got)
	key := ConnKey{Src: record.SourceSSL, PidTgid: 7, SSLPtr: 1}
	if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte("POST /v1/messages HT")}); err != nil {
		t.Errorf("first half of a start line: %v", err)
	}
	msgs, err := a.Feed(key, DirRequest, Chunk{Data: []byte("TP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\n{}")})
	if err != nil {
		t.Errorf("rest: %v", err)
	}
	// The body the full budget cannot hold is cut, as any body is (R14); the head is whole.
	if len(msgs) != 1 || msgs[0].Method != "POST" || msgs[0].Path != "/v1/messages" || !msgs[0].Truncated {
		t.Errorf("got %+v, want the request, its body cut", msgs)
	}
}

// Past the head allowance a buffer is charged again: a header block that outgrows it under a full budget gaps
// why=size-cap, so the uncharged part stays at headAllowance per half.
func TestHeadPastTheAllowanceIsChargedUnderFullBudget(t *testing.T) {
	a := NewAssembler(Options{MaxBody: 1 << 20, MaxBytes: 3 << 20})
	b := a.Budget()
	got := b.Take(b.Limit())
	defer b.Give(got)
	key := ConnKey{Src: record.SourceSSL, PidTgid: 7, SSLPtr: 1}
	line := make([]byte, headAllowance+1)
	for i := range line {
		line[i] = 'a'
	}
	if _, err := a.Feed(key, DirRequest, Chunk{Data: append([]byte("POST / HTTP/1.1\r\nX-Pad: "), line...)}); err == nil {
		t.Fatal("a partial header past the head allowance was held with the budget in full use")
	}
}
