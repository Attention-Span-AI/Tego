// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"testing"
)

// FuzzFeedWithHoles is FuzzFeedBothHalves with a hole added to a chunk: a hole after its data
// (Chunk.Skipped, C2), a numbered sequence with numbers lost (Seq, C3), and a connection closed from outside
// (CloseWhere, C4). Whatever the bytes and wherever the holes fall, a response is handed over only paired with a
// request this connection handed over earlier, in request order (I3), and once everything is closed the budget
// holds nothing: no hole, gap or close leaks a body's reservation.
//
// Each plan byte is one chunk: bit 0 its direction, bits 1-4 its length less one, bits 5-6 the hole after it in
// sevens, and bit 7 a lost chunk before it (its number skipped) or, on every fifth, a close of the connection.
func FuzzFeedWithHoles(f *testing.F) {
	exchange := postRequest(`{"n":0}`) + "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nhi"
	f.Add([]byte(exchange), []byte{15 << 1, 15 << 1, 15 << 1, 1 | 15<<1 | 1<<5, 1 | 15<<1})
	f.Add([]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n"+
		"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl\r\n0\r\n\r\n"),
		[]byte{15 << 1, 15 << 1, 15<<1 | 3<<5, 15 << 1, 15 << 1})
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\nbodybodybody"+postRequest(`{}`)), []byte{1 | 15<<1, 1 | 3<<1, 15 << 1, 15 << 1})
	f.Fuzz(func(t *testing.T, data []byte, plan []byte) {
		a := NewAssembler(Options{MaxHeaderBytes: 4096, MaxHeaderLines: 32, MaxPipeline: 4, MaxBody: 1 << 16})
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
		if len(plan) == 0 {
			plan = []byte{3 << 1}
		}
		off := 0
		var seq uint32
		for i := 0; off < len(data); i++ {
			step := plan[i%len(plan)]
			seq++
			if step&0x80 != 0 {
				if i%5 == 4 {
					// A close from outside starts the key afresh: a later response pairs with the new
					// connection's requests, whose indexes start again from 0.
					_, msgs := a.CloseWhere(func(ConnKey) bool { return true })
					check(msgs)
					emitted, last, seq = map[int]bool{}, -1, 0
					continue
				}
				seq++ // a chunk lost to a full ring used this number
			}
			n := int(step>>1&0x0f) + 1
			end := min(off+n, len(data))
			msgs, _ := a.Feed(testKey, Direction(step&1), Chunk{Data: data[off:end], Seq: seq,
				Skipped: uint64(step>>5&0x03) * 7})
			check(msgs)
			off = end
		}
		check(a.CloseAll())
		if used := a.Budget().Used(); used != 0 {
			t.Fatalf("the budget holds %d bytes once every connection is closed", used)
		}
	})
}
