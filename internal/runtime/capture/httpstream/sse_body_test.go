// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
)

// TestSSEBodyKeepsFraming checks the evidence that the provider parser needs, including empty named
// accounting events and event-only routing. Splitting CRLF or a field across capture chunks changes none.
func TestSSEBodyKeepsFraming(t *testing.T) {
	for _, body := range []string{
		"data:x",
		"data\ndata:a\ndata\ndata:b",
		"event: message_delta\ndata:\n\n",
		"event: message_start\ndata: {\"message\":{}}\n\n",
		"data: {\"a\":1,\r\ndata: \"b\":2}\r\n\r\n",
		"\xef\xbb\xbf: heartbeat\rretry: 100\rid: e\rx-proxy\revent: message_delta\rdata:\r\r",
		"",
	} {
		for _, split := range []int{0, 1, 3, 7} {
			msgs, gaps, err := run(t, Options{}, split, true, []wire{req(postRequest(reqBody)),
				resp(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: %d\r\n\r\n%s", len(body), body))})
			if err != nil || len(gaps) != 0 || len(msgs) != 2 {
				t.Fatalf("split %d body %q: messages=%d gaps=%v err=%v", split, body, len(msgs), gaps, err)
			}
			if !msgs[1].SSE || string(msgs[1].Body) != body {
				t.Fatalf("split %d body %q: SSE=%t body=%q", split, body, msgs[1].SSE, msgs[1].Body)
			}
		}
	}
}

// TestSSECompletionKeepsBudgetedBodyArray prevents a second full-body array or a per-line expansion at
// completion. The whole HTTP path, rather than a separate reducer, owns the same budgeted body array.
func TestSSECompletionKeepsBudgetedBodyArray(t *testing.T) {
	const n = 8 << 20
	for _, fill := range []string{"\n", "\r", "\r\n", ":\n", "data:\n", "event: message_delta\ndata:\n\n"} {
		t.Run(fmt.Sprintf("%q", fill), func(t *testing.T) {
			body := bytes.Repeat([]byte(fill), n/len(fill))
			a := NewAssembler(Options{})
			if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
				t.Fatal(err)
			}
			head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: %d\r\n\r\n", len(body))
			if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(head)}); err != nil {
				t.Fatal(err)
			}
			for off := 0; off < len(body)-1; {
				end := min(off+32<<10, len(body)-1)
				if _, err := a.Feed(testKey, DirResponse, Chunk{Data: body[off:end]}); err != nil {
					t.Fatal(err)
				}
				off = end
			}
			array := a.conns[testKey].halves[DirResponse].body
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			msgs, err := a.Feed(testKey, DirResponse, Chunk{Data: body[len(body)-1:]})
			runtime.ReadMemStats(&after)
			if err != nil || len(msgs) != 1 || !bytes.Equal(msgs[0].Body, body) {
				t.Fatalf("completion: messages=%d err=%v", len(msgs), err)
			}
			if &msgs[0].Body[0] != &array[0] {
				t.Error("completion replaced the already budgeted body array")
			}
			if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
				t.Errorf("completion allocated %d bytes for a %d-byte body", got, len(body))
			}
			if a.Budget().Used() != 0 {
				t.Errorf("completed body still reserves %d bytes", a.Budget().Used())
			}
		})
	}
}
