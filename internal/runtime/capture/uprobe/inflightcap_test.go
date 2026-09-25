// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestInFlightPastTheScratchMapSizeGapsAndNeverMispairs is capture-derive.md R5 at the reader. The kernel's
// scratch map holds 8192 in-flight (pid_tgid, ssl_ptr) rows, and every userspace table the source keys the
// same way is sized to match it (the reassembler's 4096 connections, maxTrackedPtrs and maxConnHosts, 8192
// each). The LRU eviction itself is the kernel's and is exercised only at root; what this drives is the reader
// under the same burst: 8192+512 connections, each with its request in flight, then every response. Past
// what the tables hold, capture must lose exchanges visibly (gap why=size-cap) and must never pair a response
// with another connection's request: each response names its connection (Request-Id: req_<i>) and each
// request its own (?i=<i>), and every ssl_response is checked against the ssl_request its pair token names.
func TestInFlightPastTheScratchMapSizeGapsAndNeverMispairs(t *testing.T) {
	const n = 8192 + 512
	records := make([][]byte, 0, 2*n)
	for i := range n {
		req := "POST /v1/messages?i=" + strconv.Itoa(i) + " HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
			"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
		records = append(records, numbered(chunkRecord(41, 900, 900, 0x10000+uint64(i)*0x40, bpf.SSLWrite,
			uint64(1_000_000+i), []byte(req), false), 1))
	}
	for i := range n {
		resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nRequest-Id: req_" + strconv.Itoa(i) +
			"\r\nContent-Length: 2\r\n\r\n{}"
		records = append(records, numbered(chunkRecord(41, 900, 900, 0x10000+uint64(i)*0x40, bpf.SSLRead,
			uint64(900_000_000+i), []byte(resp), false), 2))
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	reqOf := map[uint64]string{} // pair token -> the connection index the request named
	var resps []*record.Event
	for _, ev := range sink.events() {
		switch ev.Kind {
		case record.KindSSLRequest:
			var p record.SSLRequestPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			q, err := url.Parse(p.Path)
			if err != nil {
				t.Fatal(err)
			}
			reqOf[ev.Pair] = q.Query().Get("i")
		case record.KindSSLResponse:
			resps = append(resps, ev)
		}
	}
	for _, ev := range resps {
		var p record.SSLResponsePayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		i, ok := reqOf[ev.Pair]
		if !ok {
			t.Errorf("ssl_response %s pairs with no recorded request", p.RequestID)
			continue
		}
		if want := "req_" + i; p.RequestID != want {
			t.Errorf("connection %s's request paired with response %s (R5: a wrong pairing)", i, p.RequestID)
		}
	}
	lost := n - len(resps)
	if len(resps) == 0 {
		t.Fatal("no exchange was recorded at all")
	}
	if lost == 0 {
		t.Fatalf("all %d in-flight exchanges were recorded; the test no longer exceeds the tables", n)
	}
	if got := gapCount(u.Gaps(), GapSizeCap); got < int64(lost) {
		t.Errorf("%d exchanges lost past the tables, but size-cap counts %d: a loss without its gap (R5, I4)",
			lost, got)
	}
	t.Logf("%d of %d exchanges recorded, size-cap %d", len(resps), n, gapCount(u.Gaps(), GapSizeCap))
}

// TestAnEvictedSeqRowMidResponseNeverPairsTheRest is the other LRU of R5's key, tego_ssl_seq (capture-derive.md
// I2): a row evicted while its connection is live restarts the count at 1 mid-response. The reader takes the
// restart as a new connection, so the rest of response 1 is passed over rather than read as the answer to the
// next request, and request 2's own response pairs with it.
func TestAnEvictedSeqRowMidResponseNeverPairsTheRest(t *testing.T) {
	const ssl = 0x7700
	resp1 := taggedResponse(1)
	cut := len(resp1) - 10
	rec := func(dir uint8, mono uint64, data string, seq uint32) []byte {
		return numbered(chunkRecord(41, 710, 710, ssl, dir, mono, []byte(data), false), seq)
	}
	records := [][]byte{
		rec(bpf.SSLWrite, 1_000_000, taggedRequest(1), 1),
		rec(bpf.SSLRead, 2_000_000, resp1[:cut], 2),
		// tego_ssl_seq evicted the row: the count restarts on the same live connection
		rec(bpf.SSLRead, 3_000_000, resp1[cut:], 1),
		rec(bpf.SSLWrite, 4_000_000, taggedRequest(2), 2),
		rec(bpf.SSLRead, 5_000_000, taggedResponse(2), 3),
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	// Response 1's head may still be recorded against request 1 as the old connection ends; what must not
	// happen is its tail, or request 2's answer, pairing with the other request (checkPairs), or the cut
	// going unexplained.
	reqs, resps := checkPairs(t, sink)
	if reqs != 2 || resps < 1 {
		t.Errorf("%d ssl_request and %d ssl_response, want both requests and request 2's answer; gaps %v",
			reqs, resps, u.Gaps())
	}
	if gapCount(u.Gaps(), httpstream.GapMalformed) < 1 {
		t.Errorf("the restarted count left no gap: %v", u.Gaps())
	}
}
