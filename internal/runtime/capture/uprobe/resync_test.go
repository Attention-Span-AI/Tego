// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// TestAResponseBeforeItsRequestCostsOneExchange is kill test 2's uprobe failure at the source: the probes
// were placed after the agent's first SSL_write and before its SSL_read (R4, capture-derive.md E2 (edge case #2)), so the ring's
// first chunk on the connection is a whole response, and the agent's 19 later exchanges on the same
// keep-alive connection are all there. They are 19 ssl_request/ssl_response pairs and the lost one is one
// gap what=capture why=malformed with count 1. Before, the response abandoned the connection: no pair at
// all and a gap whose count said one, the "0 of 20" of the acceptance run.
func TestAResponseBeforeItsRequestCostsOneExchange(t *testing.T) {
	const ssl = 0x17d81f20
	mono := uint64(1_000_000)
	next := func() uint64 { mono += 1_000_000; return mono }
	records := [][]byte{chunkRecord(41, 503, 503, ssl, bpf.SSLRead, next(), []byte(taggedResponse(0)), false)}
	for i := 1; i <= 19; i++ {
		records = append(records,
			chunkRecord(41, 503, 503, ssl, bpf.SSLWrite, next(), []byte(taggedRequest(i)), false),
			chunkRecord(41, 503, 503, ssl, bpf.SSLRead, next(), []byte(taggedResponse(i)), false))
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	// Counted and paired: a response shifted onto its neighbour's request leaves both counts at 19 (I3, R18).
	reqs, resps := checkPairs(t, sink)
	if reqs != 19 || resps != 19 {
		t.Fatalf("%d ssl_request and %d ssl_response, want the 19 exchanges after the lost one; gaps %v", reqs, resps, u.Gaps())
	}
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the one exchange whose request came before the probes: %v", got, u.Gaps())
	}
}

// TestARefusedRequestIsNotHeldPastItsTurn: a request R11 refused is still emitted, and its response is passed
// over by the reassembler on a connection it now keeps, so nothing answers it here. Once a later request's
// response arrives, responses being in request order, it never will be, and the source lets it go rather
// than holding it, body and all, for derive until Stop.
func TestARefusedRequestIsNotHeldPastItsTurn(t *testing.T) {
	const ssl = 0x5e1
	mono := uint64(1_000_000)
	rec := func(dir uint8, data string) []byte {
		mono += 1_000_000
		return chunkRecord(41, 600, 600, ssl, dir, mono, []byte(data), false)
	}
	var records [][]byte
	for i := 0; i < 9; i++ { // the ninth is past R11's depth of 8
		records = append(records, rec(bpf.SSLWrite, taggedRequest(i)))
	}
	for i := 0; i < 9; i++ {
		records = append(records, rec(bpf.SSLRead, taggedResponse(i)))
	}
	records = append(records, rec(bpf.SSLWrite, taggedRequest(9)), rec(bpf.SSLRead, taggedResponse(9)))
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	// The refused request's response is passed over, never taken by the tenth request (I3).
	_, resps := checkPairs(t, sink)
	if resps != 9 {
		t.Fatalf("%d ssl_response, want the eight queued exchanges and the tenth; gaps %v", resps, u.Gaps())
	}
	if n := len(u.pending); n != 0 {
		t.Errorf("%d connections still hold requests no response will answer: %v", n, u.pending)
	}
	if got := gapCount(u.Gaps(), GapSizeCap); got != 1 {
		t.Errorf("size-cap = %d, want 1 for the refused request: %v", got, u.Gaps())
	}
}

// TestARequestWhoseHeadCameBeforeTheProbesCostsOneExchange is the attach race on the write side: an httpx
// client writes a request's head and its body in two SSL_writes, and the probes landed between them (R4,
// edge case 2), so the connection's first chunk is a body with no request line. The exchange is one gap
// what=capture why=malformed with count 1, its response is not counted again, and the 19 exchanges after it
// are 19 ssl_request/ssl_response pairs. Before, the body was a malformed request line and the whole
// connection was lost.
func TestARequestWhoseHeadCameBeforeTheProbesCostsOneExchange(t *testing.T) {
	const ssl = 0x17d81f40
	mono := uint64(1_000_000)
	next := func() uint64 { mono += 1_000_000; return mono }
	records := [][]byte{
		chunkRecord(41, 504, 504, ssl, bpf.SSLWrite, next(), []byte("{\"model\":\"opus\"}\n"), false),
		chunkRecord(41, 504, 504, ssl, bpf.SSLRead, next(), []byte(taggedResponse(0)), false),
	}
	for i := 1; i <= 19; i++ {
		records = append(records,
			chunkRecord(41, 504, 504, ssl, bpf.SSLWrite, next(), []byte(taggedRequest(i)), false),
			chunkRecord(41, 504, 504, ssl, bpf.SSLRead, next(), []byte(taggedResponse(i)), false))
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	// Counted and paired: a response shifted onto its neighbour's request leaves both counts at 19 (I3, R18).
	reqs, resps := checkPairs(t, sink)
	if reqs != 19 || resps != 19 {
		t.Fatalf("%d ssl_request and %d ssl_response, want the 19 exchanges after the lost one; gaps %v", reqs, resps, u.Gaps())
	}
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the one exchange whose request head came before the probes: %v", got, u.Gaps())
	}
}
