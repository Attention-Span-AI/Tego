// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	bin "encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// countKinds is how many ssl_request and ssl_response lines a sink holds.
func countKinds(sink *fakeSink) (reqs, resps int) {
	for _, ev := range sink.events() {
		switch ev.Kind {
		case record.KindSSLRequest:
			reqs++
		case record.KindSSLResponse:
			resps++
		}
	}
	return reqs, resps
}

// numbered sets a chunk record's seq, the number the kernel gives each chunk of a connection before its reserve.
func numbered(rec []byte, seq uint32) []byte {
	at := unsafe.Offsetof(bpf.SSLMeta{}.Seq)
	bin.NativeEndian.PutUint32(rec[at:at+4], seq)
	return rec
}

// responseLatencies is every ssl_response's latency_ms, in order.
func responseLatencies(t *testing.T, sink *fakeSink) []int64 {
	t.Helper()
	var out []int64
	for _, ev := range sink.events() {
		if ev.Kind != record.KindSSLResponse {
			continue
		}
		var p record.SSLResponsePayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p.LatencyMS)
	}
	return out
}

// TestLostChunkGapsTheConnection: a whole response lost to a full ring (the kernel counts it in its lost counter and
// nothing else) was invisible to the reassembler, because this source numbered chunks itself on arrival. The next
// response on the connection was paired with the request before its own — response 2, 1 ms after request 2, was
// recorded with latency_ms=500 as request 1's answer — and every later one after it. The kernel now numbers each
// chunk of a connection before its reserve, so the lost response leaves a hole the next chunk shows, and the
// connection gaps: a missing pair is explained, never a wrong one recorded.
func TestLostChunkGapsTheConnection(t *testing.T) {
	const ssl = 0x5100
	req := func(seq uint32, mono uint64) []byte {
		return numbered(chunkRecord(41, 700, 700, ssl, bpf.SSLWrite, mono, []byte(exchangeRequest), false), seq)
	}
	resp := func(seq uint32, mono uint64) []byte {
		return numbered(chunkRecord(41, 700, 700, ssl, bpf.SSLRead, mono, []byte(exchangeResponse), false), seq)
	}
	records := [][]byte{
		req(1, 1_000_000), // request 1 at 1 ms
		// response 1 at 2 ms, seq 2: its reserve failed, so it is not on the ring
		req(3, 500_000_000),  // request 2 at 500 ms
		resp(4, 501_000_000), // response 2 at 501 ms
		req(5, 900_000_000),  // request 3 at 900 ms
		resp(6, 901_000_000), // response 3 at 901 ms
	}
	u, sink := newTestUprobe(t, records, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	for i, ms := range responseLatencies(t, sink) {
		t.Errorf("ssl_response %d recorded with latency_ms=%d after a response of the connection was lost", i, ms)
	}
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got < 1 {
		t.Errorf("the lost response left no gap: %+v", u.Gaps())
	}
}

// TestCallOver128KiBKeepsTheConnection: at the source, one SSL_write larger than R6's 128 KiB (CPython's
// SSLSocket.sendall hands httpx's whole request to one SSL_write_ex; num=400061 was seen) is four 32 KiB chunks and a
// dropped tail. The kernel recorded the tail's length nowhere, so the request's Content-Length still counted it: the
// request never completed, its response became one with no request in flight, the connection was abandoned, and every
// later exchange on it was lost under one malformed count. The last chunk now says how many bytes it dropped, and all
// six exchanges are recorded, the first request as its truncated prefix (capture-derive.md E8 (edge case #8)).
func TestCallOver128KiBKeepsTheConnection(t *testing.T) {
	const ssl = 0x6100
	mono := uint64(1_000_000)
	next := func() uint64 { mono += 1_000_000; return mono }
	const bodyLen = 300 << 10
	head := fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\n\r\n", bodyLen)
	wire := []byte(head + `{"model":"opus","messages":[` + strings.Repeat(`{"role":"user","content":"x"},`, bodyLen/30))
	wire = wire[:len(head)+bodyLen]
	var records [][]byte
	for i := range bpf.SSLChunksMax { // what the kernel emits for the one call: four chunks, then the hole
		part := wire[i*bpf.SSLChunkMax : (i+1)*bpf.SSLChunkMax]
		var skipped uint64
		if i == bpf.SSLChunksMax-1 {
			skipped = uint64(len(wire) - bpf.SSLChunksMax*bpf.SSLChunkMax)
		}
		records = append(records, holeRecord(41, 703, 703, ssl, bpf.SSLWrite, next(), part, false, skipped))
	}
	records = append(records, chunkRecord(41, 703, 703, ssl, bpf.SSLRead, next(), []byte(exchangeResponse), false))
	for range 5 {
		records = append(records,
			chunkRecord(41, 703, 703, ssl, bpf.SSLWrite, next(), []byte(exchangeRequest), false),
			chunkRecord(41, 703, 703, ssl, bpf.SSLRead, next(), []byte(exchangeResponse), false))
	}
	blobs := &fakeBlobs{}
	u, sink := newTestUprobe(t, records, Options{Blobs: blobs})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	reqs, resps := countKinds(sink)
	if reqs != 6 || resps != 6 {
		t.Errorf("6 exchanges on the connection, %d requests and %d responses recorded; gaps %+v", reqs, resps, u.Gaps())
	}
	if len(blobs.put) == 0 || string(blobs.put[0]) != string(wire[len(head):bpf.SSLChunksMax*bpf.SSLChunkMax]) {
		t.Errorf("the first request's blob is not the prefix before the hole")
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v for a hole inside a body", gaps)
	}
}
