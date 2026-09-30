// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A request R11 refused is emitted under a pair the source keeps, so its abandonment reaches
// derive.Steps: every ssl_request pair of a pipelined stream is answered or abandoned.
func TestRefusedRequestIsAbandonedUnderItsOwnPair(t *testing.T) {
	const ssl, n = 0x7d00, 10
	u, _ := newTestUprobe(t, [][]byte{
		chunkRecord(41, 970, 970, ssl, bpf.SSLWrite, 1_000_000, []byte(strings.Repeat(exchangeRequest, n)), false),
	}, Options{})
	sink := &abandonSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	<-u.done
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	reqs := 0
	for _, ev := range sink.events() {
		if ev.Kind != record.KindSSLRequest {
			continue
		}
		reqs++
		if !slices.Contains(sink.pairs, ev.Pair) {
			t.Errorf("ssl_request pair %d was never abandoned (abandoned: %v)", ev.Pair, sink.pairs)
		}
	}
	if reqs != n {
		t.Fatalf("%d ssl_request events, want %d", reqs, n)
	}
}

// followPtr's thread-split path gives up the current key's requests as it gives up the old key's: abandoned
// and reported, not dropped silently. The pointer table is cleared at maxTrackedPtrs, which is how a key
// holding a request comes to be the current one of a split.
func TestSplitAbandonsTheCurrentKeysRequests(t *testing.T) {
	const ssl = 0x7e00
	on := func(tid uint32, dir uint8, seq uint32, mono uint64, data string) []byte {
		return numbered(chunkRecord(41, 700, tid, ssl, dir, mono, []byte(data), false), seq)
	}
	records := [][]byte{on(701, bpf.SSLWrite, 1, 1_000_000, exchangeRequest)}
	for i := 0; i < maxTrackedPtrs+2; i++ { // fills ptrs past its bound: the next new pointer clears it
		records = append(records, chunkRecord(41, 700, 701, uint64(0x100000+i), bpf.SSLWrite,
			uint64(2_000_000+i), []byte("x"), false))
	}
	records = append(records,
		on(702, bpf.SSLRead, 1, 9_000_000, exchangeResponse), // a new entry {702} for the pointer
		on(701, bpf.SSLWrite, 2, 9_000_001, exchangeRequest)) // split: old=702, key=701 holds a request
	u, _ := newTestUprobe(t, records, Options{})
	sink := &abandonSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	<-u.done
	var first uint64
	for _, ev := range sink.events() {
		if ev.Kind == record.KindSSLRequest {
			first = ev.Pair
			break
		}
	}
	sink.umu.Lock()
	got := slices.Clone(sink.pairs)
	sink.umu.Unlock()
	if first == 0 || !slices.Contains(got, first) {
		t.Errorf("the request on the current key (pair %d) was dropped without being abandoned", first)
	}
	_ = u.Stop()
}

// A body the kernel cut is stored as its prefix, and its line says so: truncated, with the wire's length.
func TestCutBodyLineCarriesTruncatedAndWireSize(t *testing.T) {
	head := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 10\r\n\r\n"
	u, sink := newTestUprobe(t, [][]byte{
		holeRecord(41, 970, 970, 0x7f00, bpf.SSLWrite, 1_000_000, []byte(head+"ab"), false, 8),
	}, Options{Blobs: &fakeBlobs{}, Rules: &agent.RuleTable{Record: agent.RecordFull}})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	for _, ev := range sink.events() {
		if ev.Kind != record.KindSSLRequest {
			continue
		}
		var p record.SSLRequestPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if !p.Truncated || p.WireSize != 10 || p.Size != 2 {
			t.Errorf("truncated=%v wire_size=%d size=%d, want true, 10, 2", p.Truncated, p.WireSize, p.Size)
		}
		return
	}
	t.Fatal("no ssl_request recorded")
}
