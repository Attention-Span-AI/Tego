// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// arrayRing is a fakeRing that remembers every array a read put a chunk into. Only the drain goroutine
// reads, and the test looks only once the drain has ended (runSource waits on u.done), so the set needs
// no lock of its own.
type arrayRing struct {
	fakeRing
	arrays map[*byte]bool
}

func (a *arrayRing) ReadInto(rec *ringbuf.Record) error {
	err := a.fakeRing.ReadInto(rec)
	if err == nil {
		a.arrays[unsafe.SliceData(rec.RawSample)] = true
	}
	return err
}

// TestDrainReadsIntoOneRecord: the drain reads every chunk into the one Record it keeps (RingReader), so a
// chunk costs no allocation for its read, and every chunk record is SSLEventSize bytes, so all of them land
// in one array. A request split over three chunks still arrives byte for byte, although each chunk's bytes
// are overwritten by the read after it: the reassembler copies them into the connection's buffer first. A
// drain that made a fresh Record per read would show one array per chunk here.
func TestDrainReadsIntoOneRecord(t *testing.T) {
	third := len(exchangeRequest) / 3
	parts := []string{exchangeRequest[:third], exchangeRequest[third : 2*third], exchangeRequest[2*third:]}
	var records [][]byte
	for i, p := range parts {
		records = append(records, chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, uint64(1_000_000+i), []byte(p), false))
	}
	records = append(records, chunkRecord(41, 100, 101, 0xabc, bpf.SSLRead, 9_000_000, []byte(exchangeResponse), false))
	ring := &arrayRing{fakeRing: fakeRing{records: records}, arrays: map[*byte]bool{}}
	blobs := &fakeBlobs{}
	u, err := New(Options{Reader: ring, Blobs: blobs, Rules: &agent.RuleTable{Record: agent.RecordFull}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sink := &fakeSink{}
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "retriever", CgroupID: 41})

	if len(ring.arrays) != 1 {
		t.Errorf("the drain's reads used %d arrays for %d chunks of one size, want 1", len(ring.arrays), len(records))
	}
	evs := sink.events()
	if len(evs) != 2 || evs[0].Kind != record.KindSSLRequest {
		t.Fatalf("events %d, want the request and the response", len(evs))
	}
	var req record.SSLRequestPayload
	if err := json.Unmarshal(evs[0].Payload, &req); err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Path != "/v1/messages" || req.Host != "api.anthropic.com" || req.Size != 17 {
		t.Errorf("request payload %+v: a chunk's bytes changed under the reassembler", req)
	}
	if len(blobs.put) == 0 || string(blobs.put[0]) != "{\"model\":\"opus\"}\n" {
		t.Errorf("stored body %q, want the request's own", blobs.put)
	}
}
