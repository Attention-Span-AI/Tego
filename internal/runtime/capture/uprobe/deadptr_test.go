// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// TestDeadPtrIsCountedAndRevivedBySeq1 covers edge case #11: an SSL* given up after its exchange split across
// threads counts each request passed over, and a count that starts afresh (Seq 1) on the thread it was last
// followed on is a new connection at a reused address whose SSL_free record was lost.
func TestDeadPtrIsCountedAndRevivedBySeq1(t *testing.T) {
	const ssl = 0x7900
	on := func(tid uint32, dir uint8, seq uint32, mono uint64, data string) []byte {
		return numbered(chunkRecord(41, 700, tid, ssl, dir, mono, []byte(data), false), seq)
	}
	records := [][]byte{
		on(701, bpf.SSLWrite, 1, 1_000_000, exchangeRequest),
		on(702, bpf.SSLRead, 1, 2_000_000, exchangeResponse), // the split: the pointer is given up
	}
	mono := uint64(3_000_000)
	for i := uint32(0); i < 3; i++ { // three exchanges on the dead pointer
		records = append(records,
			on(701, bpf.SSLWrite, 2+2*i, mono, exchangeRequest),
			on(701, bpf.SSLRead, 3+2*i, mono+1, exchangeResponse))
		mono += 2
	}
	records = append(records, // no SSL_free record: the address is reused, the kernel's count restarts
		on(701, bpf.SSLWrite, 1, mono, exchangeRequest),
		on(701, bpf.SSLRead, 2, mono+1, exchangeResponse))
	u, _ := newTestUprobe(t, records, Options{})
	sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	reqs, resps := countKinds(&sink.fakeSink)
	if reqs != 2 || resps != 1 {
		t.Errorf("requests %d responses %d, want the first request and the reused address's exchange", reqs, resps)
	}
	// One for the split and one for each of the three requests passed over.
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 4 {
		t.Errorf("malformed gaps = %d, want 4: %+v", got, u.Gaps())
	}
}
