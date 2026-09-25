// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	bin "encoding/binary"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// unreadRecord is the record the read return probe writes for a read it numbered but did not read: no bytes,
// what it knows of the call's length as skipped, and why as the hole (SSLHoleStale, edge case #3;
// SSLHoleEvicted, R5; SSLHoleNoLength, edge case #13). It is the head alone, the size the kernel reserves for it.
func unreadRecord(cgroup uint64, pid, tid uint32, ssl uint64, monoNS uint64, length uint64, seq uint32,
	hole uint8) []byte {
	rec := numbered(holeRecord(cgroup, pid, tid, ssl, bpf.SSLRead, monoNS, nil, false, length), seq)
	head := bpf.SSLRecordSizes[0]
	bin.NativeEndian.PutUint32(rec[4:8], uint32(head))
	rec[bpf.HeaderSize+14] = hole
	return rec[:head]
}

// TestUnreadReadIsAGapNotAMispairing is capture-derive.md E3 (edge case #3) and R5 at the source. A read whose return came more than
// bpf.SSLMaxCallNS after the entry probe its scratch row came from, or whose scratch row the LRU evicted before
// it returned, used to be dropped by the kernel with no number and no record, so the next response on a
// keep-alive connection paired with the request before its own (a 62 s first byte, under the old 60 s bound,
// paired request 1 with response 2). The kernel now numbers the read and emits it as a hole saying why; the
// source records the gap #3 and R5 promise, why=size-cap, gives up the request that lost its response, and
// pairs the connection's later exchanges with their own requests.
func TestUnreadReadIsAGapNotAMispairing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hole   uint8
		length uint64
	}{
		{"stale", bpf.SSLHoleStale, uint64(len(exchangeResponse))},
		{"evicted", bpf.SSLHoleEvicted, 0},
		{"no-length", bpf.SSLHoleNoLength, 0},
		{"unknown-kind", 0xee, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const ssl = 0x7100
			req := func(seq uint32, mono uint64) []byte {
				return numbered(chunkRecord(41, 710, 710, ssl, bpf.SSLWrite, mono, []byte(exchangeRequest), false), seq)
			}
			resp := func(seq uint32, mono uint64) []byte {
				return numbered(chunkRecord(41, 710, 710, ssl, bpf.SSLRead, mono, []byte(exchangeResponse), false), seq)
			}
			records := [][]byte{
				req(1, 1_000_000),
				unreadRecord(41, 710, 710, ssl, 400_000_000, tc.length, 2, tc.hole),
				req(3, 500_000_000),
				resp(4, 501_000_000),
				req(5, 900_000_000),
				resp(6, 902_000_000),
			}
			u, sink := newTestUprobe(t, records, Options{})
			runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
			lat := responseLatencies(t, sink)
			if len(lat) != 2 || lat[0] != 1 || lat[1] != 2 {
				t.Errorf("response latencies %v, want [1 2]: exchanges 2 and 3 paired with their own requests; "+
					"gaps %+v", lat, u.Gaps())
			}
			if got := gapCount(u.Gaps(), GapSizeCap); got != 1 {
				t.Errorf("size-cap = %d, want 1 for the unread read: %+v", got, u.Gaps())
			}
			if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 0 {
				t.Errorf("malformed = %d, want 0: the unread read is its size-cap gap, not a framing failure", got)
			}
		})
	}
}
