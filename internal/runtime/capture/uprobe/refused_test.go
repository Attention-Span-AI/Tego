// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// A connection the full table refused is one loss, not one per chunk: a chunk is not an exchange.
func TestRefusedConnectionIsReportedUnmeteredOnce(t *testing.T) {
	half := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 100\r\n\r\n"
	records := [][]byte{numbered(chunkRecord(41, 700, 701, 0x1000, bpf.SSLWrite, 1_000_000, []byte(half), false), 1)}
	for i := 1; i <= 20; i++ {
		records = append(records, numbered(chunkRecord(41, 700, 702, 0x2000, bpf.SSLWrite,
			uint64(2_000_000+i), []byte(exchangeRequest), false), uint32(i)))
	}
	u, _ := newTestUprobe(t, records, Options{Assembler: httpstream.NewAssembler(httpstream.Options{MaxConns: 1})})
	sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if got := sink.reported(); got != 1 {
		t.Errorf("reported %d exchanges unmetered (%q), want 1 for the one refused connection", got, sink.whys)
	}
}

// Forgetting followed pointers at the table's bound keeps the given-up ones dead.
func TestPtrTableClearKeepsDeadPointers(t *testing.T) {
	u, _ := newTestUprobe(t, nil, Options{})
	u.ptrs = map[ptrKey]ptrState{}
	dead := ptrKey{pid: 1, ssl: 0xdead}
	u.ptrs[dead] = ptrState{tid: 7, dead: true}
	for i := 0; len(u.ptrs) < maxTrackedPtrs; i++ {
		u.ptrs[ptrKey{pid: 2, ssl: uint64(i)}] = ptrState{tid: 1}
	}
	u.followPtr(httpstream.ConnKey{}, 3, 1, 0xbeef, 5, false)
	if st, ok := u.ptrs[dead]; !ok || !st.dead {
		t.Errorf("the dead pointer was forgotten by the clear: %+v, %v", st, ok)
	}
	if u.followPtr(httpstream.ConnKey{}, 1, 7, 0xdead, 5, false) {
		t.Error("a chunk of a given-up pointer was followed again")
	}
}
