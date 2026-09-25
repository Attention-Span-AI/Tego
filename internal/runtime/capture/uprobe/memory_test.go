// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// lazyRing hands out total records, each built by gen when it is read, so a test can put hundreds of MiB
// through the drain without holding them all at once.
type lazyRing struct {
	total, i int
	gen      func(int) []byte
}

func (r *lazyRing) ReadInto(rec *ringbuf.Record) error {
	if r.i >= r.total {
		return ringbuf.ErrClosed
	}
	rec.RawSample = append(rec.RawSample[:0], r.gen(r.i)...)
	r.i++
	return nil
}
func (r *lazyRing) SetDeadline(time.Time) {}
func (r *lazyRing) Close() error          { return nil }

// nopDeriver derives nothing; a source with a Deriver keeps each request's body until its response.
type nopDeriver struct{}

func (nopDeriver) Handle(*derive.Message, *derive.Message, derive.Meta) (derive.Result, error) {
	return derive.Result{}, nil
}

// TestBodiesHeldAreBudgeted: at the source, 64 connections, each sending a 4 MiB request that is
// either never answered (its body kept for derive until Stop) or never finished (its body in flight in the
// reassembler). Before the budget, the first held 64 × 4 MiB of launcher heap and the second pinned the same in
// the connections' arrays; the review measured 1.5 GiB for 24 connections of 48 MiB. Both now stay inside the
// one budget the reassembler and the source share, and what did not fit is counted as gap why=size-cap.
func TestBodiesHeldAreBudgeted(t *testing.T) {
	const (
		conns   = 64
		bodyLen = 4<<20 - 4096
		maxBody = 4 << 20
		limit   = 16 << 20
		per     = 30 << 10
	)
	for _, tc := range []struct {
		name     string
		unfinish bool
	}{{"unanswered", false}, {"unfinished", true}} {
		t.Run(tc.name, func(t *testing.T) {
			sent := bodyLen
			if tc.unfinish {
				sent--
			}
			chunks := 1 + (sent+per-1)/per
			gen := func(i int) []byte {
				c, k := i/chunks, i%chunks
				ssl, mono := uint64(0x9000+c), uint64(i+1)*1000
				if k == 0 {
					head := fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: %d\r\n\r\n", bodyLen)
					return chunkRecord(41, 800, 800, ssl, bpf.SSLWrite, mono, []byte(head), false)
				}
				n := min(per, sent-(k-1)*per)
				return chunkRecord(41, 800, 800, ssl, bpf.SSLWrite, mono, make([]byte, n), false)
			}
			asm := httpstream.NewAssembler(httpstream.Options{MaxBody: maxBody, MaxBytes: limit})
			u, err := New(Options{Reader: &lazyRing{total: conns * chunks, gen: gen}, Assembler: asm, Deriver: nopDeriver{}})
			if err != nil {
				t.Fatal(err)
			}
			sink := &fakeSink{}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			if err := u.Start(t.Context(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
				t.Fatal(err)
			}
			<-u.done
			sink.mu.Lock()
			sink.evs = nil // the events are the ledger's, not what capture holds
			sink.mu.Unlock()
			runtime.GC()
			runtime.ReadMemStats(&after)
			grew := int64(after.HeapInuse) - int64(before.HeapInuse)
			used := asm.Budget().Used()
			t.Logf("heap in use grew %d MiB, budget holds %d MiB of %d", grew>>20, used>>20, int64(limit)>>20)
			if used > limit {
				t.Errorf("the budget holds %d bytes, over its %d limit", used, limit)
			}
			if grew > 3*limit {
				t.Errorf("%d connections holding %d-byte bodies grew the heap by %d MiB against a %d MiB budget",
					conns, bodyLen, grew>>20, int64(limit)>>20)
			}
			if gapCount(u.Gaps(), GapSizeCap) == 0 {
				t.Errorf("bodies the budget could not hold left no gap why=size-cap: %+v", u.Gaps())
			}
			_ = u.Stop()
			if used := asm.Budget().Used(); used != 0 {
				t.Errorf("the budget still holds %d bytes after Stop", used)
			}
		})
	}
}
