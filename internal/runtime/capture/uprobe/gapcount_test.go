// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// TestLostCounterIsDiffedFromStart: the build's lost counter is cumulative since its pins were made and shared by
// every run of the build, and the source diffed it from zero, so drops that happened before this run began, whether
// from earlier runs or from the kernel record before the recorder counted them, became this run's ring-buffer-drop. A
// run that lost nothing reported 500.
func TestLostCounterIsDiffedFromStart(t *testing.T) {
	lost := &fakeLost{value: 500}
	records := [][]byte{
		chunkRecord(41, 900, 900, 0x77, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
		chunkRecord(41, 900, 900, 0x77, bpf.SSLRead, 2_000_000, []byte(exchangeResponse), false),
	}
	u, sink := newTestUprobe(t, records, Options{Lost: lost})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if got := gapCount(u.Gaps(), GapRingBufferDrop); got != 0 {
		t.Errorf("ring-buffer-drop = %d for a run that lost nothing", got)
	}
}

// TestUnreadableBaselineCountsFromZero: a counter that cannot be read at Start leaves the baseline at zero,
// which may overstate the gap but never hides a drop of the run (I4).
func TestUnreadableBaselineCountsFromZero(t *testing.T) {
	lost := &fakeLost{err: errors.New("unreadable")}
	u, sink := newTestUprobe(t, nil, Options{Lost: lost})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	lost.mu.Lock()
	lost.value, lost.err = 4, nil
	lost.mu.Unlock()
	<-u.done
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := gapCount(u.Gaps(), GapRingBufferDrop); got != 4 {
		t.Errorf("ring-buffer-drop = %d, want the 4 drops counted from zero", got)
	}
}

// gapCount is the count this source reports for one reason, summed over the binaries it named.
func gapCount(gaps []source.Gap, why string) int64 {
	var n int64
	for _, g := range gaps {
		if g.Why == why {
			n += g.Count
		}
	}
	return n
}

// TestSizeCapCountsBothProducers pins the arithmetic behind R37's size-cap count. Two different things
// report under it with no binary to tell them apart: a ring-buffer record this build could not decode
// (R5's scratch-map eviction) and the reassembler's own R11/R13 bounds. They therefore land on one
// counter, and folding the reassembler's cumulative figure in by taking the larger of the two silently
// discards whichever producer counted less — a gap event undercounting what it explains, which is the
// half of I4 that "every missing pair is explained" rests on.
//
// Gaps() is called twice on purpose: the reassembler counts cumulatively, so a fold that adds rather than
// replaces has to remember what it already added or it doubles the count on the second call.
func TestSizeCapCountsBothProducers(t *testing.T) {
	// Two records this build cannot decode at all, and one connection whose header block is over the
	// line cap. Three size-cap occurrences, two producers.
	var hdr strings.Builder
	hdr.WriteString("POST /v1/messages HTTP/1.1\r\n")
	for i := 0; i < 8; i++ {
		hdr.WriteString("X-Pad: pad\r\n")
	}
	hdr.WriteString("\r\n")
	records := [][]byte{
		make([]byte, 12),
		make([]byte, 12),
		chunkRecord(41, 100, 101, 0xabc, bpf.SSLWrite, 1_000_000, []byte(hdr.String()), false),
	}
	asm := httpstream.NewAssembler(httpstream.Options{MaxHeaderLines: 2})
	u, sink := newTestUprobe(t, records, Options{Assembler: asm})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})

	if got := gapCount(u.Gaps(), GapSizeCap); got != 3 {
		t.Errorf("size-cap count = %d, want 3: two undecodable records and one header block over the cap", got)
	}
	if got := gapCount(u.Gaps(), GapSizeCap); got != 3 {
		t.Errorf("size-cap count = %d on a second Gaps call, want 3: the reassembler's cumulative count was folded in twice", got)
	}
}
