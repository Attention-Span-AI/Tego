// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// arrayRing is a fakeRing that remembers every array a read put a sample into.
type arrayRing struct {
	*fakeRing
	mu     sync.Mutex
	arrays map[*byte]bool
}

func (a *arrayRing) ReadInto(rec *ringbuf.Record) error {
	err := a.fakeRing.ReadInto(rec)
	if err == nil {
		a.mu.Lock()
		a.arrays[unsafe.SliceData(rec.RawSample)] = true
		a.mu.Unlock()
	}
	return err
}

// TestDrainReadsIntoOneRecord: the drain reads every sample into the one Record it keeps (RingReader), so a
// sample costs no allocation for its read. Open records are all one struct's size, so every read of them
// lands in one array; a drain that made a fresh Record per read would show one array per sample.
func TestDrainReadsIntoOneRecord(t *testing.T) {
	f := newFixture(t)
	open := sample{Kind: KindOpen, MonoNS: 1000, CgroupID: 77, PID: 50, TID: 50, PPID: 1}
	var samples [][]byte
	for i := range 5 {
		s := open
		s.MonoNS += uint64(i)
		samples = append(samples, fsSample(s, 0o1, 3, 2049, filepath.Join(f.out, "report.md"), ""))
	}
	ring := &arrayRing{fakeRing: newFakeRing(samples...), arrays: map[*byte]bool{}}
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-host-1", Agent: "retriever"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		ring.fakeRing.mu.Lock()
		defer ring.fakeRing.mu.Unlock()
		return len(ring.samples) == 0
	}, "samples were never drained")
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if len(ring.arrays) != 1 {
		t.Errorf("the drain's reads used %d arrays for %d samples of one size, want 1", len(ring.arrays), len(samples))
	}
}
