// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// fakeStamps is the build's tego_activity as ActivityStamps reads it: each slot's mono_ns, which the test writes.
type fakeStamps struct {
	mu     sync.Mutex
	vals   map[uint32]uint64
	err    error
	reads  []uint32
	closed bool
}

func (f *fakeStamps) Stamp(slot uint32) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, slot)
	if f.closed {
		return 0, errors.New("read after close")
	}
	if f.err != nil {
		return 0, f.err
	}
	return f.vals[slot], nil
}

func (f *fakeStamps) set(slot uint32, v uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vals[slot] = v
}

func (f *fakeStamps) failWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeStamps) readSlots() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint32(nil), f.reads...)
}

// TestLastActivityReadsTheRunsOwnSlot is limits R4's reader of the kernel stamp: LastActivity is the reading at the
// slot the run's own cgroup row names, and nothing before Start has found that slot or after Stop; a slot it cannot
// read answers 0, which the watcher takes for no activity, never an error that ends the run.
func TestLastActivityReadsTheRunsOwnSlot(t *testing.T) {
	f := newFixture(t)
	stamps := &fakeStamps{vals: map[uint32]uint64{3: 7_000_000_000, 9: 99_000_000_000}}
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3, 999: 9}}
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), Proc: f.procFS, FlushInterval: time.Hour, RunSet: rs,
		Stamps: stamps})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.LastActivity(); got != 0 {
		t.Fatalf("LastActivity before Start = %d, want 0: no slot is known yet", got)
	}
	if n := len(stamps.readSlots()); n != 0 {
		t.Fatalf("the stamps were read %d times before Start", n)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if got := r.LastActivity(); got != 7_000_000_000 {
		t.Fatalf("LastActivity = %d, want slot 3's 7000000000", got)
	}
	stamps.set(3, 8_000_000_000)
	if got := r.LastActivity(); got != 8_000_000_000 {
		t.Fatalf("LastActivity = %d after the stamp moved, want 8000000000", got)
	}
	stamps.failWith(errors.New("bad descriptor"))
	if got := r.LastActivity(); got != 0 {
		t.Fatalf("LastActivity = %d on a failed read, want 0", got)
	}
	for _, slot := range stamps.readSlots() {
		if slot != 3 {
			t.Fatalf("read slot %d: only the run's own slot 3 may be read", slot)
		}
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	stamps.failWith(nil)
	n := len(stamps.readSlots())
	if got := r.LastActivity(); got != 0 {
		t.Fatalf("LastActivity after Stop = %d, want 0", got)
	}
	if len(stamps.readSlots()) != n {
		t.Fatal("the stamps were read after Stop")
	}
}

// TestLastActivityIsNothingWithoutTheRunsRow: a recorder that could not find the run's row reads nothing, the stamp
// included, so a slot that is not the run's is never taken for its activity.
func TestLastActivityIsNothingWithoutTheRunsRow(t *testing.T) {
	f := newFixture(t)
	stamps := &fakeStamps{vals: map[uint32]uint64{0: 5_000_000_000, 3: 7_000_000_000}}
	rs := &fakeRunSet{rows: map[uint64]uint32{999: 3}}
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), Proc: f.procFS, FlushInterval: time.Hour, RunSet: rs,
		Stamps: stamps})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	if got := r.LastActivity(); got != 0 {
		t.Fatalf("an inert recorder's LastActivity = %d, want 0", got)
	}
	if n := len(stamps.readSlots()); n != 0 {
		t.Fatalf("an inert recorder read the stamps %d times", n)
	}
}

// TestLastActivityReadsTheSlotWhenTheRingCannotBeOpened: a recorder that found the run's row but cannot
// open its ring reads no record, which kernel-record-unavailable says, but the BPF programs still stamp the run's slot,
// and reading the stamp needs the slot alone. Were it 0 there, a busy record: off run at a root tier, which compile no
// longer warns of (stall-reads-unseen), would be ended as stalled while it worked.
func TestLastActivityReadsTheSlotWhenTheRingCannotBeOpened(t *testing.T) {
	f := newFixture(t)
	stamps := &fakeStamps{vals: map[uint32]uint64{3: 7_000_000_000}}
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3}}
	var asked []uint32
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), Proc: f.procFS, FlushInterval: time.Hour, RunSet: rs,
		Stamps: stamps, ringFault: func(slot uint32) error {
			asked = append(asked, slot)
			return errors.New("observe: the build holds no ring at this run's slot 3")
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != 3 {
		t.Fatalf("the ring was opened at slots %v, want [3]", asked)
	}
	if r.Reading() {
		t.Fatal("Reading = true for a recorder whose ring could not be opened")
	}
	if n := gapCount(r.Gaps())[runtime.GapKernelRecordUnavailable]; n != 1 {
		t.Fatalf("gaps %+v, want %s once", r.Gaps(), runtime.GapKernelRecordUnavailable)
	}
	if got := r.LastActivity(); got != 7_000_000_000 {
		t.Fatalf("LastActivity = %d with no ring, want slot 3's 7000000000", got)
	}
	for _, slot := range stamps.readSlots() {
		if slot != 3 {
			t.Fatalf("read slot %d: only the run's own slot 3 may be read", slot)
		}
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	n := len(stamps.readSlots())
	if got := r.LastActivity(); got != 0 {
		t.Fatalf("LastActivity after Stop = %d, want 0", got)
	}
	if len(stamps.readSlots()) != n {
		t.Fatal("the stamps were read after Stop")
	}
}

// TestLastActivityRacesStop: the watcher's goroutine pulls the stamp while the run stops its sources; a read is
// either the slot's or 0, and none happens once Stop has returned (run with -race).
func TestLastActivityRacesStop(t *testing.T) {
	f := newFixture(t)
	stamps := &fakeStamps{vals: map[uint32]uint64{3: 1}}
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3}}
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), Proc: f.procFS, FlushInterval: time.Hour, RunSet: rs,
		Stamps: stamps})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if v := r.LastActivity(); v != 0 && v != 1 {
				t.Errorf("LastActivity = %d", v)
				return
			}
		}
	}()
	time.Sleep(time.Millisecond)
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	stamps.mu.Lock()
	stamps.closed = true // a read from here on fails the fake, and is counted
	n := len(stamps.reads)
	stamps.mu.Unlock()
	time.Sleep(time.Millisecond)
	close(stop)
	wg.Wait()
	if got := len(stamps.readSlots()); got != n {
		t.Fatalf("%d reads of the stamps after Stop returned", got-n)
	}
}
