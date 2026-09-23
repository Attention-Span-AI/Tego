// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeRunSet is a build's run set under test control: rows maps a cgroup to its slot, gens to its row's
// generation (0 when absent).
type fakeRunSet struct {
	mu      sync.Mutex
	rows    map[uint64]uint32
	gens    map[uint64]uint32
	lookErr error
}

func (f *fakeRunSet) Slot(cg uint64) (uint32, uint32, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookErr != nil {
		return 0, 0, false, f.lookErr
	}
	s, ok := f.rows[cg]
	return s, f.gens[cg], ok, nil
}

// hasWhy reports whether a gap report holds a reason, whatever its count.
func hasWhy(gaps []source.Gap, why string) bool {
	for _, g := range gaps {
		if g.Why == why {
			return true
		}
	}
	return false
}

// twoRunsSamples is one process of this run (cgroup 41, slot 3) and one stamped with another run's slot (cgroup
// 999, slot 9) interleaved on one ring: each execs, opens a libssl and exits.
func twoRunsSamples() [][]byte {
	mine := sample{MonoNS: 1000, CgroupID: 41, PID: 50, TID: 50, PPID: 1, RunIdx: 3}
	theirs := sample{MonoNS: 1001, CgroupID: 999, PID: 60, TID: 60, PPID: 1, RunIdx: 9}
	open := func(s sample) sample { s.Kind, s.MonoNS = KindOpen, s.MonoNS+100; return s }
	exit := func(s sample) sample { s.Kind, s.MonoNS = KindExit, s.MonoNS+200; return s }
	return [][]byte{
		execSample(theirs, 1, "curl", "/usr/bin/curl", []string{"curl", "https://example.com"}, false),
		execSample(mine, 1, "python3", "/usr/bin/python3.12", []string{"python3", "app.py"}, false),
		fsSample(open(theirs), 0, 1, 2049, "/usr/lib/x86_64-linux-gnu/libssl.so.3", ""),
		fsSample(open(mine), 0, 2, 2049, "/usr/lib/x86_64-linux-gnu/libssl.so.3", ""),
		exitSample(exit(theirs), 0, 0),
		exitSample(exit(mine), 0, 0),
	}
}

// startScoped runs a recorder over samples with a run set, as run r-A in cgroup 41, and stops it once the
// ring is drained.
func startScoped(t *testing.T, rs RunSet, hook source.ProcessHook, samples ...[]byte) (*Recorder, *fakeSink) {
	t.Helper()
	f := newFixture(t)
	ring := newFakeRing(samples...)
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour, RunSet: rs})
	if err != nil {
		t.Fatal(err)
	}
	if hook != nil {
		if err := r.AddProcessHook(hook); err != nil {
			t.Fatal(err)
		}
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, func() bool {
		ring.mu.Lock()
		defer ring.mu.Unlock()
		return len(ring.samples) == 0
	}, "the ring was never drained")
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	return r, sink
}

// TestRecorderKeepsToItsOwnRun: a run's ring is its own (ADR 0026 (1)), so a sample stamped with another run's
// slot should never be on it; were one there, it is neither recorded as this run's nor handed to a hook, so the
// uprobe source never attaches another run's libssl, and this run's own record is whole.
func TestRecorderKeepsToItsOwnRun(t *testing.T) {
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3, 999: 9}}
	hook := &hookLog{}
	r, sink := startScoped(t, rs, hook, twoRunsSamples()...)

	want := []string{"exec 50 41 /usr/bin/python3.12", "open 50 41 /usr/lib/x86_64-linux-gnu/libssl.so.3", "exit 50"}
	if got := hook.all(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("hook calls %q, want this run's process alone %q", got, want)
	}
	for _, ev := range sink.all() {
		if ev.Cgroup != 41 || ev.PID != 50 {
			t.Errorf("run r-A recorded %s from pid %d cgroup %d, which is another run's", ev.Kind, ev.PID, ev.Cgroup)
		}
	}
	if len(sink.byKind(record.KindExec)) != 1 {
		t.Errorf("%d exec events, want this run's one", len(sink.byKind(record.KindExec)))
	}
	if gaps := r.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v for a run that read its own ring whole", gaps)
	}
}

// TestRecorderDropsTheSlotsPreviousRun: a slot's rings are reused by its next run (ADR 0026 (6) as amended), so
// a record the previous run of the slot left in the ring, stamped with that run's slot and its generation, may
// be there when this run starts reading. It is not this run's: only a record of this run's own generation is
// recorded or handed to a hook.
func TestRecorderDropsTheSlotsPreviousRun(t *testing.T) {
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3}, gens: map[uint64]uint32{41: 7002}}
	hook := &hookLog{}
	prev := sample{MonoNS: 900, CgroupID: 40, PID: 60, TID: 60, PPID: 1, RunIdx: 3, Gen: 7001}
	mine := sample{MonoNS: 1000, CgroupID: 41, PID: 50, TID: 50, PPID: 1, RunIdx: 3, Gen: 7002}
	open := func(s sample) sample { s.Kind, s.MonoNS = KindOpen, s.MonoNS+100; return s }
	exit := func(s sample) sample { s.Kind, s.MonoNS = KindExit, s.MonoNS+200; return s }
	_, sink := startScoped(t, rs, hook,
		execSample(prev, 1, "curl", "/usr/bin/curl", []string{"curl", "https://example.com"}, false),
		fsSample(open(prev), 0, 1, 2049, "/usr/lib/x86_64-linux-gnu/libssl.so.3", ""),
		exitSample(exit(prev), 0, 0),
		execSample(mine, 1, "python3", "/usr/bin/python3.12", []string{"python3", "app.py"}, false),
		exitSample(exit(mine), 0, 0),
	)
	want := []string{"exec 50 41 /usr/bin/python3.12", "exit 50"}
	if got := hook.all(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("hook calls %q, want this run's process alone %q", got, want)
	}
	for _, ev := range sink.all() {
		if ev.PID == 60 {
			t.Errorf("run r-A recorded %s of pid 60, which the slot's previous run left in its ring", ev.Kind)
		}
	}
	if n := len(sink.byKind(record.KindExec)); n != 1 {
		t.Errorf("%d exec events, want this run's one", n)
	}
}

// TestRecorderAloneRecordsItsDescendants is a run whose agent made a cgroup: cgroup_track copied the run's row,
// and slot, to it. Its samples are this run's, and nothing is a gap.
func TestRecorderAloneRecordsItsDescendants(t *testing.T) {
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3, 42: 3}}
	mine := sample{MonoNS: 1000, CgroupID: 42, PID: 50, TID: 50, PPID: 1, RunIdx: 3, Kind: KindExec}
	r, sink := startScoped(t, rs, nil,
		execSample(mine, 1, "python3", "/usr/bin/python3.12", []string{"python3"}, false))
	if len(sink.byKind(record.KindExec)) != 1 {
		t.Fatalf("a sample of this run's descendant cgroup (same slot) was not recorded: %+v", sink.all())
	}
	if len(r.Gaps()) != 0 {
		t.Errorf("gaps %+v for a run and its descendant", r.Gaps())
	}
}

// TestRecorderReadsBesideAnotherRunOfItsBuild is ADR 0026 (5): with a ring per run, another run of the build, or
// a row a dead launcher left under another slot, no longer stops a recorder from reading. It used to read
// nothing and say kernel-record-unavailable, because the build's one ring took one reader.
func TestRecorderReadsBesideAnotherRunOfItsBuild(t *testing.T) {
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3, 77: 5, 12: 8}}
	hook := &hookLog{}
	r, sink := startScoped(t, rs, hook, twoRunsSamples()...)
	if len(sink.byKind(record.KindExec)) != 1 || len(hook.all()) != 3 {
		t.Errorf("recorded %d execs and fed %d hook calls beside another run of the build, want 1 and 3",
			len(sink.byKind(record.KindExec)), len(hook.all()))
	}
	if hasWhy(r.Gaps(), runtime.GapKernelRecordUnavailable) {
		t.Errorf("gaps %+v: another run of the build no longer makes this run's record unavailable", r.Gaps())
	}
}

// TestRecorderWithoutItsRowRecordsNothing is the case the recorder cannot scope at all: no row names the
// run's cgroup, or the run names none. With no slot there is no ring of the run's to read, so it reads nothing,
// feeds no hook, and says kernel-record-unavailable, without failing the run.
func TestRecorderWithoutItsRowRecordsNothing(t *testing.T) {
	cases := []struct {
		name string
		rs   *fakeRunSet
		cg   uint64
	}{
		{"no row", &fakeRunSet{rows: map[uint64]uint32{999: 9}}, 41},
		{"no cgroup", &fakeRunSet{rows: map[uint64]uint32{41: 3}}, 0},
		{"lookup failed", &fakeRunSet{lookErr: errors.New("EPERM")}, 41},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ring := newFakeRing(twoRunsSamples()...)
			r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour, RunSet: tc.rs})
			if err != nil {
				t.Fatal(err)
			}
			hook := &hookLog{}
			if err := r.AddProcessHook(hook); err != nil {
				t.Fatal(err)
			}
			sink := &fakeSink{}
			if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: tc.cg}, sink); err != nil {
				t.Fatalf("Start failed the run: %v", err)
			}
			if err := r.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			if len(sink.all()) != 0 || len(hook.all()) != 0 {
				t.Errorf("an unscoped recorder recorded %d events and fed %d hook calls", len(sink.all()), len(hook.all()))
			}
			if n := gapCount(r.Gaps())[runtime.GapKernelRecordUnavailable]; n != 1 {
				t.Errorf("gaps %+v, want %s once", r.Gaps(), runtime.GapKernelRecordUnavailable)
			}
			ring.mu.Lock()
			left := len(ring.samples)
			ring.mu.Unlock()
			if left != len(twoRunsSamples()) {
				t.Errorf("the unscoped recorder read %d samples off a ring that belongs to other runs", len(twoRunsSamples())-left)
			}
		})
	}
}

// TestARecorderOutsideTheHostNamespacesReadsNothing: a launcher in a pid
// namespace of its own named the wrong process for every sample, and one in a time namespace with an offset
// read every kernel clock on another clock, with no gap either way. Such a launcher's recorder reads nothing and the run
// records kernel-record-unavailable.
func TestARecorderOutsideTheHostNamespacesReadsNothing(t *testing.T) {
	f := newFixture(t)
	ring := newFakeRing(twoRunsSamples()...)
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour,
		RunSet:         &fakeRunSet{rows: map[uint64]uint32{41: 3}},
		namespaceCheck: func() error { return errors.New("a pid namespace of its own") }})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if n := len(sink.all()); n != 0 {
		t.Errorf("%d events recorded from outside the host's namespaces", n)
	}
	if !hasWhy(r.Gaps(), runtime.GapKernelRecordUnavailable) {
		t.Errorf("gaps %v, want kernel-record-unavailable", r.Gaps())
	}
}

// TestTimensOffset reads /proc/<pid>/timens_offsets: a zero table offsets nothing.
func TestTimensOffset(t *testing.T) {
	for _, tc := range []struct {
		table string
		want  bool
	}{
		{"monotonic           0         0\nboottime            0         0\n", false},
		{"monotonic      100000         0\nboottime            0         0\n", true},
		{"monotonic           0         0\nboottime            0       500\n", true},
		{"", false},
	} {
		if got := timensOffset([]byte(tc.table)); got != tc.want {
			t.Errorf("timensOffset(%q) = %v, want %v", tc.table, got, tc.want)
		}
	}
}
