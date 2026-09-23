// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationProcCacheAgainstARealProcess needs no privilege: it starts a real child, hands the
// recorder a sample naming that pid, and requires the exec id it stamps to be the one /proc implies.
// This is the half of the cache that the unit tests can only fake.
func TestIntegrationProcCacheAgainstARealProcess(t *testing.T) {
	child := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := child.Start(); err != nil {
		t.Skipf("no /bin/sh to start: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})
	pid := child.Process.Pid

	f := newFixture(t)
	// The real /proc, not the fixture's fake one.
	ring := newFakeRing(fsSample(sample{Kind: KindOpen, PID: uint32(pid), MonoNS: 1}, 0, 1, 1, "/usr/lib/libc.so.6", ""),
		exitSample(sample{Kind: KindExit, PID: uint32(pid), MonoNS: 2}, 0, 0))
	r, err := New(Options{Rules: f.rules, Reader: ring, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-int-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(sink.byKind(record.KindFS)) == 1 }, "the aggregate never reached the sink")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}

	st, err := proc.New().Stat(pid)
	if err != nil {
		t.Fatalf("stat the child: %v", err)
	}
	want := string(identity.NewExecID("r-int-1", pid, st.StartBootNS()))
	if len(sink.byKind(record.KindFS)) != 1 {
		t.Fatalf("%d fs events", len(sink.byKind(record.KindFS)))
	}
	t.Logf("child %d comm %q start %d exec id %s", pid, st.Comm, st.StartBootNS(), want)
	if st.Comm == "" {
		t.Error("the real stat line produced no comm")
	}
}

// TestIntegrationPinnedMaps opens a real pinned ring outer and a real pinned per-run lost counter through the same
// code path production uses, pinned the way the tier-2 loader pins them: specs pinned by name, created through
// MapOptions.PinPath (enforce/cgroup kernel.go). The run's own ring at its slot is what the recorder reads (ADR
// 0026 (1)). In a tegobpf build the specs are the real trace_proc object's own. Creating BPF maps needs CAP_BPF,
// so it skips as a normal user; test/vm runs it as root.
func TestIntegrationPinnedMaps(t *testing.T) {
	root, dir := pinRoot(t, "build0")
	outer, _ := pinRecorderMaps(t, dir)
	placeRing(t, outer, 1)

	rings, lost, err := openPinned(root, "build0")
	if err != nil {
		t.Fatalf("openPinned: %v", err)
	}
	defer rings.Close()
	defer lost.Close()
	counter := &slotLost{m: lost, slot: 1}
	n, err := counter.Lost()
	if err != nil {
		t.Fatalf("read the lost counter: %v", err)
	}
	if n != 0 {
		t.Errorf("a fresh counter reads %d", n)
	}
	ring, ok, err := bpf.RingOf(rings, 1)
	if err != nil || !ok {
		t.Fatalf("RingOf(1) = %v, %v", ok, err)
	}
	defer ring.Close()
	reader, err := ringbuf.NewReader(ring)
	if err != nil {
		t.Fatal(err)
	}
	// The reader must behave the way the drain loop expects: a deadline wakes it, Close ends it. The
	// deadline error is cilium/ebpf's wrapping of os.ErrDeadlineExceeded, which os.IsTimeout does not
	// unwrap; errors.Is is also what drain itself tests.
	reader.SetDeadline(time.Now().Add(20 * time.Millisecond))
	var sample ringbuf.Record
	if err := reader.ReadInto(&sample); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("ReadInto past the deadline = %v, want os.ErrDeadlineExceeded", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := reader.ReadInto(&sample); err == nil {
		t.Error("ReadInto after Close returned no error")
	}
	var _ RingReader = (*ringbuf.Reader)(nil)
}

// TestIntegrationPinnedRingWithoutLostCounterIsRefused is openPinned's fail-closed half: a build pin
// directory holding the ring outer and no lost counter is refused rather than drained with every
// kernel-side drop unaccounted for (§8 I7).
func TestIntegrationPinnedRingWithoutLostCounterIsRefused(t *testing.T) {
	root, dir := pinRoot(t, "build1")
	events, _ := recorderMapSpecs(t)
	m, err := ebpf.NewMapWithOptions(events, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		t.Fatalf("create and pin %s: %v", events.Name, err)
	}
	defer m.Close()
	if rings, lost, err := openPinned(root, "build1"); err == nil {
		_ = rings.Close()
		_ = lost.Close()
		t.Fatal("openPinned accepted a build with no pinned lost counter")
	}
	if _, err := New(Options{Rules: newFixture(t).rules, BPFHash: "build1", PinRoot: root}); err == nil {
		t.Fatal("New accepted a build with no pinned lost counter")
	}
}

// TestIntegrationPinnedRingWithoutRunSetIsRefused is the scope's fail-closed half: with no run set, nothing names
// the run's slot and so its ring, and New refuses the build.
func TestIntegrationPinnedRingWithoutRunSetIsRefused(t *testing.T) {
	root, dir := pinRoot(t, "build3")
	pinRecorderMaps(t, dir)
	if _, err := New(Options{Rules: newFixture(t).rules, BPFHash: "build3", PinRoot: root}); err == nil {
		t.Fatal("New accepted a build with no pinned run set")
	}
}

// TestIntegrationPinnedRunSet reads a real pinned run set the way the recorder does: its own row's slot.
func TestIntegrationPinnedRunSet(t *testing.T) {
	root, dir := pinRoot(t, "build4")
	seedRunSet(t, dir, map[uint64]uint32{41: 3})
	rs, err := openRunSet(root, "build4")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if slot, _, ok, err := rs.Slot(41); err != nil || !ok || slot != 3 {
		t.Fatalf("Slot(41) = %d %v %v, want 3", slot, ok, err)
	}
	if _, _, ok, err := rs.Slot(999); err != nil || ok {
		t.Fatalf("Slot(999) = %v %v, want no row and no error", ok, err)
	}
}

// TestIntegrationARunWithNoRingReadsNothing: a run whose slot holds no ring (a build that predates per-run rings,
// or a Prepare that did not place one) has nothing of its own to read, so the recorder records
// kernel-record-unavailable and never fails the run.
func TestIntegrationARunWithNoRingReadsNothing(t *testing.T) {
	root, dir := pinRoot(t, "build5")
	pinRecorderMaps(t, dir)
	const cg = 4141
	seedRunSet(t, dir, map[uint64]uint32{cg: 2})
	r, err := New(Options{Rules: newFixture(t).rules, BPFHash: "build5", PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-int-noring", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if g := r.Gaps(); len(g) != 1 || g[0].Why != runtime.GapKernelRecordUnavailable {
		t.Errorf("gaps %+v, want kernel-record-unavailable alone", g)
	}
}

// TestIntegrationARunWithNoRingReadsItsActivityStamp on the build's pinned maps: a recorder that found the
// run's row but finds no ring at its slot reads no record (kernel-record-unavailable), and still reads the run's slot
// of the pinned tego_activity, which the BPF programs stamp whether or not the run has a ring (limits R4). It read
// nothing there before, so a busy record: off run whose ring could not be opened was ended as stalled.
func TestIntegrationARunWithNoRingReadsItsActivityStamp(t *testing.T) {
	root, dir := pinRoot(t, "build7")
	pinRecorderMaps(t, dir)
	const cg, slot = 4747, 2
	seedRunSet(t, dir, map[uint64]uint32{cg: slot})
	spec := &ebpf.MapSpec{Name: bpf.MapActivity, Type: ebpf.Array, KeySize: 4,
		ValueSize: uint32(unsafe.Sizeof(bpf.ActivitySlot{})), MaxEntries: bpf.MaxSlots, Pinning: ebpf.PinByName}
	if bpf.Available() {
		trace, err := bpf.Load(bpf.ObjectTraceProc)
		if err != nil {
			t.Fatalf("load %s: %v", bpf.ObjectTraceProc, err)
		}
		spec = trace.Maps[bpf.MapActivity].Copy()
	}
	stamps, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		t.Fatalf("create and pin %s: %v", bpf.MapActivity, err)
	}
	t.Cleanup(func() { _ = stamps.Close() })
	const mono = 12_345_678_901
	for s, v := range map[uint32]uint64{slot: mono, slot + 1: 99_000_000_000} {
		if err := stamps.Update(s, bpf.ActivitySlot{MonoNS: v, Jiffies: 7}, ebpf.UpdateAny); err != nil {
			t.Fatalf("stamp slot %d: %v", s, err)
		}
	}
	r, err := New(Options{Rules: newFixture(t).rules, BPFHash: "build7", PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-int-noring-stamp", Agent: "a", CgroupID: cg},
		&fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if r.Reading() {
		t.Error("Reading = true for a run with no ring")
	}
	if got := r.LastActivity(); got != mono {
		t.Errorf("LastActivity = %d for a run with no ring, want its slot's %d", got, uint64(mono))
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := r.LastActivity(); got != 0 {
		t.Errorf("LastActivity after Stop = %d, want 0", got)
	}
	if g := r.Gaps(); len(g) != 1 || g[0].Why != runtime.GapKernelRecordUnavailable {
		t.Errorf("gaps %+v, want kernel-record-unavailable alone", g)
	}
}

// TestIntegrationStopReadsTheLostCounterLast is the final poll Stop owes a run that ends inside its flush
// window: the kernel counted drops since the last poll, and Stop must read them before it lets go of the
// counter. Closing the counter with the ring buffer made that read fail on a closed descriptor, silently,
// so the last window's drops never became the ringbuf-full gap §8 I7 requires.
func TestIntegrationStopReadsTheLostCounterLast(t *testing.T) {
	root, dir := pinRoot(t, "build2")
	// The run's own row and ring, as Prepare writes them before any source starts.
	const cg = 4242
	seedRunSet(t, dir, map[uint64]uint32{cg: 1})
	outer, lostMap := pinRecorderMaps(t, dir)
	placeRing(t, outer, 1)
	r, err := New(Options{Rules: newFixture(t).rules, BPFHash: "build2", PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-int-lost", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if err := lostMap.Update(uint32(1), uint64(3), ebpf.UpdateAny); err != nil {
		t.Fatalf("count three drops: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := gapCount(r.Gaps())[GapRingbufFull]; got != 3 {
		t.Fatalf("ringbuf-full = %d after Stop, want the 3 drops counted in the last window: %+v", got, r.Gaps())
	}
}

// TestIntegrationLostCounterCountsItsOwnSlot is ADR 0026 (4): the lost counter is per run, at the run's slot, so
// another run's drops (slot 2) are never this run's ringbuf-full, and the run's own count is diffed from the
// value its recorder started from.
func TestIntegrationLostCounterCountsItsOwnSlot(t *testing.T) {
	root, dir := pinRoot(t, "build6")
	const cg = 4343
	seedRunSet(t, dir, map[uint64]uint32{cg: 1})
	outer, lostMap := pinRecorderMaps(t, dir)
	placeRing(t, outer, 1)
	if err := lostMap.Update(uint32(2), uint64(500), ebpf.UpdateAny); err != nil {
		t.Fatalf("count another run's drops: %v", err)
	}
	r, err := New(Options{Rules: newFixture(t).rules, BPFHash: "build6", PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-int-base", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if err := lostMap.Update(uint32(1), uint64(3), ebpf.UpdateAny); err != nil {
		t.Fatalf("count three drops: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := gapCount(r.Gaps())[GapRingbufFull]; got != 3 {
		t.Fatalf("ringbuf-full = %d, want this run's own 3 drops: %+v", got, r.Gaps())
	}
}

// pinRecorderMaps creates and pins the build's ring outer and per-run lost counter the way the tier-2 loader pins
// them, and returns both.
func pinRecorderMaps(t *testing.T, dir string) (outer, lost *ebpf.Map) {
	t.Helper()
	events, lostSpec := recorderMapSpecs(t)
	var out []*ebpf.Map
	for _, spec := range []*ebpf.MapSpec{events, lostSpec} {
		m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: dir})
		if err != nil {
			t.Fatalf("create and pin %s: %v", spec.Name, err)
		}
		t.Cleanup(func() { _ = m.Close() })
		out = append(out, m)
	}
	return out[0], out[1]
}

// placeRing puts a run's own 64 KiB ring into outer at slot, as the tier-2 backend's Prepare does (ADR 0026 (1)).
func placeRing(t *testing.T, outer *ebpf.Map, slot uint32) *ebpf.Map {
	t.Helper()
	ring, err := bpf.NewRing(bpf.RingRecord, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	if err := bpf.InsertRing(outer, slot, ring); err != nil {
		t.Fatal(err)
	}
	return ring
}

// pinRoot makes a private pin root on the host's bpf filesystem with one build's maps directory in it,
// laid out as the tier-2 loader lays one out, and removes it when the test ends. It skips without root.
func pinRoot(t *testing.T, hash string) (root, maps string) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("creating BPF maps and writing to bpffs needs root (CAP_BPF and a writable /sys/fs/bpf)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	root = filepath.Join("/sys/fs/bpf", "tego-observe-test-"+strconv.Itoa(os.Getpid()))
	maps = filepath.Join(root, hash, "maps")
	if err := os.MkdirAll(maps, 0o700); err != nil {
		t.Fatalf("mkdir on bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root, maps
}

// seedRunSet pins the build's run set the way the tier-2 loader pins it (by name, under the maps directory)
// and gives each cgroup its slot, as Prepare does before any source starts.
func seedRunSet(t *testing.T, dir string, rows map[uint64]uint32) *ebpf.Map {
	t.Helper()
	spec := &ebpf.MapSpec{Name: bpf.MapRunSet, Type: ebpf.Hash, KeySize: 8,
		ValueSize: uint32(unsafe.Sizeof(bpf.Run{})), MaxEntries: 4096, Pinning: ebpf.PinByName}
	if bpf.Available() {
		trace, err := bpf.Load(bpf.ObjectTraceProc)
		if err != nil {
			t.Fatalf("load %s: %v", bpf.ObjectTraceProc, err)
		}
		spec = trace.Maps[bpf.MapRunSet].Copy()
	}
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		t.Fatalf("create and pin %s: %v", bpf.MapRunSet, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	for cg, slot := range rows {
		row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
		if err := m.Update(&cg, &row, ebpf.UpdateAny); err != nil {
			t.Fatalf("insert cgroup %d into the run set: %v", cg, err)
		}
	}
	return m
}

// recorderMapSpecs returns the ring outer's and the lost counter's specs: the compiled trace_proc object's own
// when this binary carries it, else hand-built ones under the same names and pinning.
func recorderMapSpecs(t *testing.T) (events, lost *ebpf.MapSpec) {
	t.Helper()
	if bpf.Available() {
		spec, err := bpf.Load(bpf.ObjectTraceProc)
		if err != nil {
			t.Fatalf("load %s: %v", bpf.ObjectTraceProc, err)
		}
		events, lost = spec.Maps[EventsMapName], spec.Maps[LostMapName]
		if events == nil || lost == nil {
			t.Fatalf("%s declares no %s or %s", bpf.ObjectTraceProc, EventsMapName, LostMapName)
		}
		return events.Copy(), lost.Copy()
	}
	return &ebpf.MapSpec{Name: EventsMapName, Type: ebpf.HashOfMaps, KeySize: 4, MaxEntries: bpf.MaxSlots,
			Pinning: ebpf.PinByName, InnerMap: &ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 1 << 16}},
		&ebpf.MapSpec{Name: LostMapName, Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: bpf.MaxSlots,
			Pinning: ebpf.PinByName}
}
