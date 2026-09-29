// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// budgetOf is the fixture's machine config with record.ringbuf and bpf.ring_budget set.
func budgetOf(ringbuf, budget config.ByteSize) func(*Options) {
	return func(o *Options) {
		m := machineLinger(0)
		m.Record.Ringbuf.Value = ringbuf
		m.BPF.RingBudget.Value = budget
		o.Machine = m
	}
}

// TestPrepareGivesEachRunItsOwnRings is ADR 0026 (1)-(3) at Prepare: a run gets a record ring of record.ringbuf
// at its own slot, and a capture ring of the same size only when its capture is uprobe; a record: off run gets
// the small fixed ring and no capture ring, whatever its capture. The rings are placed before the run's run-set
// row, since a program that finds the row and no ring emits nothing, and a second run gets its own at its own
// slot.
func TestPrepareGivesEachRunItsOwnRings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		capture agent.CaptureMode
		record  agent.RecordMode
		want    []fakeRing
	}{
		{"uprobe", agent.CaptureUprobe, agent.RecordFull,
			[]fakeRing{{ebpfbindings.RingRecord, 1 << 20}, {ebpfbindings.RingCapture, 1 << 20}}},
		{"forwarder", agent.CaptureForwarder, agent.RecordSummary, []fakeRing{{ebpfbindings.RingRecord, 1 << 20}}},
		{"off", agent.CaptureOff, agent.RecordFull, []fakeRing{{ebpfbindings.RingRecord, 1 << 20}}},
		{"record off", agent.CaptureUprobe, agent.RecordOff, []fakeRing{{ebpfbindings.RingRecord, recordOffRing}}},
	} {
		f := newFixture(t, budgetOf(1<<20, 64<<20))
		rt := *f.table
		rt.Capture, rt.Record = tc.capture, tc.record
		h, err := f.backend.Prepare(context.Background(), &rt, f.run)
		if err != nil {
			t.Fatalf("%s: Prepare: %v", tc.name, err)
		}
		if err := h.Arm(); err != nil { // the run-set row is Arm's (ADR 0021 (2))
			t.Fatalf("%s: Arm: %v", tc.name, err)
		}
		if got := f.kernel.rings[h.Slot()]; !slices.Equal(got, tc.want) {
			t.Errorf("%s: slot %d rings %v, want %v", tc.name, h.Slot(), got, tc.want)
		}
		rings := slices.Index(f.kernel.calls, "placeRing "+ebpfbindings.RingRecord)
		row := slices.Index(f.kernel.calls, "insertRun")
		if rings < 0 || row < 0 || rings > row {
			t.Errorf("%s: calls %v: the record ring must be placed before the run-set row", tc.name, f.kernel.calls)
		}
		if row := f.kernel.runs[f.run.CgroupID]; row.Gen != h.gen || row.Gen == 0 {
			t.Errorf("%s: the run-set row carries generation %d, want the slot's epoch %d", tc.name, row.Gen, h.gen)
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if got := f.kernel.rings[h.Slot()]; !slices.Equal(got, tc.want) {
			t.Errorf("%s: slot %d rings %v after Close, want %v kept for the slot's next run", tc.name, h.Slot(), got,
				tc.want)
		}
	}

	f := newFixture(t, budgetOf(1<<20, 64<<20))
	a, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	second := f.run
	second.ID = "run-2"
	b, err := f.backend.Prepare(context.Background(), f.table, second)
	if err != nil {
		t.Fatalf("a second run of the build: %v", err)
	}
	defer b.Close()
	if a.Slot() == b.Slot() || len(f.kernel.rings[a.Slot()]) != 1 || len(f.kernel.rings[b.Slot()]) != 1 {
		t.Errorf("two runs at slots %d and %d with rings %v: each needs its own", a.Slot(), b.Slot(), f.kernel.rings)
	}
}

// TestPrepareRefusesPastTheRingBudget is ADR 0026 (2)'s ErrRingBudget: a run whose record ring would take the
// host's rings past bpf.ring_budget is refused before its run-set row exists, with the numbers and the fix, and
// leaves no ring and no slot behind. Other builds' rings count against the same budget.
func TestPrepareRefusesPastTheRingBudget(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 3<<20))
	f.kernel.otherRings = 2 << 20
	_, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if !errors.Is(err, ErrRingBudget) {
		t.Fatalf("Prepare past the budget = %v, want ErrRingBudget", err)
	}
	for _, want := range []string{"bpf.ring_budget", "/etc/tego/config.yaml", "tego doctor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if len(f.kernel.rings) != 0 || len(f.kernel.runs) != 0 {
		t.Errorf("a refused run left rings %v and rows %v", f.kernel.rings, f.kernel.runs)
	}
	// The slot went back: with the other build's rings gone, the next run takes slot 0 again.
	f.kernel.otherRings = 0
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.Slot() != 0 {
		t.Errorf("slot %d after a refusal, want 0: the refused run kept its slot", h.Slot())
	}
}

// TestACaptureRingPastTheBudgetIsLeftOut: when the record ring fits the budget and the capture ring does not,
// the run is prepared without a capture ring and says why (CaptureRefused, ErrRingBudget): its uprobe source
// then finds no ring, and the runtime refuses the run only if a token, cost or repeats budget needed it
// (limits-check-doctor-cli R32).
func TestACaptureRingPastTheBudgetIsLeftOut(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 3<<20))
	f.kernel.otherRings = 1 << 20
	rt := *f.table
	rt.Capture = agent.CaptureUprobe
	h, err := f.backend.Prepare(context.Background(), &rt, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if got := f.kernel.rings[h.Slot()]; len(got) != 1 || got[0].kind != ebpfbindings.RingRecord {
		t.Errorf("rings %v, want the record ring alone", got)
	}
	if !errors.Is(h.CaptureRefused(), ErrRingBudget) {
		t.Errorf("CaptureRefused = %v, want ErrRingBudget", h.CaptureRefused())
	}
}

// TestTheSlotsNextRunReusesItsRings is ADR 0026 (6) as amended: a run's rings stay at its slot when it ends, and
// the slot's next run that needs the same rings reuses them, drained, under the shared rings lock: no ring is
// created, inserted or removed, so no grace period is waited for, and nothing is counted or reclaimed.
func TestTheSlotsNextRunReusesItsRings(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 64<<20))
	rt := *f.table
	rt.Capture = agent.CaptureUprobe
	a, err := f.backend.Prepare(context.Background(), &rt, f.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	f.kernel.calls = nil
	b, err := f.backend.Prepare(context.Background(), &rt, f.run)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Arm(); err != nil { // the run-set row is Arm's (ADR 0021 (2))
		t.Fatal(err)
	}
	if a.Slot() != b.Slot() {
		t.Fatalf("the next run took slot %d, not the free slot %d", b.Slot(), a.Slot())
	}
	for _, call := range f.kernel.calls {
		if strings.HasPrefix(call, "placeRing") || strings.HasPrefix(call, "removeRing") || call == "reclaimRings" {
			t.Errorf("calls %v: a run whose slot holds the rings it needs changed the outers (%s)", f.kernel.calls, call)
		}
	}
	if f.kernel.drained[ebpfbindings.RingRecord] != 1 || f.kernel.drained[ebpfbindings.RingCapture] != 1 {
		t.Errorf("drained %v, want each reused ring drained once", f.kernel.drained)
	}
	drain := slices.Index(f.kernel.calls, "drainRing "+ebpfbindings.RingRecord)
	row := slices.Index(f.kernel.calls, "insertRun")
	if drain < 0 || row < 0 || drain > row {
		t.Errorf("calls %v: the reused ring must be drained before the run-set row", f.kernel.calls)
	}
}

// TestAReusedSlotGetsOnlyTheRingsItsRunMayUse: the slot's previous run left rings this run must not have. A
// capture ring, when this run's capture is not uprobe, is removed before its row exists, since the probes the
// build's runs share would write this run's TLS plaintext into it; a record ring of another size is replaced.
func TestAReusedSlotGetsOnlyTheRingsItsRunMayUse(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 64<<20))
	rt := *f.table
	rt.Capture = agent.CaptureUprobe
	a, err := f.backend.Prepare(context.Background(), &rt, f.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rt.Capture = agent.CaptureOff
	f.kernel.calls = nil
	b, err := f.backend.Prepare(context.Background(), &rt, f.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Arm(); err != nil { // the run-set row is Arm's (ADR 0021 (2))
		t.Fatal(err)
	}
	want := []fakeRing{{ebpfbindings.RingRecord, 1 << 20}}
	if got := f.kernel.rings[b.Slot()]; !slices.Equal(got, want) {
		t.Errorf("a capture: off run's slot holds %v, want %v", got, want)
	}
	removed := slices.Index(f.kernel.calls, "removeRing "+ebpfbindings.RingCapture)
	row := slices.Index(f.kernel.calls, "insertRun")
	if removed < 0 || removed > row {
		t.Errorf("calls %v: the capture ring must go before the run-set row", f.kernel.calls)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	rt.Record = agent.RecordOff
	c, err := f.backend.Prepare(context.Background(), &rt, f.run)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	want = []fakeRing{{ebpfbindings.RingRecord, recordOffRing}}
	if got := f.kernel.rings[c.Slot()]; !slices.Equal(got, want) {
		t.Errorf("a record: off run's slot holds %v, want %v", got, want)
	}
}

// TestARingThatCannotBeDrainedIsReplaced: a reused ring is drained before the run's row exists; one that cannot
// be is not handed to the run, which gets a new one instead.
func TestARingThatCannotBeDrainedIsReplaced(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 64<<20))
	a, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	f.kernel.failAt = "drainRing " + ebpfbindings.RingRecord
	f.kernel.calls = nil
	b, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, want := range []string{"removeRing " + ebpfbindings.RingRecord, "placeRing " + ebpfbindings.RingRecord} {
		if !slices.Contains(f.kernel.calls, want) {
			t.Errorf("calls %v: no %s for a ring that could not be drained", f.kernel.calls, want)
		}
	}
}

// TestASlotAboveThePoolHasItsRingsTrimmed: only a build's lowest ringPoolSlots slots keep their rings for their
// next run. A run above them, once its slot is free, starts the removal of its rings off its own path.
func TestASlotAboveThePoolHasItsRingsTrimmed(t *testing.T) {
	t.Parallel()
	var trims []string
	f := newFixture(t, budgetOf(1<<20, 64<<20), func(o *Options) {
		o.trimRings = func(hash string) error { trims = append(trims, hash); return nil }
	})
	var held []*Handle
	for i := 0; i <= ringPoolSlots; i++ {
		run := f.run
		run.ID = fmt.Sprintf("run-%d", i)
		h, err := f.backend.Prepare(context.Background(), f.table, run)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, h)
	}
	for _, h := range held {
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(trims) != 1 || trims[0] != "testhash" {
		t.Errorf("trims %v, want one of this build, from the run at slot %d", trims, ringPoolSlots)
	}
	for s := uint32(0); s < ringPoolSlots; s++ {
		if len(f.kernel.rings[s]) != 1 {
			t.Errorf("pool slot %d holds %v after its run, want its record ring", s, f.kernel.rings[s])
		}
	}
}

// TestTheRingTrimmerIsAHelper: the trimmer a run above the pool starts outlives its launcher, as the linger timer
// does, so it starts as one of tego's helpers (startHelperProcess, in helpers.scope), not in the launcher's own
// cgroup, where stopping the unit or CI job the launcher ran in killed it and left its rings charged to
// bpf.ring_budget (ADR 0022's round-7 amendment). Not parallel: it swaps startHelperProcess.
func TestTheRingTrimmerIsAHelper(t *testing.T) {
	var started [][]string
	saved := startHelperProcess
	startHelperProcess = func(exe string, args ...string) error {
		started = append(started, append([]string{exe}, args...))
		return nil
	}
	t.Cleanup(func() { startHelperProcess = saved })
	h := &Handle{hash: "trimhash", slot: ringPoolSlots, kern: newFakeKernel(),
		run:  Run{StageExe: "/bin/true"},
		opts: Options{BPFFS: "/sys/fs/bpf-test", StateDir: "/run/tego-test"}}
	if err := h.parkRings(); err != nil {
		t.Fatal(err)
	}
	want := []string{"/bin/true", RingTrimCommand, "trimhash", "/sys/fs/bpf-test", "/run/tego-test"}
	if len(started) != 1 || !slices.Equal(started[0], want) {
		t.Errorf("helpers started %v, want one %v", started, want)
	}
}

// TestAPlacementReclaimsTheRingsOfIdleBuilds: a build no launcher runs, an old one after an upgrade or one whose
// launcher crashed, keeps rings that count against every build's budget. A Prepare that places a ring reclaims
// them first, under the exclusive rings lock; the rings of a build a launcher runs stay, and so does this build's
// own pool.
func TestAPlacementReclaimsTheRingsOfIdleBuilds(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 64<<20))
	f.kernel.idleRings = map[string]map[uint32]uint64{"oldhash": {3: 1 << 20}, "busyhash": {0: 1 << 20}}
	f.kernel.rings = map[uint32][]fakeRing{7: {{ebpfbindings.RingRecord, 1 << 20}}}
	busy, err := acquireBuildLock(f.dir, "busyhash")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if len(f.kernel.idleRings["oldhash"]) != 0 {
		t.Error("the idle build's ring was not reclaimed")
	}
	if len(f.kernel.idleRings["busyhash"]) != 1 {
		t.Error("the ring of a build a launcher runs was reclaimed")
	}
	if len(f.kernel.rings[7]) != 1 {
		t.Error("this build's pool ring at slot 7 was reclaimed with room to spare")
	}
}

// TestAShortBudgetReclaimsEveryRingNoRunHolds: when a ring does not fit, every ring no run holds gives its room
// back before the run is refused: this build's pool and a crashed launcher's rings, at a slot no live launcher
// holds and no run-set row carries. A slot a row carries keeps its rings.
func TestAShortBudgetReclaimsEveryRingNoRunHolds(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 3<<20))
	f.kernel.rings = map[uint32][]fakeRing{
		7: {{ebpfbindings.RingRecord, 1 << 20}},
		9: {{ebpfbindings.RingRecord, 1 << 20}},
	}
	f.kernel.runs[424242] = ebpfbindings.Run{RunIdx: 9}
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare with reclaimable room: %v", err)
	}
	defer h.Close()
	if _, ok := f.kernel.rings[7]; ok {
		t.Error("the ring of slot 7, which nothing holds, was not reclaimed")
	}
	if _, ok := f.kernel.rings[9]; !ok {
		t.Error("the ring of slot 9, which a run-set row carries, was removed")
	}
}

// TestPrepareRefusesACaptureRingTooSmallForAChunk is §5 R16's capture minimum: uprobe_ssl reserves a whole
// sizeof(tego_ev_ssl)+class record and has no smaller fallback, so a capture ring that cannot hold two of the
// largest class would drop every large chunk as ring-buffer-drop. Such a record.ringbuf refuses a uprobe-capturing
// run with ErrRingbufSize before anything is created; a run that places no capture ring still runs on it.
func TestPrepareRefusesACaptureRingTooSmallForAChunk(t *testing.T) {
	t.Parallel()
	if CaptureRingMin != 128<<10 {
		t.Fatalf("CaptureRingMin = %d, want 128 KiB (two of sizeof(tego_ev_ssl)+TEGO_SSL_CHUNK_MAX, rounded up)", CaptureRingMin)
	}
	for _, tc := range []struct {
		name    string
		ringbuf config.ByteSize
		capture agent.CaptureMode
		record  agent.RecordMode
		refused bool
	}{
		{"uprobe 64KiB", 64 << 10, agent.CaptureUprobe, agent.RecordFull, true},
		{"uprobe one page", config.ByteSize(os.Getpagesize()), agent.CaptureUprobe, agent.RecordFull, true},
		{"uprobe 128KiB", 128 << 10, agent.CaptureUprobe, agent.RecordFull, false},
		{"off 64KiB", 64 << 10, agent.CaptureOff, agent.RecordFull, false},
		{"record off 64KiB", 64 << 10, agent.CaptureUprobe, agent.RecordOff, false},
	} {
		f := newFixture(t, budgetOf(tc.ringbuf, 64<<20))
		rt := *f.table
		rt.Capture, rt.Record = tc.capture, tc.record
		h, err := f.backend.Prepare(context.Background(), &rt, f.run)
		if tc.refused {
			if !errors.Is(err, ErrRingbufSize) {
				t.Errorf("%s: Prepare = %v, want ErrRingbufSize", tc.name, err)
			}
			if len(f.kernel.calls) != 0 {
				t.Errorf("%s: refused after touching the kernel: %v", tc.name, f.kernel.calls)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Prepare: %v", tc.name, err)
			continue
		}
		if err := h.Detach(); err != nil {
			t.Errorf("%s: Detach: %v", tc.name, err)
		}
	}
}

// TestAShortBudgetReclaimErrorDoesNotRefuseTheRun: reclaim is best effort, and frees what it can before it joins
// the error of a build it could not read. A Prepare short of room placed its ring in the room reclaim freed
// instead of failing on that unrelated build's error; with no room freed it is still refused with ErrRingBudget.
func TestAShortBudgetReclaimErrorDoesNotRefuseTheRun(t *testing.T) {
	t.Parallel()
	f := newFixture(t, budgetOf(1<<20, 3<<20))
	f.kernel.rings = map[uint32][]fakeRing{7: {{ebpfbindings.RingRecord, 1 << 20}}}
	f.kernel.otherRings = 1 << 20
	f.kernel.reclaimErr = errors.New("fake kernel: another build's run set cannot be read")
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare with room reclaim freed: %v", err)
	}
	h.Close()

	g := newFixture(t, budgetOf(1<<20, 3<<20))
	g.kernel.otherRings = 3 << 20
	g.kernel.reclaimErr = errors.New("fake kernel: another build's run set cannot be read")
	if h, err := g.backend.Prepare(context.Background(), g.table, g.run); !errors.Is(err, ErrRingBudget) {
		if err == nil {
			h.Close()
		}
		t.Fatalf("Prepare with no room = %v; want ErrRingBudget", err)
	}
}

// TestTrimRingsReadsOnlyItsBuild: a trim picks only its build's rings, but it read every build's run set and
// outers first, under the exclusive rings lock, and joined their errors, so another build it could not read made
// `tego __ring-trim` exit ExitError. It skips every other build before opening anything of it.
func TestTrimRingsReadsOnlyItsBuild(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	for _, hash := range []string{"thishash", "otherhash"} {
		if err := os.MkdirAll(filepath.Join(bpffs, pinRoot, hash, pinMaps), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Not a pinned map: opening it as the other build's run set fails, not ErrNotExist.
	bad := filepath.Join(bpffs, pinRoot, "otherhash", pinMaps, ebpfbindings.MapRunSet)
	if err := os.WriteFile(bad, []byte("not a map"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := SweepOptions{BPFFS: bpffs, StateDir: state}
	if _, _, err := ReclaimRings(opts); err == nil {
		t.Fatal("ReclaimRings over an unreadable build returned no error; the fixture does not exercise the read")
	}
	if n, _, err := TrimRings(opts, "thishash"); err != nil || n != 0 {
		t.Errorf("TrimRings of thishash = %d, %v; want 0, nil: another build's read failed it", n, err)
	}
}

// TestRingReclaimReadsOnlyTheKeysOfAnotherBuildsRunSet is ADR 0022 (5) in reclaimRings: a row's run_idx is read
// only from this binary's own build, whose Run layout it knows. Of another build it reads the keys: a run set with
// a row keeps every ring of that build (no slot is offered to noOne), and an empty one carries none. Not parallel:
// it swaps the pinned run-set readers.
func TestRingReclaimReadsOnlyTheKeysOfAnotherBuildsRunSet(t *testing.T) {
	const own = "ownhash"
	base := t.TempDir()
	for _, hash := range []string{own, "foreignrows", "foreignempty"} {
		if err := os.MkdirAll(filepath.Join(base, hash, pinMaps), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	slots, hasKeys, ownHash := pinnedRunSetSlots, pinnedRunSetHasKeys, reclaimOwnHash
	defer func() { pinnedRunSetSlots, pinnedRunSetHasKeys, reclaimOwnHash = slots, hasKeys, ownHash }()
	reclaimOwnHash = func() (string, error) { return own, nil }
	var valuesRead, keysRead []string
	pinnedRunSetSlots = func(maps string) (map[uint32]bool, error) {
		valuesRead = append(valuesRead, filepath.Base(filepath.Dir(maps)))
		return map[uint32]bool{}, nil
	}
	pinnedRunSetHasKeys = func(maps string) (bool, error) {
		hash := filepath.Base(filepath.Dir(maps))
		keysRead = append(keysRead, hash)
		return hash == "foreignrows", nil
	}
	if _, _, err := reclaimRings(base, "", func(hash string, slot uint32) (bool, error) {
		t.Errorf("slot %d of %s offered for reclaim", slot, hash)
		return false, nil
	}); err != nil {
		t.Fatalf("reclaimRings: %v", err)
	}
	if !slices.Equal(valuesRead, []string{own}) {
		t.Errorf("run-set values read of %v, want only this build's %s", valuesRead, own)
	}
	slices.Sort(keysRead)
	if !slices.Equal(keysRead, []string{"foreignempty", "foreignrows"}) {
		t.Errorf("run-set keys read of %v, want the two other builds", keysRead)
	}
}
