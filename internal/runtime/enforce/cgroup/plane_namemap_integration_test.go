// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The backend's half of ADR 0043 D9 against the running kernel, as root: the slot's name map is filled with the run's
// gen before the header, and every clear path (Detach, a reaper's purge of a dead launcher's slot) leaves it empty;
// a plane whose pinned name map is gone is not adopted.

// nameMapGens reads slot's inner name map: each key's gen (the config row is key 0), and false when the slot has no
// inner name map.
func nameMapGens(t *testing.T, outer *ebpf.Map, slot uint32) (map[uint64]uint32, bool) {
	t.Helper()
	inner, ok, err := ebpfbindings.OpenInner(outer, slot)
	if err != nil {
		t.Fatalf("slot %d's name map: %v", slot, err)
	}
	if !ok {
		return nil, false
	}
	defer func() { _ = inner.Close() }()
	out := map[uint64]uint32{}
	var (
		key uint64
		val ebpfbindings.PlaneNameRow // the config row has the same size and its gen first
	)
	it := inner.Iterate()
	for it.Next(&key, &val) {
		out[key] = val.Gen
	}
	if err := it.Err(); err != nil {
		t.Fatalf("slot %d's name map: %v", slot, err)
	}
	return out, true
}

// namePlaneRun prepares a run of rt under b, holding its keyed paths, and returns its handle and rows.
func namePlaneRun(t *testing.T, b *Backend, name string, rt *agent.RuleTable) (*Handle, *decide.PlaneRows) {
	t.Helper()
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	rel, _, id := runCgroupUnderSelf(t, name)
	b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
	h, err := b.Prepare(context.Background(), rt, Run{ID: "names-" + name, CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
	if err != nil {
		t.Fatalf("Prepare %s: %v", name, err)
	}
	return h, rows
}

// TestPlaneNameRowsFillAndClear: Prepare writes the slot's config row and each name row with the run's gen and the
// header's name flag; Detach empties the slot's name map, as a reaper's purge of the slot does through the build's
// pinned planes (openPinnedPlanes); a run without name entries on the cleared slot writes none.
func TestPlaneNameRowsFillAndClear(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	hash := fmt.Sprintf("t6names%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}})
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	check := func(h *Handle, rows *decide.PlaneRows) (*bpfPlane, uint32) {
		t.Helper()
		p := h.kern.(*bpfKernel).planes[0]
		var hdr ebpfbindings.PlaneSlot
		if err := p.slots.Lookup(h.slot, &hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Flags&ebpfbindings.PlaneSlotNameDecides == 0 {
			t.Fatalf("slot %d's header %+v has no name flag", h.slot, hdr)
		}
		gens, ok := nameMapGens(t, p.nameRows, h.slot)
		if !ok || len(gens) != len(rows.NameRows)+1 {
			t.Fatalf("slot %d's name map holds %v, want the config row and %d name rows", h.slot, gens, len(rows.NameRows))
		}
		if gens[0] != hdr.Gen {
			t.Errorf("config row of gen %d, header's %d", gens[0], hdr.Gen)
		}
		for _, r := range rows.NameRows {
			if g, ok := gens[r.Key]; !ok || g != hdr.Gen {
				t.Errorf("name row %q: gen %d (present %v), want the header's %d", r.Name, g, ok, hdr.Gen)
			}
		}
		return p, hdr.Gen
	}
	empty := func(p *bpfPlane, slot uint32, when string) {
		t.Helper()
		if gens, ok := nameMapGens(t, p.nameRows, slot); ok && len(gens) != 0 {
			t.Errorf("%s: slot %d's name map still holds %v", when, slot, gens)
		}
	}

	scope := t.TempDir()
	h, rows := namePlaneRun(t, b, "first", nameTable(scope))
	if len(rows.NameRows) == 0 {
		t.Fatal("the table compiled no name rows")
	}
	_, gen1 := check(h, rows)
	slot := h.slot
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	// A handle closes its plane's map descriptors with it: read the slot through the build's pin.
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := ebpf.LoadPinnedMap(filepath.Join(newPlaneLayout(pins, hash, mode).Maps, ebpfbindings.MapPlaneNameRows), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pinned.Close() })
	empty(&bpfPlane{nameRows: pinned}, slot, "after Detach")

	// A run without name entries on the slot writes none; its own Detach leaves the map as empty.
	plain := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordSummary, Contract: &agent.Contract{}}
	h2, _ := namePlaneRun(t, b, "plain", plain)
	empty(&bpfPlane{nameRows: pinned}, h2.slot, "a run without name entries")
	if err := h2.Close(); err != nil {
		t.Fatal(err)
	}

	// The reaper's clear: the build's pinned planes, opened as a reaper opens them, clear a slot a live run filled.
	h3, rows3 := namePlaneRun(t, b, "reaped", nameTable(scope))
	t.Cleanup(func() { _ = h3.Close() })
	if _, gen3 := check(h3, rows3); gen3 == gen1 && h3.slot == slot {
		t.Errorf("slot %d reused with gen %d", slot, gen3)
	}
	planes, err := openPinnedPlanes(pins.Base, hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, pp := range planes {
			_ = pp.closePinned()
		}
	})
	var cleared bool
	for _, pp := range planes {
		if pp.mode != mode {
			continue
		}
		if pp.nameRows == nil {
			t.Fatalf("the %s plane opened for a reaper has no name map", mode)
		}
		if err := pp.clearSlot(h3.slot); err != nil {
			t.Fatal(err)
		}
		cleared = true
	}
	if !cleared {
		t.Fatalf("no pinned %s plane to clear", mode)
	}
	empty(&bpfPlane{nameRows: pinned}, h3.slot, "after the reaper's clear")
}

// TestPlaneNameMapAdoption is ADR 0043 D9's adoption rule: a plane is taken from its pins only with its name map, so
// a pinned plane whose name map pin is gone is not adopted. The next run loads the mode's programs again over a new
// name map, and its slot's name entries are written where those programs read them.
func TestPlaneNameMapAdoption(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	hash := fmt.Sprintf("t6nameadopt%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}})
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	programs := func(h *Handle) map[string]ebpf.ProgramID {
		t.Helper()
		out := map[string]ebpf.ProgramID{}
		for name, prog := range h.kern.(*bpfKernel).planes[0].coll.Programs {
			info, err := prog.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := info.ID()
			out[name] = id
		}
		return out
	}
	scope := t.TempDir()
	h1, _ := namePlaneRun(t, b, "first", nameTable(scope))
	first := programs(h1)
	if err := h1.Close(); err != nil {
		t.Fatal(err)
	}
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(newPlaneLayout(pins, hash, mode).Maps, ebpfbindings.MapPlaneNameRows)
	if err := os.Remove(pin); err != nil {
		t.Fatalf("remove the name map's pin: %v", err)
	}
	h2, rows2 := namePlaneRun(t, b, "second", nameTable(scope))
	t.Cleanup(func() { _ = h2.Close() })
	for name, id := range programs(h2) {
		if first[name] == id {
			t.Errorf("%s: the second run adopted program %d over a plane whose name map pin was gone", name, id)
		}
	}
	p := h2.kern.(*bpfKernel).planes[0]
	if gens, ok := nameMapGens(t, p.nameRows, h2.slot); !ok || len(gens) != len(rows2.NameRows)+1 {
		t.Errorf("the second run's slot %d name map holds %v, want its config row and %d name rows", h2.slot, gens,
			len(rows2.NameRows))
	}
	if _, err := os.Stat(pin); err != nil {
		t.Errorf("the second run left no name map pinned: %v", err)
	}
}
