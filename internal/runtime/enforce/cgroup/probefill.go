// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/internal/policy/decide"
)

// ProbeRows is a plane build's four row maps with the real fill over them, unpinned and this process's own: what
// doctor's mode probe fills its known-answer slots through (docs/p0/enforce-plane.md R21, §2.5). A fill through it
// is a run's Prepare's (planPlaneFill, the fill build's pass over this process's descriptors, checkPlaneFill, then
// the bare-name rows and last the slot's header), over maps that no run reads. doctor imports this package's importer, so the fill
// crosses into doctor here rather than being written twice.
type ProbeRows struct {
	// Rows, ExecRows, ListenRows and NameRows are the row outers: the probe loads its programs
	// over them (a collection's MapReplacements) and reads its slots' rows back through them.
	Rows, ExecRows, ListenRows, NameRows *ebpf.Map
	// Slots is tego_plane_slots, the slot headers (enforce-plane R6), replaced into the probe's collections as the
	// outers are: a known-answer slot is decided only once Fill has written its header.
	Slots *ebpf.Map
	// ExecPins and PinKeys are the exec pin maps (bpf.MapPlaneExecPins, MapPlanePinKeys; ADR 0048 (7)), replaced into
	// the probe's collections as the rows are: doctor's exec pin cell fills a pinned slot (FillPinned) and writes its
	// pins (PutPin) through them.
	ExecPins, PinKeys                                       *ebpf.Map
	rowsInner, execInner, listenInner, nameInner, pinsInner *ebpf.MapSpec
	// slotPins are the pin maps of the slots this ProbeRows made, kept open for PutPin.
	slotPins map[uint32]*ebpf.Map
	// slotRows and slotNames are the fs row maps and the name maps (ADR 0043 D9) of the slots this ProbeRows made,
	// kept open: on 6.1 each look-up of a slot through an outer map costs about 40 ms (AL2023, the known answers'
	// timing), so a slot made here is never looked up.
	slotRows, slotNames map[uint32]*ebpf.Map
	fill                ebpfbindings.Object
	filler              *planeFiller
	// Load is what loading the fill build took, 0 until the first fill loads it.
	Load time.Duration
	// LastFill splits the last Fill's time: the plan, the templates, the pass, the check and the key rows.
	LastFill string
}

// NewProbeRows makes plane build o's four outer row maps, unpinned. The fill build that goes with o is loaded by
// the first Fill.
func NewProbeRows(o ebpfbindings.Object) (*ProbeRows, error) {
	fill, ok := ebpfbindings.PlaneFillFor(o)
	if !ok {
		return nil, fmt.Errorf("plane probe: no fill build goes with %s", o)
	}
	spec, err := ebpfbindings.Load(o)
	if err != nil {
		return nil, err
	}
	p := &ProbeRows{fill: fill}
	for _, m := range []struct {
		name  string
		outer **ebpf.Map
		inner **ebpf.MapSpec
	}{{ebpfbindings.MapPlaneRows, &p.Rows, &p.rowsInner}, {ebpfbindings.MapPlaneExecRows, &p.ExecRows, &p.execInner},
		{ebpfbindings.MapPlaneListenRows, &p.ListenRows, &p.listenInner}, {ebpfbindings.MapPlaneExecPins, &p.ExecPins, &p.pinsInner},
		{ebpfbindings.MapPlaneNameRows, &p.NameRows, &p.nameInner}} {
		ms, err := probeMapSpec(spec, m.name, true)
		if err != nil {
			_ = p.Close()
			return nil, err
		}
		if *m.outer, err = ebpf.NewMap(ms); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("plane probe: create %s: %w", m.name, err)
		}
		*m.inner = ms.InnerMap
	}
	ms, err := probeMapSpec(spec, ebpfbindings.MapPlaneSlots, false)
	if err != nil {
		_ = p.Close()
		return nil, err
	}
	if p.Slots, err = ebpf.NewMap(ms); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("plane probe: create %s: %w", ebpfbindings.MapPlaneSlots, err)
	}
	if ms, err = probeMapSpec(spec, ebpfbindings.MapPlanePinKeys, false); err != nil {
		_ = p.Close()
		return nil, err
	}
	if p.PinKeys, err = ebpf.NewMap(ms); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("plane probe: create %s: %w", ebpfbindings.MapPlanePinKeys, err)
	}
	return p, nil
}

// probeMapSpec makes a private copy; the published production definition keeps
// its pinning and map identity. A missing declared listener map is a hard error.
func probeMapSpec(spec *ebpf.CollectionSpec, name string, inner bool) (*ebpf.MapSpec, error) {
	ms := spec.Maps[name]
	if ms == nil || (inner && ms.InnerMap == nil) {
		detail := ""
		if inner {
			detail = " with an inner map"
		}
		return nil, fmt.Errorf("plane probe: no %s%s", name, detail)
	}
	ms = ms.Copy()
	ms.Pinning = ebpf.PinNone
	return ms, nil
}

// Preload loads the fill build and makes each slot's maps, so that a Fill of them pays neither; it may run beside
// the loads of programs over Rows and ExecRows, and must end before any Fill.
func (p *ProbeRows) Preload(slots ...uint32) error {
	for _, s := range slots {
		if err := p.makeSlot(s); err != nil {
			return err
		}
	}
	if p.filler != nil {
		return nil
	}
	f, err := newPlaneFiller(p.fill, p.Rows, p.ExecRows, p.ListenRows)
	if err != nil {
		return err
	}
	p.filler, p.Load = f, f.Load
	return nil
}

// makeSlot makes slot's four row maps (the name map, ADR 0043 D9, among them) and its pin map in the outers, once: the
// outers are this process's own and made empty, so a slot not made here has none, and one made here is not looked up
// again. Each insert into an outer waits for an RCU grace period below 6.7 (about 40 ms on AL2023's 6.1), which
// Preload keeps off the probe's path, the pin map's included, since doctor's exec pin cell reuses the known answers'
// slot.
func (p *ProbeRows) makeSlot(slot uint32) error {
	if _, ok := p.slotRows[slot]; ok {
		return nil
	}
	pins, err := ebpf.NewMap(p.pinsInner)
	if err != nil {
		return fmt.Errorf("plane probe: create slot %d's %s map: %w", slot, ebpfbindings.MapPlaneExecPins, err)
	}
	if err := p.ExecPins.Update(slot, pins, ebpf.UpdateNoExist); err != nil {
		_ = pins.Close()
		return fmt.Errorf("plane probe: put slot %d's %s map: %w", slot, ebpfbindings.MapPlaneExecPins, err)
	}
	if p.slotPins == nil {
		p.slotPins = map[uint32]*ebpf.Map{}
	}
	p.slotPins[slot] = pins
	rows, err := ebpf.NewMap(p.rowsInner)
	if err != nil {
		return fmt.Errorf("plane probe: create slot %d's %s map: %w", slot, ebpfbindings.MapPlaneRows, err)
	}
	exec, err := ebpf.NewMap(p.execInner)
	if err != nil {
		_ = rows.Close()
		return fmt.Errorf("plane probe: create slot %d's %s map: %w", slot, ebpfbindings.MapPlaneExecRows, err)
	}
	defer func() { _ = exec.Close() }() // the outer holds its own reference
	listen, err := ebpf.NewMap(p.listenInner)
	if err != nil {
		_ = rows.Close()
		return fmt.Errorf("plane probe: create slot %d's %s map: %w", slot, ebpfbindings.MapPlaneListenRows, err)
	}
	defer func() { _ = listen.Close() }() // the outer holds its own reference
	if err := p.Rows.Update(slot, rows, ebpf.UpdateNoExist); err != nil {
		_ = rows.Close()
		return fmt.Errorf("plane probe: put slot %d's %s map: %w", slot, ebpfbindings.MapPlaneRows, err)
	}
	if err := p.ExecRows.Update(slot, exec, ebpf.UpdateNoExist); err != nil {
		_ = rows.Close()
		return fmt.Errorf("plane probe: put slot %d's %s map: %w", slot, ebpfbindings.MapPlaneExecRows, err)
	}
	if err := p.ListenRows.Update(slot, listen, ebpf.UpdateNoExist); err != nil {
		_ = rows.Close()
		return fmt.Errorf("plane probe: put slot %d's %s map: %w", slot, ebpfbindings.MapPlaneListenRows, err)
	}
	names, err := ebpf.NewMap(p.nameInner)
	if err != nil {
		_ = rows.Close()
		return fmt.Errorf("plane probe: create slot %d's %s map: %w", slot, ebpfbindings.MapPlaneNameRows, err)
	}
	if err := p.NameRows.Update(slot, names, ebpf.UpdateNoExist); err != nil {
		_ = rows.Close()
		_ = names.Close()
		return fmt.Errorf("plane probe: put slot %d's %s map: %w", slot, ebpfbindings.MapPlaneNameRows, err)
	}
	if p.slotRows == nil {
		p.slotRows, p.slotNames = map[uint32]*ebpf.Map{}, map[uint32]*ebpf.Map{}
	}
	p.slotRows[slot], p.slotNames[slot] = rows, names
	return nil
}

// SlotRows is slot's fs row map, which this ProbeRows made (Preload, Fill), or nil for a slot it did not make. The
// ProbeRows keeps it open until Close.
func (p *ProbeRows) SlotRows(slot uint32) *ebpf.Map { return p.slotRows[slot] }

// Fill writes table's fs and exec rows into slot with gen through the real fill, from the descriptors held gives
// for their paths (this process's own), and checks them as Prepare does; with table.ExecPolicy, the bare-name rows
// too; the table's name entries (ADR 0043 D9, writeNameEntries); and last the slot's header of gen (slotHeader, exec
// decided as table.ExecPolicy says, the name check as the table's name rows say, no unix or net section). The
// slot's maps are made first where it has none.
func (p *ProbeRows) Fill(slot, gen uint32, table *decide.PlaneRows, held func(path string) (int, bool)) error {
	return p.fillSlot(slot, gen, table, held, nil)
}

// FillPinned is Fill for a slot whose run is pinned (ADR 0048 (7), doctor's exec pin cell), as Prepare fills a
// pinned run's: the slot's pin map is made and left empty, key is written with gen, and the header carries
// PlaneSlotExecPin and this process's pid namespace, so the plane holds each exec of the slot's run to the pin PutPin
// wrote for it.
func (p *ProbeRows) FillPinned(slot, gen uint32, table *decide.PlaneRows, held func(path string) (int, bool),
	key execpin.Key) error {
	dev, ino, err := launcherPidns()
	if err != nil {
		return err
	}
	return p.fillSlot(slot, gen, table, held, &planePin{Key: key, PidnsDev: dev, PidnsIno: ino})
}

// PutPin writes one exec's pin for thread tid (in this process's pid namespace) started at startTicks into the pin
// map of slot, which FillPinned made, with gen and seq.
func (p *ProbeRows) PutPin(slot, gen, seq, tid uint32, startTicks uint64, pin []byte) error {
	m := p.slotPins[slot]
	if m == nil || len(pin) != execpin.Size {
		return fmt.Errorf("plane probe: slot %d has no pin map", slot)
	}
	b := append([]byte(nil), pin...)
	execpin.SetGenSeq(b, gen, seq)
	return ebpfPinMap{m}.put(ebpfbindings.PinKey{TID: tid, Start: startTicks}, b)
}

// makePins makes slot's maps, once, and writes the run's key with gen (putPins, over this ProbeRows' maps).
func (p *ProbeRows) makePins(slot, gen uint32, pin *planePin) error {
	if err := p.makeSlot(slot); err != nil {
		return err
	}
	k0, k1 := pin.Key.Halves()
	if err := p.PinKeys.Put(slot, &ebpfbindings.PinKeyval{Gen: gen, K0: k0, K1: k1}); err != nil {
		return fmt.Errorf("plane probe: write slot %d's %s: %w", slot, ebpfbindings.MapPlanePinKeys, err)
	}
	return nil
}

// fillSlot is Fill, and with pin FillPinned.
func (p *ProbeRows) fillSlot(slot, gen uint32, table *decide.PlaneRows, held func(path string) (int, bool),
	pin *planePin) error {
	start := time.Now()
	if err := p.makeSlot(slot); err != nil {
		return err
	}
	if err := p.Preload(); err != nil {
		return err
	}
	slotMaps := time.Since(start)
	start = time.Now()
	plan, err := planPlaneFill(table, slot, gen, held, hostIdentity{})
	if err != nil {
		return err
	}
	planned := time.Since(start)
	start = time.Now()
	rep, err := p.filler.fill(plan, table, planeFillOptions{})
	if err != nil {
		return err
	}
	filled := time.Since(start)
	start = time.Now()
	defer func() {
		p.LastFill = fmt.Sprintf("slot maps %v, plan %v, fill %v (templates %v, pass %v, check %v), key rows and header %v",
			slotMaps, planned, filled, rep.Wants, rep.Fill, rep.Check, time.Since(start))
	}()
	req := planeFillRequest{Slot: slot, Gen: gen, Rows: table, Exec: planeExecPolicy{Decides: table.ExecPolicy}, Pin: pin}
	if pin != nil {
		if err := p.makePins(slot, gen, pin); err != nil {
			return err
		}
	}
	keys, vals, err := execKeyRows(req)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		exec, err := innerOf(p.ExecRows, slot, ebpfbindings.MapPlaneExecRows)
		if err != nil {
			return err
		}
		defer func() { _ = exec.Close() }()
		for i := range keys {
			if err := exec.Put(keys[i], &vals[i]); err != nil {
				return mapFull(ebpfbindings.MapPlaneExecRows, err)
			}
		}
	}
	if len(table.NameRows) > 0 {
		if err := writeNameEntries(p.slotNames[slot], slot, gen, table); err != nil {
			return err
		}
	}
	hdr := slotHeader(req, false, rep.Rows, rep.ExecRows+len(keys))
	if err := nameHeaderFits(req, &hdr); err != nil {
		return err
	}
	if err := p.Slots.Put(slot, &hdr); err != nil {
		return fmt.Errorf("plane probe: write slot %d's %s: %w", slot, ebpfbindings.MapPlaneSlots, err)
	}
	return nil
}

// Close releases the fill build and the four outers, and with them every slot's rows.
func (p *ProbeRows) Close() error {
	var errs []error
	if p.filler != nil {
		errs = append(errs, p.filler.Close())
	}
	for _, m := range p.slotRows {
		errs = append(errs, m.Close())
	}
	for _, m := range p.slotPins {
		errs = append(errs, m.Close())
	}
	for _, m := range p.slotNames {
		errs = append(errs, m.Close())
	}
	for _, m := range []*ebpf.Map{p.Rows, p.ExecRows, p.ListenRows, p.NameRows, p.Slots, p.ExecPins, p.PinKeys} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	return errors.Join(errs...)
}
