// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// A run's live blocks in its plane slot (ADR 0124, amendment 2026-11-21). The launcher's live-block poll
// (internal/runtime liveblock_plane.go) decides which objects a block's path names and holds an O_PATH descriptor of
// each; this file writes and deletes their rows through the plane's fill, in the kernel, so no key leaves it, and
// writes the slot's block state the hooks read first.

// PlaneBlockFill is one live-block row to write or delete.
type PlaneBlockFill struct {
	// FD is the launcher's O_PATH descriptor of the keyed object, or of a name row's directory. Each row has its own:
	// the fill's wants key has one kind left for them (bpf.PlaneFillBlockKey). The fill lends its number for the pass
	// only (sys.LendAll).
	FD *sys.FD
	// Ino is FD's inode number when it was opened (fstat), which the fill must find there.
	Ino uint64
	// Name is a name row: NameKey (bpf.PlaneBlockNameKey of a name that did not exist) under the directory FD.
	Name    bool
	NameKey uint64
	// Delete removes the row instead of writing it.
	Delete bool
	// From is the CLOCK_BOOTTIME instant before which the row refuses nothing (a dormant block), 0 for now.
	From uint64
	// Read, Write and Guard are the blocks' ids (bpf.PlaneBlockRow's), 0 for none; Flags its PlaneBlock* flags.
	Read, Write, Guard uint16
	Flags              uint8
}

// PlaneBlockResult is what the fill did with one PlaneBlockFill: nil, ErrPlaneBlockFull (the slot's block map has no
// room), ErrPlaneBlockClash (another object's row has the key) or another error.
type PlaneBlockResult struct{ Err error }

// ErrPlaneBlockFull is a live-block row the slot's map had no room for (bpf.PlaneBlockRowsMax).
var ErrPlaneBlockFull = errors.New("the slot's live-block map is full")

// ErrPlaneBlockClash is a live-block row whose key another object's row of the run holds (two names' keys that
// collided).
var ErrPlaneBlockClash = errors.New("another object's live-block row has the key")

// PlaneBlockWriter writes a run's live-block rows and state in its plane slot. The runtime holds it for the run.
type PlaneBlockWriter interface {
	// SetState writes the slot's block state whole: on and names as the rows now are or are about to be, over the
	// classes in overflow (bpf.PlaneBlockRead, PlaneBlockWrite) and the blocks they are named by.
	SetState(st ebpfbindings.PlaneBlockState) error
	// Fill writes or deletes rows, one result each, in order; the error is a fill that could not run at all.
	Fill(rows []PlaneBlockFill) ([]PlaneBlockResult, error)
}

// PlaneBlocks is the run's live-block writer, and false when the run has no plane that decides its file changes in
// the kernel (no plane mode, a Prepare that has not filled, a plane without the block maps).
func (h *Handle) PlaneBlocks() (PlaneBlockWriter, bool) {
	if h == nil || h.planeMode == "" || !h.planeFilled {
		return nil, false
	}
	p, ok := h.plane.(*bpfPlane)
	if !ok || p.blocks == nil || p.blockStates == nil || p.filler == nil || p.filler.blocks == nil {
		return nil, false
	}
	return &planeBlockWriter{h: h, plane: p}, true
}

type planeBlockWriter struct {
	h     *Handle
	plane *bpfPlane
}

func (w *planeBlockWriter) live() error {
	w.h.netMu.Lock()
	defer w.h.netMu.Unlock()
	if w.h.detached {
		return fmt.Errorf("%w: run %s is detached", ErrNotPrepared, w.h.run.ID)
	}
	return nil
}

func (w *planeBlockWriter) SetState(st ebpfbindings.PlaneBlockState) error {
	if err := w.live(); err != nil {
		return err
	}
	st.Gen = w.h.gen
	if err := w.plane.blockStates.Put(w.h.slot, &st); err != nil {
		return fmt.Errorf("cgroup: write slot %d's %s: %w", w.h.slot, ebpfbindings.MapPlaneBlockStates, err)
	}
	return nil
}

func (w *planeBlockWriter) Fill(rows []PlaneBlockFill) ([]PlaneBlockResult, error) {
	if err := w.live(); err != nil {
		return nil, err
	}
	got, err := w.plane.filler.fillBlocks(w.h.slot, w.h.gen, rows)
	if err != nil {
		return nil, err
	}
	return blockResults(rows, got), nil
}

// blockResults reads the fill's report of each row: written (or deleted) at the inode the descriptor had when the
// launcher opened it, or why not.
func blockResults(rows []PlaneBlockFill, got []ebpfbindings.PlaneFillRow) []PlaneBlockResult {
	out := make([]PlaneBlockResult, len(rows))
	for i, r := range rows {
		g := got[i]
		switch {
		case g.Status == ebpfbindings.PlaneFillOK && g.Ino == r.Ino:
		case g.Status == ebpfbindings.PlaneFillOK:
			out[i].Err = fmt.Errorf("plane block: %s named inode %d at the fill, %d when opened", r.FD, g.Ino, r.Ino)
		case g.Status == ebpfbindings.PlaneFillUpdate && (unix.Errno(-g.Err) == unix.E2BIG || unix.Errno(-g.Err) == unix.ENOMEM):
			out[i].Err = ErrPlaneBlockFull
		case g.Status == ebpfbindings.PlaneFillDup:
			out[i].Err = ErrPlaneBlockClash
		default:
			out[i].Err = fmt.Errorf("plane block: %s: %s", r.FD, g.Status)
		}
	}
	return out
}

// blockTemplate is a row's fill template, for the launcher's tgid and the run's gen.
func blockTemplate(r PlaneBlockFill, gen uint32) ebpfbindings.PlaneFillRow {
	v := ebpfbindings.PlaneFillRow{Gen: gen, BlockFrom: r.From, BlockRead: r.Read, BlockWrite: r.Write,
		BlockGuard: r.Guard, BlockFlags: r.Flags}
	switch {
	case r.Name && r.Delete:
		v.What = ebpfbindings.PlaneFillBlockNameDel
	case r.Name:
		v.What = ebpfbindings.PlaneFillBlockName
	case r.Delete:
		v.What = ebpfbindings.PlaneFillBlockDel
	default:
		v.What = ebpfbindings.PlaneFillBlock
	}
	if r.Name {
		v.BlockNameKey = r.NameKey
	}
	return v
}

// fillBlocks writes rows' templates under this launcher's tgid, runs one pass of the fill over its descriptor table,
// and returns what the kernel reported for each, in order. A row's descriptor appears at most once. The templates are
// keyed by the descriptors' numbers, which sys.LendAll lends for the pass: they are written, read and deleted inside
// it, so no key outlives the lease that makes its number name the row's file (ADR 0023 amendment 2026-11-22).
func (f *planeFiller) fillBlocks(runIdx, gen uint32, rows []PlaneBlockFill) (got []ebpfbindings.PlaneFillRow, err error) {
	if f.blocks == nil {
		return nil, fmt.Errorf("plane block: the %s fill has no %s", f.obj, ebpfbindings.MapPlaneBlocks)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if gen == 0 {
		return nil, errors.New("plane block: gen 0 is no run's")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tgid := uint32(os.Getpid())
	owners := make([]*sys.FD, len(rows))
	vals := make([]ebpfbindings.PlaneFillRow, len(rows))
	seen := make(map[*sys.FD]bool, len(rows))
	for i, r := range rows {
		if r.FD == nil || seen[r.FD] {
			return nil, fmt.Errorf("plane block: descriptor %s named twice or not at all", r.FD)
		}
		seen[r.FD] = true
		owners[i] = r.FD
		vals[i] = blockTemplate(r, gen)
	}
	cfg := ebpfbindings.PlaneFillCfg{Tgid: tgid, RunIdx: runIdx, Gen: gen}
	if err := putRoom(func() error { return f.config.Put(tgid, &cfg) }, f.purgeStale); err != nil {
		return nil, fmt.Errorf("plane block: config: %w", err)
	}
	defer func() {
		if derr := f.config.Delete(tgid); derr != nil && err == nil {
			err = fmt.Errorf("plane block: remove the config: %w", derr)
		}
	}()
	err = sys.LendAll(owners, func(nums []int) error {
		keys := ebpfbindings.PlaneFillBlockKeys(tgid, nums)
		perr := putWantsRoom(f.wants, keys, vals, f.purgeStale)
		if perr == nil {
			_, perr = runFillPass(f.prog, false)
		}
		if perr == nil {
			got, perr = readWants(f.wants, keys)
		}
		if derr := deleteWants(f.wants, keys); derr != nil && perr == nil {
			perr = derr
		}
		return perr
	})
	if err != nil {
		return nil, err
	}
	return got, nil
}

// putWantsRoom is putWants under putRoom: the fill templates at keys, the stale ones of dead launchers purged once
// when the map is full. tools/fdcheck admits keys here as lent numbers' encoding (lentSinks), as it does readWants'
// and deleteWants': the caller deletes them before its lease ends.
func putWantsRoom(m *ebpf.Map, keys []uint64, vals []ebpfbindings.PlaneFillRow, purge func() error) error {
	return putRoom(func() error { return putWants(m, keys, vals) }, purge)
}
