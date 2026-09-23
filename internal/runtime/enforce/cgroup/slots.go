// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// run_idx is a dense per-host slot, never the run's string id (§5 R12), and it must be unique across launcher
// *processes*, not just goroutines (§6 E21) — the spec leaves the mechanism open (§11). This implementation
// is a fixed-size table of owner records in the runtime directory, mutated under an exclusive flock on the
// table itself: it needs no kernel, works before any BPF object is loaded, is testable without privilege, and
// costs one open and one short read-modify-write per run.
//
// Each record is a pid and that pid's start time, so a slot whose owner died — including one whose pid has
// since been reused by another process — is reclaimed on the next acquire. A slot is therefore leaked only
// for as long as no one asks for one.
const (
	// slotRecordSize is the on-disk width of one slot record: pid, flags, start ticks.
	slotRecordSize = 16
	// slotFlagInUse marks an occupied record.
	slotFlagInUse uint32 = 1
	// slotEpochShift places the slot's epoch in the flags word above slotFlagInUse: the gen of the slot's current or
	// last run (Run.Gen), which release keeps, so the slot's next acquire hands out the one after it.
	slotEpochShift = 1
	// slotEpochMax is the largest epoch the flags word holds (31 bits); the next is 1 again, never 0.
	slotEpochMax uint32 = 1<<(32-slotEpochShift) - 1
	// slotTableName is the table's file name inside the runtime directory; the build hash is part of it
	// because two coexisting builds have two disjoint run_idx spaces (§6 E22).
	slotTableName = "slots"
)

// slotTable is the host-wide run_idx allocator. It holds no state between calls beyond the file's path, so
// two slotTable values over one path are as safe as two processes.
type slotTable struct {
	dir  *hoststate.Dir
	name string
	path string // for messages
	self owner
	// alive reports whether a slot's owner still exists; replaced in tests.
	alive func(owner) bool
	// peek opens the table without creating it: another build's, read by a ring reclaim (peekHeld).
	peek bool
}

// openSlotTableIn prepares the table for one build hash in a verified state directory (ADR 0034), which it
// takes over and closes in close. The file is created on first use, relative to the directory's descriptor.
func openSlotTableIn(d *hoststate.Dir, hash string) (*slotTable, error) {
	self, err := selfOwner()
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("cgroup: identify this process for slot allocation: %w", err)
	}
	name := slotTableName + "-" + hash
	return &slotTable{
		dir:   d,
		name:  name,
		path:  filepath.Join(d.Path(), name),
		self:  self,
		alive: owner.alive,
	}, nil
}

// close releases the table's directory.
func (s *slotTable) close() error {
	if s == nil {
		return nil
	}
	return s.dir.Close()
}

// acquireGen takes the lowest free slot and records this process as its owner. A slot occupied by a process that
// no longer exists is reclaimed. A slot carried says a run-set row still names it, a dead launcher's orphaned
// processes or a row its teardown could not remove, so it is not handed out, free or not: the new run would
// receive that row's samples and rows (ADR 0026 (6)). ErrSlotsExhausted means every slot is held by a live
// launcher or carried (§6 E12). carriedOf (nil: none) is called under the table's lock, so a launcher that
// inserted its row and died just before counts: read earlier, its slot would look held by a dead owner and not
// carried, and be reclaimed.
//
// It also returns the slot's new epoch: one more than the epoch its record kept (nextSlotEpoch), written back
// with the record. It is the gen the run's run-set row, plane rows and slot header carry (Run.Gen,
// ADR 0025 (1)): per slot, never 0, and repeated only after 2^31 - 1 acquires of that one slot, where the low half
// of a cgroup id repeated once kernfs's idr wrapped, host-wide.
func (s *slotTable) acquireGen(carriedOf func() (map[uint32]bool, error)) (uint32, uint32, error) {
	var idx, gen uint32
	err := s.withTable(func(f *os.File, records []byte) error {
		var carried map[uint32]bool
		if carriedOf != nil {
			var err error
			if carried, err = carriedOf(); err != nil {
				return err
			}
		}
		free := -1
		for i := 0; i < bpf.MaxSlots; i++ {
			if carried[uint32(i)] {
				continue
			}
			rec := records[i*slotRecordSize : (i+1)*slotRecordSize]
			flags := binary.LittleEndian.Uint32(rec[4:8])
			if flags&slotFlagInUse == 0 {
				if free < 0 {
					free = i
				}
				continue
			}
			o := owner{PID: binary.LittleEndian.Uint32(rec[0:4]), StartTicks: binary.LittleEndian.Uint64(rec[8:16])}
			// free first: once a slot is found, asking whether a later owner is alive changes nothing and is a
			// /proc read under the exclusive flock every launcher waits on.
			if free < 0 && !s.alive(o) {
				free = i // reclaimed from a launcher that died without releasing it
			}
		}
		if free < 0 {
			return fmt.Errorf("%w: all %d slots are held by live launchers or carried by run-set rows",
				ErrSlotsExhausted, bpf.MaxSlots)
		}
		idx = uint32(free)
		rec := records[free*slotRecordSize : (free+1)*slotRecordSize]
		gen = nextSlotEpoch(binary.LittleEndian.Uint32(rec[4:8]) >> slotEpochShift)
		binary.LittleEndian.PutUint32(rec[0:4], s.self.PID)
		binary.LittleEndian.PutUint32(rec[4:8], slotFlagInUse|gen<<slotEpochShift)
		binary.LittleEndian.PutUint64(rec[8:16], s.self.StartTicks)
		return writeRecord(f, free, rec)
	})
	if err != nil {
		return 0, 0, err
	}
	return idx, gen, nil
}

// nextSlotEpoch is the epoch after e: e+1, and 1 after slotEpochMax. Never 0, which a cleared slot header holds.
func nextSlotEpoch(e uint32) uint32 {
	if e >= slotEpochMax {
		return 1
	}
	return e + 1
}

// release frees a slot this process holds. It is idempotent: releasing a slot that is already free, or one
// another process now owns, changes nothing and reports no error, so Detach can run twice (§8 I10).
func (s *slotTable) release(idx uint32) error {
	if idx >= bpf.MaxSlots {
		return fmt.Errorf("%w: slot %d", ErrSlotsExhausted, idx)
	}
	return s.withTable(func(f *os.File, records []byte) error {
		rec := records[int(idx)*slotRecordSize : (int(idx)+1)*slotRecordSize]
		o := owner{PID: binary.LittleEndian.Uint32(rec[0:4]), StartTicks: binary.LittleEndian.Uint64(rec[8:16])}
		if o != s.self {
			return nil
		}
		// The owner and the in-use flag go; the epoch stays, for the slot's next acquire.
		epoch := binary.LittleEndian.Uint32(rec[4:8]) &^ slotFlagInUse
		for i := range rec {
			rec[i] = 0
		}
		binary.LittleEndian.PutUint32(rec[4:8], epoch)
		return writeRecord(f, int(idx), rec)
	})
}

// heldBy reports whether a live launcher holds slot idx.
func (s *slotTable) heldBy(idx uint32) (bool, error) {
	if idx >= bpf.MaxSlots {
		return false, fmt.Errorf("%w: slot %d", ErrSlotsExhausted, idx)
	}
	held := false
	err := s.withTable(func(_ *os.File, records []byte) error {
		rec := records[int(idx)*slotRecordSize : (int(idx)+1)*slotRecordSize]
		if binary.LittleEndian.Uint32(rec[4:8])&slotFlagInUse == 0 {
			return nil
		}
		held = s.alive(owner{PID: binary.LittleEndian.Uint32(rec[0:4]), StartTicks: binary.LittleEndian.Uint64(rec[8:16])})
		return nil
	})
	return held, err
}

// withTable opens the table, takes an exclusive flock on it, reads every record, runs fn, and releases the
// lock. flock is the right primitive here for the reason the build lock uses it too: it is released by the
// kernel when the holder's last descriptor closes, so it cannot go stale if a launcher is killed.
func (s *slotTable) withTable(fn func(f *os.File, records []byte) error) error {
	flags := os.O_RDWR | os.O_CREATE
	if s.peek {
		flags = os.O_RDWR
	}
	f, err := s.dir.OpenFile(s.name, flags, 0o600)
	if err != nil {
		return fmt.Errorf("cgroup: open slot table %s: %w", s.path, err)
	}
	defer func() { _ = f.Close() }()

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("cgroup: lock slot table %s: %w", s.path, err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()

	// A short or empty file is the normal first-use case: the zero records it is missing are free slots.
	const size = bpf.MaxSlots * slotRecordSize
	records := make([]byte, size)
	if _, err := f.ReadAt(records, 0); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("cgroup: read slot table %s: %w", s.path, err)
	}
	return fn(f, records)
}

// writeRecord writes one record back in place, so two processes that touch different slots never overwrite
// each other's work even though each read the whole table.
func writeRecord(f *os.File, idx int, rec []byte) error {
	if _, err := f.WriteAt(rec, int64(idx*slotRecordSize)); err != nil {
		return fmt.Errorf("cgroup: write slot %d: %w", idx, err)
	}
	return nil
}
