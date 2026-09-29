// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Ring kinds: a run's two rings, each in its own outer (ADR 0026 (1)). The value is the name the kernel shows
// for the ring (bpftool map list), at most 15 bytes.
const (
	// RingRecord is a run's record ring, in MapEvents.
	RingRecord = "tego_rec_ring"
	// RingCapture is a run's capture ring, in MapCaptureEvents.
	RingCapture = "tego_cap_ring"
)

// OuterOf names the outer map a ring kind lives in.
func OuterOf(kind string) string {
	if kind == RingCapture {
		return MapCaptureEvents
	}
	return MapEvents
}

// NewRing creates one run's ring buffer of size bytes, which must be a power of two and a multiple of the page
// size (the kernel refuses anything else). It is inserted into its outer at the run's slot by InsertRing.
func NewRing(kind string, size uint32) (*ebpf.Map, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: kind, Type: ebpf.RingBuf, MaxEntries: size})
	if err != nil {
		return nil, fmt.Errorf("bpf: create a %d-byte %s: %w", size, kind, err)
	}
	return m, nil
}

// InsertRing puts ring into outer at slot, replacing whatever ring the slot held: the kernel drops the outer's
// reference on the old one, which is freed once no reader holds it either.
func InsertRing(outer *ebpf.Map, slot uint32, ring *ebpf.Map) error {
	if slot >= MaxSlots {
		return fmt.Errorf("%w: %d", ErrSlot, slot)
	}
	if err := outer.Update(slot, ring, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: insert the ring of slot %d: %w", slot, err)
	}
	return nil
}

// RingOf opens the ring outer holds at slot. ok is false when the slot has none, which is not an error: a run
// whose capture is not uprobe has no capture ring. A ring removed between the outer's lookup and its opening by
// id is none as well. The caller closes the map it gets.
func RingOf(outer *ebpf.Map, slot uint32) (ring *ebpf.Map, ok bool, err error) {
	return OpenInner(outer, slot)
}

// OpenInner opens the map a HASH_OF_MAPS outer (a ring outer, a plane rows outer) holds at key, read as InnerIDs
// reads it. ok is false when the key holds none, or held one that is gone by the time it is opened. The caller
// closes the map it gets.
func OpenInner(outer *ebpf.Map, key uint32) (inner *ebpf.Map, ok bool, err error) {
	ids, err := InnerIDs(outer)
	if err != nil {
		return nil, false, err
	}
	id, ok := ids[key]
	if !ok {
		return nil, false, nil
	}
	return OpenRing(id)
}

// InnerIDs lists the inner maps a HASH_OF_MAPS outer holds, by key, as map ids, in one BPF_MAP_LOOKUP_BATCH.
//
// Not bpf(BPF_MAP_LOOKUP_ELEM): below 6.7 every userspace lookup of a map-of-maps ends in synchronize_rcu
// (bpf_map_copy_value's maybe_wait_bpf_programs, dropped upstream by 2a0c6b41eec9), 20-60 ms each on a loaded host,
// and a run's start made about nine of them: 440 ms of a 600 ms start on AL2023's 6.1 (enforce-plane §2.18). The
// hash table's batch lookup reads each inner map's id without that wait on every supported kernel. A kernel or map
// whose batch lookup fails is walked and looked up key by key as before (RingIDs's walk), so the answer never
// depends on which ran; either is a snapshot a concurrent insert or removal may or may not be in.
func InnerIDs(outer *ebpf.Map) (map[uint32]uint32, error) {
	if ids, err := batchInnerIDs(outer); err == nil {
		return ids, nil
	}
	return ringIDs(outer)
}

// batchInnerIDs is InnerIDs through BPF_MAP_LOOKUP_BATCH: one call for the whole outer, a batch as large as the
// outer (so no bucket is larger than it, which the hash table's batch refuses with ENOSPC), and at most one call per
// entry however the kernel splits it.
func batchInnerIDs(outer *ebpf.Map) (map[uint32]uint32, error) {
	n := int(outer.MaxEntries())
	if n == 0 || outer.KeySize() != 4 || outer.ValueSize() != 4 {
		return nil, fmt.Errorf("bpf: %s is not an outer keyed and valued by 32 bits", outer)
	}
	keys, vals := make([]uint32, n), make([]uint32, n)
	out := map[uint32]uint32{}
	var cursor ebpf.MapBatchCursor
	for range n + 1 {
		got, err := outer.BatchLookup(&cursor, keys, vals, nil)
		for i := range got {
			out[keys[i]] = vals[i]
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("bpf: the batch lookup of %s did not end", outer)
}

// OpenRing opens a ring by the map id an outer holds for it. ok is false when the ring is gone: freed since the
// id was read, which a walk of the outers meets whenever another process removes a ring meanwhile.
func OpenRing(id uint32) (ring *ebpf.Map, ok bool, err error) {
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("bpf: open ring %d: %w", id, err)
	}
	return m, true, nil
}

// DeleteRing removes outer's ring at slot; a slot with none is not an error.
func DeleteRing(outer *ebpf.Map, slot uint32) error {
	if err := outer.Delete(slot); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("bpf: remove the ring of slot %d: %w", slot, err)
	}
	return nil
}

// RingIDs lists the rings outer holds, by slot, as map ids to open with OpenRing. It walks the keys first and
// looks each up after, so a ring another process inserts or removes meanwhile is only missing or present, never
// an error: a slot whose lookup finds nothing any more is left out. A key removed under the walk restarts the
// kernel's walk at the first key; the walk then skips every key it has already seen and goes on past them, so
// the keys it had not reached yet are still listed. The walk is bounded by twice the outer's size. It reads the
// outer as InnerIDs does, by one batch lookup where the kernel answers one, and by this walk otherwise.
func RingIDs(outer *ebpf.Map) (map[uint32]uint32, error) { return InnerIDs(outer) }

// ringOuter is what RingIDs needs of the outer, so a test can remove a key under the walk.
type ringOuter interface {
	NextKey(key, nextKeyOut any) error
	Lookup(key, valueOut any) error
	MaxEntries() uint32
}

func ringIDs(outer ringOuter) (map[uint32]uint32, error) {
	var (
		keys []uint32
		seen = map[uint32]bool{}
		prev any
		next uint32
	)
	for i := 0; i < 2*int(outer.MaxEntries())+1; i++ {
		err := outer.NextKey(prev, &next)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bpf: walk the ring outer: %w", err)
		}
		k := next
		prev = &k
		if seen[k] {
			continue // a removal restarted the walk at the first key: skip what was seen and go on past it
		}
		seen[k] = true
		keys = append(keys, k)
	}
	out := make(map[uint32]uint32, len(keys))
	for _, k := range keys {
		var id uint32
		err := outer.Lookup(k, &id)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bpf: look up the ring of slot %d: %w", k, err)
		}
		out[k] = id
	}
	return out, nil
}

// DrainRing consumes every record ring holds that a producer has committed, so the run that reuses it starts
// reading at an empty ring (ADR 0026 (6) as amended). It does not stop at a record still being written:
// cilium's Reader.ReadInto retries a record whose header is busy (reserved, not yet submitted or discarded)
// until the producer commits it, so the drain waits for that record, which a BPF program always submits or
// discards before it returns, and moves past it (a discarded one is skipped, not counted). It stops once the consumer reaches the producer position it
// reads, with the deadline already passed; a record reserved after that is left for the reusing run's reader,
// which drops it by its generation. It returns how many it consumed.
func DrainRing(ring *ebpf.Map) (int, error) {
	rd, err := ringbuf.NewReader(ring)
	if err != nil {
		return 0, fmt.Errorf("bpf: read %s to drain it: %w", ring, err)
	}
	defer func() { _ = rd.Close() }()
	rd.SetDeadline(time.Now())
	var (
		rec ringbuf.Record
		n   int
	)
	for {
		err := rd.ReadInto(&rec)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return n, nil
		}
		if err != nil {
			return n, fmt.Errorf("bpf: drain %s: %w", ring, err)
		}
		n++
	}
}

// SlotCount reads a per-run counter (MapLost, MapCaptureLost, MapCaptureMiss) at slot.
func SlotCount(m *ebpf.Map, slot uint32) (uint64, error) {
	var n uint64
	if err := m.Lookup(slot, &n); err != nil {
		return 0, fmt.Errorf("bpf: read slot %d of %s: %w", slot, m, err)
	}
	return n, nil
}

// ActivityAt reads the activity stamp at slot of MapActivity (ActivitySlot.MonoNS): 0 is no activity.
func ActivityAt(m *ebpf.Map, slot uint32) (uint64, error) {
	var a ActivitySlot
	if err := m.Lookup(slot, &a); err != nil {
		return 0, fmt.Errorf("bpf: read slot %d of %s: %w", slot, m, err)
	}
	return a.MonoNS, nil
}

// ZeroSlot resets a per-run slot map at slot, a counter (so the slot's next run counts from its own start, ADR 0026
// (4)) or the activity stamp: the value is zeroed whole, whatever its size.
func ZeroSlot(m *ebpf.Map, slot uint32) error {
	if err := m.Update(slot, make([]byte, m.ValueSize()), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: zero slot %d of %s: %w", slot, m, err)
	}
	return nil
}

// Memlock reads the memory a map charges, the "memlock:" line of its fdinfo: for a ring buffer, its data pages
// (mapped twice, counted once), its page array and its header (about 8,433,944 B for 8 MiB, ADR 0026).
//
// A kernel whose ring buffer reports no size (the map's memory-usage operation is 6.2's: AL2023's 6.1 prints
// "memlock: 0" for a ring) would read as a ring that costs nothing and let bpf.ring_budget be passed without
// limit, so a ring reading 0 is charged what its layout holds (ringFootprint).
func Memlock(m *ebpf.Map) (uint64, error) {
	n, err := fdinfoMemlock(m)
	if err == nil && n == 0 && m.Type() == ebpf.RingBuf {
		n = ringFootprint(m.MaxEntries(), uint64(os.Getpagesize()))
	}
	return n, err
}

// ringFootprint is what a ring buffer of size bytes holds: its data pages, the page array that maps them (8 B a
// page) and the consumer, producer and header pages, a little under what the kernel charges an 8 MiB ring
// (8,433,944 B) and never under the ring's own bytes.
func ringFootprint(size uint32, page uint64) uint64 {
	return uint64(size) + uint64(size)/page*8 + 3*page
}

// fdinfoMemlock reads the memlock line of m's fdinfo inside MapFD's lend: procfs looks the number up in the
// descriptor table each time the fdinfo is read, not when it is opened, so the open, the read and the close all run
// while m's number is lent (ADR 0023).
func fdinfoMemlock(m *ebpf.Map) (uint64, error) {
	var n uint64
	var found bool
	err := MapFD(m, func(fd int) error {
		f, err := sys.Own(unix.Open("/proc/self/fdinfo/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			return err
		}
		file, err := f.Release("fdinfo")
		if err != nil {
			_ = f.Close()
			return err
		}
		defer func() { _ = file.Close() }()
		s := bufio.NewScanner(file)
		for s.Scan() {
			if v, ok := strings.CutPrefix(s.Text(), "memlock:"); ok {
				found = true
				n, err = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
				return err
			}
		}
		return s.Err()
	})
	switch {
	case err != nil && found:
		return 0, fmt.Errorf("bpf: memlock of %s: %w", m, err)
	case err != nil:
		return 0, fmt.Errorf("bpf: read the fdinfo of %s: %w", m, err)
	case !found:
		return 0, fmt.Errorf("bpf: the fdinfo of %s has no memlock line", m)
	}
	return n, nil
}
