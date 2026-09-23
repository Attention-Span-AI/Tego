// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// TestPlaceRingOnARealOuter is placeRing, slotRings, drainRing and removeRing over a real ring outer, as root: a ring of a size other
// than the outer's 64 KiB prototype goes in at its slot, a reader opens it by the slot, its memlock (the kernel's
// own fdinfo figure) is at least its size, a ring whose memlock passes the room it is given is not inserted, and
// removeRing leaves the slot empty (ADR 0026 (1), (2)).
func TestPlaceRingOnARealOuter(t *testing.T) {
	outer, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "tego_it_rings", Type: ebpf.HashOfMaps, KeySize: 4, MaxEntries: 16,
		InnerMap: &ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 64 << 10},
	})
	if err != nil {
		t.Skipf("creating a ring outer needs CAP_BPF: %v", err)
	}
	defer func() { _ = outer.Close() }()
	k := &bpfKernel{maps: map[string]*ebpf.Map{ebpfbindings.MapEvents: outer}}

	memlock, placed, err := k.placeRing(ebpfbindings.RingRecord, 3, 1<<20, 1<<30)
	if err != nil || !placed {
		t.Fatalf("placeRing 1 MiB at slot 3 = %d, %v, %v", memlock, placed, err)
	}
	if memlock < 1<<20 || memlock > 1<<20+1<<16 {
		t.Errorf("a 1 MiB ring charges %d B of memlock", memlock)
	}
	ring, ok, err := ebpfbindings.RingOf(outer, 3)
	if err != nil || !ok {
		t.Fatalf("RingOf slot 3 = %v, %v", ok, err)
	}
	if ring.Type() != ebpf.RingBuf || ring.MaxEntries() != 1<<20 {
		t.Errorf("slot 3 holds a %s of %d bytes", ring.Type(), ring.MaxEntries())
	}
	_ = ring.Close()
	if _, placed, err := k.placeRing(ebpfbindings.RingRecord, 4, 1<<20, memlock-1); err != nil || placed {
		t.Errorf("a ring past its room was placed (%v, %v)", placed, err)
	}
	if _, ok, _ := ebpfbindings.RingOf(outer, 4); ok {
		t.Error("slot 4 holds a ring its room refused")
	}
	if have, err := k.slotRings(3); err != nil || have[ebpfbindings.RingRecord] != 1<<20 || len(have) != 1 {
		t.Errorf("slotRings(3) = %v, %v, want the 1 MiB record ring alone", have, err)
	}
	if err := k.drainRing(ebpfbindings.RingRecord, 3); err != nil {
		t.Errorf("drain an empty ring: %v", err)
	}
	if err := k.removeRing(ebpfbindings.RingRecord, 3); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ebpfbindings.RingOf(outer, 3); ok {
		t.Error("slot 3 still holds a ring after removeRing")
	}
	if err := k.removeRing(ebpfbindings.RingRecord, 3); err != nil {
		t.Errorf("removing a ring that is gone: %v", err)
	}
}

// TestInsertRunRefusesAnotherRunsRow is insertRun's re-read on EEXIST over a real run set: a row cgroup_track
// materialized with the value this run writes is this run's, and a row of another run is refused. A run
// cgroup made under another run's subtree gets the outer run's row from cgroup_track before its own Attach,
// and insertRun ignored EEXIST, so the inner run was recorded, and its record mode applied, as the outer's.
func TestInsertRunRefusesAnotherRunsRow(t *testing.T) {
	runSet, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "tego_it_runset",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  uint32(unsafe.Sizeof(ebpfbindings.Run{})),
		MaxEntries: 16,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("creating a BPF map needs CAP_BPF (kernel.unprivileged_bpf_disabled): %v", err)
		}
		t.Fatalf("create the run set: %v", err)
	}
	defer func() { _ = runSet.Close() }()
	k := &bpfKernel{maps: map[string]*ebpf.Map{ebpfbindings.MapRunSet: runSet}}

	mine := ebpfbindings.Run{RunIdx: 7, Descendants: 1, Tier: 2, Record: uint8(ebpfbindings.RecordSummary)}
	outer := ebpfbindings.Run{RunIdx: 3, Descendants: 1, Tier: 2, Record: uint8(ebpfbindings.RecordFull)}
	const fresh, materialized, nested = uint64(100), uint64(101), uint64(102)
	if err := runSet.Update(uint64(materialized), &mine, ebpf.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	if err := runSet.Update(uint64(nested), &outer, ebpf.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	if err := k.insertRun(fresh, mine); err != nil {
		t.Errorf("a new row: %v", err)
	}
	if err := k.insertRun(materialized, mine); err != nil {
		t.Errorf("a row cgroup_track wrote with this run's value: %v", err)
	}
	if err := k.insertRun(nested, mine); err == nil {
		t.Error("a cgroup the outer run's cgroup_track materialized was taken as this run's")
	}
	var got ebpfbindings.Run
	if err := runSet.Lookup(uint64(nested), &got); err != nil || got != outer {
		t.Errorf("the outer run's row is %+v (%v), want it untouched", got, err)
	}
}

// TestPurgeSlotOverRealMaps exercises the iterate-and-delete purgeSlot does against real maps of the three
// verdict layouts, which the fake kernel's Go maps cannot cover: a get_next_key walk of a BPF hash and of two
// LPM tries (the CIDR rows and the unix name rows, §5 R7), and the rule that only rows of the slot being
// reclaimed go (§5 R12, §8 I5). It is the kernel half of TestPrepareScrubsARecycledSlotsLeftoverRows.
func TestPurgeSlotOverRealMaps(t *testing.T) {
	exact, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "tego_it_exact",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(ebpfbindings.NetKey{})),
		ValueSize:  uint32(unsafe.Sizeof(ebpfbindings.NetVerdict{})),
		MaxEntries: ebpfbindings.NetRowsMax,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("creating a BPF map needs CAP_BPF (kernel.unprivileged_bpf_disabled): %v", err)
		}
		t.Fatalf("create the exact map: %v", err)
	}
	defer func() { _ = exact.Close() }()
	cidr, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "tego_it_cidr",
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(ebpfbindings.NetLPMKey{})),
		ValueSize:  uint32(unsafe.Sizeof(ebpfbindings.NetVerdict{})),
		MaxEntries: ebpfbindings.NetRowsMax,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		t.Fatalf("create the cidr trie: %v", err)
	}
	defer func() { _ = cidr.Close() }()
	names, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "tego_it_unix",
		Type:       ebpf.LPMTrie,
		KeySize:    4 + 4 + 1 + 1 + ebpfbindings.UnixNameMax, // struct tego_unix_key is packed
		ValueSize:  uint32(unsafe.Sizeof(ebpfbindings.NetVerdict{})),
		MaxEntries: ebpfbindings.UnixRowsMax,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		t.Fatalf("create the unix name trie: %v", err)
	}
	defer func() { _ = names.Close() }()

	k := &bpfKernel{maps: map[string]*ebpf.Map{
		ebpfbindings.MapNetExact:  exact,
		ebpfbindings.MapNetCIDR:   cidr,
		ebpfbindings.MapUnixNames: names,
	}}

	// Two runs' rows side by side, as the pinned maps hold them: one slot is being reclaimed from a launcher
	// that died, the other belongs to a launcher still running and must not lose a row.
	const dead, live = uint32(3), uint32(4)
	for _, slot := range []uint32{dead, live} {
		if err := k.populate(rowsForSlot(t, slot)); err != nil {
			t.Fatalf("populate slot %d: %v", slot, err)
		}
	}
	if err := k.purgeSlot(dead); err != nil {
		t.Fatalf("purgeSlot(%d): %v", dead, err)
	}

	var (
		key      ebpfbindings.NetKey
		lpmKey   ebpfbindings.NetLPMKey
		val      ebpfbindings.NetVerdict
		survived int
	)
	it := exact.Iterate()
	for it.Next(&key, &val) {
		if key.RunIdx == dead {
			t.Fatalf("%s still holds a row of the reclaimed slot %d (§5 R12, §8 I5)", ebpfbindings.MapNetExact, dead)
		}
		survived++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("walk %s: %v", ebpfbindings.MapNetExact, err)
	}
	if survived == 0 {
		t.Fatalf("%s: the live launcher's rows went with the dead one's", ebpfbindings.MapNetExact)
	}

	survived = 0
	it = cidr.Iterate()
	for it.Next(&lpmKey, &val) {
		if lpmKey.RunIdx == dead {
			t.Fatalf("%s still holds a row of the reclaimed slot %d (§5 R12, §8 I5)", ebpfbindings.MapNetCIDR, dead)
		}
		survived++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("walk %s: %v", ebpfbindings.MapNetCIDR, err)
	}
	if survived == 0 {
		t.Fatalf("%s: the live launcher's rows went with the dead one's", ebpfbindings.MapNetCIDR)
	}

	var unixKey ebpfbindings.UnixKey
	survived = 0
	it = names.Iterate()
	for it.Next(&unixKey, &val) {
		if unixKey.RunIdx == dead {
			t.Fatalf("%s still holds a row of the reclaimed slot %d (§5 R12, §8 I5)", ebpfbindings.MapUnixNames, dead)
		}
		survived++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("walk %s: %v", ebpfbindings.MapUnixNames, err)
	}
	if survived == 0 {
		t.Fatalf("%s: the live launcher's rows went with the dead one's", ebpfbindings.MapUnixNames)
	}
}

// rowsForSlot builds one run's worth of rows in the three maps through the production key builders, so the
// layout the purge walks is the one the hooks look up.
func rowsForSlot(t *testing.T, slot uint32) RuleMaps {
	t.Helper()
	var out RuleMaps
	allow := ebpfbindings.NetVerdict{Verdict: uint8(ebpfbindings.VerdictAllow), RuleIdx: 1}
	keys, err := ebpfbindings.NetKeys(slot, ebpfbindings.ProtoTCP, netip.MustParseAddr("198.51.100.4"), 443)
	if err != nil {
		t.Fatalf("exact keys for slot %d: %v", slot, err)
	}
	for _, k := range keys {
		out.Exact = append(out.Exact, NetRow{Key: k, Val: allow})
	}
	lpm, err := ebpfbindings.NetLPMKeys(slot, ebpfbindings.ProtoTCP, netip.MustParsePrefix("198.51.100.0/24"), 443)
	if err != nil {
		t.Fatalf("cidr keys for slot %d: %v", slot, err)
	}
	for _, k := range lpm {
		out.CIDR = append(out.CIDR, CIDRRow{Key: k, Val: allow})
	}
	for _, sub := range []bool{false, true} {
		k, err := ebpfbindings.UnixPathKey(slot, "/run/tego-it", sub)
		if err != nil {
			t.Fatalf("unix keys for slot %d: %v", slot, err)
		}
		out.Unix = append(out.Unix, UnixRow{Key: k, Val: allow})
	}
	return out
}
