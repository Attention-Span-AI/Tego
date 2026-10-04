// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// TestInnerIDsReadTheOuterByBatch: on this kernel a HASH_OF_MAPS outer is read by one batch lookup, never by the
// per-key lookups that end in synchronize_rcu below 6.7 (enforce-plane §2.18), and the batch reads what they read:
// each key's inner map id, and no key the outer does not hold. OpenInner opens the map a key holds and says none for
// a key it does not. The timings are logged: on AL2023's 6.1 a lookup of the outer waits a grace period.
func TestInnerIDsReadTheOuterByBatch(t *testing.T) {
	requireBPF(t)
	inner := &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	outer, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.HashOfMaps, KeySize: 4, MaxEntries: MaxSlots, InnerMap: inner})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outer.Close() }()
	want := map[uint32]uint32{}
	for _, key := range []uint32{0, 3, 17, MaxSlots - 1} {
		m, err := ebpf.NewMap(inner)
		if err != nil {
			t.Fatal(err)
		}
		if err := outer.Update(key, m, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := info.ID()
		want[key] = uint32(id)
		_ = m.Close()
	}

	start := time.Now()
	got, err := batchInnerIDs(outer)
	batch := time.Since(start)
	if err != nil {
		t.Fatalf("this kernel's batch lookup of a HASH_OF_MAPS failed, so every run would take the per-key lookups: %v", err)
	}
	if !maps.Equal(got, want) {
		t.Fatalf("batchInnerIDs = %v, want %v", got, want)
	}
	start = time.Now()
	walked, err := ringIDs(outer)
	walk := time.Since(start)
	if err != nil || !maps.Equal(walked, want) {
		t.Fatalf("the per-key walk = %v, %v, want %v", walked, err, want)
	}
	t.Logf("%d inner maps: batch lookup %v, per-key lookups %v", len(want), batch, walk)

	for key, id := range want {
		m, ok, err := OpenInner(outer, key)
		if err != nil || !ok {
			t.Fatalf("OpenInner(%d) = %v, %v", key, ok, err)
		}
		info, err := m.Info()
		_ = m.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := info.ID(); uint32(got) != id {
			t.Errorf("OpenInner(%d) opened map %d, the outer holds %d", key, got, id)
		}
	}
	if m, ok, err := OpenInner(outer, 5); ok || err != nil {
		t.Errorf("OpenInner of a key the outer does not hold = %v, %v, %v", m, ok, err)
	}
	if err := outer.Delete(uint32(3)); err != nil {
		t.Fatal(err)
	}
	if got, err := InnerIDs(outer); err != nil || len(got) != len(want)-1 {
		t.Errorf("InnerIDs after a removal = %v, %v", got, err)
	} else if _, ok := got[3]; ok {
		t.Errorf("InnerIDs still lists the removed key: %v", got)
	}
	if _, err := outer.BatchLookup(new(ebpf.MapBatchCursor), make([]uint32, 1), make([]uint32, 1), nil); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Logf("a batch of one: %v (batchInnerIDs asks for the whole outer at once)", err)
	}
}
