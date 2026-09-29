// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"slices"
	"testing"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// churnMap is a hash map as the kernel walks one: get_next_key on a key that is gone restarts at the first key.
// afterNext runs after every step, as another launcher's Detach or a cgroup_rmdir would between two syscalls.
type churnMap[K comparable] struct {
	keys      []K
	rows      map[K]ebpfbindings.Run
	max       uint32
	steps     int
	deleted   []K
	afterNext func(m *churnMap[K], handed K)
}

func (m *churnMap[K]) MaxEntries() uint32 { return m.max }

func (m *churnMap[K]) NextKey(key, out any) error {
	m.steps++
	i := 0
	if key != nil {
		i = slices.Index(m.keys, *key.(*K)) + 1 // a key that is gone gives index -1+1: the first key
	}
	if i >= len(m.keys) {
		return ebpf.ErrKeyNotExist
	}
	handed := m.keys[i]
	*out.(*K) = handed
	if m.afterNext != nil {
		m.afterNext(m, handed)
	}
	return nil
}

func (m *churnMap[K]) Lookup(key, out any) error {
	row, ok := m.rows[*key.(*K)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*out.(*ebpfbindings.Run) = row
	return nil
}

func (m *churnMap[K]) Delete(key any) error {
	k := *key.(*K)
	i := slices.Index(m.keys, k)
	if i < 0 {
		return ebpf.ErrKeyNotExist
	}
	m.keys = slices.Delete(m.keys, i, i+1)
	delete(m.rows, k)
	m.deleted = append(m.deleted, k)
	return nil
}

// TestPurgeRowsOfSlotWalksThroughChurn pins that a verdict map other runs are deleting from does not fail the
// purge. The map is more than half full and another run's Detach removes each of its rows just as the walk
// hands it over, so every such step restarts the walk. cilium's MapIterator counted those restarts against
// max_entries and returned ErrIterationAborted, failing this run's Prepare although its own rows were fine.
func TestPurgeRowsOfSlotWalksThroughChurn(t *testing.T) {
	t.Parallel()
	key := func(slot uint32, port uint16) ebpfbindings.NetKey {
		return ebpfbindings.NetKey{RunIdx: slot, Port: port}
	}
	// A third run's row and the dead run's rows in slot 2 come first in walk order, so every restart walks
	// back over them; then another live run's rows, detaching now.
	m := &churnMap[ebpfbindings.NetKey]{max: 16, keys: []ebpfbindings.NetKey{key(7, 1), key(2, 1), key(2, 2)}}
	for p := uint16(1); p <= 12; p++ {
		m.keys = append(m.keys, key(1, p))
	}
	var detached []ebpfbindings.NetKey
	m.afterNext = func(m *churnMap[ebpfbindings.NetKey], handed ebpfbindings.NetKey) {
		if handed.RunIdx == 1 {
			_ = m.Delete(&handed)
			detached = append(detached, handed)
		}
	}
	err := purgeRowsOfSlotIn(m, m, "tego_net_exact", 2, func(k *ebpfbindings.NetKey) uint32 { return k.RunIdx })
	if err != nil {
		t.Fatalf("purgeRowsOfSlotIn: %v", err)
	}
	if m.steps <= int(m.max) {
		t.Fatalf("the walk took %d steps; the fixture must take more than max_entries %d to be the case "+
			"cilium's iterator aborts on", m.steps, m.max)
	}
	purged := slices.DeleteFunc(slices.Clone(m.deleted), func(k ebpfbindings.NetKey) bool { return k.RunIdx == 1 })
	if want := []ebpfbindings.NetKey{key(2, 1), key(2, 2)}; !slices.Equal(purged, want) {
		t.Fatalf("purged %v, want %v", purged, want)
	}
	if !slices.Equal(m.keys, []ebpfbindings.NetKey{key(7, 1)}) {
		t.Fatalf("left %v, want only the third run's row", m.keys)
	}
}

// TestRunSetSlotsWalksThroughChurn is the same for the run set acquire reads under the slot table's flock:
// cgroup_rmdir removing rows under the walk must neither fail the acquire nor drop a slot a surviving row
// carries, since handing that slot out would give a live cgroup's tasks another run's rows (ADR 0026 (6)).
func TestRunSetSlotsWalksThroughChurn(t *testing.T) {
	t.Parallel()
	m := &churnMap[uint64]{max: 8, keys: []uint64{200}, rows: map[uint64]ebpfbindings.Run{200: {RunIdx: 5}}}
	for id := uint64(100); id < 106; id++ {
		m.keys = append(m.keys, id)
		m.rows[id] = ebpfbindings.Run{RunIdx: 3}
	}
	m.afterNext = func(m *churnMap[uint64], handed uint64) {
		if handed < 200 {
			_ = m.Delete(&handed) // the cgroup is removed as the walk reaches its row
		}
	}
	got, err := runSetSlotsIn(m)
	if err != nil {
		t.Fatalf("runSetSlotsIn: %v", err)
	}
	if m.steps <= int(m.max) {
		t.Fatalf("the walk took %d steps, want more than max_entries %d", m.steps, m.max)
	}
	if !got[5] || got[3] {
		t.Fatalf("slots %v, want {5}: slot 3's rows were all gone before their lookup", got)
	}
}

// TestMapKeysFailsAWalkThatCannotFinish pins the bound: a map whose first key is deleted and replaced on every
// step never lets the walk end, and the walk fails (closed) instead of returning a partial list as complete.
func TestMapKeysFailsAWalkThatCannotFinish(t *testing.T) {
	t.Parallel()
	m := &churnMap[uint32]{max: 4, keys: []uint32{1, 2}}
	next := uint32(10)
	m.afterNext = func(m *churnMap[uint32], handed uint32) {
		_ = m.Delete(&handed)
		m.keys = append([]uint32{next}, m.keys...)
		next++
	}
	_, err := mapKeys[uint32](m)
	if !errors.Is(err, ebpf.ErrIterationAborted) {
		t.Fatalf("mapKeys = %v, want ErrIterationAborted", err)
	}
}
