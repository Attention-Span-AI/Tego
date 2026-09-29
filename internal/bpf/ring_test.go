// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// fakeOuter is a ring outer with the kernel's hash-map walk: NextKey of a key no longer there restarts at the
// first key. afterNext runs once each key is handed out, so a test can remove one under the walk.
type fakeOuter struct {
	keys      []uint32 // in walk order
	ids       map[uint32]uint32
	afterNext func(f *fakeOuter, handed uint32)
}

func (f *fakeOuter) NextKey(key, out any) error {
	i := 0
	if key != nil {
		prev := *key.(*uint32)
		i = -1
		for j, k := range f.keys {
			if k == prev {
				i = j + 1
			}
		}
		if i < 0 {
			i = 0 // prev is gone: the kernel starts again at the first key
		}
	}
	if i >= len(f.keys) {
		return ebpf.ErrKeyNotExist
	}
	k := f.keys[i]
	*out.(*uint32) = k
	if f.afterNext != nil {
		f.afterNext(f, k)
	}
	return nil
}

func (f *fakeOuter) Lookup(key, out any) error {
	id, ok := f.ids[key.(uint32)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*out.(*uint32) = id
	return nil
}

func (f *fakeOuter) MaxEntries() uint32 { return 16 }

func (f *fakeOuter) remove(k uint32) {
	for j, v := range f.keys {
		if v == k {
			f.keys = append(f.keys[:j], f.keys[j+1:]...)
		}
	}
	delete(f.ids, k)
}

// TestRingIDsWalksPastARestart pins that a ring removed under the walk, which restarts the kernel's walk at the
// first key, does not end it: the rings after the removed one were never visited and are still there, so an
// unlocked reader (tego doctor, the build listing) that stopped at the restart would undercount the budget.
func TestRingIDsWalksPastARestart(t *testing.T) {
	t.Parallel()
	f := &fakeOuter{
		keys: []uint32{1, 2, 3, 4},
		ids:  map[uint32]uint32{1: 11, 2: 12, 3: 13, 4: 14},
	}
	f.afterNext = func(f *fakeOuter, handed uint32) {
		if handed == 2 {
			f.afterNext = nil
			f.remove(2) // another launcher trims slot 2 while the walk is on it
		}
	}
	got, err := ringIDs(f)
	if err != nil {
		t.Fatalf("ringIDs: %v", err)
	}
	want := map[uint32]uint32{1: 11, 3: 13, 4: 14}
	if len(got) != len(want) {
		t.Fatalf("ringIDs = %v, want %v", got, want)
	}
	for k, id := range want {
		if got[k] != id {
			t.Fatalf("ringIDs = %v, want %v", got, want)
		}
	}
}
