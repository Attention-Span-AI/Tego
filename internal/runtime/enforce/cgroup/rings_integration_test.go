// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// ringBuild is a stand-in for one build's pins under a private tego tree in the bpf filesystem: a record ring
// outer and a run set, pinned by name as the objects pin theirs.
type ringBuild struct {
	outer, runSet *ebpf.Map
}

// ringTree makes a private bpf-filesystem root for this test, as root, and returns it: its tego tree is where
// ringUse and the reclaims look.
func ringTree(t *testing.T) string {
	t.Helper()
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("no bpf filesystem: %v", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to pin maps")
	}
	root := filepath.Join(DefaultBPFFS, "tego-it-rings-"+strconv.Itoa(os.Getpid())+"-"+t.Name())
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Mkdir(filepath.Join(root, pinRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

// newRingBuild pins a build's record ring outer and run set under root's tego tree.
func newRingBuild(t *testing.T, root, hash string) ringBuild {
	t.Helper()
	maps := filepath.Join(root, pinRoot, hash, pinMaps)
	if err := os.MkdirAll(maps, 0o700); err != nil {
		t.Fatal(err)
	}
	outer, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "tego_it_rings", Type: ebpf.HashOfMaps, KeySize: 4, MaxEntries: 64,
		InnerMap: &ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 64 << 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outer.Close() })
	if err := outer.Pin(filepath.Join(maps, ebpfbindings.MapEvents)); err != nil {
		t.Fatal(err)
	}
	runSet, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "tego_it_runset", Type: ebpf.Hash, KeySize: 8,
		ValueSize: uint32(unsafe.Sizeof(ebpfbindings.Run{})), MaxEntries: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runSet.Close() })
	if err := runSet.Pin(filepath.Join(maps, ebpfbindings.MapRunSet)); err != nil {
		t.Fatal(err)
	}
	return ringBuild{outer: outer, runSet: runSet}
}

// put places a 64 KiB ring at slot.
func (b ringBuild) put(t *testing.T, slot uint32) {
	t.Helper()
	ring, err := ebpfbindings.NewRing(ebpfbindings.RingRecord, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ring.Close() }()
	if err := ebpfbindings.InsertRing(b.outer, slot, ring); err != nil {
		t.Fatal(err)
	}
}

// has reports whether the build holds a ring at slot.
func (b ringBuild) has(t *testing.T, slot uint32) bool {
	t.Helper()
	ring, ok, err := ebpfbindings.RingOf(b.outer, slot)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		_ = ring.Close()
	}
	return ok
}

// TestRingUseWhileRingsComeAndGo is L1 of the round-7 review: the walk that counts every build's rings opens each
// inner ring by id, and a ring another process removes meanwhile (a trim, a reclaim, a build's removal: none
// holds the rings lock the counting Prepare holds shared or not at all) is gone by the time it is opened. That is a
// ring not counted, never an error that fails the Prepare. Four writers replace rings as fast as the kernel lets
// them while the walk runs over and over. Slots 32 to 39 hold rings no writer touches, so every walk must count
// at least those: a walk that loses rings the outer kept the whole time (a listing cut short while the map changes)
// under-reads the rings in use, and placeRings' ring budget would then let more in than it allows. The churned
// slots may all be caught mid-replacement, so a walk may count only the stable eight (GitHub's runner, 2026-11-02).
func TestRingUseWhileRingsComeAndGo(t *testing.T) {
	root := ringTree(t)
	b := newRingBuild(t, root, "churn")
	const churned, stable = 32, 8
	const rings = churned + stable
	for s := uint32(0); s < rings; s++ {
		b.put(t, s)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := uint32(0); w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := uint32(0); ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				slot := w*8 + i%8
				_ = ebpfbindings.DeleteRing(b.outer, slot)
				ring, err := ebpfbindings.NewRing(ebpfbindings.RingRecord, 64<<10)
				if err != nil {
					continue
				}
				_ = ebpfbindings.InsertRing(b.outer, slot, ring)
				_ = ring.Close()
			}
		}()
	}
	base := filepath.Join(root, pinRoot)
	walks := 0
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); walks++ {
		used, n, err := ringUse(base)
		if err != nil {
			t.Errorf("walk %d: %v", walks, err)
			break
		}
		if n > rings || n < stable || used == 0 {
			t.Errorf("walk %d counted %d rings charging %d B, want %d to %d", walks, n, used, stable, rings)
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("%d walks", walks)
}

// TestReclaimTakesOnlyRingsNoRunHolds is the reclaim `tego gc --builds` and a short Prepare run, on real outers:
// a ring at a slot a live launcher holds stays, and so does one at a slot a run-set row carries (its tasks still
// write there); one at a slot no one holds goes, in this build and in a build with no slot table at all (one whose
// launchers are long gone). Another binary's build whose run set has a row keeps every ring, its run set read by
// key only (ADR 0022 (5)). TrimRings takes only the rings above a build's pool. Not parallel: it names this
// binary's build "live".
func TestReclaimTakesOnlyRingsNoRunHolds(t *testing.T) {
	ownHash := reclaimOwnHash
	defer func() { reclaimOwnHash = ownHash }()
	reclaimOwnHash = func() (string, error) { return "live", nil }
	root := ringTree(t)
	state := t.TempDir()
	live := newRingBuild(t, root, "live")
	old := newRingBuild(t, root, "old")
	foreign := newRingBuild(t, root, "foreign")
	foreignCg := uint64(4343)
	if err := foreign.runSet.Put(&foreignCg, &ebpfbindings.Run{RunIdx: 9, Descendants: 1, Tier: 2}); err != nil {
		t.Fatal(err)
	}
	foreign.put(t, 3)
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	slots, err := openSlotTableIn(d, "live")
	if err != nil {
		t.Fatal(err)
	}
	defer slots.close()
	held, err := slots.acquire(nil)
	if err != nil || held != 0 {
		t.Fatalf("acquire = %d, %v", held, err)
	}
	cg := uint64(4242)
	if err := live.runSet.Put(&cg, &ebpfbindings.Run{RunIdx: 1, Descendants: 1, Tier: 2}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []uint32{0, 1, 2, ringPoolSlots + 1} {
		live.put(t, s)
	}
	old.put(t, 5)

	n, freed, err := TrimRings(SweepOptions{BPFFS: root, StateDir: state}, "live")
	if err != nil || n != 1 || freed == 0 {
		t.Errorf("TrimRings = %d, %d, %v: want the one ring above the pool", n, freed, err)
	}
	if live.has(t, ringPoolSlots+1) || !live.has(t, 2) || !old.has(t, 5) {
		t.Error("TrimRings took other rings than the one above this build's pool")
	}

	n, _, err = ReclaimRings(SweepOptions{BPFFS: root, StateDir: state})
	if err != nil || n != 2 {
		t.Errorf("ReclaimRings = %d, %v: want slot 2 of this build and slot 5 of the old one", n, err)
	}
	if !live.has(t, 0) {
		t.Error("the ring of a slot a live launcher holds was reclaimed")
	}
	if !live.has(t, 1) {
		t.Error("the ring of a slot a run-set row carries was reclaimed")
	}
	if live.has(t, 2) || old.has(t, 5) {
		t.Error("a ring no run holds was left")
	}
	if !foreign.has(t, 3) {
		t.Error("a ring of another binary's build with a run-set row was reclaimed")
	}
	if used, count, err := ringUse(filepath.Join(root, pinRoot)); err != nil || count != 3 || used == 0 {
		t.Errorf("ringUse after the reclaim = %d B, %d rings, %v: want the three kept rings", used, count, err)
	}
}
