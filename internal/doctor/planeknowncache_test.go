// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// matchedKnown is today's table with every cell answered as it must be.
func matchedKnown() []PlaneKnownAnswer {
	cells := planeKnownCells()
	for i := range cells {
		cells[i].Got, cells[i].GotCounts = cells[i].Want, cells[i].WantCounts
	}
	return cells
}

// TestPlaneKnownCacheKeepsOnlyAFullMatch is R21's known answers kept per boot (planeknowncache.go): a mode whose
// every cell matched is read back under its own key, mode and build; a mode with a cell that differs is not kept and
// removes what was; another key, mode or build reads nothing; and a probe with a flipped cell neither reads nor keeps.
func TestPlaneKnownCacheKeepsOnlyAFullMatch(t *testing.T) {
	c, _ := testCache(t)
	k := testKey()
	p := planeKnownCache{cache: c, key: k, ok: true}
	const o = bpfobj.ObjectPlaneRdonly
	if _, _, ok := p.load(bpfobj.PlaneLSM, o); ok {
		t.Fatal("an empty cache answered")
	}
	pin := &PlaneExecPinCell{OK: true}
	p.store(bpfobj.PlaneLSM, o, matchedKnown(), pin)
	got, gotPin, ok := p.load(bpfobj.PlaneLSM, o)
	if !ok || len(got) != len(planeKnownCells()) || gotPin == nil || *gotPin != *pin {
		t.Fatalf("a kept full match read back %v, %+v, %v", got, gotPin, ok)
	}
	if _, _, ok := p.load(bpfobj.PlaneFmodRet, o); ok {
		t.Error("another mode read lsm's answers")
	}
	if _, _, ok := p.load(bpfobj.PlaneLSM, bpfobj.ObjectPlaneProbe); ok {
		t.Error("another build read this build's answers")
	}
	other := k
	other.BootID = "another boot"
	if _, _, ok := (planeKnownCache{cache: c, key: other, ok: true}).load(bpfobj.PlaneLSM, o); ok {
		t.Error("another boot's key read this boot's answers")
	}

	planeKnownFlip = "stale-row"
	if _, _, ok := p.load(bpfobj.PlaneLSM, o); ok {
		t.Error("a probe with a flipped cell read kept answers")
	}
	planeKnownFlip = ""

	// ADR 0048 (7): a failed exec pin cell is kept with its detail (pins off for the boot), and answers kept with no
	// cell's answer (a cell that could not run) are none.
	off := &PlaneExecPinCell{Detail: "answer 3 (covered vector differs): ran, want killed"}
	p.store(bpfobj.PlaneLSM, o, matchedKnown(), off)
	if _, gotPin, ok := p.load(bpfobj.PlaneLSM, o); !ok || gotPin == nil || *gotPin != *off {
		t.Errorf("a failed exec pin cell read back %+v, %v", gotPin, ok)
	}
	p.store(bpfobj.PlaneLSM, o, matchedKnown(), nil)
	if _, _, ok := p.load(bpfobj.PlaneLSM, o); ok {
		t.Error("answers kept without the exec pin cell's answer read back")
	}

	bad := matchedKnown()
	bad[2].GotCounts = PlaneCountDelta{}
	p.store(bpfobj.PlaneLSM, o, matchedKnown(), pin)
	p.store(bpfobj.PlaneLSM, o, bad, pin)
	if _, _, ok := p.load(bpfobj.PlaneLSM, o); ok {
		t.Error("a mode with a cell that differs still reads kept answers")
	}
	if _, err := os.Stat(c.base + "/run/tego/" + p.name(bpfobj.PlaneLSM, o)); !os.IsNotExist(err) {
		t.Errorf("a differing answer left the kept file: %v", err)
	}
	if (planeKnownCache{cache: c, key: k}).name(bpfobj.PlaneLSM, o) == "" {
		t.Error("no name")
	}
}
