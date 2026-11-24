// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// deputyPlane is a fakePlane that takes a deputy's identity (bpfPlane.setDeputy's seam).
type deputyPlane struct {
	fakePlane
	slot, gen, tgid uint32
	start, dev, ino uint64
	calls           int
	err             error
}

func (p *deputyPlane) setDeputy(slot, gen, tgid uint32, start, pidnsDev, pidnsIno uint64) error {
	p.calls++
	p.slot, p.gen, p.tgid, p.start, p.dev, p.ino = slot, gen, tgid, start, pidnsDev, pidnsIno
	return p.err
}

// TestExemptDeputyWritesItsIdentityBeforeArm (ADR 0128, amended 2026-11-21): a flagged slot gets the deputy's pid and
// start ticks with the launcher's pid namespace; an unflagged one (no kernel assurance, no hook) gets nothing; a slot
// already armed, a missing pid or start, a launcher whose boot clock is not the kernel's, and a plane that cannot take
// it are each ErrDeputyNotExempt, which refuses the run.
func TestExemptDeputyWritesItsIdentityBeforeArm(t *testing.T) {
	p := &deputyPlane{}
	h := &Handle{plane: p, importsFlagged: true, slot: 5, gen: 9}
	if err := h.ExemptDeputy(1234, 5678); err != nil {
		t.Fatalf("ExemptDeputy: %v", err)
	}
	dev, ino, err := launcherPidns()
	if err != nil {
		t.Skipf("no pid namespace to read: %v", err)
	}
	if p.calls != 1 || p.slot != 5 || p.gen != 9 || p.tgid != 1234 || p.start != 5678 || p.dev != dev || p.ino != ino {
		t.Errorf("setDeputy got %+v, want slot 5 gen 9 tgid 1234 start 5678 in pidns %d/%d", p, dev, ino)
	}
	if err := (&Handle{plane: &deputyPlane{}}).ExemptDeputy(1234, 5678); err != nil {
		t.Errorf("an unflagged slot: %v, want nothing to do", err)
	}
	for name, h := range map[string]*Handle{
		"armed":             {plane: &deputyPlane{}, importsFlagged: true, armed: true},
		"detached":          {plane: &deputyPlane{}, importsFlagged: true, detached: true},
		"no exemption seam": {plane: &fakePlane{}, importsFlagged: true},
		"plane refuses":     {plane: &deputyPlane{err: errors.New("header of another gen")}, importsFlagged: true},
	} {
		if err := h.ExemptDeputy(1234, 5678); !errors.Is(err, ErrDeputyNotExempt) {
			t.Errorf("%s: %v, want ErrDeputyNotExempt", name, err)
		}
	}
	for _, id := range [][2]uint64{{0, 5678}, {1234, 0}} {
		if err := (&Handle{plane: &deputyPlane{}, importsFlagged: true}).ExemptDeputy(int(id[0]), id[1]); !errors.Is(err, ErrDeputyNotExempt) {
			t.Errorf("pid %d start %d: %v, want ErrDeputyNotExempt", id[0], id[1], err)
		}
	}
}

// TestPlaneBlockResultsReadTheFill: a block row is in only when the fill wrote it at the inode its descriptor had when
// the launcher opened it; a full map, a clashing key and any other status are each their own error.
func TestPlaneBlockResultsReadTheFill(t *testing.T) {
	rows := []PlaneBlockFill{{Ino: 10}, {Ino: 11}, {Ino: 12}, {Ino: 13}, {Ino: 14}}
	got := []ebpfbindings.PlaneFillRow{
		{Status: ebpfbindings.PlaneFillOK, Ino: 10},
		{Status: ebpfbindings.PlaneFillOK, Ino: 99},
		{Status: ebpfbindings.PlaneFillUpdate, Err: -int32(unix.E2BIG)},
		{Status: ebpfbindings.PlaneFillDup},
		{Status: ebpfbindings.PlaneFillUnseen},
	}
	res := blockResults(rows, got)
	if res[0].Err != nil || res[1].Err == nil || !errors.Is(res[2].Err, ErrPlaneBlockFull) ||
		!errors.Is(res[3].Err, ErrPlaneBlockClash) || res[4].Err == nil {
		t.Errorf("results %+v", res)
	}
	for _, tc := range []struct {
		r    PlaneBlockFill
		want ebpfbindings.PlaneFillWhat
	}{
		{PlaneBlockFill{}, ebpfbindings.PlaneFillBlock},
		{PlaneBlockFill{Name: true, NameKey: 77}, ebpfbindings.PlaneFillBlockName},
		{PlaneBlockFill{Delete: true}, ebpfbindings.PlaneFillBlockDel},
		{PlaneBlockFill{Name: true, Delete: true, NameKey: 77}, ebpfbindings.PlaneFillBlockNameDel},
	} {
		v := blockTemplate(tc.r, 4)
		if v.What != tc.want || v.Gen != 4 || (tc.r.Name && v.BlockNameKey != 77) {
			t.Errorf("template of %+v = %+v, want what %d", tc.r, v, tc.want)
		}
	}
	// The wants key of a block row is kind 0, which no Prepare row uses.
	if k := ebpfbindings.PlaneFillBlockKey(7, 9); k>>30&3 != 0 || ebpfbindings.PlaneFillKeyTgid(k) != 7 || uint32(k)&(1<<30-1) != 9 {
		t.Errorf("PlaneFillBlockKey(7, 9) = %#x", k)
	}
}
