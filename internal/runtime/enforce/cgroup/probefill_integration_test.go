// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/cilium/ebpf"
)

// fillPlane is the single-use fill convenience used only by integration tests.
func fillPlane(fill bpfobj.Object, rows, execRows *ebpf.Map, plan *planeFillPlan, table *decide.PlaneRows, opts planeFillOptions, listeners ...*ebpf.Map) (planeFillReport, error) {
	f, err := newPlaneFiller(fill, rows, execRows, listeners...)
	if err != nil {
		return planeFillReport{}, err
	}
	defer func() { _ = f.Close() }()
	return f.fill(plan, table, opts)
}

func TestPlaneProbeRowsOwnListenerMapThroughFillAndClose(t *testing.T) {
	requireBPFCaps(t)
	for _, fill := range fillBuilds(t) {
		object := bpfobj.ObjectPlaneProbe
		if fill == bpfobj.ObjectPlaneFillRdonly {
			object = bpfobj.ObjectPlaneRdonly
		}
		t.Run(string(object), func(t *testing.T) {
			p, err := NewProbeRows(object)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })
			if err := p.Preload(17); err != nil {
				t.Fatalf("preload including owned listener map: %v", err)
			}
			var listener *ebpf.Map
			if err := p.ListenRows.Lookup(uint32(17), &listener); err != nil {
				t.Fatal(err)
			}
			info, err := listener.Info()
			_ = listener.Close()
			if err != nil || info.KeySize != 128 || info.ValueSize != 24 {
				t.Fatalf("listener inner shape: %v, %v", info, err)
			}
			outerInfo, err := p.ListenRows.Info()
			if err != nil {
				t.Fatal(err)
			}
			want, ok := outerInfo.ID()
			if !ok {
				t.Fatal("listener outer has no ID")
			}
			progInfo, err := p.filler.prog.Info()
			if err != nil {
				t.Fatal(err)
			}
			ids, ok := progInfo.MapIDs()
			found := false
			for _, id := range ids {
				found = found || id == want
			}
			if !ok || !found {
				t.Fatal("fill program did not adopt the same owned listener outer")
			}
			maps := []*ebpf.Map{p.Rows, p.ExecRows, p.ListenRows, p.Slots, p.slotRows[17], p.filler.config, p.filler.wants}
			programs := []*ebpf.Program{p.filler.prog, p.filler.clear}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			for _, m := range maps {
				if m.FD() != -1 {
					t.Fatal("probe retained an owned map descriptor")
				}
			}
			for _, prog := range programs {
				if prog.FD() != -1 {
					t.Fatal("probe retained an owned program descriptor")
				}
			}
		})
	}
}
