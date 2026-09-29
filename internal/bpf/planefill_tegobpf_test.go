// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// TestPlaneFillLayoutParity compares the fill's hand-written mirrors with bpf2go's.
func TestPlaneFillLayoutParity(t *testing.T) {
	var (
		cfg  PlaneFillCfg
		gCfg planefillrdTegoPlaneFillCfg
		row  PlaneFillRow
		gRow planefillrdTegoPlaneFillRow
		clr  PlaneClearCtx
		gClr planefillrdTegoPlaneClearCtx
	)
	cases := []struct {
		name      string
		mine, gen uintptr
	}{
		{"sizeof PlaneFillCfg", unsafe.Sizeof(cfg), unsafe.Sizeof(gCfg)},
		{"sizeof PlaneFillRow", unsafe.Sizeof(row), unsafe.Sizeof(gRow)},
		{"sizeof PlaneClearCtx", unsafe.Sizeof(clr), unsafe.Sizeof(gClr)},
		{"PlaneFillCfg.Gen", unsafe.Offsetof(cfg.Gen), unsafe.Offsetof(gCfg.Gen)},
		{"PlaneFillCfg.Visited", unsafe.Offsetof(cfg.Visited), unsafe.Offsetof(gCfg.Visited)},
		{"PlaneFillCfg.Matched", unsafe.Offsetof(cfg.Matched), unsafe.Offsetof(gCfg.Matched)},
		{"PlaneFillCfg.Row", unsafe.Offsetof(cfg.Row), unsafe.Offsetof(gCfg.Row)},
		{"PlaneFillRow.Gen", unsafe.Offsetof(row.Gen), unsafe.Offsetof(gRow.Gen)},
		{"PlaneFillRow.RuleIdx", unsafe.Offsetof(row.RuleIdx), unsafe.Offsetof(gRow.RuleIdx)},
		{"PlaneFillRow.NameLen", unsafe.Offsetof(row.NameLen), unsafe.Offsetof(gRow.NameLen)},
		{"PlaneFillRow.Scope", unsafe.Offsetof(row.Scope), unsafe.Offsetof(gRow.Scope)},
		{"PlaneFillRow.ExecRule", unsafe.Offsetof(row.ExecRule), unsafe.Offsetof(gRow.ExecRule)},
		{"PlaneFillRow.Status", unsafe.Offsetof(row.Status), unsafe.Offsetof(gRow.Status)},
		{"PlaneFillRow.OtherRule", unsafe.Offsetof(row.OtherRule), unsafe.Offsetof(gRow.OtherRule)},
		{"PlaneFillRow.Err", unsafe.Offsetof(row.Err), unsafe.Offsetof(gRow.Err)},
		{"PlaneFillRow.MntID", unsafe.Offsetof(row.MntID), unsafe.Offsetof(gRow.MntId)},
		{"PlaneFillRow.Ino", unsafe.Offsetof(row.Ino), unsafe.Offsetof(gRow.Ino)},
		{"PlaneFillRow.ParentIno", unsafe.Offsetof(row.ParentIno), unsafe.Offsetof(gRow.ParentIno)},
		{"PlaneFillRow.Name", unsafe.Offsetof(row.Name), unsafe.Offsetof(gRow.Name)},
		{"PlaneClearCtx.KeepGen", unsafe.Offsetof(clr.KeepGen), unsafe.Offsetof(gClr.KeepGen)},
		{"PlaneClearCtx.ExecDeleted", unsafe.Offsetof(clr.ExecDeleted), unsafe.Offsetof(gClr.ExecDeleted)},
		{"PlaneClearCtx.ListenDeleted", unsafe.Offsetof(clr.ListenDeleted), unsafe.Offsetof(gClr.ListenDeleted)},
		{"PlaneClearCtx.Status", unsafe.Offsetof(clr.Status), unsafe.Offsetof(gClr.Status)},
	}
	for _, tc := range cases {
		if tc.mine != tc.gen {
			t.Errorf("%s: %d in planefill.go, %d in bpf2go's mirror", tc.name, tc.mine, tc.gen)
		}
	}
}

// TestPlaneFillObjectShape asserts each fill build carries the iter/task_file fill and the syscall clear, its two
// unpinned maps sized for a slot's rows, and the plane's row maps exactly as the plane builds declare them, which
// the loader replaces with the plane's pinned instances (a replacement must match the declaration).
func TestPlaneFillObjectShape(t *testing.T) {
	if got := PlaneFillObjects(); !slices.Equal(got, []Object{ObjectPlaneFillProbe, ObjectPlaneFillRdonly}) {
		t.Fatalf("PlaneFillObjects() = %v", got)
	}
	for _, plane := range PlaneObjects() {
		fill, ok := PlaneFillFor(plane)
		if !ok {
			t.Fatalf("no fill build for %s", plane)
		}
		t.Run(fill.String(), func(t *testing.T) {
			spec, err := Load(fill)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(spec.Programs) != 2 {
				t.Fatalf("programs %v, want the fill and the clear", programNames(spec))
			}
			if p := spec.Programs[ProgPlaneFill]; p == nil || p.Type != ebpf.Tracing || p.AttachType != ebpf.AttachTraceIter ||
				p.AttachTo != "task_file" || p.License != "Dual BSD/GPL" {
				t.Errorf("%s is %+v, want an iter/task_file tracing program", ProgPlaneFill, p)
			}
			if p := spec.Programs[ProgPlaneClear]; p == nil || p.Type != ebpf.Syscall {
				t.Errorf("%s is %+v, want a syscall program", ProgPlaneClear, p)
			}
			if m := spec.Maps[MapPlaneFillWants]; m == nil || m.Type != ebpf.Hash || m.KeySize != 8 ||
				m.ValueSize != uint32(unsafe.Sizeof(PlaneFillRow{})) || m.MaxEntries != PlaneFillMax*PlaneFillLaunchers ||
				m.Flags&unix.BPF_F_NO_PREALLOC == 0 || m.Pinning != ebpf.PinNone {
				t.Errorf("%s is %+v", MapPlaneFillWants, m)
			}
			if m := spec.Maps[MapPlaneFillConfig]; m == nil || m.Type != ebpf.Hash || m.KeySize != 4 || m.MaxEntries != PlaneFillCfgs ||
				m.ValueSize != uint32(unsafe.Sizeof(PlaneFillCfg{})) || m.Pinning != ebpf.PinNone {
				t.Errorf("%s is %+v", MapPlaneFillConfig, m)
			}
			pspec, err := Load(plane)
			if err != nil {
				t.Fatalf("Load %s: %v", plane, err)
			}
			for _, name := range []string{MapPlaneRows, MapPlaneExecRows, MapPlaneListenRows} {
				f, p := spec.Maps[name], pspec.Maps[name]
				if f == nil || p == nil || f.Type != p.Type || f.KeySize != p.KeySize || f.ValueSize != p.ValueSize ||
					f.MaxEntries != p.MaxEntries || f.Flags != p.Flags || f.InnerMap == nil || p.InnerMap == nil ||
					f.InnerMap.KeySize != p.InnerMap.KeySize || f.InnerMap.ValueSize != p.InnerMap.ValueSize || f.InnerMap.MaxEntries != p.InnerMap.MaxEntries ||
					f.InnerMap.Flags != p.InnerMap.Flags {
					t.Errorf("%s: the fill declares %+v, the plane %+v", name, f, p)
				}
			}
		})
	}
}

// TestPlaneFillCORERelocationsResolve is TestPlaneCORERelocationsResolve for the fill builds.
func TestPlaneFillCORERelocationsResolve(t *testing.T) {
	kernel := kernelBTF(t)
	for _, o := range PlaneFillObjects() {
		t.Run(o.String(), func(t *testing.T) {
			spec, err := Load(o)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			total := 0
			for name, prog := range spec.Programs {
				relos := coreRelocations(prog.Instructions)
				total += len(relos)
				if len(relos) == 0 {
					continue
				}
				fixups, err := btf.CORERelocate(relos, []*btf.Spec{kernel}, spec.ByteOrder, spec.Types.TypeID)
				if err != nil {
					t.Errorf("%s: relocations do not resolve: %v", name, err)
					continue
				}
				for i, f := range fixups {
					if strings.Contains(f.String(), "poison") {
						t.Errorf("%s: relocation %s is poisoned on this kernel", name, relos[i])
					}
				}
			}
			if total == 0 {
				t.Fatal("no CO-RE relocations: the fill reads struct mount only through them")
			}
		})
	}
}
