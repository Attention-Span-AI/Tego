// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestPlaneRunAdoptsThePinnedPlane is enforce-plane R20 against the running kernel, as root: a run of a build whose
// plane a lingering build keeps pinned runs the pinned programs, and loads and verifies none of its own. A map of the
// plane's that was not pinned by name (tego_plane_path_buf until 2026-09-30) made adoptObjectIn refuse every later
// launcher, so each run of a plane mode loaded the mode's programs again: 0.6 s of its start in the 6.17 guest, a
// start that stayed within kill test 4's budget only for workloads long enough to hide it (enforce-plane §2.18). The
// program ids say which copy a run holds. Keeping the first run open also gives the second a new slot: adopting
// the plane through compact metadata must still create that slot's row maps from the full ELF's BTF types.
func TestPlaneRunAdoptsThePinnedPlane(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	fullSpec, err := ebpfbindings.Load(build)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("t6adopt%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}})
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	prepare := func(name string) (*Handle, map[string]ebpf.ProgramID) {
		t.Helper()
		rel, _, id := runCgroupUnderSelf(t, name)
		rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordSummary, Contract: &agent.Contract{}}
		rows, err := decide.CompilePlane(rt)
		if err != nil {
			t.Fatal(err)
		}
		b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
		start := time.Now()
		h, err := b.Prepare(context.Background(), rt, Run{ID: "t6-adopt-" + name, CgroupID: id, CgroupPath: rel,
			CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
		if err != nil {
			t.Fatalf("Prepare %s: %v", name, err)
		}
		t.Logf("Prepare %s: %v", name, time.Since(start))
		t.Cleanup(func() {
			if err := h.Close(); err != nil {
				t.Errorf("Close %s: %v", name, err)
			}
		})
		planes := h.kern.(*bpfKernel).planes
		if len(planes) != 1 || planes[0].coll == nil || len(planes[0].coll.Programs) == 0 {
			t.Fatalf("run %s holds no plane", name)
		}
		for _, row := range []struct {
			name  string
			outer *ebpf.Map
		}{{ebpfbindings.MapPlaneRows, planes[0].rows}, {ebpfbindings.MapPlaneExecRows, planes[0].execRows}} {
			inner, err := innerOf(row.outer, h.slot, row.name)
			if err != nil {
				t.Fatalf("run %s slot %d %s: %v", name, h.slot, row.name, err)
			}
			t.Cleanup(func() { _ = inner.Close() })
			want := fullSpec.Maps[row.name].InnerMap
			if err := want.Compatible(inner); err != nil {
				t.Fatalf("run %s slot %d %s shape: %v", name, h.slot, row.name, err)
			}
			btfHandle, err := inner.Handle()
			if err != nil {
				t.Fatalf("run %s slot %d %s has no BTF: %v", name, h.slot, row.name, err)
			}
			gotSpec, err := btfHandle.Spec(nil)
			_ = btfHandle.Close()
			if err != nil {
				t.Fatalf("run %s slot %d %s BTF: %v", name, h.slot, row.name, err)
			}
			// The map's own key and value types, by the ids the kernel holds for them: a lookup by name was
			// ambiguous once the map's BTF carried two identical __u64 typedefs, and could have matched a
			// same-named type that was not the key's (amended 2026-10-05, v73 review R3).
			keyID, valueID, err := mapBTFTypeIDs(inner)
			if err != nil {
				t.Fatalf("run %s slot %d %s: %v", name, h.slot, row.name, err)
			}
			for _, side := range []struct {
				what string
				id   btf.TypeID
				typ  btf.Type
			}{{"key", keyID, want.Key}, {"value", valueID, want.Value}} {
				if side.typ == nil || side.typ.TypeName() == "" {
					t.Fatalf("full ELF %s has no named %s BTF", row.name, side.what)
				}
				got, err := gotSpec.TypeByID(side.id)
				if err != nil || !reflect.DeepEqual(got, side.typ) {
					t.Fatalf("run %s slot %d %s BTF %s type (id %d) differs from full ELF: got %v, want %v, err %v",
						name, h.slot, row.name, side.what, side.id, got, side.typ, err)
				}
			}
		}
		out := map[string]ebpf.ProgramID{}
		for prog, p := range planes[0].coll.Programs {
			info, err := p.Info()
			if err != nil {
				t.Fatalf("program %s: %v", prog, err)
			}
			pid, ok := info.ID()
			if !ok {
				t.Fatalf("program %s has no id", prog)
			}
			out[prog] = pid
		}
		return h, out
	}
	firstHandle, first := prepare("first")
	secondHandle, second := prepare("second")
	if firstHandle.slot == secondHandle.slot {
		t.Fatalf("concurrent runs reused slot %d; the second run must create new inner maps", firstHandle.slot)
	}
	if len(first) != len(second) {
		t.Fatalf("plane programs: first run %d, second %d", len(first), len(second))
	}
	for prog, id := range first {
		if second[prog] != id {
			t.Errorf("%s: the second run holds program %d, the first %d: it loaded and verified its own copy "+
				"instead of adopting the pinned plane", prog, second[prog], id)
		}
	}
	testPlaneLinkVerifiedPrograms(t, secondHandle, fullSpec)
}

// mapBTFTypeIDs is the BTF type ids the kernel holds for map m's key and value (struct bpf_map_info's
// btf_key_type_id and btf_value_type_id), which ebpf.MapInfo does not expose.
func mapBTFTypeIDs(m *ebpf.Map) (key, value btf.TypeID, err error) {
	// struct bpf_map_info up to btf_value_type_id, padded to 8 bytes; the kernel fills what it has of it.
	var info struct {
		Type, ID, KeySize, ValueSize, MaxEntries, MapFlags uint32
		Name                                               [16]byte
		Ifindex, BTFVmlinuxValueTypeID                     uint32
		NetnsDev, NetnsIno                                 uint64
		BTFID, BTFKeyTypeID, BTFValueTypeID                uint32
		_                                                  uint32
	}
	attr := struct {
		FD, InfoLen uint32
		Info        uint64
	}{uint32(m.FD()), uint32(unsafe.Sizeof(info)), uint64(uintptr(unsafe.Pointer(&info)))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	if errno != 0 {
		return 0, 0, fmt.Errorf("map info: %w", errno)
	}
	if info.BTFID == 0 {
		return 0, 0, errors.New("the map carries no BTF")
	}
	return btf.TypeID(info.BTFKeyTypeID), btf.TypeID(info.BTFValueTypeID), nil
}

// Exercise the link shortcut using real adopted programs, links and map IDs.
// A changed link program and a closed validation descriptor must keep using the
// complete ownership check, and a partial adoption must retain no proven IDs.
func testPlaneLinkVerifiedPrograms(t *testing.T, h *Handle, full *ebpf.CollectionSpec) {
	t.Helper()
	k := h.kern.(*bpfKernel)
	p := k.planes[0]
	spec := full.Copy()
	for name := range spec.Programs {
		if p.coll.Programs[name] == nil {
			delete(spec.Programs, name)
		}
	}
	var names []string
	for name := range spec.Programs {
		names = append(names, name)
	}
	external := map[string]*ebpf.Map{}
	for name := range spec.Maps {
		if m := k.maps[name]; m != nil {
			external[name] = m
		}
	}
	verified := map[ebpf.ProgramID]*ebpf.Program{}
	coll, adopted := adoptObjectInWithPrograms(p.layout.pinLayout, spec, names, external, verified)
	if !adopted {
		t.Fatal("could not adopt the complete plane for link ownership checks")
	}
	defer coll.Close()
	if len(verified) != len(coll.Programs) {
		t.Fatalf("verified %d IDs for %d held plane programs", len(verified), len(coll.Programs))
	}
	owns, err := planeOwns(spec, coll, external)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	counted := func(prog *ebpf.Program) string {
		calls++
		return owns(prog)
	}
	for _, l := range p.links {
		if why := linkOwned(l.Link, counted, verified); why != "" {
			t.Fatalf("a verified plane link was refused: %s", why)
		}
	}
	if calls != 0 {
		t.Fatalf("verified links repeated %d complete ownership checks", calls)
	}
	// The same valid link with no proven ID must still pass the ordinary check.
	if why := linkOwned(p.links[0].Link, counted, nil); why != "" || calls != 1 {
		t.Fatalf("uncached plane link: why=%s checks=%d, want one successful check", why, calls)
	}
	info, err := p.links[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if err := verified[info.Program].Close(); err != nil {
		t.Fatal(err)
	}
	if why := linkOwned(p.links[0].Link, counted, verified); why != "" || calls != 2 {
		t.Fatalf("closed validation descriptor: why=%s checks=%d, want fallback check", why, calls)
	}
	// A tracing link belongs to another program, even while the plane's proven
	// IDs are kept alive. It must reach the full validator, never the shortcut.
	const refused = "different-program-checked"
	if why := linkOwned(k.shared[0].Link, func(*ebpf.Program) string { return refused }, verified); why != refused {
		t.Fatalf("different link program: why=%s, want complete ownership check", why)
	}
	broken := spec.Copy()
	broken.Programs["missing-pinned-program"] = &ebpf.ProgramSpec{Type: ebpf.Tracing}
	if failed, ok := adoptObjectInWithPrograms(p.layout.pinLayout, broken, names, external, verified); ok || failed != nil || len(verified) != 0 {
		if failed != nil {
			failed.Close()
		}
		t.Fatalf("partial adoption retained programs: adopted=%v collection=%v verified=%d", ok, failed, len(verified))
	}
}
