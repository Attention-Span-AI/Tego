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
)

// TestPlaneLayoutParity compares the hand-written plane mirrors with bpf2go's, field by field where a size alone
// would miss a swap.
func TestPlaneLayoutParity(t *testing.T) {
	var (
		row        PlaneRow
		gRow       planerdTegoPlaneRow
		exec       PlaneExecRow
		gExec      planerdTegoPlaneExecRow
		dec        PlaneDecision
		gDec       planerdTegoPlaneDecision
		cnt        PlaneCounts
		gCnt       planerdTegoPlaneCounts
		ev         PlaneEvent
		gEv        planerdTegoEvPlane
		ux         PlaneUnix
		gUx        planerdTegoPlaneUnix
		sl         PlaneSlot
		gSl        planerdTegoPlaneSlot
		bind       PlaneBind
		gBind      planerdTegoPlaneBind
		listenKey  PlaneListenKey
		gListenKey planerdTegoPlaneListenKey
		listenRow  PlaneListenRow
		gListenRow planerdTegoPlaneListenRow
		nameRow    PlaneNameRow
		gNameRow   planerdTegoPlaneNameRow
		nameCfg    PlaneNameConfig
		gNameCfg   planerdTegoPlaneNameCfg
		pin        ExecPin
		gPin       planerdTegoExecPin
		pinKey     PinKey
		gPinKey    planerdTegoPinKey
		pinKV      PinKeyval
		gPinKV     planerdTegoPinKeyval
		kill       ExecKillEvent
		gKill      planerdTegoEvExecKill
		held       ExecHeldEvent
		gHeld      planerdTegoEvExecHeld
	)
	cases := []struct {
		name      string
		mine, gen uintptr
	}{
		{"sizeof PlaneRow", unsafe.Sizeof(row), unsafe.Sizeof(gRow)},
		{"sizeof PlaneExecRow", unsafe.Sizeof(exec), unsafe.Sizeof(gExec)},
		{"sizeof PlaneDecision", unsafe.Sizeof(dec), unsafe.Sizeof(gDec)},
		{"sizeof PlaneCounts", unsafe.Sizeof(cnt), unsafe.Sizeof(gCnt)},
		{"PlaneRow.Dev", unsafe.Offsetof(row.Dev), unsafe.Offsetof(gRow.S_dev)},
		{"PlaneRow.Gen", unsafe.Offsetof(row.Gen), unsafe.Offsetof(gRow.Gen)},
		{"PlaneRow.RuleIdx", unsafe.Offsetof(row.RuleIdx), unsafe.Offsetof(gRow.RuleIdx)},
		{"PlaneRow.Kind", unsafe.Offsetof(row.Kind), unsafe.Offsetof(gRow.Kind)},
		{"PlaneRow.ExecRule", unsafe.Offsetof(row.ExecRule), unsafe.Offsetof(gRow.ExecRule)},
		{"PlaneExecRow.Inode", unsafe.Offsetof(exec.Inode), unsafe.Offsetof(gExec.Inode)},
		{"PlaneExecRow.Ino", unsafe.Offsetof(exec.Ino), unsafe.Offsetof(gExec.I_ino)},
		{"PlaneExecRow.Gen", unsafe.Offsetof(exec.Gen), unsafe.Offsetof(gExec.Gen)},
		{"PlaneExecRow.NameLen", unsafe.Offsetof(exec.NameLen), unsafe.Offsetof(gExec.NameLen)},
		{"PlaneExecRow.Flags", unsafe.Offsetof(exec.Flags), unsafe.Offsetof(gExec.Flags)},
		{"PlaneExecRow.Name", unsafe.Offsetof(exec.Name), unsafe.Offsetof(gExec.Name)},
		{"PlaneDecision.Hook", unsafe.Offsetof(dec.Hook), unsafe.Offsetof(gDec.Hook)},
		{"PlaneDecision.Verdict", unsafe.Offsetof(dec.Verdict), unsafe.Offsetof(gDec.Verdict)},
		{"PlaneDecision.Obj", unsafe.Offsetof(dec.Obj), unsafe.Offsetof(gDec.Obj)},
		{"PlaneDecision.LaunderMnt", unsafe.Offsetof(dec.LaunderMnt), unsafe.Offsetof(gDec.LaunderMnt)},
		{"PlaneDecision.ExecObj", unsafe.Offsetof(dec.ExecObj), unsafe.Offsetof(gDec.ExecObj)},
		{"PlaneDecision.ExecRule", unsafe.Offsetof(dec.ExecRule), unsafe.Offsetof(gDec.ExecRule)},
		{"PlaneDecision.ExecVerdict", unsafe.Offsetof(dec.ExecVerdict), unsafe.Offsetof(gDec.ExecVerdict)},
		{"PlaneDecision.ListenSock", unsafe.Offsetof(dec.ListenSock), unsafe.Offsetof(gDec.ListenSock)},
		{"PlaneDecision.ListenRunIdx", unsafe.Offsetof(dec.ListenRunIdx), unsafe.Offsetof(gDec.ListenRunIdx)},
		{"PlaneDecision.ListenGen", unsafe.Offsetof(dec.ListenGen), unsafe.Offsetof(gDec.ListenGen)},
		{"PlaneDecision.Bind", unsafe.Offsetof(dec.Bind), unsafe.Offsetof(gDec.Bind)},
		{"sizeof PlaneBind", unsafe.Sizeof(bind), unsafe.Sizeof(gBind)},
		{"PlaneBind.StartNS", unsafe.Offsetof(bind.StartNS), unsafe.Offsetof(gBind.StartNs)},
		{"PlaneBind.Dev", unsafe.Offsetof(bind.Dev), unsafe.Offsetof(gBind.Dev)},
		{"PlaneBind.DirIno", unsafe.Offsetof(bind.DirIno), unsafe.Offsetof(gBind.DirIno)},
		{"PlaneBind.RuleIdx", unsafe.Offsetof(bind.RuleIdx), unsafe.Offsetof(gBind.RuleIdx)},
		{"PlaneBind.Flags", unsafe.Offsetof(bind.Flags), unsafe.Offsetof(gBind.Flags)},
		{"PlaneBind.NameLen", unsafe.Offsetof(bind.NameLen), unsafe.Offsetof(gBind.NameLen)},
		{"PlaneBind.Reason", unsafe.Offsetof(bind.Reason), unsafe.Offsetof(gBind.Reason)},
		{"PlaneBind.Op", unsafe.Offsetof(bind.Op), unsafe.Offsetof(gBind.Op)},
		{"PlaneBind.Name", unsafe.Offsetof(bind.Name), unsafe.Offsetof(gBind.Name)},
		{"sizeof PlaneListenKey", unsafe.Sizeof(listenKey), unsafe.Sizeof(gListenKey)},
		{"PlaneListenKey.Parent", unsafe.Offsetof(listenKey.Parent), unsafe.Offsetof(gListenKey.Parent)},
		{"PlaneListenKey.NameLen", unsafe.Offsetof(listenKey.NameLen), unsafe.Offsetof(gListenKey.NameLen)},
		{"PlaneListenKey.Abstract", unsafe.Offsetof(listenKey.Abstract), unsafe.Offsetof(gListenKey.Abstract)},
		{"PlaneListenKey.Name", unsafe.Offsetof(listenKey.Name), unsafe.Offsetof(gListenKey.Name)},
		{"sizeof PlaneListenRow", unsafe.Sizeof(listenRow), unsafe.Sizeof(gListenRow)},
		{"PlaneListenRow.ParentIno", unsafe.Offsetof(listenRow.ParentIno), unsafe.Offsetof(gListenRow.ParentIno)},
		{"PlaneListenRow.ParentGeneration", unsafe.Offsetof(listenRow.ParentGeneration), unsafe.Offsetof(gListenRow.ParentGeneration)},
		{"PlaneListenRow.Dev", unsafe.Offsetof(listenRow.Dev), unsafe.Offsetof(gListenRow.S_dev)},
		{"PlaneListenRow.Gen", unsafe.Offsetof(listenRow.Gen), unsafe.Offsetof(gListenRow.Gen)},
		{"PlaneListenRow.RuleIdx", unsafe.Offsetof(listenRow.RuleIdx), unsafe.Offsetof(gListenRow.RuleIdx)},
		{"sizeof PlaneEvent", unsafe.Sizeof(ev), unsafe.Sizeof(gEv)},
		{"PlaneEvent.StartNS", unsafe.Offsetof(ev.StartNS), unsafe.Offsetof(gEv.StartNs)},
		{"PlaneEvent.RuleIdx", unsafe.Offsetof(ev.RuleIdx), unsafe.Offsetof(gEv.RuleIdx)},
		{"PlaneEvent.Hook", unsafe.Offsetof(ev.Hook), unsafe.Offsetof(gEv.Hook)},
		{"PlaneEvent.PathOK", unsafe.Offsetof(ev.PathOK), unsafe.Offsetof(gEv.PathOk)},
		{"PlaneEvent.Dev", unsafe.Offsetof(ev.Dev), unsafe.Offsetof(gEv.Dev)},
		{"PlaneEvent.DirIno", unsafe.Offsetof(ev.DirIno), unsafe.Offsetof(gEv.DirIno)},
		{"PlaneEvent.Flags", unsafe.Offsetof(ev.Flags), unsafe.Offsetof(gEv.Flags)},
		{"PlaneEvent.Path", unsafe.Offsetof(ev.Path), unsafe.Offsetof(gEv.Path)},
		{"PlaneCounts.NoRows", unsafe.Offsetof(cnt.NoRows), unsafe.Offsetof(gCnt.Norows)},
		{"sizeof PlaneSlot", unsafe.Sizeof(sl), unsafe.Sizeof(gSl)},
		{"PlaneSlot.Gen", unsafe.Offsetof(sl.Gen), unsafe.Offsetof(gSl.Gen)},
		{"PlaneSlot.Flags", unsafe.Offsetof(sl.Flags), unsafe.Offsetof(gSl.Flags)},
		{"PlaneSlot.FSRows", unsafe.Offsetof(sl.FSRows), unsafe.Offsetof(gSl.FsRows)},
		{"PlaneSlot.ExecRows", unsafe.Offsetof(sl.ExecRows), unsafe.Offsetof(gSl.ExecRows)},
		{"PlaneSlot.NLeads", unsafe.Offsetof(sl.NLeads), unsafe.Offsetof(gSl.Nleads)},
		{"PlaneSlot.NPrefixes", unsafe.Offsetof(sl.NPrefixes), unsafe.Offsetof(gSl.Nprefixes)},
		{"PlaneSlot.LeadLen", unsafe.Offsetof(sl.LeadLen), unsafe.Offsetof(gSl.LeadLen)},
		{"PlaneSlot.PrefixLen", unsafe.Offsetof(sl.PrefixLen), unsafe.Offsetof(gSl.PrefixLen)},
		{"PlaneSlot.MinLen", unsafe.Offsetof(sl.MinLen), unsafe.Offsetof(gSl.MinLen)},
		{"PlaneSlot.Lead", unsafe.Offsetof(sl.Lead), unsafe.Offsetof(gSl.Lead)},
		{"PlaneSlot.PidnsDev", unsafe.Offsetof(sl.PidnsDev), unsafe.Offsetof(gSl.PidnsDev)},
		{"PlaneSlot.PidnsIno", unsafe.Offsetof(sl.PidnsIno), unsafe.Offsetof(gSl.PidnsIno)},
		{"sizeof ExecPin", unsafe.Sizeof(pin), unsafe.Sizeof(gPin)},
		{"ExecPin.Seq", unsafe.Offsetof(pin.Seq), unsafe.Offsetof(gPin.Seq)},
		{"ExecPin.Form", unsafe.Offsetof(pin.Form), unsafe.Offsetof(gPin.Form)},
		{"ExecPin.Flags", unsafe.Offsetof(pin.Flags), unsafe.Offsetof(gPin.Flags)},
		{"ExecPin.NChain", unsafe.Offsetof(pin.NChain), unsafe.Offsetof(gPin.Nchain)},
		{"ExecPin.K", unsafe.Offsetof(pin.K), unsafe.Offsetof(gPin.K)},
		{"ExecPin.Argc", unsafe.Offsetof(pin.Argc), unsafe.Offsetof(gPin.Argc)},
		{"ExecPin.LenCov", unsafe.Offsetof(pin.LenCov), unsafe.Offsetof(gPin.LenCov)},
		{"ExecPin.LenTail", unsafe.Offsetof(pin.LenTail), unsafe.Offsetof(gPin.LenTail)},
		{"ExecPin.LenPath", unsafe.Offsetof(pin.LenPath), unsafe.Offsetof(gPin.LenPath)},
		{"ExecPin.Image", unsafe.Offsetof(pin.Image), unsafe.Offsetof(gPin.Image)},
		{"ExecPin.MACCov", unsafe.Offsetof(pin.MACCov), unsafe.Offsetof(gPin.MacCov)},
		{"ExecPin.MACTail", unsafe.Offsetof(pin.MACTail), unsafe.Offsetof(gPin.MacTail)},
		{"ExecPin.MACName", unsafe.Offsetof(pin.MACName), unsafe.Offsetof(gPin.MacName)},
		{"ExecPin.MACPath", unsafe.Offsetof(pin.MACPath), unsafe.Offsetof(gPin.MacPath)},
		{"ExecPin.Chain", unsafe.Offsetof(pin.Chain), unsafe.Offsetof(gPin.Chain)},
		{"sizeof PinKey", unsafe.Sizeof(pinKey), unsafe.Sizeof(gPinKey)},
		{"PinKey.Start", unsafe.Offsetof(pinKey.Start), unsafe.Offsetof(gPinKey.Start)},
		{"sizeof PinKeyval", unsafe.Sizeof(pinKV), unsafe.Sizeof(gPinKV)},
		{"PinKeyval.K0", unsafe.Offsetof(pinKV.K0), unsafe.Offsetof(gPinKV.K0)},
		{"PinKeyval.K1", unsafe.Offsetof(pinKV.K1), unsafe.Offsetof(gPinKV.K1)},
		{"sizeof ExecKillEvent", unsafe.Sizeof(kill), unsafe.Sizeof(gKill)},
		{"ExecKillEvent.ExecStartNS", unsafe.Offsetof(kill.ExecStartNS), unsafe.Offsetof(gKill.ExecStartNs)},
		{"ExecKillEvent.Seq", unsafe.Offsetof(kill.Seq), unsafe.Offsetof(gKill.Seq)},
		{"ExecKillEvent.KillErr", unsafe.Offsetof(kill.KillErr), unsafe.Offsetof(gKill.KillErr)},
		{"ExecKillEvent.Form", unsafe.Offsetof(kill.Form), unsafe.Offsetof(gKill.Form)},
		{"ExecKillEvent.Interpreted", unsafe.Offsetof(kill.Interpreted), unsafe.Offsetof(gKill.Interpreted)},
		{"ExecKillEvent.Argv", unsafe.Offsetof(kill.Argv), unsafe.Offsetof(gKill.Argv)},
		{"sizeof ExecHeldEvent", unsafe.Sizeof(held), unsafe.Sizeof(gHeld)},
		{"ExecHeldEvent.ExecStartNS", unsafe.Offsetof(held.ExecStartNS), unsafe.Offsetof(gHeld.ExecStartNs)},
		{"ExecHeldEvent.OldTID", unsafe.Offsetof(held.OldTID), unsafe.Offsetof(gHeld.OldTid)},
		{"ExecHeldEvent.Seq", unsafe.Offsetof(held.Seq), unsafe.Offsetof(gHeld.Seq)},
		// The header's first cache line holds the four words, the counts and lengths, and leads 0 to 3 (ADR 0043 D9).
		{"PlaneSlot.Lead[4] starts the second line", unsafe.Offsetof(sl.Lead) + 4*8, 64},
		{"PlaneRow.Scope", unsafe.Offsetof(row.Scope), unsafe.Offsetof(gRow.Scope)},
		{"sizeof PlaneNameRow", unsafe.Sizeof(nameRow), unsafe.Sizeof(gNameRow)},
		{"PlaneNameRow.Flags", unsafe.Offsetof(nameRow.Flags), unsafe.Offsetof(gNameRow.Flags)},
		{"PlaneNameRow.NameLen", unsafe.Offsetof(nameRow.NameLen), unsafe.Offsetof(gNameRow.NameLen)},
		{"PlaneNameRow.Exempt", unsafe.Offsetof(nameRow.Exempt), unsafe.Offsetof(gNameRow.Exempt)},
		{"PlaneNameRow.ExceptFrom", unsafe.Offsetof(nameRow.ExceptFrom), unsafe.Offsetof(gNameRow.ExceptFrom)},
		{"PlaneNameRow.Deny", unsafe.Offsetof(nameRow.Deny), unsafe.Offsetof(gNameRow.Deny)},
		{"PlaneNameRow.Except", unsafe.Offsetof(nameRow.Except), unsafe.Offsetof(gNameRow.Except)},
		{"PlaneNameRow.Name", unsafe.Offsetof(nameRow.Name), unsafe.Offsetof(gNameRow.Name)},
		{"sizeof PlaneNameConfig", unsafe.Sizeof(nameCfg), unsafe.Sizeof(gNameCfg)},
		{"PlaneNameConfig.NDeps", unsafe.Offsetof(nameCfg.NDeps), unsafe.Offsetof(gNameCfg.Ndeps)},
		{"PlaneNameConfig.NEntries", unsafe.Offsetof(nameCfg.NEntries), unsafe.Offsetof(gNameCfg.Nentries)},
		{"PlaneNameConfig.Scopes", unsafe.Offsetof(nameCfg.Scopes), unsafe.Offsetof(gNameCfg.Scopes)},
		{"PlaneNameConfig.Entries", unsafe.Offsetof(nameCfg.Entries), unsafe.Offsetof(gNameCfg.Entries)},
		{"PlaneNameConfig.BitEntries", unsafe.Offsetof(nameCfg.BitEntries), unsafe.Offsetof(gNameCfg.BitEntries)},
		{"PlaneNameConfig.EntryMask", unsafe.Offsetof(nameCfg.EntryMask), unsafe.Offsetof(gNameCfg.EntryMask)},
		{"PlaneNameConfig.Dep", unsafe.Offsetof(nameCfg.Dep), unsafe.Offsetof(gNameCfg.Dep)},
		{"PlaneNameConfig.DepLens", unsafe.Offsetof(nameCfg.DepLens), unsafe.Offsetof(gNameCfg.DepLens)},
		{"PlaneNameConfig.Zero", unsafe.Offsetof(nameCfg.Zero), unsafe.Offsetof(gNameCfg.Zero)},
		{"the config row is a name row's size", unsafe.Sizeof(nameCfg), unsafe.Sizeof(nameRow)},
		{"sizeof PlaneUnix", unsafe.Sizeof(ux), unsafe.Sizeof(gUx)},
		{"PlaneUnix.Gen", unsafe.Offsetof(ux.Gen), unsafe.Offsetof(gUx.Gen)},
		{"PlaneUnix.Decides", unsafe.Offsetof(ux.Decides), unsafe.Offsetof(gUx.Decides)},
	}
	for _, tc := range cases {
		if tc.mine != tc.gen {
			t.Errorf("%s: %d in plane.go, %d in bpf2go's mirror", tc.name, tc.mine, tc.gen)
		}
	}
}

// TestPlaneObjectShape asserts each plane build carries exactly both modes' programs of every hook, with the
// program type, attach type and target each mode needs, the dual licence, and the plane's maps beside the shared
// ones, pinned by name.
func TestPlaneObjectShape(t *testing.T) {
	if got := PlaneObjects(); !slices.Equal(got, []Object{ObjectPlaneProbe, ObjectPlaneRdonly}) {
		t.Fatalf("PlaneObjects() = %v", got)
	}
	for _, o := range PlaneObjects() {
		t.Run(o.String(), func(t *testing.T) {
			spec, err := Load(o)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(spec.Programs) != 2*len(PlaneHooks)+len(PlaneModes) {
				t.Fatalf("%d programs, want %d: %v", len(spec.Programs), 2*len(PlaneHooks)+len(PlaneModes), programNames(spec))
			}
			// The exec-pin program, one per mode, is a tp_btf tracing program in both (ADR 0048 (3) P2).
			for _, m := range PlaneModes {
				p := spec.Programs[PlaneExecPinProgram(m)]
				if p == nil {
					t.Fatalf("program %s missing", PlaneExecPinProgram(m))
				}
				if p.Type != ebpf.Tracing || p.AttachType != ebpf.AttachTraceRawTp || p.AttachTo != "sched_process_exec" ||
					p.SectionName != PlaneExecPinSection || p.License != "Dual BSD/GPL" {
					t.Errorf("%s: %s/%s to %q in %q (%q), want tracing/trace_raw_tp to sched_process_exec in %q",
						p.Name, p.Type, p.AttachType, p.AttachTo, p.SectionName, p.License, PlaneExecPinSection)
				}
			}
			for _, h := range PlaneHooks {
				for _, m := range PlaneModes {
					p := spec.Programs[h.Program(m)]
					if p == nil {
						t.Fatalf("program %s missing", h.Program(m))
					}
					want := struct {
						typ    ebpf.ProgramType
						attach ebpf.AttachType
						to     string
					}{ebpf.LSM, ebpf.AttachLSMMac, h.LSM}
					if m == PlaneFmodRet {
						want.typ, want.attach, want.to = ebpf.Tracing, ebpf.AttachModifyReturn, h.Security
					}
					if p.Type != want.typ || p.AttachType != want.attach || p.AttachTo != want.to {
						t.Errorf("%s: %s/%s to %q, want %s/%s to %q", p.Name, p.Type, p.AttachType, p.AttachTo,
							want.typ, want.attach, want.to)
					}
					if p.SectionName != h.Section(m) {
						t.Errorf("%s: section %q, want %q", p.Name, p.SectionName, h.Section(m))
					}
					if p.License != "Dual BSD/GPL" {
						t.Errorf("%s: licence %q", p.Name, p.License)
					}
				}
			}
			for _, name := range append(slices.Clone(SharedMaps), PlaneMaps...) {
				m := spec.Maps[name]
				if m == nil {
					t.Fatalf("map %s missing", name)
				}
				if m.Pinning != ebpf.PinByName {
					t.Errorf("map %s: pinning %v, want PinByName", name, m.Pinning)
				}
			}
			const noPrealloc = 1 // BPF_F_NO_PREALLOC
			for _, tc := range []struct {
				name            string
				key, value, max uint32
			}{
				{MapPlaneRows, 8, uint32(unsafe.Sizeof(PlaneRow{})), PlaneRowsMax},
				{MapPlaneExecRows, 8, uint32(unsafe.Sizeof(PlaneExecRow{})), PlaneExecRowsMax},
				{MapPlaneListenRows, uint32(unsafe.Sizeof(PlaneListenKey{})), uint32(unsafe.Sizeof(PlaneListenRow{})), PlaneListenRowsMax},
				{MapPlaneNameRows, 8, uint32(unsafe.Sizeof(PlaneNameRow{})), PlaneNameKeys},
				{MapPlaneExecPins, uint32(unsafe.Sizeof(PinKey{})), uint32(unsafe.Sizeof(ExecPin{})), PinRows},
			} {
				m := spec.Maps[tc.name]
				in := m.InnerMap
				if m.Type != ebpf.HashOfMaps || m.KeySize != 4 || m.MaxEntries != MaxSlots || in == nil ||
					in.Type != ebpf.Hash || in.KeySize != tc.key || in.ValueSize != tc.value || in.MaxEntries != tc.max ||
					in.Flags&noPrealloc == 0 {
					t.Errorf("%s is %+v (inner %+v), want a HASH_OF_MAPS by run_idx of no-prealloc HASHes of %d "+
						"%d-byte rows with %d-byte keys", tc.name, m, in, tc.max, tc.value, tc.key)
				}
			}
			if m := spec.Maps[MapPlaneScratch]; m.Type != ebpf.TaskStorage || m.ValueSize != uint32(unsafe.Sizeof(PlaneDecision{})) {
				t.Errorf("%s is %+v", MapPlaneScratch, m)
			}
			if m := spec.Maps[MapPlaneCounters]; m.Type != ebpf.Array || m.MaxEntries != MaxSlots ||
				m.ValueSize != uint32(unsafe.Sizeof(PlaneCounts{})) {
				t.Errorf("%s is %+v", MapPlaneCounters, m)
			}
			if m := spec.Maps[MapPlaneUnixPolicy]; m.Type != ebpf.Array || m.MaxEntries != MaxSlots ||
				m.ValueSize != uint32(unsafe.Sizeof(PlaneUnix{})) {
				t.Errorf("%s is %+v", MapPlaneUnixPolicy, m)
			}
			if m := spec.Maps[MapUnixNames]; m == nil || m.Pinning != ebpf.PinByName {
				t.Errorf("%s is %+v: the unix hooks read the build's own instance, which the loader hands them by name",
					MapUnixNames, m)
			}
			if m := spec.Maps[MapUnixApprovals]; m == nil || m.Pinning != ebpf.PinByName || m.Type != ebpf.Hash ||
				m.KeySize != uint32(unsafe.Sizeof(UnixApprovalKey{})) || m.ValueSize != uint32(unsafe.Sizeof(UnixCredit{})) {
				t.Errorf("%s is %+v: socket_connect reads the build's own grants, which the loader hands it by name",
					MapUnixApprovals, m)
			}
		})
	}
}

// TestPlaneCORERelocationsResolve is TestCORERelocationsResolve for the plane builds: every relocation of every
// program resolves against this kernel's BTF, unprivileged. The rd build's bpf_rdonly_cast calls also relocate
// type ids of the kernel's own structs (struct mount among them, which is no exported type).
func TestPlaneCORERelocationsResolve(t *testing.T) {
	kernel := kernelBTF(t)
	for _, o := range PlaneObjects() {
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
					// Step C reads a backing file's user path only under bpf_core_field_exists(struct backing_file,
					// user_path), which resolves to 0 on a kernel without that member (below 6.8); the reads beneath
					// it are poisoned there and the verifier never reaches them (TestPlaneLoadsAndAttaches loads
					// the build on such a kernel). Any other poisoned relocation fails.
					if strings.Contains(f.String(), "poison") && strings.Contains(relos[i].String(), `Struct:"backing_file"`) &&
						!kernelHasMember(kernel, "backing_file", "user_path") {
						continue
					}
					if strings.Contains(f.String(), "poison") {
						t.Errorf("%s: relocation %s is poisoned on this kernel", name, relos[i])
					}
				}
			}
			if total == 0 {
				t.Fatal("no CO-RE relocations: the walk reads kernel structs only through them")
			}
		})
	}
}

// TestAdoptedObjectsPinEveryMapByName: a later launcher of a build adopts an object's pinned programs only when every
// map the object declares, but its global-variable sections, is pinned by name (enforce/cgroup adoptObjectIn), or it
// loads and verifies the whole object again. The plane's unpinned tego_plane_path_buf did that to every run of a
// plane mode, 0.6 s of each start in the 6.17 guest (enforce-plane §2.18), and no test noticed: each still ran.
func TestAdoptedObjectsPinEveryMapByName(t *testing.T) {
	type build struct {
		obj    Object
		reader Reader
	}
	builds := []build{{obj: ObjectCgroupNet}, {obj: ObjectCgroupTrack}, {obj: ObjectPlaneRdonly}, {obj: ObjectPlaneProbe}}
	for _, r := range Readers {
		builds = append(builds, build{obj: ObjectTraceProc, reader: r})
	}
	for _, b := range builds {
		var (
			spec *ebpf.CollectionSpec
			err  error
		)
		if b.reader != "" {
			spec, err = LoadReader(b.obj, b.reader)
		} else {
			spec, err = Load(b.obj)
		}
		if err != nil {
			t.Fatalf("load %s %s: %v", b.obj, b.reader, err)
		}
		for name, ms := range spec.Maps {
			if strings.HasPrefix(name, ".") {
				continue
			}
			if ms.Pinning != ebpf.PinByName {
				t.Errorf("%s %s: map %s is not pinned by name (pinning %v): no launcher after the first adopts the "+
					"object's programs", b.obj, b.reader, name, ms.Pinning)
			}
		}
	}
}
