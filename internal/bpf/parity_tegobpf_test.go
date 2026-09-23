// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"runtime"
	"slices"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

// TestLayoutParity asserts that every hand-written mirror in types.go has the same size as the mirror bpf2go
// derived from the object's own BTF. The hand-written ones are what an untagged build decodes with, so a
// field added to bpf/include/events.h without a Go counterpart must fail here rather than shift a decode.
func TestLayoutParity(t *testing.T) {
	cases := []struct {
		name       string
		mine, gen  uintptr
		fieldCheck func(t *testing.T)
	}{
		{name: "Run", mine: unsafe.Sizeof(Run{}), gen: unsafe.Sizeof(cgroupnetTegoRun{})},
		{name: "NetOwner", mine: unsafe.Sizeof(NetOwner{}), gen: unsafe.Sizeof(cgroupnetTegoNetOwner{})},
		{name: "NetKey", mine: unsafe.Sizeof(NetKey{}), gen: unsafe.Sizeof(cgroupnetTegoNetKey{})},
		{name: "NetLPMKey", mine: unsafe.Sizeof(NetLPMKey{}), gen: unsafe.Sizeof(cgroupnetTegoNetLpmKey{})},
		{name: "NetVerdict", mine: unsafe.Sizeof(NetVerdict{}), gen: unsafe.Sizeof(cgroupnetTegoNetVerdict{})},
		{name: "UnixKey", mine: unsafe.Sizeof(UnixKey{}), gen: unsafe.Sizeof(cgroupnetTegoUnixKey{})},
		{name: "Breadcrumb", mine: unsafe.Sizeof(Breadcrumb{}), gen: unsafe.Sizeof(cgroupnetTegoReason{})},
		{name: "Header", mine: unsafe.Sizeof(Header{}), gen: unsafe.Sizeof(traceTegoHdr{})},
		{name: "ExecEvent", mine: unsafe.Sizeof(ExecEvent{}), gen: unsafe.Sizeof(traceTegoEvExec{})},
		{name: "ExitEvent", mine: unsafe.Sizeof(ExitEvent{}), gen: unsafe.Sizeof(traceTegoEvExit{})},
		{name: "ExecResultEvent", mine: unsafe.Sizeof(ExecResultEvent{}), gen: unsafe.Sizeof(traceTegoEvExecResult{})},
		{name: "BindResultEvent", mine: unsafe.Sizeof(BindResultEvent{}), gen: unsafe.Sizeof(traceTegoEvBindResult{})},
		{name: "FSEvent", mine: unsafe.Sizeof(FSEvent{}), gen: unsafe.Sizeof(traceTegoEvFs{})},
		{name: "FSOpEvent", mine: unsafe.Sizeof(FSOpEvent{}), gen: unsafe.Sizeof(traceTegoEvFsop{})},
		{name: "NetEvent", mine: unsafe.Sizeof(NetEvent{}), gen: unsafe.Sizeof(traceTegoEvNet{})},
		{name: "CgroupEvent", mine: unsafe.Sizeof(CgroupEvent{}), gen: unsafe.Sizeof(cgrouptrackTegoEvCgroup{})},
		{name: "SockEvent", mine: unsafe.Sizeof(SockEvent{}), gen: unsafe.Sizeof(cgroupnetTegoEvSock{})},
		{name: "SockoptEvent", mine: unsafe.Sizeof(SockoptEvent{}), gen: unsafe.Sizeof(cgroupnetTegoEvSockopt{})},
		{name: "ActivitySlot", mine: unsafe.Sizeof(ActivitySlot{}), gen: unsafe.Sizeof(traceTegoActivitySlot{})},
	}
	for _, tc := range cases {
		if tc.mine != tc.gen {
			t.Errorf("%s: types.go says %d bytes, bpf2go's BTF mirror says %d", tc.name, tc.mine, tc.gen)
		}
	}
}

// TestFieldParity spot-checks the offsets that a size comparison alone cannot catch: two fields swapped keep
// the size and change every decode.
func TestFieldParity(t *testing.T) {
	var (
		mineHdr  Header
		genHdr   traceTegoHdr
		mineKey  NetKey
		genKey   cgroupnetTegoNetKey
		mineFsop FSOpEvent
		genFsop  traceTegoEvFsop
		mineOwn  NetOwner
		genOwn   cgroupnetTegoNetOwner
		mineUnix UnixKey
		genUnix  cgroupnetTegoUnixKey
		// The three left unchecked: the breadcrumb, the CIDR key and the run-set row
		// were compared by size alone, which two swapped fields of one width keep.
		mineCrumb Breadcrumb
		genCrumb  cgroupnetTegoReason
		mineLPM   NetLPMKey
		genLPM    cgroupnetTegoNetLpmKey
		mineRun   Run
		genRun    cgroupnetTegoRun
		// The records whose layouts the same review changed: every field added since, and one behind each.
		mineExec       ExecEvent
		genExec        traceTegoEvExec
		mineFS         FSEvent
		genFS          traceTegoEvFs
		mineExecResult ExecResultEvent
		genExecResult  traceTegoEvExecResult
		mineBindResult BindResultEvent
		genBindResult  traceTegoEvBindResult
		mineNet        NetEvent
		genNet         traceTegoEvNet
		mineSock       SockEvent
		genSock        cgroupnetTegoEvSock
		mineSockopt    SockoptEvent
		genSockopt     cgroupnetTegoEvSockopt
	)
	cases := []struct {
		field     string
		mine, gen uintptr
	}{
		{"Header.Kind", unsafe.Offsetof(mineHdr.Kind), unsafe.Offsetof(genHdr.Kind)},
		{"Header.Size", unsafe.Offsetof(mineHdr.Size), unsafe.Offsetof(genHdr.Size)},
		{"Header.CgroupID", unsafe.Offsetof(mineHdr.CgroupID), unsafe.Offsetof(genHdr.CgroupId)},
		{"Header.RunIdx", unsafe.Offsetof(mineHdr.RunIdx), unsafe.Offsetof(genHdr.RunIdx)},
		{"Header.Reason", unsafe.Offsetof(mineHdr.Reason), unsafe.Offsetof(genHdr.Reason)},
		{"NetKey.Family", unsafe.Offsetof(mineKey.Family), unsafe.Offsetof(genKey.Family)},
		{"NetKey.Port", unsafe.Offsetof(mineKey.Port), unsafe.Offsetof(genKey.Port)},
		{"NetKey.Addr", unsafe.Offsetof(mineKey.Addr), unsafe.Offsetof(genKey.Addr)},
		{"FSOpEvent.DirIno2", unsafe.Offsetof(mineFsop.DirIno2), unsafe.Offsetof(genFsop.DirIno2)},
		{"FSOpEvent.Name2", unsafe.Offsetof(mineFsop.Name2), unsafe.Offsetof(genFsop.Name2)},
		{"FSOpEvent.DirState", unsafe.Offsetof(mineFsop.DirState), unsafe.Offsetof(genFsop.DirState)},
		{"FSOpEvent.Dir2Off", unsafe.Offsetof(mineFsop.Dir2Off), unsafe.Offsetof(genFsop.Dir2Off)},
		{"FSOpEvent.Dir", unsafe.Offsetof(mineFsop.Dir), unsafe.Offsetof(genFsop.Dir)},
		{"FSOpEvent.Dir2", unsafe.Offsetof(mineFsop.Dir2), unsafe.Offsetof(genFsop.Dir2)},
		{"NetOwner.Flags", unsafe.Offsetof(mineOwn.Flags), unsafe.Offsetof(genOwn.Flags)},
		{"NetOwner.RelayCgroupID", unsafe.Offsetof(mineOwn.RelayCgroupID), unsafe.Offsetof(genOwn.RelayCgroupId)},
		{"NetOwner.Gen", unsafe.Offsetof(mineOwn.Gen), unsafe.Offsetof(genOwn.Gen)},
		{"SockEvent.Family", unsafe.Offsetof(mineSock.Family), unsafe.Offsetof(genSock.Family)},
		{"SockEvent.Type", unsafe.Offsetof(mineSock.Type), unsafe.Offsetof(genSock.Type)},
		{"SockEvent.Protocol", unsafe.Offsetof(mineSock.Protocol), unsafe.Offsetof(genSock.Protocol)},
		{"SockoptEvent.Level", unsafe.Offsetof(mineSockopt.Level), unsafe.Offsetof(genSockopt.Level)},
		{"SockoptEvent.Optname", unsafe.Offsetof(mineSockopt.Optname), unsafe.Offsetof(genSockopt.Optname)},
		{"SockoptEvent.Optlen", unsafe.Offsetof(mineSockopt.Optlen), unsafe.Offsetof(genSockopt.Optlen)},
		{"SockoptEvent.Name", unsafe.Offsetof(mineSockopt.Name), unsafe.Offsetof(genSockopt.Name)},
		{"UnixKey.Kind", unsafe.Offsetof(mineUnix.Kind), unsafe.Offsetof(genUnix.Kind)},
		{"UnixKey.Name", unsafe.Offsetof(mineUnix.Name), unsafe.Offsetof(genUnix.Name)},
		{"Breadcrumb.Verdict", unsafe.Offsetof(mineCrumb.Verdict), unsafe.Offsetof(genCrumb.Verdict)},
		{"Breadcrumb.Reason", unsafe.Offsetof(mineCrumb.Reason), unsafe.Offsetof(genCrumb.Reason)},
		{"Breadcrumb.Family", unsafe.Offsetof(mineCrumb.Family), unsafe.Offsetof(genCrumb.Family)},
		{"Breadcrumb.Proto", unsafe.Offsetof(mineCrumb.Proto), unsafe.Offsetof(genCrumb.Proto)},
		{"Breadcrumb.Port", unsafe.Offsetof(mineCrumb.Port), unsafe.Offsetof(genCrumb.Port)},
		{"Breadcrumb.Addr", unsafe.Offsetof(mineCrumb.Addr), unsafe.Offsetof(genCrumb.Addr)},
		{"Breadcrumb.MonoNS", unsafe.Offsetof(mineCrumb.MonoNS), unsafe.Offsetof(genCrumb.MonoNs)},
		{"Breadcrumb.RunIdx", unsafe.Offsetof(mineCrumb.RunIdx), unsafe.Offsetof(genCrumb.RunIdx)},
		{"Breadcrumb.RuleIdx", unsafe.Offsetof(mineCrumb.RuleIdx), unsafe.Offsetof(genCrumb.RuleIdx)},
		{"NetLPMKey.RunIdx", unsafe.Offsetof(mineLPM.RunIdx), unsafe.Offsetof(genLPM.RunIdx)},
		{"NetLPMKey.Family", unsafe.Offsetof(mineLPM.Family), unsafe.Offsetof(genLPM.Family)},
		{"NetLPMKey.Proto", unsafe.Offsetof(mineLPM.Proto), unsafe.Offsetof(genLPM.Proto)},
		{"NetLPMKey.Port", unsafe.Offsetof(mineLPM.Port), unsafe.Offsetof(genLPM.Port)},
		{"NetLPMKey.Addr", unsafe.Offsetof(mineLPM.Addr), unsafe.Offsetof(genLPM.Addr)},
		{"Run.Descendants", unsafe.Offsetof(mineRun.Descendants), unsafe.Offsetof(genRun.Descendants)},
		{"Run.Tier", unsafe.Offsetof(mineRun.Tier), unsafe.Offsetof(genRun.Tier)},
		{"Run.Record", unsafe.Offsetof(mineRun.Record), unsafe.Offsetof(genRun.Record)},
		{"Run.Plane", unsafe.Offsetof(mineRun.Plane), unsafe.Offsetof(genRun.Plane)},
		{"Run.Gen", unsafe.Offsetof(mineRun.Gen), unsafe.Offsetof(genRun.Gen)},
		{"Run.Flags", unsafe.Offsetof(mineRun.Flags), unsafe.Offsetof(genRun.Flags)},
		{"Run.Pad", unsafe.Offsetof(mineRun.Pad), unsafe.Offsetof(genRun.Pad)},
		{"ExecEvent.ParentStartNS", unsafe.Offsetof(mineExec.ParentStartNS), unsafe.Offsetof(genExec.ParentStartNs)},
		{"ExecEvent.CwdDev", unsafe.Offsetof(mineExec.CwdDev), unsafe.Offsetof(genExec.CwdDev)},
		{"ExecEvent.CwdIno", unsafe.Offsetof(mineExec.CwdIno), unsafe.Offsetof(genExec.CwdIno)},
		{"ExecEvent.OldTID", unsafe.Offsetof(mineExec.OldTID), unsafe.Offsetof(genExec.OldTid)},
		{"ExecEvent.Interpreted", unsafe.Offsetof(mineExec.Interpreted), unsafe.Offsetof(genExec.Interpreted)},
		{"ExecEvent.Comm", unsafe.Offsetof(mineExec.Comm), unsafe.Offsetof(genExec.Comm)},
		{"ExecEvent.Path", unsafe.Offsetof(mineExec.Path), unsafe.Offsetof(genExec.Path)},
		{"ExecEvent.PinSeq", unsafe.Offsetof(mineExec.PinSeq), unsafe.Offsetof(genExec.PinSeq)},
		{"FSEvent.StartNS", unsafe.Offsetof(mineFS.StartNS), unsafe.Offsetof(genFS.StartNs)},
		{"FSEvent.Dev", unsafe.Offsetof(mineFS.Dev), unsafe.Offsetof(genFS.Dev)},
		{"FSEvent.ExecOpen", unsafe.Offsetof(mineFS.ExecOpen), unsafe.Offsetof(genFS.ExecOpen)},
		{"FSEvent.Path", unsafe.Offsetof(mineFS.Path), unsafe.Offsetof(genFS.Path)},
		{"ExecResultEvent.StartNS", unsafe.Offsetof(mineExecResult.StartNS), unsafe.Offsetof(genExecResult.StartNs)},
		{"ExecResultEvent.Ret", unsafe.Offsetof(mineExecResult.Ret), unsafe.Offsetof(genExecResult.Ret)},
		{"BindResultEvent.StartNS", unsafe.Offsetof(mineBindResult.StartNS), unsafe.Offsetof(genBindResult.StartNs)},
		{"BindResultEvent.Ret", unsafe.Offsetof(mineBindResult.Ret), unsafe.Offsetof(genBindResult.Ret)},
		{"BindResultEvent.Dev", unsafe.Offsetof(mineBindResult.Dev), unsafe.Offsetof(genBindResult.Dev)},
		{"BindResultEvent.DirIno", unsafe.Offsetof(mineBindResult.DirIno), unsafe.Offsetof(genBindResult.DirIno)},
		{"BindResultEvent.RuleIdx", unsafe.Offsetof(mineBindResult.RuleIdx), unsafe.Offsetof(genBindResult.RuleIdx)},
		{"BindResultEvent.Flags", unsafe.Offsetof(mineBindResult.Flags), unsafe.Offsetof(genBindResult.Flags)},
		{"BindResultEvent.NameLen", unsafe.Offsetof(mineBindResult.NameLen), unsafe.Offsetof(genBindResult.NameLen)},
		{"BindResultEvent.Name", unsafe.Offsetof(mineBindResult.Name), unsafe.Offsetof(genBindResult.Name)},
		{"FSOpEvent.StartNS", unsafe.Offsetof(mineFsop.StartNS), unsafe.Offsetof(genFsop.StartNs)},
		{"FSOpEvent.Dev", unsafe.Offsetof(mineFsop.Dev), unsafe.Offsetof(genFsop.Dev)},
		{"NetEvent.StartNS", unsafe.Offsetof(mineNet.StartNS), unsafe.Offsetof(genNet.StartNs)},
		{"NetEvent.Family", unsafe.Offsetof(mineNet.Family), unsafe.Offsetof(genNet.Family)},
		{"NetEvent.Addr", unsafe.Offsetof(mineNet.Addr), unsafe.Offsetof(genNet.Addr)},
	}
	for _, tc := range cases {
		if tc.mine != tc.gen {
			t.Errorf("%s at %d in types.go, %d in bpf2go's mirror", tc.field, tc.mine, tc.gen)
		}
	}
}

// TestObjectShape asserts every object carries exactly the programs and maps this package names, with the
// program type and attach type the spec requires, and the dual licence without which the kernel refuses a
// GPL-only helper (§9 conventions).
func TestObjectShape(t *testing.T) {
	cases := []struct {
		object   Object
		programs []string
		progType ebpf.ProgramType
		attach   map[string]ebpf.AttachType
	}{
		{
			object: ObjectCgroupNet, programs: append(append(slices.Clone(CgroupPrograms), NetControlPrograms...), SocketPrograms...),
			progType: ebpf.CGroupSockAddr,
			attach: map[string]ebpf.AttachType{
				ProgConnect4: ebpf.AttachCGroupInet4Connect, ProgConnect6: ebpf.AttachCGroupInet6Connect,
				ProgSendmsg4: ebpf.AttachCGroupUDP4Sendmsg, ProgSendmsg6: ebpf.AttachCGroupUDP6Sendmsg,
				ProgBind4: ebpf.AttachCGroupInet4Bind, ProgBind6: ebpf.AttachCGroupInet6Bind,
				ProgConnectUnix: ebpf.AttachCgroupUnixConnect, ProgSendmsgUnix: ebpf.AttachCgroupUnixSendmsg,
				ProgPostBind4: ebpf.AttachCGroupInet4PostBind, ProgPostBind6: ebpf.AttachCGroupInet6PostBind,
				ProgNetIngress: ebpf.AttachCGroupInetIngress, ProgNetEgress: ebpf.AttachCGroupInetEgress,
				ProgNetSockOps: ebpf.AttachCGroupSockOps, ProgNetRelease: ebpf.AttachCgroupInetSockRelease,
				ProgSockCreate: ebpf.AttachCGroupInetSockCreate, ProgSetsockopt: ebpf.AttachCGroupSetsockopt,
			},
		},
		{
			object: ObjectCgroupTrack, programs: TrackPrograms, progType: ebpf.Tracing,
			attach: map[string]ebpf.AttachType{
				ProgCgroupMkdir: ebpf.AttachTraceRawTp, ProgCgroupRmdir: ebpf.AttachTraceRawTp,
			},
		},
		{
			object: ObjectTraceProc, programs: TracePrograms, progType: ebpf.Tracing,
			attach: map[string]ebpf.AttachType{
				ProgSchedExec: ebpf.AttachTraceRawTp, ProgSchedExit: ebpf.AttachTraceRawTp,
				// ADR 0016 (3): the fs programs are fexit, carrying the chain's return; connect stays fentry.
				ProgFileOpen: ebpf.AttachTraceFExit, ProgPathUnlink: ebpf.AttachTraceFExit,
				ProgPathRename: ebpf.AttachTraceFExit, ProgPathMkdir: ebpf.AttachTraceFExit,
				ProgPathMknod: ebpf.AttachTraceFExit, ProgPathRmdir: ebpf.AttachTraceFExit,
				ProgPathLink: ebpf.AttachTraceFExit, ProgPathSymlink: ebpf.AttachTraceFExit,
				ProgPathTruncate: ebpf.AttachTraceFExit, ProgFileTruncate: ebpf.AttachTraceFExit,
				ProgSocketConnect: ebpf.AttachTraceFEntry,
				// enforce-plane §2.20: io_uring's bind and listen results, fexit on the ops.
				ProgURingBindResult: ebpf.AttachTraceFExit, ProgURingListenResult: ebpf.AttachTraceFExit,
			},
		},
		{
			// SEC("uprobe")/SEC("uretprobe") with no attach information: which symbol each
			// program lands on is userspace's choice (R1, R2), so the object declares none.
			object: ObjectUprobeSSL, programs: SSLPrograms, progType: ebpf.Kprobe,
			attach: map[string]ebpf.AttachType{
				ProgSSLWrite: ebpf.AttachNone, ProgSSLWriteEx: ebpf.AttachNone,
				ProgSSLRead: ebpf.AttachNone, ProgSSLReadEx: ebpf.AttachNone,
				ProgSSLReadReturn: ebpf.AttachNone,
				ProgSSLMultiEnter: ebpf.AttachTraceUprobeMulti, ProgSSLMultiReturn: ebpf.AttachTraceUprobeMulti,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.object.String(), func(t *testing.T) {
			if tc.object == ObjectUprobeSSL && !sslCompiledHere() {
				t.Skipf("uprobessl is compiled for amd64 and arm64 only (gen.go), not %s", runtime.GOARCH)
			}
			spec, err := Load(tc.object)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(spec.Programs) != len(tc.programs) {
				t.Fatalf("%d programs, want %d: %v", len(spec.Programs), len(tc.programs), programNames(spec))
			}
			for _, name := range tc.programs {
				p, ok := spec.Programs[name]
				if !ok {
					t.Fatalf("program %q missing; object has %v", name, programNames(spec))
				}
				wantType := tc.progType
				switch name {
				case ProgExecResult, ProgExecatResult, ProgBindResult, ProgListenResult:
					wantType = ebpf.TracePoint
				case ProgNetIngress, ProgNetEgress:
					wantType = ebpf.CGroupSKB
				case ProgNetSockOps:
					wantType = ebpf.SockOps
				case ProgNetRelease, ProgPostBind4, ProgPostBind6, ProgSockCreate:
					wantType = ebpf.CGroupSock
				case ProgSetsockopt:
					wantType = ebpf.CGroupSockopt
				}
				if p.Type != wantType {
					t.Errorf("%s: type %s, want %s", name, p.Type, wantType)
				}
				if want := tc.attach[name]; p.AttachType != want {
					t.Errorf("%s: attach type %s, want %s", name, p.AttachType, want)
				}
				if p.License != "Dual BSD/GPL" {
					t.Errorf("%s: licence %q, want Dual BSD/GPL", name, p.License)
				}
			}
			maps := SharedMaps
			if tc.object == ObjectTraceProc {
				maps = append(slices.Clone(SharedMaps), TraceMaps...)
			} else if _, ok := spec.Maps[MapTaskScratch]; ok {
				t.Errorf("%s defines %s, which only %s's programs use", tc.object, MapTaskScratch, ObjectTraceProc)
			}
			if tc.object == ObjectCgroupNet {
				maps = append(slices.Clone(SharedMaps), NetMaps...)
			} else if _, ok := spec.Maps[MapNetOwners]; ok {
				t.Errorf("%s defines %s, which only %s's programs can read", tc.object, MapNetOwners, ObjectCgroupNet)
			}
			for _, m := range maps {
				ms, ok := spec.Maps[m]
				if !ok {
					t.Fatalf("map %q missing from %s", m, tc.object)
				}
				if ms.Pinning != ebpf.PinByName {
					t.Errorf("map %s: pinning %v, want PinByName", m, ms.Pinning)
				}
			}
		})
	}
}

// TestMapShapes pins the key and value widths the kernel will enforce at insert time and the LPM trie's
// mandatory no-prealloc flag.
func TestMapShapes(t *testing.T) {
	spec, err := Load(ObjectCgroupNet)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		name         string
		typ          ebpf.MapType
		key, value   uint32
		maxEntries   uint32
		wantNoPreall bool
	}{
		{MapRunSet, ebpf.Hash, 8, uint32(unsafe.Sizeof(Run{})), RunSetMax, false},
		{MapNetExact, ebpf.Hash, uint32(unsafe.Sizeof(NetKey{})), uint32(unsafe.Sizeof(NetVerdict{})), NetRowsMax, false},
		{MapNetCIDR, ebpf.LPMTrie, uint32(unsafe.Sizeof(NetLPMKey{})), uint32(unsafe.Sizeof(NetVerdict{})), NetRowsMax, true},
		{MapReason, ebpf.Hash, 8, uint32(unsafe.Sizeof(Breadcrumb{})), CgroupMax, false},
		// Per-run counters indexed by run_idx, zeroed at Prepare (ADR 0026 (4)).
		{MapLost, ebpf.Array, 4, 8, MaxSlots, false},
		{MapTrackingFailed, ebpf.Array, 4, 8, MaxSlots, false},
		{MapCaptureLost, ebpf.Array, 4, 8, MaxSlots, false},
		{MapCaptureMiss, ebpf.Array, 4, 8, MaxSlots, false},
		// Each run's activity stamp, an ActivitySlot by run_idx, zeroed at Prepare like the counters (limits R4).
		{MapActivity, ebpf.Array, 4, uint32(unsafe.Sizeof(ActivitySlot{})), MaxSlots, false},
		// The kernel refuses a cgroup storage map with any max_entries but 0, and an 8-byte key is what makes
		// one value serve every attach type on a cgroup (§5 R1, R2).
		{MapNetOwners, ebpf.CGroupStorage, 8, uint32(unsafe.Sizeof(NetOwner{})), 0, false},
		// struct tego_unix_key is packed: 118 bytes, where Go's UnixKey pads to 120. cilium/ebpf marshals a
		// key whose Go layout has padding field by field, which writes the packed 118 (TestUnixKeyMarshalsPacked).
		{MapUnixNames, ebpf.LPMTrie, 4 + 4 + 1 + 1 + UnixNameMax, uint32(unsafe.Sizeof(NetVerdict{})), UnixRowsMax, true},
		// struct tego_unix_credit is 136 bytes, which UnixCredit's flat fields fill with no Go padding.
		{MapUnixApprovals, ebpf.Hash, 16, 136, UnixApprovalsMax, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := spec.Maps[tc.name]
			if m == nil {
				t.Fatalf("map missing")
			}
			if m.Type != tc.typ {
				t.Errorf("type %s, want %s", m.Type, tc.typ)
			}
			if m.KeySize != tc.key {
				t.Errorf("key size %d, want %d", m.KeySize, tc.key)
			}
			if m.ValueSize != tc.value {
				t.Errorf("value size %d, want %d", m.ValueSize, tc.value)
			}
			if m.MaxEntries != tc.maxEntries {
				t.Errorf("max entries %d, want %d", m.MaxEntries, tc.maxEntries)
			}
			const noPrealloc = 1 // BPF_F_NO_PREALLOC
			if got := m.Flags&noPrealloc != 0; got != tc.wantNoPreall {
				t.Errorf("BPF_F_NO_PREALLOC = %v, want %v", got, tc.wantNoPreall)
			}
		})
	}
	// The ring outers: a run's own ring at its slot, of any size, inside a prototype of the ring type (ADR 0026 (1)).
	for _, name := range RingMaps {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.HashOfMaps || m.KeySize != 4 || m.MaxEntries != MaxSlots || m.Pinning != ebpf.PinByName ||
			m.InnerMap == nil || m.InnerMap.Type != ebpf.RingBuf {
			t.Errorf("%s is %+v, want a pinned HASH_OF_MAPS of %d ring buffers keyed by run_idx", name, m, MaxSlots)
		}
	}
}

// TestHashIsStableAndDistinct asserts the build identity is deterministic within a build and covers every
// object, so two binaries compiled from different C can never share a pin directory (§6 E22).
func TestHashIsStableAndDistinct(t *testing.T) {
	first, err := Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if first != second {
		t.Fatalf("Hash is not stable: %q then %q", first, second)
	}
	if len(first) != HashLen {
		t.Fatalf("Hash() = %q, want %d characters", first, HashLen)
	}
	want := 3
	if sslCompiledHere() {
		want = 4
	}
	if len(Objects()) != want {
		t.Fatalf("Objects() = %v, want %d on %s", Objects(), want, runtime.GOARCH)
	}
	for _, o := range Objects() {
		raw, err := Raw(o)
		if err != nil || len(raw) == 0 {
			t.Fatalf("Raw(%s) = %d bytes, %v", o, len(raw), err)
		}
	}
}

// sslCompiledHere reports whether gen.go compiles uprobessl for the architecture under test, which is the
// same set objects_ssl_gen.go's build constraint names.
func sslCompiledHere() bool {
	switch runtime.GOARCH {
	case "386", "amd64", "arm64":
		return true
	default:
		return false
	}
}

func programNames(spec *ebpf.CollectionSpec) []string {
	out := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		out = append(out, n)
	}
	return out
}
