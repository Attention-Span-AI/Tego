// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"slices"
	"testing"
	"unsafe"
)

// TestStructSizes pins every wire width to the value bpf/include/events.h produces. The kernel writes these
// bytes and userspace reads them with no length negotiation, so a silent size change is a silent corruption.
func TestStructSizes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Run", unsafe.Sizeof(Run{}), 16},
		{"NetOwner", unsafe.Sizeof(NetOwner{}), 32},
		{"NetKey", unsafe.Sizeof(NetKey{}), 24},
		{"NetLPMKey", unsafe.Sizeof(NetLPMKey{}), 28},
		{"NetVerdict", unsafe.Sizeof(NetVerdict{}), 16},
		{"Breadcrumb", unsafe.Sizeof(Breadcrumb{}), 40},
		{"Header", unsafe.Sizeof(Header{}), 48},
		{"ExecEvent", unsafe.Sizeof(ExecEvent{}), 888},
		{"ExitEvent", unsafe.Sizeof(ExitEvent{}), 64},
		{"ExecResultEvent", unsafe.Sizeof(ExecResultEvent{}), 64},
		{"FSEvent", unsafe.Sizeof(FSEvent{}), 336},
		{"FSOpEvent", unsafe.Sizeof(FSOpEvent{}), 1128},
		{"NetEvent", unsafe.Sizeof(NetEvent{}), 80},
		{"CgroupEvent", unsafe.Sizeof(CgroupEvent{}), 72},
		{"SockEvent", unsafe.Sizeof(SockEvent{}), 64},
		{"SockoptEvent", unsafe.Sizeof(SockoptEvent{}), 80},
		{"PlaneRow", unsafe.Sizeof(PlaneRow{}), 32},
		{"PlaneExecRow", unsafe.Sizeof(PlaneExecRow{}), 312},
		{"PlaneDecision", unsafe.Sizeof(PlaneDecision{}), 216},
		{"PlaneBind", unsafe.Sizeof(PlaneBind{}), 152},
		{"BindResultEvent", unsafe.Sizeof(BindResultEvent{}), 200},
		{"PlaneListenKey", unsafe.Sizeof(PlaneListenKey{}), 128},
		{"PlaneListenRow", unsafe.Sizeof(PlaneListenRow{}), 24},
		{"PlaneEvent", unsafe.Sizeof(PlaneEvent{}), 352},
		{"PlaneCounts", unsafe.Sizeof(PlaneCounts{}), 32},
		{"PlaneSlot", unsafe.Sizeof(PlaneSlot{}), 128},
		{"PlaneNameRow", unsafe.Sizeof(PlaneNameRow{}), 288},
		{"PlaneNameConfig", unsafe.Sizeof(PlaneNameConfig{}), 288},
		{"ExecPin", unsafe.Sizeof(ExecPin{}), 160},
		{"PinKey", unsafe.Sizeof(PinKey{}), 16},
		{"PinKeyval", unsafe.Sizeof(PinKeyval{}), 24},
		{"ExecKillEvent", unsafe.Sizeof(ExecKillEvent{}), 592},
		{"ExecHeldEvent", unsafe.Sizeof(ExecHeldEvent{}), 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("sizeof(%s) = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestNoImplicitPadding asserts that every struct's Go size equals its packed wire size. They can only differ
// if a field needed alignment padding the C side did not name, which would shift every field after it.
func TestNoImplicitPadding(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		v    any
		size uintptr
	}{
		{"Run", Run{}, unsafe.Sizeof(Run{})},
		{"NetOwner", NetOwner{}, unsafe.Sizeof(NetOwner{})},
		{"NetKey", NetKey{}, unsafe.Sizeof(NetKey{})},
		{"NetLPMKey", NetLPMKey{}, unsafe.Sizeof(NetLPMKey{})},
		{"NetVerdict", NetVerdict{}, unsafe.Sizeof(NetVerdict{})},
		{"Breadcrumb", Breadcrumb{}, unsafe.Sizeof(Breadcrumb{})},
		{"Header", Header{}, unsafe.Sizeof(Header{})},
		{"ExecEvent", ExecEvent{}, unsafe.Sizeof(ExecEvent{})},
		{"ExitEvent", ExitEvent{}, unsafe.Sizeof(ExitEvent{})},
		{"ExecResultEvent", ExecResultEvent{}, unsafe.Sizeof(ExecResultEvent{})},
		{"FSEvent", FSEvent{}, unsafe.Sizeof(FSEvent{})},
		{"FSOpEvent", FSOpEvent{}, unsafe.Sizeof(FSOpEvent{})},
		{"NetEvent", NetEvent{}, unsafe.Sizeof(NetEvent{})},
		{"CgroupEvent", CgroupEvent{}, unsafe.Sizeof(CgroupEvent{})},
		{"SockEvent", SockEvent{}, unsafe.Sizeof(SockEvent{})},
		{"SockoptEvent", SockoptEvent{}, unsafe.Sizeof(SockoptEvent{})},
		{"PlaneRow", PlaneRow{}, unsafe.Sizeof(PlaneRow{})},
		{"PlaneExecRow", PlaneExecRow{}, unsafe.Sizeof(PlaneExecRow{})},
		{"PlaneDecision", PlaneDecision{}, unsafe.Sizeof(PlaneDecision{})},
		{"PlaneBind", PlaneBind{}, unsafe.Sizeof(PlaneBind{})},
		{"BindResultEvent", BindResultEvent{}, unsafe.Sizeof(BindResultEvent{})},
		{"PlaneListenKey", PlaneListenKey{}, unsafe.Sizeof(PlaneListenKey{})},
		{"PlaneListenRow", PlaneListenRow{}, unsafe.Sizeof(PlaneListenRow{})},
		{"PlaneEvent", PlaneEvent{}, unsafe.Sizeof(PlaneEvent{})},
		{"PlaneCounts", PlaneCounts{}, unsafe.Sizeof(PlaneCounts{})},
		{"PlaneSlot", PlaneSlot{}, unsafe.Sizeof(PlaneSlot{})},
		{"PlaneNameRow", PlaneNameRow{}, unsafe.Sizeof(PlaneNameRow{})},
		{"PlaneNameConfig", PlaneNameConfig{}, unsafe.Sizeof(PlaneNameConfig{})},
		{"ExecPin", ExecPin{}, unsafe.Sizeof(ExecPin{})},
		{"PinKey", PinKey{}, unsafe.Sizeof(PinKey{})},
		{"PinKeyval", PinKeyval{}, unsafe.Sizeof(PinKeyval{})},
		{"ExecKillEvent", ExecKillEvent{}, unsafe.Sizeof(ExecKillEvent{})},
		{"ExecHeldEvent", ExecHeldEvent{}, unsafe.Sizeof(ExecHeldEvent{})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := binary.Size(tc.v); got < 0 || uintptr(got) != tc.size {
				t.Fatalf("%s: packed size %d, Go size %d", tc.name, got, tc.size)
			}
		})
	}
}

// TestHeaderOffsets pins the field offsets DecodeHeader hard-codes.
func TestHeaderOffsets(t *testing.T) {
	t.Parallel()
	var h Header
	cases := []struct {
		field string
		got   uintptr
		want  uintptr
	}{
		{"Version", unsafe.Offsetof(h.Version), 0},
		{"Kind", unsafe.Offsetof(h.Kind), 2},
		{"Size", unsafe.Offsetof(h.Size), 4},
		{"TSMonoNS", unsafe.Offsetof(h.TSMonoNS), 8},
		{"CgroupID", unsafe.Offsetof(h.CgroupID), 16},
		{"PID", unsafe.Offsetof(h.PID), 24},
		{"TID", unsafe.Offsetof(h.TID), 28},
		{"PPID", unsafe.Offsetof(h.PPID), 32},
		{"RunIdx", unsafe.Offsetof(h.RunIdx), 36},
		{"Verdict", unsafe.Offsetof(h.Verdict), 40},
		{"Reason", unsafe.Offsetof(h.Reason), 41},
		{"RuleIdx", unsafe.Offsetof(h.RuleIdx), 42},
		{"Gen", unsafe.Offsetof(h.Gen), 44},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("Header.%s at %d, want %d", tc.field, tc.got, tc.want)
		}
	}
}

// TestKindString covers every named kind plus the unknown fallback.
func TestKindString(t *testing.T) {
	t.Parallel()
	cases := map[Kind]string{
		KindExec: "exec", KindExit: "exit", KindOpen: "open", KindUnlink: "unlink",
		KindRename: "rename", KindMkdir: "mkdir", KindConnect: "connect", KindSendmsg: "sendmsg",
		KindBind: "bind", KindCgroupMkdir: "cgroup_mkdir", KindCgroupRmdir: "cgroup_rmdir",
		KindSSLChunk: "ssl_chunk", KindSSLClose: "ssl_close", KindMknod: "mknod", KindRmdir: "rmdir",
		KindLink: "link", KindSymlink: "symlink", KindTruncate: "truncate", KindPlaneExec: "plane_exec",
		KindPlaneAttr: "plane_attr", KindPlaneSocket: "plane_socket", KindPlaneMap: "plane_map", KindPlaneFS: "plane_fs",
		KindExecResult: "exec_result", KindPlaneControl: "plane_control", KindBindResult: "bind_result", KindListenResult: "listen_result", KindSockCreate: "sock_create", KindSockopt: "sockopt", KindPlaneExecKill: "plane_exec_kill",
		KindPlaneExecHeld: "plane_exec_held", Kind(250): "kind(250)",
		Kind(0): "kind(0)",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", uint16(k), got, want)
		}
	}
}

// TestProgramNameSetsAreDisjoint guards against a copy-paste that would attach one object's program through
// another's name list.
func TestProgramNameSetsAreDisjoint(t *testing.T) {
	t.Parallel()
	seen := map[string]string{}
	for group, names := range map[string][]string{
		"cgroup": CgroupPrograms, "track": TrackPrograms, "trace": TracePrograms,
	} {
		for _, n := range names {
			if prev, dup := seen[n]; dup {
				t.Fatalf("program %q listed in both %s and %s", n, prev, group)
			}
			seen[n] = group
		}
	}
	if len(CgroupPrograms) != 8 || len(TrackPrograms) != 2 || len(TracePrograms) != 19 {
		t.Fatalf("program counts changed: %d/%d/%d", len(CgroupPrograms), len(TrackPrograms), len(TracePrograms))
	}
	if len(SharedMaps) != 11 {
		t.Fatalf("SharedMaps has %d entries, want the eleven of §3 (including the durable tracking-failure counter "+
			"and the activity stamp)", len(SharedMaps))
	}
}

// TestActivityIsASharedSlotMapZeroedAtPrepare: tego_activity is pinned with the build's other shared maps, so
// whichever object a launcher loads first makes the one instance, and Prepare and the dead-slot purge zero it with
// the slot's counters, so a stamp the slot's previous run left reads as nothing to the next (limits R4). RunActivity
// is events.h's TEGO_RUN_ACTIVITY, a bit no other run flag uses.
func TestActivityIsASharedSlotMapZeroedAtPrepare(t *testing.T) {
	if !slices.Contains(SharedMaps, MapActivity) {
		t.Errorf("SharedMaps lacks %s", MapActivity)
	}
	if !slices.Contains(SlotCounters, MapActivity) {
		t.Errorf("SlotCounters lacks %s: Prepare would hand a slot's next run its previous run's stamp", MapActivity)
	}
	if RunActivity != 2 || RunActivity&RunListenerResults != 0 {
		t.Errorf("RunActivity = %#x, want TEGO_RUN_ACTIVITY 0x02, apart from RunListenerResults", RunActivity)
	}
	if n := unsafe.Sizeof(ActivitySlot{}); n != 16 {
		t.Errorf("ActivitySlot is %d bytes, want struct tego_activity_slot's 16", n)
	}
}
