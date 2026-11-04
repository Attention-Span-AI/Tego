// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
)

func TestPlaneListenerFillRequiresDistinctCurrentParentDescriptors(t *testing.T) {
	rows := &decide.PlaneRows{Listen: []decide.PlaneListenRow{{Path: "/w/one", Parent: "/w", Name: "one", Rule: 0}, {Path: "/w/two", Parent: "/w", Name: "two", Rule: 1}}}
	held := map[string]int{"/w/one": 10, "/w/two": 11}
	id := &fakeIdentity{fds: map[int][3]uint64{10: {30, 7, 100}, 11: {30, 7, 100}}, paths: map[string][2]uint64{"/w": {7, 100}}}
	plan := &planeFillPlan{RunIdx: 2, Gen: 4}
	if err := planPlaneListenFill(plan, rows, heldOf(held), id); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 2 || plan.Entries[0].What != bpf.PlaneFillListen || plan.Entries[0].ParentIno != 100 || plan.Entries[0].Name != "one" {
		t.Fatalf("plan %+v", plan)
	}
	_, vals := plan.wants(17)
	if vals[0].What != bpf.PlaneFillListen || vals[0].NameLen != 3 || string(vals[0].Name[:4]) != "one\x00" {
		t.Fatalf("template %+v", vals[0])
	}
	held["/w/two"] = 10
	if err := planPlaneListenFill(&planeFillPlan{}, rows, heldOf(held), id); err == nil {
		t.Fatal("shared descriptor accepted")
	}
	held["/w/two"] = 11
	id.paths["/w"] = [2]uint64{8, 100}
	if err := planPlaneListenFill(&planeFillPlan{}, rows, heldOf(held), id); err == nil {
		t.Fatal("same inode on another filesystem accepted")
	}
}

func TestAbstractPlaneListenersUseExactBytesAndGeneration(t *testing.T) {
	req := planeFillRequest{Gen: 3, Rows: &decide.PlaneRows{Listen: []decide.PlaneListenRow{{Abstract: true, Name: "svc\x00x", Rule: 2}, {Abstract: true, Name: "svc", Rule: 3}}}}
	keys, vals, err := abstractListenRows(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] == keys[1] || keys[0].Parent != 0 || keys[0].Abstract != 1 || keys[0].NameLen != 5 || string(keys[0].Name[:5]) != "svc\x00x" || vals[0].Gen != 3 || vals[0].RuleIdx != 2 {
		t.Fatalf("keys %+v values %+v", keys, vals)
	}
	req.Rows.Listen = append(req.Rows.Listen, req.Rows.Listen[0])
	if _, _, err := abstractListenRows(req); err == nil {
		t.Fatal("duplicate exact abstract name accepted")
	}
	req.Rows.Listen = req.Rows.Listen[:1]
	req.Gen = 0
	if _, _, err := abstractListenRows(req); err == nil {
		t.Fatal("generation zero accepted")
	}
	req.Gen = 3
	req.Rows.Listen[0].Name = strings.Repeat("x", 108)
	if _, _, err := abstractListenRows(req); err == nil {
		t.Fatal("oversized name accepted")
	}
	req.Rows.Listen = make([]decide.PlaneListenRow, bpf.PlaneListenRowsMax+1)
	if _, _, err := abstractListenRows(req); err == nil {
		t.Fatal("over capacity accepted")
	}
	if err := planPlaneListenFill(&planeFillPlan{}, req.Rows, nil, &fakeIdentity{}); err == nil {
		t.Fatal("over capacity fill accepted")
	}
}

func TestBuiltinNameFillCoalescesAliasesAndOverridesListener(t *testing.T) {
	rows := &decide.PlaneRows{
		Protected: []decide.PlaneListenRow{{Path: "builtin:one", Parent: "/w", Name: "blocked", Rule: 0x8000}, {Path: "builtin:two", Parent: "/alias", Name: "blocked", Rule: 0x8001}},
		Listen:    []decide.PlaneListenRow{{Path: "/w/blocked", Parent: "/w", Name: "blocked", Rule: 0}},
	}
	held := map[string]int{"builtin:one": 10, "builtin:two": 11, "/w/blocked": 12}
	id := &fakeIdentity{fds: map[int][3]uint64{10: {30, 7, 100}, 11: {30, 7, 100}, 12: {30, 7, 100}}, paths: map[string][2]uint64{"/w": {7, 100}, "/alias": {7, 100}}}
	plan := &planeFillPlan{RunIdx: 2, Gen: 4}
	if err := planPlaneListenFill(plan, rows, heldOf(held), id); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 1 || plan.Entries[0].RuleIdx != 0x8000 {
		t.Fatalf("immutable alias/listener conflict: %+v", plan.Entries)
	}
}

func TestBuiltinTTYSlotDelegatesToTheDomain(t *testing.T) {
	plain := slotHeader(planeFillRequest{Rows: &decide.PlaneRows{}}, false, 0, 0)
	builtin := slotHeader(planeFillRequest{Rows: &decide.PlaneRows{BuiltinTerminals: true}}, false, 0, 0)
	if plain.Flags&bpf.PlaneSlotBuiltinTTY != 0 || builtin.Flags&bpf.PlaneSlotBuiltinTTY == 0 {
		t.Fatalf("terminal delegation flags plain=%#x builtin=%#x", plain.Flags, builtin.Flags)
	}
}

func TestBuiltinPeerExceptionKeepsMutationRefusal(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		protected := []decide.PlaneListenRow{{Path: "deny", Parent: "/w", Name: "ssh", Rule: 0x8007}, {Path: "peer", Parent: "/w", Name: "ssh", Rule: 0x2000}}
		if reverse {
			protected[0], protected[1] = protected[1], protected[0]
		}
		rows := &decide.PlaneRows{Protected: protected}
		held := map[string]int{"deny": 10, "peer": 11}
		id := &fakeIdentity{fds: map[int][3]uint64{10: {30, 7, 100}, 11: {30, 7, 100}}, paths: map[string][2]uint64{"/w": {7, 100}}}
		plan := &planeFillPlan{}
		if err := planPlaneListenFill(plan, rows, heldOf(held), id); err != nil {
			t.Fatal(err)
		}
		if len(plan.Entries) != 1 || plan.Entries[0].RuleIdx != 0xa007 {
			t.Fatalf("peer/write separation: %+v", plan.Entries)
		}
	}
}

func TestBuiltinLedgerClassifierReachesFillTemplate(t *testing.T) {
	plan := &planeFillPlan{Entries: []planeFillEntry{{BuiltinFlags: 1}}}
	_, v := plan.wants(1)
	if len(v) != 1 || v[0].Pad2 != 1 {
		t.Fatalf("lost ledger ancestry classifier: %+v", v)
	}
}
