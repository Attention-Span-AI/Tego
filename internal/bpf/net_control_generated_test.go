// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// These mirrors are initialized/read by userspace, while the kernel shares
// their exact BTF map layouts across all network producers and the plane.
func TestNetworkControlGeneratedABI(t *testing.T) {
	for _, tc := range []struct {
		name            string
		mine, generated any
	}{
		{"NetControl", NetControl{}, cgroupnetTegoNcConfig{}},
		{"IngressKey", IngressKey{}, cgroupnetTegoIngressKey{}},
		{"NetFlowKey", NetFlowKey{}, cgroupnetTegoNetFlowKey{}},
		{"NetFlow", NetFlow{}, cgroupnetTegoNetFlow{}},
		{"NetReservation", NetReservation{}, cgroupnetTegoNetReservation{}},
		{"NetSocketKey", NetSocketKey{}, cgroupnetTegoNetSocketKey{}},
		{"NetSocket", NetSocket{}, cgroupnetTegoNetSocket{}},
		{"BindAttemptKey", BindAttemptKey{}, cgroupnetTegoBindAttemptKey{}},
		{"ConnectApprovalKey", ConnectApprovalKey{}, cgroupnetTegoConnectApprovalKey{}},
		{"ConnectCredit", ConnectCredit{}, cgroupnetTegoConnectCredit{}},
		{"NetStats", NetStats{}, cgroupnetTegoNcStats{}},
		{"NetVerdict", NetVerdict{}, cgroupnetTegoNetVerdict{}},
		{"NetTimelineKey", NetTimelineKey{}, cgroupnetTegoNetTimelineKey{}},
		{"NetTimeline", NetTimeline{}, cgroupnetTegoNetChain{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			networkFieldParity(t, tc.name, reflect.TypeOf(tc.mine), reflect.TypeOf(tc.generated))
			if binary.Size(tc.mine) != binary.Size(tc.generated) {
				t.Fatalf("packed mirror%d != generated%d", binary.Size(tc.mine), binary.Size(tc.generated))
			}
		})
	}
}

func networkFieldParity(t *testing.T, path string, mine, generated reflect.Type) {
	t.Helper()
	if mine.Size() != generated.Size() {
		t.Errorf("%s mirror size%d != generated%d", path, mine.Size(), generated.Size())
	}
	if mine.Kind() == reflect.Array && generated.Kind() == reflect.Array {
		if mine.Len() != generated.Len() {
			t.Errorf("%s array width mismatch", path)
		}
		networkFieldParity(t, path+"[]", mine.Elem(), generated.Elem())
		return
	}
	if mine.Kind() != reflect.Struct || generated.Kind() != reflect.Struct {
		return
	}
	fields := map[string]reflect.StructField{}
	for i := 0; i < generated.NumField(); i++ {
		f := generated.Field(i)
		if f.Name != "_" {
			fields[strings.ToLower(f.Name)] = f
		}
	}
	for i := 0; i < mine.NumField(); i++ {
		f := mine.Field(i)
		if f.Name == "_" {
			continue
		}
		name := strings.ToLower(f.Name)
		g, ok := fields[name]
		if !ok {
			t.Errorf("%s.%s missing generated field", path, f.Name)
			continue
		}
		delete(fields, name)
		if f.Offset != g.Offset {
			t.Errorf("%s.%s offset%d != generated%d", path, f.Name, f.Offset, g.Offset)
		}
		networkFieldParity(t, path+"."+f.Name, f.Type, g.Type)
	}
	for _, f := range fields {
		t.Errorf("%s.%s has no userspace mirror", path, f.Name)
	}
}

func TestNetworkControlGeneratedMapShapes(t *testing.T) {
	spec, err := Load(ObjectCgroupNet)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		key, value any
		typ        ebpf.MapType
	}{
		{MapNetControl, uint32(0), NetControl{}, ebpf.Hash},
		{MapBindExact, NetKey{}, NetVerdict{}, ebpf.Hash},
		{MapIngress, IngressKey{}, NetVerdict{}, ebpf.LPMTrie},
		{MapNetFlows, NetFlowKey{}, NetFlow{}, ebpf.LRUHash},
		{MapNetPending, NetFlowKey{}, NetReservation{}, ebpf.Hash},
		{MapNetSockets, NetSocketKey{}, NetSocket{}, ebpf.Hash},
		{MapNetStats, uint32(0), NetStats{}, ebpf.Hash},
		{MapNetBinds, NetSocketKey{}, uint32(0), ebpf.Hash},
		{MapBindPending, BindAttemptKey{}, uint32(0), ebpf.LRUHash},
		{MapConnectApprovals, ConnectApprovalKey{}, ConnectCredit{}, ebpf.Hash},
		{MapNetTimeline, NetTimelineKey{}, NetTimeline{}, ebpf.Hash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := spec.Maps[tc.name]
			if m == nil {
				t.Fatal("required map missing from object")
			}
			if m.Type != tc.typ || int(m.KeySize) != binary.Size(tc.key) || int(m.ValueSize) != binary.Size(tc.value) {
				t.Fatalf("map type%s key%d value%d != %s key%d value%d", m.Type, m.KeySize, m.ValueSize, tc.typ, binary.Size(tc.key), binary.Size(tc.value))
			}
		})
	}
}
