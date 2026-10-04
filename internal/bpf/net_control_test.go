// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func TestNetworkControlWireSizes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		value      any
		size, want uintptr
	}{
		{"NetControl", NetControl{}, unsafe.Sizeof(NetControl{}), 40},
		{"IngressKey", IngressKey{}, unsafe.Sizeof(IngressKey{}), 48},
		{"NetFlowKey", NetFlowKey{}, unsafe.Sizeof(NetFlowKey{}), 48},
		{"NetFlow", NetFlow{}, unsafe.Sizeof(NetFlow{}), 32},
		{"NetReservation", NetReservation{}, unsafe.Sizeof(NetReservation{}), 32},
		{"NetSocketKey", NetSocketKey{}, unsafe.Sizeof(NetSocketKey{}), 16},
		{"NetSocket", NetSocket{}, unsafe.Sizeof(NetSocket{}), 64},
		{"BindAttemptKey", BindAttemptKey{}, unsafe.Sizeof(BindAttemptKey{}), 24},
		{"ConnectApprovalKey", ConnectApprovalKey{}, unsafe.Sizeof(ConnectApprovalKey{}), 40},
		{"ConnectCredit", ConnectCredit{}, unsafe.Sizeof(ConnectCredit{}), 16},
		{"NetStats", NetStats{}, unsafe.Sizeof(NetStats{}), 112},
		{"NetDecision", NetDecision{}, unsafe.Sizeof(NetDecision{}), 16},
		{"NetTimeline", NetTimeline{}, unsafe.Sizeof(NetTimeline{}), 264},
	} {
		if tc.size != tc.want || binary.Size(tc.value) != int(tc.want) {
			t.Errorf("%s Go=%d packed=%d C=%d", tc.name, tc.size, binary.Size(tc.value), tc.want)
		}
	}
}

// TestSYNReservationIsTheKernelDefine: NetSYNReservation is TEGO_NET_SYN_RESERVATION_NS, the lifetime the kernel
// arms each admitted inbound SYN's timer with (bpf-1).
func TestSYNReservationIsTheKernelDefine(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "bpf", "include", "net_control.h"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("#define TEGO_NET_SYN_RESERVATION_NS %dULL\n", NetSYNReservation.Nanoseconds())
	if !strings.Contains(string(b), want) {
		t.Fatalf("net_control.h lacks %q", want)
	}
}
