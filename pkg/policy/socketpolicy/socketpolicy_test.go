// SPDX-License-Identifier: Apache-2.0

package socketpolicy

import "testing"

// TestAllowed spot-checks ADR 0018 (1)'s table; internal/bpf's TestSocketAllowedIsTheADR0018Table holds every
// family, type and protocol of it to an independent spelling, and its root test to the kernel's C function.
func TestAllowed(t *testing.T) {
	for _, c := range []struct {
		name                  string
		family, typ, protocol int32
		icmp, want            bool
	}{
		{"unix stream", 1, 1, 0, false, true},
		{"netlink route", 16, 3, 0, false, true},
		{"netlink route as a datagram socket", 16, 2, 0, false, true},
		{"netlink generic", 16, 3, 16, false, false},
		{"netlink sock_diag", 16, 2, 4, false, false},
		{"netlink audit", 16, 3, 9, false, false},
		{"a netlink protocol whose low byte is route", 16, 3, 256, false, false},
		{"tcp", 2, 1, 0, false, true},
		{"tcp6 by protocol, nonblocking", 10, 1 | 0o4000, 6, false, true},
		{"udp", 2, 2, 17, false, true},
		{"sctp", 2, 1, 132, false, false},
		{"mptcp", 2, 1, 262, false, false},
		{"raw", 2, 3, 1, true, false},
		{"ping without icmp", 2, 2, 1, false, false},
		{"ping with icmp", 2, 2, 1, true, true},
		{"ping6 with icmp", 10, 2, 58, true, true},
		{"packet", 17, 3, 0, false, false},
		{"a negative family", -1, 1, 0, false, false},
	} {
		if got := Allowed(c.family, c.typ, c.protocol, c.icmp); got != c.want {
			t.Errorf("%s: Allowed(%d, %#x, %d, %v) = %v, want %v", c.name, c.family, c.typ, c.protocol, c.icmp, got, c.want)
		}
	}
}
