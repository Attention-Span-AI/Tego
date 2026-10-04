// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

// TestNetSocketPolicy pins the one socket predicate the seccomp filter's socket arm and the decision plane's
// socket_create row both read (ADR 0018 (1), (5)): nothing without a net: section, the allowlist with one,
// ping sockets only when a non-unix entry names port 0. Before it lived here each layer kept its own copy,
// and nothing failed when the two drifted.
func TestNetSocketPolicy(t *testing.T) {
	restricted := &Contract{Net: &NetSection{}}
	for _, tc := range []struct {
		name string
		rt   *RuleTable
		want SocketPolicy
	}{
		{"nil table", nil, SocketPolicy{}},
		{"no net: section", &RuleTable{Contract: &Contract{}}, SocketPolicy{}},
		{"no contract fails closed", &RuleTable{}, SocketPolicy{Restricted: true}},
		{"net: {}", &RuleTable{Contract: restricted}, SocketPolicy{Restricted: true}},
		{"a tcp entry", &RuleTable{Contract: restricted, Net: []NetRule{{Proto: ProtoTCP, Port: 443}}}, SocketPolicy{Restricted: true}},
		{"an inet port-0 entry", &RuleTable{Contract: restricted, Net: []NetRule{{Proto: ProtoInet}}}, SocketPolicy{Restricted: true, ICMP: true}},
		{"a udp port-0 entry", &RuleTable{Contract: restricted, Net: []NetRule{{Proto: ProtoUDP}}}, SocketPolicy{Restricted: true, ICMP: true}},
		{"a unix entry is no icmp entry", &RuleTable{Contract: restricted, Net: []NetRule{{Proto: ProtoUnix}}}, SocketPolicy{Restricted: true}},
		{"icmp among others", &RuleTable{Contract: restricted, Net: []NetRule{{Proto: ProtoUnix}, {Proto: ProtoTCP, Port: 22}, {Proto: ProtoInet}}},
			SocketPolicy{Restricted: true, ICMP: true}},
	} {
		if got := tc.rt.NetSocketPolicy(); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
