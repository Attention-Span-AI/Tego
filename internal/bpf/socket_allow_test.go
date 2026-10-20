// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The table's axes: every family, type and protocol ADR 0018 names or that a runtime is known to ask for, and the
// SOCK_NONBLOCK | SOCK_CLOEXEC flags socket(2) carries in its type argument.
var (
	socketTableFamilies = []int32{afUnix, afInet, afInet6, afNetlink, 17 /* AF_PACKET */, 30 /* AF_TIPC */, 40, /* AF_VSOCK */
		43 /* AF_SMC */, 0 /* AF_UNSPEC */}
	socketTableTypes  = []int32{sockStream, sockDgram, 3 /* SOCK_RAW */, 5 /* SOCK_SEQPACKET */, sockStream | 0x800 | 0x80000}
	socketTableProtos = []int32{0, ipprotoTCP, ipprotoUDP, ipprotoICMP, ipprotoICMPv6, 136 /* UDPLITE */, 132, /* SCTP */
		262 /* MPTCP */, 256 /* SMC */, 255 /* RAW */, 256 + ipprotoTCP, 256 + ipprotoUDP,
		4 /* NETLINK_SOCK_DIAG */, 9 /* NETLINK_AUDIT */, 16 /* NETLINK_GENERIC */}
)

// socketAdmitted is ADR 0018 (1) written out as the set it admits, independently of SocketAllowed's own branches:
// a triple is in it when one of these rows names it.
func socketAdmitted(family, typ, protocol int32, icmp bool) bool {
	type row struct {
		families []int32
		types    []int32 // nil: any
		protos   []int32 // nil: any
		icmp     bool    // the row needs the net section's ICMP entry
	}
	inet := []int32{afInet, afInet6}
	rows := []row{
		{families: []int32{afUnix}},
		{families: []int32{afNetlink}, protos: []int32{netlinkRoute}},
		{families: inet, types: []int32{sockStream}, protos: []int32{0, ipprotoTCP}},
		{families: inet, types: []int32{sockDgram}, protos: []int32{0, ipprotoUDP}},
		{families: inet, types: []int32{sockDgram}, protos: []int32{ipprotoICMP, ipprotoICMPv6}, icmp: true},
	}
	in := func(v int32, set []int32) bool {
		if set == nil {
			return true
		}
		for _, s := range set {
			if s == v {
				return true
			}
		}
		return false
	}
	for _, r := range rows {
		if in(family, r.families) && in(typ&sockTypeMask, r.types) && in(protocol, r.protos) && (!r.icmp || icmp) {
			return true
		}
	}
	return false
}

// TestSocketAllowedIsTheADR0018Table is the parity table of ADR 0018 PR 2: SocketAllowed, the Go spelling of
// bpf/include/socket_allow.h, admits exactly ADR 0018 (1)'s set over every family × type × protocol × ICMP cell the
// table names, a protocol above 255 never reads as its low byte (MPTCP 262 is not TCP, IPPROTO_SMC 256 not 0), and
// type's flags change nothing. The seccomp filter's arm is held to it in enforce/landlock
// (TestFilterSocketArmIsTheKernelAllowlist), and the C function in the kernel as root (sockcreate_integration_test).
func TestSocketAllowedIsTheADR0018Table(t *testing.T) {
	t.Parallel()
	cells := 0
	for _, family := range socketTableFamilies {
		for _, typ := range socketTableTypes {
			for _, protocol := range socketTableProtos {
				for _, icmp := range []bool{false, true} {
					cells++
					if got, want := SocketAllowed(family, typ, protocol, icmp), socketAdmitted(family, typ, protocol, icmp); got != want {
						t.Errorf("SocketAllowed(family %d, type %#x, protocol %d, icmp %v) = %v, want %v",
							family, typ, protocol, icmp, got, want)
					}
				}
			}
		}
	}
	for _, c := range []struct {
		name                  string
		family, typ, protocol int32
		icmp, want            bool
	}{
		{"mptcp is not tcp", afInet, sockStream, 262, false, false},
		{"smc is not protocol 0", afInet6, sockStream, 256, false, false},
		{"udp-lite", afInet, sockDgram, 136, false, false},
		{"sctp one-to-many", afInet6, 5, 132, false, false},
		{"ping without an icmp entry", afInet, sockDgram, ipprotoICMP, false, false},
		{"ping with an icmp entry", afInet, sockDgram, ipprotoICMP, true, true},
		{"raw icmp even with an icmp entry", afInet, 3, ipprotoICMP, true, false},
		{"nonblocking cloexec tcp", afInet6, sockStream | 0x800 | 0x80000, 0, false, true},
	} {
		if got := SocketAllowed(c.family, c.typ, c.protocol, c.icmp); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	t.Logf("%d cells", cells)
}

// TestSocketAllowedTakesICMPFromTheSocketPolicy ties the icmp argument to agent.RuleTable.NetSocketPolicy, the one
// predicate the seccomp arm, the plane's slot header and cgroup/sock_create's owner flag read (ADR 0018 (1), (5)):
// a ping socket is admitted exactly when the net section names an ICMP destination, a port-0 entry.
func TestSocketAllowedTakesICMPFromTheSocketPolicy(t *testing.T) {
	t.Parallel()
	net := &agent.Contract{Net: &agent.NetSection{}}
	for _, c := range []struct {
		name string
		rt   *agent.RuleTable
		ping bool
	}{
		{"net: {}", &agent.RuleTable{Contract: net}, false},
		{"a tcp entry", &agent.RuleTable{Contract: net, Net: []agent.NetRule{{Proto: agent.ProtoInet, Port: 443}}}, false},
		{"an icmp entry", &agent.RuleTable{Contract: net, Net: []agent.NetRule{{Proto: agent.ProtoInet, Port: 0}}}, true},
		{"a unix entry is no icmp entry", &agent.RuleTable{Contract: net, Net: []agent.NetRule{{Proto: agent.ProtoUnix}}}, false},
	} {
		p := c.rt.NetSocketPolicy()
		if !p.Restricted {
			t.Fatalf("%s: a net: section is not restricted", c.name)
		}
		for _, family := range []int32{afInet, afInet6} {
			for _, protocol := range []int32{ipprotoICMP, ipprotoICMPv6} {
				if got := SocketAllowed(family, sockDgram, protocol, p.ICMP); got != c.ping {
					t.Errorf("%s: ping family %d protocol %d admitted %v, want %v", c.name, family, protocol, got, c.ping)
				}
			}
		}
	}
}

// TestSocketAllowedConstantsAreCommonH holds the Go constants to bpf/include/common.h's, and to socket_allow.h's
// NETLINK_ROUTE, the numbers the C function compares with.
func TestSocketAllowedConstantsAreCommonH(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "bpf", "include", "common.h"))
	if err != nil {
		t.Fatal(err)
	}
	allow, err := os.ReadFile(filepath.Join("..", "..", "bpf", "include", "socket_allow.h"))
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, allow...)
	for name, v := range map[string]int{"TEGO_AF_UNIX": afUnix, "TEGO_AF_INET": afInet, "TEGO_AF_INET6": afInet6,
		"TEGO_AF_NETLINK": afNetlink, "TEGO_NETLINK_ROUTE": netlinkRoute, "TEGO_SOCK_STREAM": sockStream, "TEGO_SOCK_DGRAM": sockDgram,
		"TEGO_SOCK_TYPE_MASK": sockTypeMask, "TEGO_IPPROTO_ICMP": ipprotoICMP, "TEGO_IPPROTO_TCP": ipprotoTCP,
		"TEGO_IPPROTO_UDP": ipprotoUDP, "TEGO_IPPROTO_ICMPV6": ipprotoICMPv6} {
		m := regexp.MustCompile(`(?m)^#define ` + name + ` (0x[0-9a-f]+|[0-9]+)$`).FindSubmatch(b)
		if m == nil {
			t.Errorf("common.h and socket_allow.h do not define %s", name)
			continue
		}
		if got, err := strconv.ParseInt(string(m[1]), 0, 32); err != nil || int(got) != v {
			t.Errorf("%s is %s in common.h, %d here", name, m[1], v)
		}
	}
}
