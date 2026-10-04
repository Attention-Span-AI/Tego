// SPDX-License-Identifier: Apache-2.0
package dns

import (
	"fmt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"net/netip"
	"testing"
	"time"
)

func TestGateHostsCompleteAliasesProtocolExpiryAndBound(t *testing.T) {
	now := time.Unix(1000, 0)
	zero := time.Duration(0)
	ip := netip.MustParseAddr("93.184.216.34")
	rules := []agent.NetRule{{Raw: "first.example:443", Host: "first.example", Port: 443, Proto: agent.ProtoTCP, IPs: []netip.Addr{ip}, TTL: time.Minute, ResolvedAt: now}, {Raw: "second.example:443", Host: "second.example", Port: 443, Proto: agent.ProtoTCP, IPs: []netip.Addr{ip}, TTL: time.Minute, ResolvedAt: now}, {Raw: "udp.example:443", Host: "udp.example", Port: 443, Proto: agent.ProtoUDP, IPs: []netip.Addr{ip}, TTL: time.Minute, ResolvedAt: now}}
	s := NewSet(rules, nil, Options{MaxStale: &zero, Now: func() time.Time { return now }})
	hosts, complete := s.GateHosts(netip.AddrPortFrom(ip, 443), ProtoTCP)
	if !complete || len(hosts) != 2 || hosts[0] != "first.example" || hosts[1] != "second.example" {
		t.Fatalf("aliases %v complete%t", hosts, complete)
	}
	now = now.Add(2 * time.Minute)
	if hosts, complete = s.GateHosts(netip.AddrPortFrom(ip, 443), ProtoTCP); !complete || len(hosts) != 0 {
		t.Fatalf("expired %v %t", hosts, complete)
	}
	rules = nil
	for i := 0; i < 257; i++ {
		rules = append(rules, agent.NetRule{Raw: fmt.Sprintf("h%d.example:443", i), Host: fmt.Sprintf("h%d.example", i), Port: 443, Proto: agent.ProtoTCP, IPs: []netip.Addr{ip}, Static: true})
	}
	s = NewSet(rules, nil, Options{})
	if hosts, complete = s.GateHosts(netip.AddrPortFrom(ip, 443), ProtoTCP); complete || len(hosts) != 0 {
		t.Fatalf("incomplete bound accepted %d %t", len(hosts), complete)
	}
}
