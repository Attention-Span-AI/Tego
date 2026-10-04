// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestNetworkExpiryComposesIndependentGrantsAndRefusals(t *testing.T) {
	wall := time.Unix(1000, 0)
	ip := netip.MustParseAddr("198.51.100.4")
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	rules := []agent.NetRule{
		{Proto: agent.ProtoTCP, Port: 443, IPs: []netip.Addr{ip}, Verdict: agent.VerdictAllow, ExpiresAt: wall.Add(time.Second)},
		{Proto: agent.ProtoInet, Port: 443, CIDR: &prefix, Verdict: agent.VerdictAllow},
		{Proto: agent.ProtoTCP, Port: 443, IPs: []netip.Addr{ip}, Verdict: agent.VerdictAsk, ExpiresAt: wall.Add(2 * time.Second)},
	}
	cover := newNetCover(rules)
	_, chain, err := cover.timelineVerdict(bpf.ProtoTCP, 443, netip.PrefixFrom(ip, 32), true, deadlineClock{wall: wall, mono: 50, dynamic: true})
	if err != nil {
		t.Fatal(err)
	}
	// The earlier allow's expiry causes no decision change while the refusing
	// entry is active; after refusal expires, the independent CIDR admits.
	if chain.Count != 2 || chain.Steps[0].RuleIdx != 3 || chain.Steps[0].Verdict != uint8(bpf.VerdictRefused) || chain.Steps[0].DeadlineNS != 2000000050 || chain.Steps[1].RuleIdx != 2 || chain.Steps[1].DeadlineNS != 0 {
		t.Fatalf("chain=%+v", chain)
	}
	_, udp, err := cover.timelineVerdict(bpf.ProtoUDP, 443, netip.PrefixFrom(ip, 32), true, deadlineClock{wall: wall, mono: 50, dynamic: true})
	if err != nil || udp.Count != 0 {
		t.Fatalf("unrelated TCP expiry changed UDP: %+v %v", udp, err)
	}
}

func TestNetworkExpiryBoundariesAndCapacity(t *testing.T) {
	wall := time.Unix(1000, 0)
	ip := netip.MustParseAddr("198.51.100.4")
	var rules []agent.NetRule
	for i := 0; i < bpf.MaxNetIntervals; i++ {
		rules = append(rules, agent.NetRule{Proto: agent.ProtoTCP, Port: 443, IPs: []netip.Addr{ip}, Verdict: agent.VerdictAllow, ExpiresAt: wall.Add(time.Duration(i+1) * time.Second)})
	}
	clock := deadlineClock{wall: wall, mono: 100, dynamic: true}
	_, _, err := newNetCover(rules).timelineVerdict(bpf.ProtoTCP, 443, netip.PrefixFrom(ip, 32), true, clock)
	if !errors.Is(err, ErrMapFull) {
		t.Fatalf("17 intervals accepted: %v", err)
	}
	rules = rules[:bpf.MaxNetIntervals-1]
	value, chain, err := newNetCover(rules).timelineVerdict(bpf.ProtoTCP, 443, netip.PrefixFrom(ip, 32), true, clock)
	if err != nil || chain.Count != 16 || value.DeadlineNS != 1000000100 || chain.Steps[15].Verdict != uint8(bpf.VerdictRefused) || chain.Steps[15].RuleIdx != 0 {
		t.Fatalf("bounded complete chain: %+v %v", chain, err)
	}
	clock.wall = wall.Add(time.Second)
	value, chain, err = newNetCover(rules[:2]).timelineVerdict(bpf.ProtoTCP, 443, netip.PrefixFrom(ip, 32), true, clock)
	if err != nil || value.RuleIdx != 2 || chain.Count != 2 {
		t.Fatalf("exact boundary retained expired rule: %+v %+v %v", value, chain, err)
	}
}
