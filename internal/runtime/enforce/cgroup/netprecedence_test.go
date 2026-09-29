// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// kernelNet is the kernel's lookup over the rows (§5 R3): the exact row, else the longest matching prefix row,
// else refused with no rule.
func kernelNet(t *testing.T, m RuleMaps, proto uint8, addr netip.Addr, port uint16) (bool, string) {
	t.Helper()
	k, err := bpf.NewNetKey(0, proto, addr, port)
	if err != nil {
		t.Fatalf("NewNetKey: %v", err)
	}
	for _, row := range m.Exact {
		if row.Key == k {
			return row.Val.Verdict == uint8(bpf.VerdictAllow), m.RuleName(row.Val.RuleIdx)
		}
	}
	look, err := bpf.LookupLPMKey(0, proto, addr, port)
	if err != nil {
		t.Fatalf("LookupLPMKey: %v", err)
	}
	var best *CIDRRow
	for i := range m.CIDR {
		row := &m.CIDR[i]
		if row.Key.Matches(look) && (best == nil || row.Key.PrefixLen > best.Key.PrefixLen) {
			best = row
		}
	}
	if best == nil {
		return false, agent.UnmatchedRule
	}
	return best.Val.Verdict == uint8(bpf.VerdictAllow), m.RuleName(best.Val.RuleIdx)
}

// TestNetPrecedenceMatchesEvaluate is SEMANTICS §5's overlap rule: over every ordering of overlapping allow and
// ask (refused) entries, literal and prefix, the kernel's rows, Evaluate and the supervisor's set give each
// destination the same verdict and name the same entry: a refusing covering entry, else the first declared.
func TestNetPrecedenceMatchesEvaluate(t *testing.T) {
	t.Parallel()
	wide := netip.MustParsePrefix("10.0.0.0/8")
	narrow := netip.MustParsePrefix("10.1.0.0/16")
	lit := netip.MustParseAddr("10.1.2.3")
	pool := []agent.NetRule{
		{Raw: "10.0.0.0/8:443", Port: 443, Proto: agent.ProtoInet, CIDR: &wide, Verdict: agent.VerdictAllow},
		{Raw: "ask 10.0.0.0/8:443", Port: 443, Proto: agent.ProtoInet, CIDR: &wide, Verdict: agent.VerdictAsk},
		{Raw: "10.1.0.0/16:443", Port: 443, Proto: agent.ProtoInet, CIDR: &narrow, Verdict: agent.VerdictAllow},
		{Raw: "ask 10.1.0.0/16:443", Port: 443, Proto: agent.ProtoInet, CIDR: &narrow, Verdict: agent.VerdictAsk},
		{Raw: "10.1.2.3:443", Host: "10.1.2.3", Port: 443, Proto: agent.ProtoInet, IPs: []netip.Addr{lit}, Verdict: agent.VerdictAllow},
		{Raw: "ask 10.1.2.3:443", Host: "10.1.2.3", Port: 443, Proto: agent.ProtoInet, IPs: []netip.Addr{lit}, Verdict: agent.VerdictAsk},
	}
	dests := []netip.Addr{lit, netip.MustParseAddr("10.1.9.9"), netip.MustParseAddr("10.9.9.9"), netip.MustParseAddr("11.0.0.1")}

	var orders [][]int
	for a := range pool {
		for b := range pool {
			if b == a {
				continue
			}
			orders = append(orders, []int{a, b})
			for c := range pool {
				if c != a && c != b {
					orders = append(orders, []int{a, b, c})
				}
			}
		}
	}
	for _, order := range orders {
		var entries []agent.NetRule
		for _, i := range order {
			entries = append(entries, pool[i])
		}
		rt := table(entries...)
		m, err := BuildRuleMaps(rt, 0, nil, nil)
		if err != nil {
			t.Fatalf("%v: BuildRuleMaps: %v", order, err)
		}
		set := dns.NewSet(entries, nil, dns.Options{})
		for _, dst := range dests {
			for _, proto := range []string{agent.ProtoTCP, agent.ProtoUDP} {
				want := decide.Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: dst.String(), Port: 443, Proto: proto}, backend.TierCgroup)
				desc := fmt.Sprintf("order %v, %s:443/%s", order, dst, proto)
				bproto := uint8(bpf.ProtoTCP)
				if proto == agent.ProtoUDP {
					bproto = bpf.ProtoUDP
				}
				for _, a := range []netip.Addr{dst, netip.AddrFrom16(dst.As16())} {
					allowed, rule := kernelNet(t, m, bproto, a, 443)
					if allowed != (want.Verdict == agent.VerdictAllow) || rule != want.Rule {
						t.Fatalf("%s (key %s): kernel %v %q, Evaluate %s %q", desc, a, allowed, rule, want.Verdict, want.Rule)
					}
				}
				got := set.Match(netip.AddrPortFrom(dst, 443), proto)
				gotRule, gotAllow := agent.UnmatchedRule, false
				if got != nil {
					gotRule, gotAllow = got.Rule, got.Verdict == agent.VerdictAllow
				}
				if gotAllow != (want.Verdict == agent.VerdictAllow) || gotRule != want.Rule {
					t.Fatalf("%s: supervisor set %v %q, Evaluate %s %q", desc, gotAllow, gotRule, want.Verdict, want.Rule)
				}
			}
		}
	}
}
