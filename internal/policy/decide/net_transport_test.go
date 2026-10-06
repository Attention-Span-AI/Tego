// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestSelectedTransportMatchingAndRefusalPrecedence(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.0/24")
	for _, reverse := range []bool{false, true} {
		rules := []agent.NetRule{
			{Raw: "udp://192.0.2.8:443", Proto: agent.ProtoUDP, Port: 443, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.8")}, Verdict: agent.VerdictAllow},
			{Raw: "tcp://192.0.2.0/24:443", Proto: agent.ProtoTCP, Port: 443, CIDR: &p, Verdict: agent.VerdictRefused},
			{Raw: "192.0.2.8:443", Proto: agent.ProtoInet, Port: 443, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.8")}, Verdict: agent.VerdictAllow},
		}
		if reverse {
			rules[0], rules[1] = rules[1], rules[0]
		}
		rt := &agent.RuleTable{Net: rules}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			for _, host := range []string{"192.0.2.8", "::ffff:192.0.2.8"} {
				for _, proto := range []string{agent.ProtoTCP, agent.ProtoUDP} {
					got := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: host, Port: 443, Proto: proto}, tier)
					want, raw := agent.VerdictAllow, "udp://192.0.2.8:443"
					if proto == agent.ProtoTCP {
						want, raw = agent.VerdictRefused, "tcp://192.0.2.0/24:443"
					}
					if got.Verdict != want || got.Rule != (agent.NetRule{Raw: raw}).RuleName() {
						t.Fatalf("tier %s %s %s reverse=%v: %+v", tier, proto, host, reverse, got)
					}
				}
			}
		}
	}
}

func TestTCPRuntimeCaptureGrantDoesNotAdmitUDPModelTraffic(t *testing.T) {
	rt := &agent.RuleTable{Capture: agent.CaptureForwarder, Contract: &agent.Contract{Net: &agent.NetSection{}, Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}}},
		Net: []agent.NetRule{{Raw: "127.0.0.1:8443", Proto: agent.ProtoTCP, Runtime: agent.CaptureGrant, Port: 8443, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Verdict: agent.VerdictAllow}}}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, proto := range []string{agent.ProtoTCP, agent.ProtoUDP} {
			got := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: "127.0.0.1", Port: 8443, Proto: proto}, tier)
			want := agent.VerdictAllow
			if proto == agent.ProtoUDP {
				want = agent.VerdictRefused
			}
			if got.Verdict != want {
				t.Fatalf("%s %s: %+v", tier, proto, got)
			}
		}
	}
}
