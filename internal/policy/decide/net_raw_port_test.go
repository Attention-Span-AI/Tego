// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Port zero grants an ICMP/raw destination by host; the sockaddr's port is not
// a TCP/UDP service port. The evaluator and runtime attribution must choose the
// same covering rule, including refusal precedence.
func TestEvaluateRawPortMatchesRuntimeAttribution(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	grant := agent.NetRule{Raw: "192.0.2.1:0", Host: addr.String(), IPs: []netip.Addr{addr},
		Port: 0, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, Static: true}
	for _, tc := range []struct {
		name  string
		rules []agent.NetRule
	}{
		{"literal", []agent.NetRule{grant}},
		{"cidr", []agent.NetRule{{Raw: "192.0.2.0/24:0", CIDR: &prefix, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow}}},
		{"refusal wins", []agent.NetRule{
			{Raw: "192.0.2.1:443", Host: addr.String(), IPs: []netip.Addr{addr}, Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow},
			{Raw: "192.0.2.0/24:0", CIDR: &prefix, Proto: agent.ProtoInet, Verdict: agent.VerdictRefused},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Net: tc.rules}
			i, ok := MatchNetLPM(rt.Net, addr, 443, ProtoRaw)
			if !ok {
				t.Fatal("runtime attribution found no rule")
			}
			want := rt.Net[i]
			for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
				got := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: addr.String(), Port: 443, Proto: ProtoRaw}, tier)
				if got.Verdict != want.Verdict || got.Rule != want.RuleName() {
					t.Errorf("%s: %+v, want runtime %s/%s", tier, got, want.Verdict, want.RuleName())
				}
			}
		})
	}
	for _, proto := range []string{agent.ProtoTCP, agent.ProtoUDP} {
		got := Evaluate(&agent.RuleTable{Net: []agent.NetRule{grant}}, agent.Action{Kind: agent.ActionNetConnect, Host: addr.String(), Port: 443, Proto: proto}, backend.TierLandlock)
		if got.Verdict != agent.VerdictRefused {
			t.Errorf("a port-zero entry admitted %s port 443: %+v", proto, got)
		}
	}
}

func TestRawPortUnresolvedCandidates(t *testing.T) {
	const host = "unresolved.example"
	rule := agent.NetRule{Raw: host + ":0", Host: host, Port: 0, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow}
	rt := &agent.RuleTable{Net: []agent.NetRule{rule}}
	if got := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.1", Port: 443, Proto: ProtoRaw}, backend.TierLandlock); got.Rule != agent.UnresolvedRule {
		t.Errorf("raw literal with unresolved port-zero host: %+v", got)
	}
	rule.Denied = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	rt.Net[0] = rule
	if got := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: host, Port: 443, Proto: ProtoRaw}, backend.TierLandlock); got.Rule != agent.UnresolvedRule {
		t.Errorf("raw named destination with filtered port-zero host: %+v", got)
	}
}
