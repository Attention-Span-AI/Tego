// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestEvaluateInResolver pins R14 in compile --test: a TCP or UDP connect to a machine resolver on port 53
// is allowed as net.resolver ahead of every entry, as the supervisor decides it (IsResolver); another port,
// another address or an empty list falls through to the entries.
func TestEvaluateInResolver(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierLandlock, Contract: &agent.Contract{}}
	rt.Net = []agent.NetRule{{Host: "127.0.0.1", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
		IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}
	env := Env{Resolvers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.2:53")}}
	cases := []struct {
		host  string
		port  int
		proto string
		env   Env
		want  string
	}{
		{"127.0.0.2", 53, "udp", env, agent.ResolverRule},
		{"127.0.0.2", 53, "tcp", env, agent.ResolverRule},
		{"::ffff:127.0.0.2", 53, "UDP", env, agent.ResolverRule},
		{"127.0.0.2", 54, "udp", env, agent.UnmatchedRule},
		{"127.0.0.3", 53, "udp", env, agent.UnmatchedRule},
		{"127.0.0.2", 53, "udp", Env{}, agent.UnmatchedRule},
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, c := range cases {
			got := EvaluateIn(rt, agent.Action{Kind: agent.ActionNetConnect, Host: c.host, Port: c.port, Proto: c.proto}, tier, c.env)
			if got.Rule != c.want {
				t.Errorf("%s %s:%d/%s: rule %q, want %q", tier, c.host, c.port, c.proto, got.Rule, c.want)
			}
			if c.want == agent.ResolverRule && got.Verdict != agent.VerdictAllow {
				t.Errorf("%s %s:%d/%s: verdict %s, want allow", tier, c.host, c.port, c.proto, got.Verdict)
			}
		}
	}
}
