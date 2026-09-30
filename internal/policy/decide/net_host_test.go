// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestEvaluateNetCanonicalHost: a connect row's host is compared in the spelling ParseEndpoint gives an
// entry's Host (agent.CanonicalHost), as evalGuard compares it. `example.com.` is the name `example.com`,
// which the run admits on the addresses both resolve to; matchNet alone compared the row's text and
// refused it.
func TestEvaluateNetCanonicalHost(t *testing.T) {
	rt := &agent.RuleTable{Net: []agent.NetRule{
		{Proto: agent.ProtoInet, Host: "example.com", Port: 443, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
		{Proto: agent.ProtoInet, Host: "::1", Port: 8080, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{netip.MustParseAddr("::1")}},
	}}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, c := range []struct {
			host  string
			port  int
			allow bool
		}{
			{"example.com", 443, true},
			{"example.com.", 443, true},
			{"EXAMPLE.Com.", 443, true},
			{"::ffff:93.184.216.34", 443, true},
			{"[::1]", 8080, true},
			{"0:0::1", 8080, true},
			{"example.com..", 443, false},
			{"example.org.", 443, false},
			{"example.com.", 80, false},
		} {
			res := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: c.host, Port: c.port}, tier)
			if (res.Verdict == agent.VerdictAllow) != c.allow {
				t.Errorf("tier %v connect %s:%d = %v %s, want allow=%v", tier, c.host, c.port, res.Verdict, res.Rule, c.allow)
			}
		}
	}
}
