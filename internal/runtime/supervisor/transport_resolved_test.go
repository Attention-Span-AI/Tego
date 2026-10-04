// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestResolvedRefusalCannotBorrowOtherTransport(t *testing.T) {
	ap := netip.MustParseAddrPort("169.254.169.254:443")
	for _, selected := range []string{agent.ProtoTCP, agent.ProtoUDP} {
		other := agent.ProtoTCP
		if selected == other {
			other = agent.ProtoUDP
		}
		for _, reverse := range []bool{false, true} {
			host := netRule(selected+"://rebind.example:443", "rebind.example", 443, ap.Addr().String())
			host.Proto = selected
			literal := netRule(other+"://169.254.169.254:443", ap.Addr().String(), 443, ap.Addr().String())
			literal.Proto = other
			rules := []agent.NetRule{host, literal}
			if reverse {
				rules[0], rules[1] = rules[1], rules[0]
			}
			rt := &agent.RuleTable{Net: rules}
			set := dns.NewSet(rules, nil, dns.Options{})
			c := &compiled{pol: &Policy{Rules: rt, Resolver: set}}
			if v := c.admitResolved(ap, selected, set.Match(ap, selected)); v.allowed || v.rule != agent.DeniedResolvedRule(host.Raw) {
				t.Fatalf("%s reversed=%v: %+v", selected, reverse, v)
			}
			if v := c.admitResolved(ap, other, set.Match(ap, other)); !v.allowed || v.rule != literal.RuleName() {
				t.Fatalf("literal %s reversed=%v: %+v", other, reverse, v)
			}
			host.IPs = nil
			host.Denied = []netip.Addr{ap.Addr()}
			rt.Net = []agent.NetRule{host}
			if v := c.admitResolved(ap, other, nil); v.rule != ruleUnmatched {
				t.Fatalf("nil match attributed other transport: %+v", v)
			}
			if v := c.admitResolved(ap, selected, nil); v.rule != agent.DeniedResolvedRule(host.Raw) {
				t.Fatalf("nil match lost selected attribution: %+v", v)
			}
		}
	}
}
