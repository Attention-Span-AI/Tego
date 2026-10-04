// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestTransportSelectorsMatchAndRefresh(t *testing.T) {
	now := time.Unix(1, 0)
	lookup := newLookup()
	lookup.answers["shared.example"] = [][]netip.Addr{{netip.MustParseAddr("203.0.113.8")}}
	rules := []agent.NetRule{
		{Raw: "tcp://shared.example:443", Proto: agent.ProtoTCP, Host: "shared.example", Port: 443, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.8")}, TTL: time.Second, ResolvedAt: now},
		{Raw: "udp://shared.example:443", Proto: agent.ProtoUDP, Host: "shared.example", Port: 443, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.8")}, TTL: time.Second, ResolvedAt: now},
	}
	set := NewSet(rules, nil, Options{Lookup: lookup, Now: func() time.Time { return now }, MinTTL: time.Second})
	for _, proto := range []string{ProtoTCP, ProtoUDP} {
		m := set.Match(netip.MustParseAddrPort("[::ffff:192.0.2.8]:443"), proto)
		if m == nil || m.Proto != proto || m.Raw != proto+"://shared.example:443" {
			t.Fatalf("%s: %+v", proto, m)
		}
	}
	if set.Match(netip.MustParseAddrPort("192.0.2.8:443"), ProtoRaw) != nil {
		t.Fatal("selected transports admitted raw")
	}
	now = now.Add(time.Hour)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lookup.calls["shared.example"] != 1 {
		t.Fatalf("lookups: %v", lookup.calls)
	}
	refreshed := set.Refreshed(rules)
	for i, r := range refreshed {
		if r.Proto != rules[i].Proto || len(r.IPs) != 1 || r.IPs[0] != netip.MustParseAddr("203.0.113.8") {
			t.Fatalf("refreshed: %+v", r)
		}
	}
	wrong := append([]agent.NetRule(nil), rules...)
	wrong[0].Proto = agent.ProtoUDP
	if got := set.Refreshed(wrong); got[0].IPs[0] != rules[0].IPs[0] {
		t.Fatal("refresh rewrote a different transport")
	}
}

func TestTransportRefusingOverlapAndLegacy(t *testing.T) {
	ap := netip.MustParseAddrPort("192.0.2.1:443")
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	for _, reverse := range []bool{false, true} {
		rules := []agent.NetRule{
			{Raw: "udp://192.0.2.1:443", Proto: agent.ProtoUDP, Port: 443, IPs: []netip.Addr{ap.Addr()}, Static: true},
			{Raw: "tcp://192.0.2.0/24:443", Proto: agent.ProtoTCP, Port: 443, CIDR: &prefix, Verdict: agent.VerdictRefused},
			{Raw: "192.0.2.1:443", Proto: agent.ProtoInet, Port: 443, IPs: []netip.Addr{ap.Addr()}, Static: true},
		}
		if reverse {
			rules[0], rules[1] = rules[1], rules[0]
		}
		set := NewSet(rules, nil, Options{})
		if m := set.Match(ap, ProtoTCP); m == nil || m.Verdict != agent.VerdictRefused || m.Proto != agent.ProtoTCP {
			t.Fatalf("TCP refusal lost: %+v", m)
		}
		if m := set.Match(ap, ProtoUDP); m == nil || m.Verdict != agent.VerdictAllow || m.Proto != agent.ProtoUDP {
			t.Fatalf("TCP refusal leaked to UDP: %+v", m)
		}
	}
}
