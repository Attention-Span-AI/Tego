// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestDeniedResolvedNAT64MatchesTransportAndEmbeddedRanges(t *testing.T) {
	a := netip.MustParseAddr("64:ff9b::808:808")
	for _, prefix := range []string{"::/0", "64:ff9b::/96", "8.8.8.0/24"} {
		t.Run(prefix, func(t *testing.T) {
			class, denied := DeniedResolvedClass(a, []netip.Prefix{netip.MustParsePrefix(prefix)})
			if !denied || class != ResolvedMachine {
				t.Fatalf("%s under %s: class=%q denied=%v, want machine denial", a, prefix, class, denied)
			}
		})
	}
	mixed := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("64:ff9b::/96")}
	if class, denied := DeniedResolvedClass(a, mixed); !denied || class != ResolvedMachine {
		t.Fatalf("mixed prefixes: class=%q denied=%v", class, denied)
	}
	if class, denied := DeniedResolvedClass(netip.MustParseAddr("64:ff9b::a9fe:a9fe"), mixed); !denied || class != ResolvedMetadata {
		t.Fatalf("built-in metadata class lost precedence: class=%q denied=%v", class, denied)
	}
	// An IPv4-mapped answer uses IPv4 transport; an IPv6-only machine prefix does not deny it.
	if _, denied := DeniedResolvedClass(netip.MustParseAddr("::ffff:8.8.8.8"), []netip.Prefix{netip.MustParsePrefix("::/0")}); denied {
		t.Fatal("IPv4 transport was denied by an IPv6 prefix")
	}
}

func TestCompileDropsMachineDeniedNAT64HostAnswers(t *testing.T) {
	f := newFixture(t)
	a := netip.MustParseAddr("64:ff9b::808:808")
	f.resolver.table["nat64.example"] = []netip.Addr{a}
	f.machine.DeniedResolved = config.Setting[[]netip.Prefix]{Value: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}}
	c := f.load("version: 0\nname: t\ncommand: [python]\nnet:\n  allow: [nat64.example:443, '[64:ff9b::808:808]:444', '64:ff9b::/96:445']\n")
	rt, ds := f.compile(c)
	if len(rt.Net) != 3 {
		t.Fatalf("rules: %+v", rt.Net)
	}
	r := rt.Net[0]
	if len(r.IPs) != 0 || len(r.Denied) != 1 || r.Denied[0] != a {
		t.Errorf("host answer was not filtered: %+v", r)
	}
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "nat64.example", Port: 443}, rt.Tier); got.Verdict != VerdictRefused {
		t.Errorf("denied host name evaluates as %+v", got)
	}
	for _, r := range rt.Net[1:] {
		if !r.Static || len(r.Denied) != 0 {
			t.Errorf("explicit literal/CIDR grant changed: %+v", r)
		}
	}
	for _, row := range []struct {
		port int
		want Verdict
	}{{443, VerdictRefused}, {444, VerdictAllow}, {445, VerdictAllow}} {
		if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: a.String(), Port: row.port}, rt.Tier); got.Verdict != row.want {
			t.Errorf("NAT64 address on port %d: %+v, want %s", row.port, got, row.want)
		}
	}
	warned := false
	for _, d := range ds {
		warned = warned || d.Code == CodeResolvedDenied
	}
	if !warned {
		t.Error("missing resolved-denied diagnostic")
	}
}
