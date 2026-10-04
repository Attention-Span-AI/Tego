// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestRefreshedDropsWhatTheTableRefuses is agent-contract R18 for the kernel copy of the set: a refresh that
// rebinds a host name to the metadata endpoint, loopback, a machine-denied range or (after a public first
// answer) a private address must not hand that address to tier 2's rows, which admit whatever Refreshed
// holds. The refused address moves to the entry's Denied, as Compile does with the first answer. Match still
// finds the entry, so the supervisor refuses such a destination under the entry's name rather than as
// unmatched, and a Set built without the check (the models[] guard's) filters nothing.
func TestRefreshedDropsWhatTheTableRefuses(t *testing.T) {
	now := time.Now()
	lk := newLookup()
	lk.answers["api.example.com"] = [][]netip.Addr{addrs("203.0.113.5", "169.254.169.254", "127.0.0.1", "192.0.2.77")}
	lk.answers["public.example.com"] = [][]netip.Addr{addrs("203.0.113.9", "192.168.1.1")}
	lk.answers["localhost"] = [][]netip.Addr{addrs("127.0.0.1")}
	machine := netip.MustParsePrefix("192.0.2.0/24")
	cidr := netip.MustParsePrefix("169.254.0.0/16")
	base := []agent.NetRule{
		hostRule("api.example.com", 443, "203.0.113.4"),
		hostRule("public.example.com", 443, "203.0.113.8"),
		hostRule("localhost", 3000, "127.0.0.1"),
		{Raw: "169.254.0.0/16:80", Port: 80, Proto: agent.ProtoInet, CIDR: &cidr, Static: true, Verdict: agent.VerdictAllow},
	}
	base[0].Denied = addrs("127.0.0.1") // what Compile dropped from the first answer: kept, never repeated
	base[1].PublicAnswer = true
	rt := &agent.RuleTable{Net: base, DeniedResolved: []netip.Prefix{machine}}

	filtered := NewSet(base, nil, Options{Lookup: lk, Now: func() time.Time { return now }, MinTTL: time.Second,
		ResolvedDenied: rt.ResolvedDenied})
	now = now.Add(2 * time.Minute)
	if err := filtered.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := filtered.Refreshed(base)
	if want := addrs("203.0.113.5"); !slices.Equal(got[0].IPs, want) {
		t.Errorf("rebound host entry holds %v, want only %v: the rows would admit what the contract refuses", got[0].IPs, want)
	}
	if want := addrs("127.0.0.1", "169.254.169.254", "192.0.2.77"); !slices.Equal(sorted(got[0].Denied), want) {
		t.Errorf("rebound host entry's Denied %v, want %v", got[0].Denied, want)
	}
	if want := addrs("203.0.113.9"); !slices.Equal(got[1].IPs, want) || !slices.Contains(got[1].Denied, netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("a public name rebound to a private address: IPs %v Denied %v", got[1].IPs, got[1].Denied)
	}
	if want := addrs("127.0.0.1"); !slices.Equal(got[2].IPs, want) {
		t.Errorf("a localhost name keeps loopback: %v", got[2].IPs)
	}
	if got[3].CIDR == nil || len(got[3].Denied) != 0 {
		t.Errorf("a cidr entry the author wrote is never filtered: %+v", got[3])
	}
	if len(base[0].Denied) != 1 || !slices.Equal(base[0].IPs, addrs("203.0.113.4")) {
		t.Errorf("Refreshed modified base: %+v", base[0])
	}
	if m := filtered.Match(netip.MustParseAddrPort("169.254.169.254:443"), ProtoTCP); m == nil || m.Raw != "api.example.com" {
		t.Errorf("Match = %+v: the supervisor names the refusal after the entry, so Match must still find it", m)
	}

	lk2 := newLookup()
	lk2.answers["api.example.com"] = [][]netip.Addr{addrs("203.0.113.5", "169.254.169.254")}
	plain := NewSet(base[:1], nil, Options{Lookup: lk2, Now: func() time.Time { return now }, MinTTL: time.Second})
	now = now.Add(2 * time.Minute)
	if err := plain.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := plain.Refreshed(base[:1]); !slices.Equal(got[0].IPs, addrs("169.254.169.254", "203.0.113.5")) {
		t.Errorf("a Set with no check filtered %v", got[0].IPs)
	}
}

func sorted(in []netip.Addr) []netip.Addr {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}
