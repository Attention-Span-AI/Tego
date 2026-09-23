// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestDeniedResolvedClass pins R18's classes, including the spellings of one address a resolver can
// answer with: IPv4-mapped, NAT64 and a zoned link-local address are the address they stand for.
func TestDeniedResolvedClass(t *testing.T) {
	extra := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		addr   string
		class  string
		denied bool
	}{
		{"169.254.169.254", ResolvedMetadata, true},
		{"::ffff:169.254.169.254", ResolvedMetadata, true},
		{"64:ff9b::a9fe:a9fe", ResolvedMetadata, true},
		{"169.254.170.2", ResolvedLinkLocal, true},
		{"fe80::1%eth0", ResolvedLinkLocal, true},
		{"fd00:ec2::254", ResolvedMetadata, true},
		{"fd00:ec2::23", ResolvedMetadata, true},
		{"fd20:ce::254", ResolvedMetadata, true}, // GCE's IPv6 metadata server, a ULA a private first answer would keep
		{"169.254.170.23", ResolvedLinkLocal, true},
		{"100.100.100.200", ResolvedMetadata, true},
		{"168.63.129.16", ResolvedMetadata, true},
		{"127.0.0.1", ResolvedLoopback, true},
		{"127.3.2.1", ResolvedLoopback, true},
		{"::1", ResolvedLoopback, true},
		{"0.0.0.0", ResolvedLoopback, true},
		{"::", ResolvedLoopback, true},
		{"224.0.0.1", ResolvedMulticast, true},
		{"239.255.255.250", ResolvedMulticast, true},
		{"ff01::1", ResolvedMulticast, true},
		{"ff02::fb", ResolvedMulticast, true},
		{"ff0e::1", ResolvedMulticast, true},
		{"::ffff:224.0.0.251", ResolvedMulticast, true},
		{"10.0.0.5", ResolvedMachine, true},
		{"192.168.1.10", "", false},
		{"fd12::1", "", false},
		{"93.184.216.34", "", false},
		{"2607:6bc0::10", "", false},
	}
	for _, c := range cases {
		class, denied := DeniedResolvedClass(netip.MustParseAddr(c.addr), extra)
		if class != c.class || denied != c.denied {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.addr, class, denied, c.class, c.denied)
		}
	}
	if _, denied := DeniedResolvedClass(netip.MustParseAddr("10.0.0.5"), nil); denied {
		t.Error("a private address is refused only when the machine config adds its range")
	}
}

// TestCompileDropsDeniedResolved is R18 at compile: a host name that resolves to the metadata endpoint
// keeps only the addresses it may admit, and says so; one that resolves only to loopback admits nothing;
// a localhost name keeps loopback; a literal address and a CIDR are the author's own and never filtered;
// the machine config's ranges join the built-in classes. Evaluate then refuses the dropped address and
// still allows the declared literal.
func TestCompileDropsDeniedResolved(t *testing.T) {
	f := newFixture(t)
	f.resolver.table["rebind.example"] = []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("93.184.216.34")}
	f.resolver.table["dev.example"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	f.resolver.table["localhost"] = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}
	c := f.load("version: 0\nname: t\ncommand: [\"python\"]\nnet:\n  allow: [\"rebind.example:80\", \"dev.example:3000\", \"localhost:11434\", \"169.254.169.254:8080\", \"127.0.0.0/8:9000\", \"mcp.internal:8080\"]\n")
	rt, ds := f.compile(c)

	byRaw := map[string]NetRule{}
	for _, r := range rt.Net {
		byRaw[r.Raw] = r
	}
	check := func(raw string, ips, denied []string) {
		t.Helper()
		r := byRaw[raw]
		if got := addrStrings(r.IPs); !slices.Equal(got, ips) {
			t.Errorf("%s: IPs %v, want %v", raw, got, ips)
		}
		if got := addrStrings(r.Denied); !slices.Equal(got, denied) {
			t.Errorf("%s: Denied %v, want %v", raw, got, denied)
		}
	}
	check("rebind.example:80", []string{"93.184.216.34"}, []string{"169.254.169.254"})
	check("dev.example:3000", []string{}, []string{"127.0.0.1"})
	check("localhost:11434", []string{"127.0.0.1", "::1"}, nil)
	check("169.254.169.254:8080", []string{"169.254.169.254"}, nil)
	check("mcp.internal:8080", []string{"10.0.0.5"}, nil)
	for raw, want := range map[string]bool{
		"rebind.example:80": true, "dev.example:3000": false, "localhost:11434": false, "mcp.internal:8080": false,
		"169.254.169.254:8080": false,
	} {
		if got := byRaw[raw].PublicAnswer; got != want {
			t.Errorf("%s: PublicAnswer %v, want %v", raw, got, want)
		}
	}

	var warned []string
	for _, d := range ds {
		if d.Code == CodeResolvedDenied {
			warned = append(warned, d.Message)
		}
	}
	if len(warned) != 2 || !strings.Contains(strings.Join(warned, "\n"), "169.254.169.254 (cloud metadata)") ||
		!strings.Contains(strings.Join(warned, "\n"), "admits nothing") {
		t.Errorf("want one resolved-denied warning per filtered entry, naming the address and its class:\n%s", render(ds))
	}

	for _, row := range []struct {
		host string
		port int
		want Verdict
	}{
		{"169.254.169.254", 80, VerdictRefused},
		{"93.184.216.34", 80, VerdictAllow},
		{"169.254.169.254", 8080, VerdictAllow},
		{"127.0.0.1", 3000, VerdictRefused},
		// The name row of an entry R18 left with no address: the run connects to 127.0.0.1 and refuses it,
		// so compile --test must not certify the name.
		{"dev.example", 3000, VerdictRefused},
		{"DEV.example", 3000, VerdictRefused},
		{"rebind.example", 80, VerdictAllow},
		{"127.0.0.1", 11434, VerdictAllow},
	} {
		got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: row.host, Port: row.port}, rt.Tier)
		if got.Verdict != row.want {
			t.Errorf("%s:%d: %+v, want %s", row.host, row.port, got, row.want)
		}
	}
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "dev.example", Port: 3000}, rt.Tier); got.Rule != UnresolvedRule {
		t.Errorf("an entry R18 left with no address is E18's entry with no addresses: %+v, want rule %s", got, UnresolvedRule)
	}

	f.machine.DeniedResolved = config.Setting[[]netip.Prefix]{Value: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	rt, _ = f.compile(c)
	for _, r := range rt.Net {
		if r.Raw == "mcp.internal:8080" && (len(r.IPs) != 0 || len(r.Denied) != 1) {
			t.Errorf("a machine range must join the built-in classes: %+v", r)
		}
	}
	if len(rt.DeniedResolved) != 1 {
		t.Errorf("the table must carry the machine ranges for the supervisor: %v", rt.DeniedResolved)
	}
}

func addrStrings(as []netip.Addr) []string {
	if as == nil {
		return nil
	}
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}

// TestResolvedDeniedPrivateForAPublicAnswer is R18's private class: an entry whose compile-time answer was
// public only refuses a private address a later answer brings in (RFC 1918, the shared 100.64/10, fc00::/7, in
// any spelling a resolver can give), and keeps admitting public ones; an entry whose first answer was already
// private (split-horizon DNS) or never came is not held to it. The built-in classes keep their own names.
func TestResolvedDeniedPrivateForAPublicAnswer(t *testing.T) {
	rt := &RuleTable{}
	public := NetRule{Raw: "api.example:443", Host: "api.example", Port: 443, Proto: ProtoInet, PublicAnswer: true}
	split := NetRule{Raw: "git.corp:443", Host: "git.corp", Port: 443, Proto: ProtoInet}
	for _, c := range []struct {
		addr  string
		class string
	}{
		{"10.0.0.5", ResolvedPrivate},
		{"172.20.1.1", ResolvedPrivate},
		{"192.168.1.1", ResolvedPrivate},
		{"100.64.0.9", ResolvedPrivate},
		{"fd12::1", ResolvedPrivate},
		{"::ffff:10.0.0.5", ResolvedPrivate},
		{"64:ff9b::a00:5", ResolvedPrivate},
		{"fd00:ec2::254", ResolvedMetadata},
		{"100.100.100.200", ResolvedMetadata},
		{"169.254.169.254", ResolvedMetadata},
		{"93.184.216.34", ""},
		{"2607:6bc0::10", ""},
	} {
		a := netip.MustParseAddr(c.addr)
		class, denied := rt.ResolvedDenied(public, a)
		if class != c.class || denied != (c.class != "") {
			t.Errorf("public answer, %s: (%q, %v), want %q", c.addr, class, denied, c.class)
		}
		if c.class == ResolvedPrivate {
			if _, denied := rt.ResolvedDenied(split, a); denied {
				t.Errorf("a name whose first answer was private keeps %s", c.addr)
			}
		}
	}
}
