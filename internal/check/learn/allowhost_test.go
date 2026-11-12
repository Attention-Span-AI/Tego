// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// addrs parses each address.
func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// exampleCom is what example.com resolved to in the guest on 2026-11-10: the four addresses its lookup returned,
// which the run's address-sorting UDP connects (#139 to #144) show.
var exampleCom = HostAnswer{Host: "example.com", Addrs: addrs("104.20.23.154", "172.66.147.243", "2606:4700:10::6814:179a", "2606:4700:10::ac42:93f3")}

// hostProblems is the problems of the HostError err is, or fails.
func hostProblems(t *testing.T, err error) []string {
	t.Helper()
	var he *HostError
	if !errors.As(err, &he) || len(he.Problems) == 0 {
		t.Fatalf("want a HostError, got %v", err)
	}
	return he.Problems
}

// TestAllowHostNamesTheGuestsService: the guest's watched run (u2404Watch) reached example.com at 104.20.23.154 over
// TCP and probed all four of its addresses over UDP. With --allow-host example.com, every one of them is in the name's
// answer here now, so the proposal allows the service by name, once per protocol, and lists no address: the next run,
// which picked 172.66.147.243 first and was refused, is allowed it by tcp://example.com:443. The UDP entry keeps the
// probe's note, and each named entry says what the lookup showed and what tego does not know.
func TestAllowHostNamesTheGuestsService(t *testing.T) {
	p := u2404Watch(t).propose(Options{Hosts: []HostAnswer{exampleCom}})
	c := p.Contract()
	want := []string{"tcp://example.com:443", "udp://example.com:443", "unix:/var/run/nscd/socket"}
	if got := entries(c, "net"); !slices.Equal(got, want) {
		t.Fatalf("net.allow = %q, want %q\n%s", got, want, c)
	}
	if got := p.AddressEntries(); len(got) != 0 {
		t.Errorf("address entries left: %q", got)
	}
	if slices.Contains(p.Warnings(), AddressWarning) || strings.Contains(c, "# WARNING: net.allow has entries that are addresses") {
		t.Errorf("a proposal with no address entry still warns about addresses\n%s", c)
	}
	tcp := lineOf(c, `"tcp://example.com:443"`)
	for _, part := range []string{"# seen once; by name (--allow-host): resolves here now to 104.20.23.154, 172.66.147.243, 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3",
		"covers 104.20.23.154, an address the run reached; tego does not know which name the run looked up for it"} {
		if !strings.Contains(tcp, part) {
			t.Errorf("the tcp entry lacks %q: %q", part, tcp)
		}
	}
	udp := lineOf(c, `"udp://example.com:443"`)
	for _, part := range []string{"seen 4 times; by name (--allow-host)", "addresses the run reached; tego does not know which name the run looked up for them",
		"possibly the C library's address-sorting probe", "remove it unless the agent speaks UDP (QUIC)"} {
		if !strings.Contains(udp, part) {
			t.Errorf("the udp entry lacks %q: %q", part, udp)
		}
	}
	for _, part := range []string{"allows every address that name resolves to when a run starts",
		"names given with --allow-host", "A udp entry by host name allows UDP, QUIC included"} {
		if !strings.Contains(flat(c), part) {
			t.Errorf("the header lacks %q\n%s", part, c)
		}
	}
	if len(p.Named) != 1 || p.Named[0].Host != "example.com" || len(p.Named[0].Answer) != 4 ||
		!slices.Equal(p.Named[0].Reached, []string{"tcp 104.20.23.154:443", "udp 104.20.23.154:443", "udp 172.66.147.243:443",
			"udp [2606:4700:10::6814:179a]:443", "udp [2606:4700:10::ac42:93f3]:443"}) {
		t.Errorf("Named = %+v", p.Named)
	}
	load(t, c)

	// With a port, only that port's destinations are named; another port covers nothing, and nothing is proposed.
	p = u2404Watch(t).propose(Options{Hosts: []HostAnswer{{Host: "example.com", Port: 443, Addrs: exampleCom.Addrs}}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, want) {
		t.Errorf("--allow-host example.com:443: net.allow = %q, want %q", got, want)
	}
	_, err := propose(u2404Watch(t).events, Options{Hosts: []HostAnswer{{Host: "example.com", Port: 8443, Addrs: exampleCom.Addrs}}})
	if got := hostProblems(t, err); len(got) != 1 || !strings.Contains(got[0], "none is an address the run reached on port 8443") {
		t.Errorf("a port the run did not use: %q", got)
	}
}

// TestAllowHostLeavesWhatItDoesNotCover: a name covers only the addresses its answer holds; the run's other addresses
// stay addresses, with the warning, and the proposal says which.
func TestAllowHostLeavesWhatItDoesNotCover(t *testing.T) {
	r := newRun(t, ws)
	r.net("tcp", "104.20.23.154:443")
	r.net("tcp", "151.101.1.69:443")
	p := r.propose(Options{Hosts: []HostAnswer{{Host: "api.example.com", Addrs: addrs("104.20.23.154")}}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://api.example.com:443", "tcp://151.101.1.69:443"}) {
		t.Errorf("net.allow = %q", got)
	}
	if got := p.AddressEntries(); !slices.Equal(got, []string{"tcp://151.101.1.69:443"}) {
		t.Errorf("AddressEntries = %q", got)
	}
	if !slices.Contains(p.Warnings(), AddressWarning) {
		t.Error("the address left lost its warning")
	}
}

// TestAllowHostNamesEveryNameGiven: two names the person gave that cover one address are both written; tego never
// picks one of them, and never names an address by itself.
func TestAllowHostNamesEveryNameGiven(t *testing.T) {
	r := newRun(t, ws)
	r.net("tcp", "104.20.23.154:443")
	p := r.propose(Options{Hosts: []HostAnswer{{Host: "a.example", Addrs: addrs("104.20.23.154")}, {Host: "b.example", Addrs: addrs("104.20.23.154", "104.20.23.155")}}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://a.example:443", "tcp://b.example:443"}) {
		t.Errorf("net.allow = %q", got)
	}
	if p = r.propose(Options{}); !slices.Equal(entries(p.Contract(), "net"), []string{"tcp://104.20.23.154:443"}) {
		t.Errorf("no --allow-host named something: %q", entries(p.Contract(), "net"))
	}
}

// TestAllowHostCoversNothing: a name whose answer here now holds no address the run reached is refused, with what it
// resolves to and how long ago the run was: the name may be wrong, or the service moved since.
func TestAllowHostCoversNothing(t *testing.T) {
	r := newRun(t, ws)
	r.net("tcp", "104.20.23.154:443")
	_, err := propose(r.events, Options{Now: r.t0.Add(74 * time.Hour), Hosts: []HostAnswer{{Host: "api.example.com", Addrs: addrs("104.18.6.192", "104.18.7.192")}}})
	got := hostProblems(t, err)
	if len(got) != 1 || got[0] != "api.example.com resolves here now to 104.18.6.192, 104.18.7.192; none is an address the run reached, "+
		"so the name may be wrong, or its addresses changed since the run (it started 3 days ago)" {
		t.Errorf("problems = %q", got)
	}
}

// TestAllowHostPrivateAnswer: a name whose answer here now holds a private address the run did not reach is refused:
// an entry by name keeps every private address it answers with at run start, so the next run could reach the host's
// own network on that port. A private address the run did reach under the name is the service, and is named.
func TestAllowHostPrivateAnswer(t *testing.T) {
	r := newRun(t, ws)
	r.net("tcp", "104.20.23.154:443")
	_, err := propose(r.events, Options{Hosts: []HostAnswer{{Host: "split.example", Addrs: addrs("104.20.23.154", "10.0.0.5")}}})
	if got := hostProblems(t, err); len(got) != 1 || !strings.Contains(got[0], "among them the private address 10.0.0.5, which the run did not reach") {
		t.Errorf("problems = %q", got)
	}
	r = newRun(t, ws)
	r.net("tcp", "10.0.0.5:8080")
	p := r.propose(Options{Hosts: []HostAnswer{{Host: "git.internal", Addrs: addrs("10.0.0.5")}}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://git.internal:8080"}) {
		t.Errorf("a private address the run reached: net.allow = %q", got)
	}
}

// TestAllowHostNeverNamesWhatANameCannotAdmit: an address no name entry ever admits (loopback, link-local, cloud
// metadata) stays an address even when the run reached it and the name's answer holds it: compile drops it from a
// name's answer, so the name would not allow it. A name that covers only such addresses covers nothing.
func TestAllowHostNeverNamesWhatANameCannotAdmit(t *testing.T) {
	r := newRun(t, ws)
	r.net("tcp", "104.20.23.154:443")
	r.net("tcp", "169.254.169.254:443")
	p := r.propose(Options{Hosts: []HostAnswer{{Host: "rebind.example", Addrs: addrs("104.20.23.154", "169.254.169.254")}}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://rebind.example:443", "tcp://169.254.169.254:443"}) {
		t.Errorf("net.allow = %q", got)
	}
	r = newRun(t, ws)
	r.net("tcp", "127.0.0.1:8080")
	_, err := propose(r.events, Options{Hosts: []HostAnswer{{Host: "localhost", Addrs: addrs("127.0.0.1", "::1")}}})
	if got := hostProblems(t, err); len(got) != 1 || !strings.Contains(got[0], "it reached 127.0.0.1 (loopback), which learn keeps as an address, never by name") {
		t.Errorf("problems = %q", got)
	}
}

// TestAllowHostMachineDeniedRange: the machine config's denied_resolved_addresses are ranges compile drops from a
// name's answer, as it drops the built-in classes, so a name never stands for an address in them: it stays an address,
// a name that covers only such an address covers nothing, and a private address of the answer in them is not one a
// later run could reach by the name.
func TestAllowHostMachineDeniedRange(t *testing.T) {
	denied := []netip.Prefix{netip.MustParsePrefix("104.20.0.0/16"), netip.MustParsePrefix("10.0.0.0/8")}
	r := newRun(t, ws)
	r.net("tcp", "104.20.23.154:443")
	r.net("tcp", "172.66.147.243:443")
	p := r.propose(Options{DeniedResolved: denied, Hosts: []HostAnswer{exampleCom}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://104.20.23.154:443", "tcp://example.com:443"}) {
		t.Errorf("net.allow = %q", got)
	}
	if len(p.Named) != 1 || !slices.Equal(p.Named[0].Reached, []string{"tcp 172.66.147.243:443"}) {
		t.Errorf("Named = %+v", p.Named)
	}
	if got := p.AddressEntries(); !slices.Equal(got, []string{"tcp://104.20.23.154:443"}) {
		t.Errorf("AddressEntries = %q", got)
	}

	r = newRun(t, ws)
	r.net("tcp", "104.20.23.154:443")
	_, err := propose(r.events, Options{DeniedResolved: denied, Hosts: []HostAnswer{exampleCom}})
	if got := hostProblems(t, err); len(got) != 1 || !strings.Contains(got[0], "it reached 104.20.23.154 (machine config), which learn keeps as an address, never by name") {
		t.Errorf("a name that covers only a machine-denied address: problems = %q", got)
	}

	r = newRun(t, ws)
	r.net("tcp", "172.66.147.243:443")
	p = r.propose(Options{DeniedResolved: denied, Hosts: []HostAnswer{{Host: "split.example", Addrs: addrs("172.66.147.243", "10.0.0.5")}}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://split.example:443"}) {
		t.Errorf("a private answer the machine denies to names: net.allow = %q", got)
	}
}

// TestAllowHostRefusesLeaveLeaksToCaller: with the leak rule left to the caller, learn knows no withheld address, so a
// name could be written over an address the caller's own verdict would withhold, and the caller, which withholds by
// address, would not find it. Learn refuses the two together and proposes nothing.
func TestAllowHostRefusesLeaveLeaksToCaller(t *testing.T) {
	r := newRun(t, "/work")
	r.sent("198.51.100.7:443", "")
	r.padding(20)
	r.read(keyFile)
	r.sent(sink, "")
	r.padding(20)
	p, err := propose(r.events, Options{LeaveLeaksToCaller: true, Hosts: []HostAnswer{{Host: "api.example.com", Addrs: addrs("198.51.100.7", "203.0.113.9")}}})
	var he *HostError
	if err == nil || p != nil || errors.As(err, &he) || !strings.Contains(err.Error(), "LeaveLeaksToCaller") {
		t.Errorf("Hosts with LeaveLeaksToCaller: err %v, proposal %v", err, p != nil)
	}
}

// TestAllowHostKeepsAWithheldAddressWithheld (LEARN-NAMES-CHECK M1): the leak rule withholds an address the run's
// secrets may have gone to. A name whose answer holds that address would admit it again, so the name is refused
// whole, whether or not it covers another address; without --allow-host the address stays withheld as before.
func TestAllowHostKeepsAWithheldAddressWithheld(t *testing.T) {
	r := newRun(t, "/work")
	r.sent("198.51.100.7:443", "")
	r.padding(20)
	r.read(keyFile)
	r.sent(sink, "")
	r.padding(20)
	p := r.propose(Options{})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://198.51.100.7:443"}) {
		t.Fatalf("without --allow-host: net.allow = %q (the sink must be withheld)", got)
	}
	for _, answer := range [][]netip.Addr{addrs("203.0.113.9"), addrs("198.51.100.7", "203.0.113.9")} {
		_, err := propose(r.events, Options{Hosts: []HostAnswer{{Host: "api.example.com", Addrs: answer}}})
		if got := hostProblems(t, err); len(got) != 1 || !strings.Contains(got[0], "among them 203.0.113.9, which learn withheld") {
			t.Errorf("answer %s: problems = %q", answer, got)
		}
	}
	// The run's own record names nothing here, so the dashboard's path (LeaveLeaksToCaller) is not changed by a name.
	p = r.propose(Options{LeaveLeaksToCaller: true})
	if got := entries(p.Contract(), "net"); !slices.Contains(got, "tcp://"+sink) {
		t.Errorf("LeaveLeaksToCaller: net.allow = %q", got)
	}
}

// TestAllowHostRecordNames: a record whose line holds the name of the entry that allowed it keeps that name; a name
// the person gives as well is added, not swapped in.
func TestAllowHostRecordNames(t *testing.T) {
	r := newRun(t, ws)
	r.netLine(r.t0, "tcp", "104.20.23.154:443", "net[tcp://example.com:443]", "example.com", record.VerdictAllow)
	p := r.propose(Options{Hosts: []HostAnswer{{Host: "www.example.com", Addrs: addrs("104.20.23.154")}}})
	if got := entries(p.Contract(), "net"); !slices.Equal(got, []string{"tcp://example.com:443", "tcp://www.example.com:443"}) {
		t.Errorf("net.allow = %q", got)
	}
}

// TestAllowHostDoesNotNameTheMachinesResolver: a name whose answer holds the machine's resolver does not stand for it
// (review S1 of 2026-11-11). Covering it alone, the name covers nothing, and the problem says the run reached that
// address only as the resolver; beside another address it reached, the name covers that one only, and the resolver
// is left out as before.
func TestAllowHostDoesNotNameTheMachinesResolver(t *testing.T) {
	router := HostAnswer{Host: "router.lan", Addrs: addrs("10.0.2.3")}
	r := newRun(t, ws)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	_, err := propose(r.events, Options{Hosts: []HostAnswer{router}})
	want := "router.lan resolves here now to 10.0.2.3; the run reached 10.0.2.3 only as the machine's resolver, which tego" +
		" allows itself and learn never writes by name, and no other address of the answer"
	if got := hostProblems(t, err); !slices.Equal(got, []string{want}) {
		t.Errorf("problems = %q, want %q", got, want)
	}

	r = newRun(t, ws)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	r.netLine(r.t0, "tcp", "10.0.2.3:443", "unmatched", "", record.VerdictObserved)
	p := r.propose(Options{Hosts: []HostAnswer{router}})
	c := p.Contract()
	if got := entries(c, "net"); !slices.Equal(got, []string{"tcp://router.lan:443"}) {
		t.Errorf("net.allow = %q\n%s", got, c)
	}
	if len(p.Named) != 1 || !slices.Equal(p.Named[0].Reached, []string{"tcp 10.0.2.3:443"}) {
		t.Errorf("Named = %+v, want router.lan to have reached tcp 10.0.2.3:443 only", p.Named)
	}
	if !strings.Contains(c, resolverComment("udp://10.0.2.3:53")) {
		t.Errorf("the machine's resolver is not left out\n%s", c)
	}
}
