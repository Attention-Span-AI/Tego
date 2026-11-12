// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// netLine adds one net line as the supervisor writes it on a watched run: rule, verdict and host as given.
func (r *run) netLine(at time.Time, proto, dst, rule, host string, verdict record.Verdict) {
	r.t.Helper()
	e := r.add(record.KindNet, verdict, record.NetPayload{Proto: proto, Dst: dst, Host: host})
	e.TS, e.Rule, e.Source = at, rule, record.SourceSupervisor
}

// u2404Watch is run r-cde3e540-0dmrq34zi1yp6-kah821 of 2026-11-10 (Ubuntu 24.04 guest, `tego watch -- python3
// agent.py` in /home/tego/myagent, an agent that fetches https://example.com): its network lines #130 to #145 in
// order, with their times, protocols and destinations as the dashboard's Logs page and `tego learn` showed them, plus
// the writes and the git start that make the rest of its proposal. The guest's ledger itself is gone, so the lines are
// rebuilt from those screens; the secret read at #126 is left out, as it changes nothing in net.allow (no leak was
// found in the real run).
func u2404Watch(t *testing.T) *run {
	r := newRun(t, "/home/tego/myagent", "python3", "agent.py")
	r.events[0].Agent = "watch-python3"
	r.exec(100, "/usr/bin/python3", "python3", "agent.py")
	at := time.Date(2026, 11, 10, 17, 55, 49, 0, time.UTC)
	r.netLine(at, "unix", "unix:/var/run/nscd/socket", "unmatched", "", record.VerdictObserved) // #130, #131
	r.netLine(at, "unix", "unix:/var/run/nscd/socket", "unmatched", "", record.VerdictObserved)
	r.netLine(at, "udp", "127.0.0.53:53", "net.resolver", "127.0.0.53", record.VerdictObserved) // #136
	at = at.Add(5 * time.Second)
	for _, l := range []struct{ proto, dst string }{ // #138 to #145
		{"raw", "family(16)"},
		{"udp", "104.20.23.154:443"}, {"udp", "unspec"}, {"udp", "172.66.147.243:443"},
		{"udp", "[2606:4700:10::6814:179a]:443"}, {"udp", "unspec"}, {"udp", "[2606:4700:10::ac42:93f3]:443"},
		{"tcp", "104.20.23.154:443"},
	} {
		r.netLine(at, l.proto, l.dst, "unmatched", "", record.VerdictObserved)
	}
	r.exec(101, "/usr/bin/git", "git", "--version")
	r.open("/dev/null", wronly)
	r.fs(record.FSMkdir, "/home/tego/myagent/out", "", 0)
	r.open("/home/tego/myagent/out/report.txt", wronly|creat)
	r.end(13<<20, 5, 5200*time.Millisecond)
	return r
}

// TestLearnedAddressesSayTheyMayBreak: the record of a watched run holds the address the agent connected to, never the
// name it looked up, so the proposal can only name addresses. On 2026-11-10 the next run under such a proposal picked
// the other address its lookup returned, 172.66.147.243, and was refused. The proposal must say so where a person
// reads it (stderr, the file's first lines), and the UDP lines that are the C library probing the lookup's other
// answers must say that a later run may use those over TCP.
func TestLearnedAddressesSayTheyMayBreak(t *testing.T) {
	p := u2404Watch(t).propose(Options{})
	c := p.Contract()
	want := []string{"tcp://104.20.23.154:443", "udp://104.20.23.154:443", "udp://172.66.147.243:443",
		"udp://[2606:4700:10::6814:179a]:443", "udp://[2606:4700:10::ac42:93f3]:443", "unix:/var/run/nscd/socket"}
	if got := entries(c, "net"); !slices.Equal(got, want) {
		t.Fatalf("net.allow = %q, want %q (the guest's own proposal)\n%s", got, want, c)
	}
	var warning string
	for _, w := range p.Warnings() {
		if strings.HasPrefix(w, "net.allow has entries that are addresses") {
			warning = w
		}
	}
	for _, part := range []string{"not host names", "can be refused a connection this run made",
		"write the name the agent uses in place of its addresses", "tcp://api.example.com:443"} {
		if !strings.Contains(warning, part) {
			t.Errorf("the address warning lacks %q: %q", part, warning)
		}
	}
	if warning != "" && !strings.HasPrefix(c, "# WARNING: "+warning+".\n") {
		t.Errorf("the file's header does not carry the address warning\n%s", c)
	}
	for _, dst := range []string{"172.66.147.243:443", "[2606:4700:10::6814:179a]:443"} {
		line := lineOf(c, `"udp://`+dst+`"`)
		if !strings.Contains(line, "a later run may connect to it over TCP, which this file does not allow") {
			t.Errorf("udp://%s does not say a later run may use it over TCP: %q", dst, line)
		}
	}
	load(t, c)
}

// TestLearnedNamesFromTheRecord: a run under a contract that allows a service by name records, on each connect that
// entry allowed, the entry's host name. The proposal then writes that name once, not the addresses it resolved to on
// that day, and says nothing about addresses; a literal address entry and the resolver keep their addresses.
func TestLearnedNamesFromTheRecord(t *testing.T) {
	r := newRun(t, ws)
	at := r.t0
	r.netLine(at, "udp", "127.0.0.53:53", "net.resolver", "127.0.0.53", record.VerdictAllow)
	r.netLine(at, "tcp", "172.66.147.243:443", "net[tcp://example.com:443]", "example.com", record.VerdictAllow)
	r.netLine(at, "tcp", "104.20.23.154:443", "net[tcp://example.com:443]", "example.com", record.VerdictAllow)
	r.netLine(at, "tcp", "10.1.2.3:8080", "net[10.1.2.3:8080]", "10.1.2.3", record.VerdictAllow)
	p := r.propose(Options{})
	c := p.Contract()
	want := []string{"tcp://10.1.2.3:8080", "tcp://example.com:443"}
	if got := entries(c, "net"); !slices.Equal(got, want) {
		t.Fatalf("net.allow = %q, want %q\n%s", got, want, c)
	}
	if line := lineOf(c, `"tcp://example.com:443"`); !strings.Contains(line, "seen 2 times") {
		t.Errorf("the named entry does not count both connects: %q", line)
	}
	r = newRun(t, ws)
	r.netLine(at, "tcp", "104.20.23.154:443", "net[tcp://example.com:443]", "example.com", record.VerdictAllow)
	c = r.propose(Options{}).Contract()
	if strings.Contains(c, "WARNING") || strings.Contains(c, "never the host name") {
		t.Errorf("a proposal of names only warns about addresses\n%s", c)
	}
	load(t, c)
}

// lineOf is the first line of c that contains s.
func lineOf(c, s string) string {
	for _, l := range strings.Split(c, "\n") {
		if strings.Contains(l, s) {
			return l
		}
	}
	return ""
}

// TestNamedEntrySaysWhatItAllows: the header said the proposal allows what the run did and no more, but an entry by
// host name allows every address the name resolves to when a run starts and on each refresh, not only the ones this run
// connected to. A proposal of addresses alone keeps "no more".
func TestNamedEntrySaysWhatItAllows(t *testing.T) {
	const (
		noMore = "It allows what that run did and no\n# more."
		names  = "except that a net.allow entry by host name allows every address that name resolves to"
	)
	r := newRun(t, ws)
	r.netLine(r.t0, "tcp", "104.20.23.154:443", "net[tcp://example.com:443]", "example.com", record.VerdictAllow)
	if c := r.propose(Options{}).Contract(); strings.Contains(c, noMore) || !strings.Contains(flat(c), names) {
		t.Errorf("a proposal with a name entry says it allows no more than the run did:\n%s", c)
	}
	// A localhost entry resolves to loopback (agent-contract.md R18), so the header must not say a name entry never
	// allows a loopback address: on 2026-11-10 it said so directly above tcp://localhost:11434.
	r = newRun(t, ws)
	r.netLine(r.t0, "tcp", "127.0.0.1:11434", "net[tcp://localhost:11434]", "localhost", record.VerdictAllow)
	if c := flat(r.propose(Options{}).Contract()); strings.Contains(c, "loopback") || !strings.Contains(c, "never admits some addresses by name") {
		t.Errorf("a proposal with a localhost entry says a name entry never allows loopback, or lost the sentence on refused addresses:\n%s", c)
	}
	r = newRun(t, ws)
	r.netLine(r.t0, "tcp", "10.1.2.3:8080", "net[10.1.2.3:8080]", "10.1.2.3", record.VerdictAllow)
	if c := r.propose(Options{}).Contract(); !strings.Contains(c, noMore) || strings.Contains(flat(c), names) {
		t.Errorf("a proposal of addresses alone lost its \"no more\":\n%s", c)
	}
}

// flat is c's words on one line, without the "# " each comment line starts with.
func flat(c string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(c, "\n# ", "\n")), " ")
}

// alma98Watch is the AlmaLinux 9.8 guest's case of 2026-11-10: NetworkManager's resolv.conf names 10.0.2.3, a
// resolver that is not on loopback, and the watched run's two queries to it carry the engine's net.resolver, then the
// run reached pypi.org at two of its addresses over TCP and probed them over UDP.
func alma98Watch(t *testing.T) *run {
	r := newRun(t, ws, "python3", "fetch.py")
	r.events[0].Agent = "watch-python3"
	at := r.t0
	r.netLine(at, "unix", "unix:/var/run/nscd/socket", "unmatched", "", record.VerdictObserved)
	r.netLine(at, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	r.netLine(at, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	for _, l := range []struct{ proto, dst string }{
		{"udp", "151.101.192.223:443"}, {"udp", "151.101.64.223:443"}, {"tcp", "151.101.192.223:443"}, {"tcp", "151.101.64.223:443"},
	} {
		r.netLine(at, l.proto, l.dst, "unmatched", "", record.VerdictObserved)
	}
	return r
}

// TestTheMachinesResolverIsNotAnAddressToName: a resolver the engine named net.resolver on every line to it is left out
// of net.allow: tego allows the run's resolver itself (decide.EvaluateIn, SEMANTICS §5), and a private address kept
// there would admit whatever answers on it once the contract is copied to another network. The net section says so
// in one comment, and nothing tells the person to name it: neither the address warning, the net comment, the --save
// addresses: line nor an --allow-host hint counts it. Port 53 of an address the engine did not name a resolver on
// every line to it is a connect like any other: it is still proposed, and still an address to name.
func TestTheMachinesResolverIsNotAnAddressToName(t *testing.T) {
	pypi := HostAnswer{Host: "pypi.org", Addrs: addrs("151.101.192.223", "151.101.0.223", "151.101.128.223", "151.101.64.223")}
	p := alma98Watch(t).propose(Options{Hosts: []HostAnswer{pypi}})
	c := p.Contract()
	want := []string{"tcp://pypi.org:443", "udp://pypi.org:443", "unix:/var/run/nscd/socket"}
	if got := entries(c, "net"); !slices.Equal(got, want) {
		t.Fatalf("net.allow = %q, want %q (the guest's proposal without the machine's resolver)\n%s", got, want, c)
	}
	if !strings.Contains(c, resolverComment("udp://10.0.2.3:53")) {
		t.Errorf("the net section does not say the machine's resolver was left out\n%s", c)
	}
	if got := p.AddressEntries(); len(got) != 0 {
		t.Errorf("AddressEntries = %q, want none: the machine's resolver is no address to name", got)
	}
	if slices.Contains(p.Warnings(), AddressWarning) || strings.Contains(c, "# WARNING: net.allow has entries that are addresses") ||
		strings.Contains(c, "never the host name") {
		t.Errorf("a proposal whose only address is the machine's resolver warns about addresses\n%s", c)
	}
	load(t, c)

	// Port 53 elsewhere, with no net.resolver on a line to it, is an address to name, alone or beside a resolver line.
	r := newRun(t, ws)
	r.netLine(r.t0, "udp", "203.0.113.9:53", "unmatched", "", record.VerdictObserved)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "unmatched", "", record.VerdictObserved)
	p = r.propose(Options{})
	c = p.Contract()
	if got := entries(c, "net"); !slices.Equal(got, []string{"udp://10.0.2.3:53", "udp://203.0.113.9:53"}) {
		t.Errorf("port 53 the engine did not name a resolver on every line: net.allow = %q, want both proposed\n%s", got, c)
	}
	if strings.Contains(c, "the machine's resolver when this run") {
		t.Errorf("port 53 the engine did not name a resolver on every line is called the machine's resolver\n%s", c)
	}
	if got := p.AddressEntries(); !slices.Equal(got, []string{"udp://10.0.2.3:53", "udp://203.0.113.9:53"}) {
		t.Errorf("port 53 the engine did not name a resolver: AddressEntries = %q", got)
	}
	if !slices.Contains(p.Warnings(), AddressWarning) {
		t.Error("port 53 the engine did not name a resolver lost the address warning")
	}
}

// resolverComment is the net section's comment on an entry left out as the machine's resolver.
func resolverComment(entry string) string {
	return "  # left out: " + entry + ", the machine's resolver when this run was recorded; tego allows the run's resolver itself, so it needs no entry\n"
}

// TestTheMachinesResolverIsKeptWhenNoOtherAddressIs: Landlock grants port 53 only beside a TCP or UDP entry
// (enforce-landlock R6, R22), so with none an addressed UDP lookup, which the supervisor continues into the run's own
// domain, may be refused from ABI 10 while the decision allows it as net.resolver (review M1 of 2026-11-11; TCP and
// connected UDP lookups are made by the supervisor, outside the domain, at every ABI: keepResolvers). Then the
// resolver stays the address it is, with a note that says why, and is still nothing to name; any other TCP or UDP
// entry, a name entry included, and it is left out.
func TestTheMachinesResolverIsKeptWhenNoOtherAddressIs(t *testing.T) {
	const kept = "udp://10.0.2.3:53"
	lookup := func(r *run) {
		r.netLine(r.t0, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	}
	for _, tc := range []struct {
		name  string
		build func(r *run)
		want  []string
		left  bool // the resolver is left out, with the comment
	}{
		{"a lookup only", lookup, []string{kept}, false},
		{"a lookup through nscd", func(r *run) {
			r.netLine(r.t0, "unix", "unix:/var/run/nscd/socket", "unmatched", "", record.VerdictObserved)
			lookup(r)
		}, []string{kept, "unix:/var/run/nscd/socket"}, false},
		{"a lookup and a send the leak rule withheld", func(r *run) {
			lookup(r)
			r.read(keyFile)
			r.sent("203.0.113.9:443", "")
		}, []string{kept}, false},
		{"a lookup and a TCP connect", func(r *run) {
			lookup(r)
			r.netLine(r.t0, "tcp", "203.0.113.9:443", "unmatched", "", record.VerdictObserved)
		}, []string{"tcp://203.0.113.9:443"}, true},
		{"a lookup and a connect by name", func(r *run) {
			lookup(r)
			r.netLine(r.t0, "tcp", "10.1.2.3:443", "net[tcp://api.example.com:443]", "api.example.com", record.VerdictAllow)
		}, []string{"tcp://api.example.com:443"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRun(t, ws, "getent", "hosts", "pypi.org")
			tc.build(r)
			p := r.propose(Options{})
			c := p.Contract()
			if got := entries(c, "net"); !slices.Equal(got, tc.want) {
				t.Fatalf("net.allow = %q, want %q\n%s", got, tc.want, c)
			}
			load(t, c)
			if got := strings.Contains(c, resolverComment(kept)); got != tc.left {
				t.Errorf("the left-out comment is there: %v, want %v\n%s", got, tc.left, c)
			}
			if got := strings.Contains(c, resolverKeptNote); got == tc.left {
				t.Errorf("the kept note is there: %v, want %v\n%s", got, !tc.left, c)
			}
			if got := p.AddressEntries(); slices.Contains(got, kept) {
				t.Errorf("AddressEntries = %q counts the machine's resolver", got)
			}
			if got := strings.Contains(c, "need no entry: tego allows the resolver itself"); got != tc.left {
				t.Errorf("the header says the resolver needs no entry: %v, want %v\n%s", got, tc.left, c)
			}
		})
	}
}

// TestTheMachinesResolverIsOneEntry: two spellings of one resolver (an AF_INET6 socket's IPv4-mapped one and the
// plain one) are one comment line, and a resolver entry that another address's line proposes anyway is not called
// left out (review S3 of 2026-11-11).
func TestTheMachinesResolverIsOneEntry(t *testing.T) {
	r := newRun(t, ws)
	r.netLine(r.t0, "tcp", "203.0.113.9:443", "unmatched", "", record.VerdictObserved)
	r.netLine(r.t0, "udp", "[::ffff:10.0.2.3]:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	c := r.propose(Options{}).Contract()
	if n := strings.Count(c, resolverComment("udp://10.0.2.3:53")); n != 1 {
		t.Errorf("the left-out comment is there %d times, want once\n%s", n, c)
	}
	r = newRun(t, ws)
	r.netLine(r.t0, "udp", "[::ffff:10.0.2.3]:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "unmatched", "", record.VerdictObserved)
	c = r.propose(Options{}).Contract()
	if got := entries(c, "net"); !slices.Equal(got, []string{"udp://10.0.2.3:53"}) {
		t.Errorf("net.allow = %q, want the address with another line proposed\n%s", got, c)
	}
	if strings.Contains(c, "# left out: udp://10.0.2.3:53") || strings.Contains(c, resolverKeptNote) {
		t.Errorf("an entry proposed for its other line is called the machine's resolver\n%s", c)
	}
}

// TestNetResolverOffPort53IsAConnect: the engine names a resolver query on port 53 only (decide.IsResolver), so a
// line that says net.resolver on another port is a connect like any other: proposed, and an address to name (review
// N1 of 2026-11-11).
func TestNetResolverOffPort53IsAConnect(t *testing.T) {
	r := newRun(t, ws)
	r.netLine(r.t0, "tcp", "203.0.113.7:443", "net.resolver", "203.0.113.7", record.VerdictObserved)
	p := r.propose(Options{})
	c := p.Contract()
	if got := entries(c, "net"); !slices.Equal(got, []string{"tcp://203.0.113.7:443"}) {
		t.Errorf("net.allow = %q, want the connect proposed\n%s", got, c)
	}
	if strings.Contains(c, "# left out:") || strings.Contains(c, resolverKeptNote) {
		t.Errorf("port 443 is called the machine's resolver\n%s", c)
	}
	if got := p.AddressEntries(); !slices.Equal(got, []string{"tcp://203.0.113.7:443"}) {
		t.Errorf("AddressEntries = %q", got)
	}
}

// TestTheKeptResolversNoteClaimsOnlyWhatHolds: the note and the summary line of a kept resolver say only what holds.
// An allowed TCP lookup is made by the supervisor outside the run's Landlock domain, so no ABI refuses it (guests at
// ABI 4 and 6 looked names up over TCP with an empty net.allow, a guest acceptance run of 2026-11-11); what Landlock may
// refuse is an addressed UDP lookup from ABI 10 (Linux 7.2), read from the code, not measured.
func TestTheKeptResolversNoteClaimsOnlyWhatHolds(t *testing.T) {
	r := newRun(t, ws)
	r.netLine(r.t0, "udp", "10.0.2.3:53", "net.resolver", "10.0.2.3", record.VerdictObserved)
	p := r.propose(Options{})
	texts := append([]string{p.Contract()}, p.leftOut()...)
	for _, s := range texts {
		if strings.Contains(s, "over TCP") || strings.Contains(s, "ABI 4") || strings.Contains(s, "Landlock refuses") ||
			strings.Contains(s, "Landlock opens port 53 only") {
			t.Errorf("a kept resolver's text claims Landlock refuses what no guest refused:\n%s", s)
		}
	}
	if !strings.Contains(p.Contract(), resolverKeptNote) || !strings.Contains(resolverKeptNote, "may refuse") ||
		!strings.Contains(resolverKeptNote, "UDP from Linux 7.2") {
		t.Errorf("the kept resolver's note is not the UDP, Linux 7.2, may note:\n%s", p.Contract())
	}
}
