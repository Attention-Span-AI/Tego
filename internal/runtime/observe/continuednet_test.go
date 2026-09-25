// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package observe

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecorderNamesAContinuedConnectAsTheSupervisor is supervisor.md R7's cross-check. With no net:
// section the supervisor continues each of the agent's IP connects, and at tier 2 writes no line for one
// the kernel recorder reads, so the recorder's line is the connect's only one. The recorder named it from
// its own matcher over the contract's entries, which knows neither the resolver exception nor the
// resolved-address check nor the capture listener the runtime adds: a DNS query the supervisor recorded
// net.resolver allow became unmatched observed. For a table of contracts × destinations, the recorder's rule,
// verdict and host for a continued connect equal the supervisor's (supervisor.Loop.ContinuedNet, which
// TestContinuedNetIsTheLoopsOwnLine holds to the supervisor's own line).
func TestRecorderNamesAContinuedConnectAsTheSupervisor(t *testing.T) {
	resolvers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53"), netip.MustParseAddrPort("[2001:db8::53]:53")}
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	entries := []agent.NetRule{
		{Raw: "127.0.0.1:40000", Host: "127.0.0.1", Port: 40000, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
			IPs: parseAddrs("127.0.0.1"), Static: true, Runtime: agent.CaptureGrant},
		{Raw: "localhost:8080", Host: "localhost", Port: 8080, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
			IPs: parseAddrs("127.0.0.1", "::1"), TTL: time.Minute, ResolvedAt: time.Now()},
		{Raw: "api.example.com:443", Host: "api.example.com", Port: 443, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: parseAddrs("93.184.216.34", "127.0.0.1"), TTL: time.Minute,
			ResolvedAt: time.Now()},
		{Raw: "10.0.0.0/8:443", CIDR: &cidr, Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, Static: true},
	}
	contracts := map[string][]agent.NetRule{"no entries": nil, "implicit and declared entries": entries}
	dsts := []struct {
		dst   string
		proto uint8
		name  string // the supervisor's spelling of proto
	}{
		{"192.0.2.53:53", unix.IPPROTO_UDP, agent.ProtoUDP},
		{"192.0.2.53:53", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"[2001:db8::53]:53", unix.IPPROTO_UDP, agent.ProtoUDP},
		{"[::ffff:192.0.2.53]:53", unix.IPPROTO_UDP, agent.ProtoUDP},
		{"192.0.2.53:5353", unix.IPPROTO_UDP, agent.ProtoUDP},
		{"192.0.2.53:53", unix.IPPROTO_RAW, protoRaw},
		{"127.0.0.1:40000", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"127.0.0.1:8080", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"[::1]:8080", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"93.184.216.34:443", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"127.0.0.1:443", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"10.1.2.3:443", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"203.0.113.9:443", unix.IPPROTO_TCP, agent.ProtoTCP},
		{"[2001:db8::9]:443", unix.IPPROTO_UDP, agent.ProtoUDP},
		{"192.0.2.9:0", unix.IPPROTO_ICMP, protoRaw},
		{"[2001:db8::9]:0", unix.IPPROTO_ICMPV6, protoRaw},
		{"10.1.2.3:443", unix.IPPROTO_SCTP, protoRaw},
		{"[fe80::1]:443", unix.IPPROTO_TCP, agent.ProtoTCP},
	}
	for name, net := range contracts {
		rt := &agent.RuleTable{Net: net, Contract: &agent.Contract{}, Record: agent.RecordSummary, Tier: "cgroup"}
		loop := continuedLoop(t, rt, resolvers)
		for _, d := range dsts {
			t.Run(fmt.Sprintf("%s/%s/%s", name, d.name, d.dst), func(t *testing.T) {
				ap := netip.MustParseAddrPort(d.dst)
				// The supervisor reads a v4-mapped sockaddr_in6 as the IPv4 address (parseSockaddr).
				rule, host, verdict, ok := loop.ContinuedNet(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), d.name)
				if !ok {
					t.Fatal("the supervisor does not continue this connect")
				}
				family, raw := uint8(unix.AF_INET6), ap.Addr().As16()
				if ap.Addr().Is4() {
					family, raw = unix.AF_INET, addr4(ap.Addr().As4()[0], ap.Addr().As4()[1], ap.Addr().As4()[2], ap.Addr().As4()[3])
				}
				f := newFixture(t)
				f.rules = rt
				_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, ContinuedNet: loop.ContinuedNet},
					netSample(sample{Kind: KindConnect, PID: 50, MonoNS: 1}, family, d.proto, ap.Port(), raw))
				nets := sink.byKind(record.KindNet)
				if len(nets) != 1 {
					t.Fatalf("%d net lines, want 1", len(nets))
				}
				np := payload[record.NetPayload](t, nets[0])
				if nets[0].Rule != rule || nets[0].Verdict != verdict || np.Host != host {
					t.Errorf("recorder %s/%s host %q, supervisor %s/%s host %q", nets[0].Rule, nets[0].Verdict, np.Host,
						rule, verdict, host)
				}
				if np.Proto != d.name {
					t.Errorf("recorder proto %s, supervisor %s", np.Proto, d.name)
				}
				if want := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(); np.Dst != want {
					t.Errorf("recorder dst %s, the supervisor's spelling %s", np.Dst, want)
				}
				if err := nets[0].Validate(); err != nil {
					t.Errorf("the line does not satisfy spec/record/v1: %v", err)
				}
			})
		}
	}
}

// TestRecorderNamesAProtocolAsTheSupervisor: for each socket the kernel's security_socket_connect can see, the
// proto the recorder names from sk_protocol is the one the supervisor names from the same socket's SO_TYPE and
// SO_PROTOCOL (supervisor.ProtoOfSocket), so a continued connect's line says the same whichever writes it. A
// ping socket and SCTP are raw on both sides, and MPTCP is tcp: the hook reads its sk_protocol (262) truncated to
// a byte, TCP's number. A SOCK_RAW socket opened with IPPROTO_TCP or IPPROTO_UDP is the stated exception: the
// supervisor names it raw, the kernel by its protocol (supervisor.md R7).
func TestRecorderNamesAProtocolAsTheSupervisor(t *testing.T) {
	for _, s := range []struct{ typ, proto int }{
		{unix.SOCK_STREAM, unix.IPPROTO_TCP},
		{unix.SOCK_STREAM, unix.IPPROTO_MPTCP},
		{unix.SOCK_DGRAM, unix.IPPROTO_UDP},
		{unix.SOCK_DGRAM, unix.IPPROTO_ICMP},
		{unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6},
		{unix.SOCK_DGRAM, unix.IPPROTO_UDPLITE},
		{unix.SOCK_STREAM, unix.IPPROTO_SCTP},
		{unix.SOCK_SEQPACKET, unix.IPPROTO_SCTP},
		{unix.SOCK_RAW, unix.IPPROTO_RAW},
		{unix.SOCK_RAW, unix.IPPROTO_ICMP},
		{unix.SOCK_RAW, unix.IPPROTO_ICMPV6},
	} {
		if k, u := protoName(uint8(s.proto)), supervisor.ProtoOfSocket(s.typ, s.proto); k != u {
			t.Errorf("type %d protocol %d: recorder %s, supervisor %s", s.typ, s.proto, k, u)
		}
	}
}

// continuedLoop is the run's supervisor over rt, never run: what the recorder asks of it is ContinuedNet alone.
func continuedLoop(t *testing.T, rt *agent.RuleTable, resolvers []netip.AddrPort) *supervisor.Loop {
	t.Helper()
	// New takes a listener; a loop that never runs never reads it, and never closes it either, so the test does.
	null, err := sys.Own(unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = null.Close() })
	l, err := supervisor.New(null, &supervisor.Policy{
		Rules: rt, Resolver: dns.NewSet(rt.Net, resolvers, dns.Options{}),
		RunID: "2026-09-24T00-00-00Z-abcd", Agent: "claude-code",
	}, discardSink{}, supervisor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// The runtime hands the lookup to a recorder that takes it (runtime.nameKernelConnects).
var _ runtime.ContinuedNetNamer = (*Recorder)(nil)

type discardSink struct{}

func (discardSink) Emit(*record.Event) {}
