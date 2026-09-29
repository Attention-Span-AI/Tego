// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestContinuedNetIsTheLoopsOwnLine: ContinuedNet, the lookup the tier-2 kernel recorder names a connect
// with once this loop writes no line for it (R7), answers what this loop's own line for that continued
// connect says: the same rule, host and verdict, for every case the loop names specially: the resolver
// exception on UDP and TCP 53, v4-mapped, a resolver on another port, the capture listener the runtime
// adds, a localhost entry, a host entry whose loopback answer the resolved-address check refuses, a cidr,
// and a destination nothing names. internal/runtime/observe's TestRecorderNamesAContinuedConnectAsTheSupervisor
// is the other half: the recorder's line equals this answer.
func TestContinuedNetIsTheLoopsOwnLine(t *testing.T) {
	const addr = 0x40000
	resolvers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53"), netip.MustParseAddrPort("[2001:db8::53]:53")}
	capture := netRule("127.0.0.1:40000", "127.0.0.1", 40000, "127.0.0.1")
	capture.Runtime = agent.CaptureGrant
	contracts := map[string][]agent.NetRule{
		"no entries": nil,
		"implicit and declared entries": {
			capture,
			netRule("localhost:8080", "localhost", 8080, "127.0.0.1", "::1"),
			netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34", "127.0.0.1"),
			{Raw: "10.0.0.0/8:443", CIDR: ptrPrefix(netip.MustParsePrefix("10.0.0.0/8")), Port: 443, Proto: agent.ProtoInet,
				Verdict: agent.VerdictAllow, Static: true},
		},
	}
	linkLocal := sockaddrIn6("fe80::1", 443)
	putU32(linkLocal[sin6ScopeOff:], 3)
	dsts := []struct {
		sa        []byte
		sockType  int
		proto     string
		sockProto int // SO_PROTOCOL; 0 leaves the fake's default, which names none
	}{
		{sockaddrIn4("192.0.2.53", 53), unix.SOCK_DGRAM, protoUDP, 0},
		{sockaddrIn4("192.0.2.53", 53), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn6("2001:db8::53", 53), unix.SOCK_DGRAM, protoUDP, 0},
		{sockaddrIn6("::ffff:192.0.2.53", 53), unix.SOCK_DGRAM, protoUDP, 0},
		{sockaddrIn4("192.0.2.53", 5353), unix.SOCK_DGRAM, protoUDP, 0},
		{sockaddrIn4("192.0.2.53", 53), unix.SOCK_RAW, protoRaw, 0},
		{sockaddrIn4("127.0.0.1", 40000), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn4("127.0.0.1", 8080), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn6("::1", 8080), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn4("93.184.216.34", 443), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn4("127.0.0.1", 443), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn4("10.1.2.3", 443), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn4("203.0.113.9", 443), unix.SOCK_STREAM, protoTCP, 0},
		{sockaddrIn6("2001:db8::9", 443), unix.SOCK_DGRAM, protoUDP, 0},
		// The kernel names a socket by its protocol (observe's protoName), not its type: a ping socket and
		// SCTP are raw there, so they are here, and a link-local destination's line carries no zone, which the
		// kernel's copy of the address does not give it.
		{sockaddrIn4("192.0.2.9", 0), unix.SOCK_DGRAM, protoRaw, unix.IPPROTO_ICMP},
		{sockaddrIn6("2001:db8::9", 0), unix.SOCK_DGRAM, protoRaw, unix.IPPROTO_ICMPV6},
		{sockaddrIn4("10.1.2.3", 443), unix.SOCK_STREAM, protoRaw, unix.IPPROTO_SCTP},
		{sockaddrIn4("10.1.2.3", 443), unix.SOCK_SEQPACKET, protoRaw, unix.IPPROTO_SCTP},
		{sockaddrIn4("10.1.2.3", 443), unix.SOCK_STREAM, protoTCP, unix.IPPROTO_MPTCP},
		{sockaddrIn4("192.0.2.53", 53), unix.SOCK_DGRAM, protoUDP, unix.IPPROTO_UDP},
		{linkLocal, unix.SOCK_STREAM, protoTCP, unix.IPPROTO_TCP},
	}
	for name, entries := range contracts {
		for _, d := range dsts {
			ap := parseSockaddr(d.sa).ap
			t.Run(fmt.Sprintf("%s/%s/%s", name, d.proto, ap), func(t *testing.T) {
				f := newFake()
				f.put(addr, d.sa)
				f.sockType = d.sockType
				f.sockProto = d.sockProto
				pol := contractPolicy(&agent.Contract{HostSockets: true}, entries, nil)
				pol.Resolver = staticResolverOf(entries, resolvers)
				l, sink := newTestLoop(t, f, pol)
				l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(d.sa))))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v, want CONTINUE", got)
				}
				ev := sink.one(t)
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.Proto != d.proto {
					t.Errorf("the loop's line says proto %s, the kernel's would say %s", p.Proto, d.proto)
				}
				if want := netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port()).String(); p.Dst != want {
					t.Errorf("the loop's line says dst %s, the kernel's would say %s", p.Dst, want)
				}
				rule, host, v, ok := l.ContinuedNet(ap, d.proto)
				if !ok {
					t.Fatal("ContinuedNet declined a connect this loop continued")
				}
				if rule != ev.Rule || host != p.Host || v != ev.Verdict {
					t.Errorf("ContinuedNet = %s/%q/%s, the loop's line %s/%q/%s", rule, host, v, ev.Rule, p.Host, ev.Verdict)
				}
			})
		}
	}

	// A connect this loop relays or refuses is never the agent's own, so the kernel records none and there is
	// nothing to name: under a net: section, for one.
	t.Run("a net: section", func(t *testing.T) {
		pol := contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, nil, nil)
		l, _ := newTestLoop(t, newFake(), pol)
		if _, _, _, ok := l.ContinuedNet(netip.MustParseAddrPort("203.0.113.9:443"), protoTCP); ok {
			t.Error("ContinuedNet named a connect under a net: section, which this loop relays")
		}
	})
}

// staticResolverOf is testPolicy's resolver over entries with a resolver list.
func staticResolverOf(entries []agent.NetRule, resolvers []netip.AddrPort) Resolver {
	return testPolicy(entries, nil, resolvers).Resolver
}

// TestKernelRecordsNeedsTheFamilysAddress: security_socket_connect returns before recording a connect whose
// address is shorter than its family's (sizeof(sockaddr_in) for AF_INET, SIN6_LEN_RFC2133 for AF_INET6), so
// this loop keeps its own line for one, whatever bytes it read; it recorded one from two bytes up, as a
// 0.0.0.0:0 for a call that fails EINVAL and named nothing. From the family's length up the kernel's line is
// the connect's.
func TestKernelRecordsNeedsTheFamilysAddress(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	l.kernelConnects = func() bool { return true }
	for _, tc := range []struct {
		name string
		d    dest
		want map[int64]bool
	}{
		{"v4", parseSockaddr(sockaddrIn4("192.0.2.9", 443)),
			map[int64]bool{0: false, 1: false, 2: false, 8: false, 15: false, 16: true, sockaddrMax: true, sockaddrMax + 1: false}},
		{"v6", parseSockaddr(sockaddrIn6("2001:db8::9", 443)),
			map[int64]bool{0: false, 1: false, 2: false, 16: false, 23: false, 24: true, 28: true, sockaddrMax: true, sockaddrMax + 1: false}},
	} {
		for addrlen, want := range tc.want {
			if got := l.kernelRecords(tc.d, addrlen); got != want {
				t.Errorf("%s: kernelRecords(addrlen %d) = %v, want %v", tc.name, addrlen, got, want)
			}
		}
	}
}
