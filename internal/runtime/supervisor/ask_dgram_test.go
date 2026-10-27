// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	dgramAddr    = 0x40000
	dgramPayload = 0x9000
)

var dgramDst = netip.MustParseAddrPort("93.184.216.34:53")

// revokedTaken is a fake granter's revoke of a credit the run's hook took, as it takes every relay's it admits.
var revokedTaken Revoke = func() (bool, error) { return false, nil }

// udpAskLoop is a loop over a UDP socket under one net.ask scope, raw (udp://, a bare host:port or tcp://), with hold.
func udpAskLoop(t *testing.T, tier backend.Tier, raw, proto string, hold agent.AskHold) (*Loop, *fakeKernel, *testSink) {
	t.Helper()
	f := newFake()
	f.put(dgramAddr, sockaddrIn4(dgramDst.Addr().String(), dgramDst.Port()))
	f.put(dgramPayload, []byte("ping"))
	f.sockType, f.sockProto, f.sockDomain = unix.SOCK_DGRAM, unix.IPPROTO_UDP, unix.AF_INET
	r := netRule(raw, dgramDst.Addr().String(), int(dgramDst.Port()), dgramDst.Addr().String())
	r.Proto, r.Verdict = proto, agent.VerdictAsk
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Tier = tier
	pol.Rules.Record = agent.RecordFull
	pol.Rules.Contract = &agent.Contract{Net: &agent.NetSection{}}
	pol.Rules.NetAsk = []agent.NetRule{r}
	pol.Rules.AskConfig = &agent.AskConfig{Hold: hold, Timeout: agent.Duration(time.Second), MaxPending: 4}
	l, sink := newTestLoop(t, f, pol)
	l.askResolver = staticResolver{set: dns.NewSet(pol.Rules.NetAsk, nil, dns.Options{})}
	return l, f, sink
}

func sendDatagram(l *Loop, flags uint64) {
	l.handle(notifFor(sendToNR(), 42, 5, dgramPayload, 4, flags, dgramAddr, uint64(unix.SizeofSockaddrInet4)))
}

func netLines(sink *testSink) []*record.Event {
	var out []*record.Event
	for _, ev := range sink.all() {
		if ev.Kind == record.KindNet {
			out = append(out, ev)
		}
	}
	return out
}

// TestAskDatagramApprovalDenialAndRootCredit (R13d): an addressed UDP datagram whose destination nothing admits and
// that a udp:// or bare host:port net.ask scope reaches is held while a person decides; an approval sends the payload
// and address copied before the wait, which the target rewrote meanwhile, on the duplicate, with the person's allow
// line; a denial refuses with its reason and sends nothing. At a root tier the send needs the kernel's one-datagram
// grant for exactly that destination: without a granter nothing is asked, a grant that fails refuses
// ask-unavailable, and a grant made is revoked once the relay returns.
func TestAskDatagramApprovalDenialAndRootCredit(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		tier                       backend.Tier
		raw, proto                 string
		approved, grant, grantFail bool
		asks                       int
		reason                     string
	}{
		{name: "approved udp scope", raw: "udp://93.184.216.34:53", proto: agent.ProtoUDP, approved: true, asks: 1},
		{name: "approved bare scope", raw: "93.184.216.34:53", proto: agent.ProtoInet, approved: true, asks: 1},
		{name: "denied", raw: "udp://93.184.216.34:53", proto: agent.ProtoUDP, asks: 1, reason: ask.ReasonDenied},
		{name: "root missing grant", tier: backend.TierCgroup, raw: "udp://93.184.216.34:53", proto: agent.ProtoUDP, approved: true, reason: ask.ReasonUnavailable},
		{name: "root grant fails", tier: backend.TierBPFLSM, raw: "udp://93.184.216.34:53", proto: agent.ProtoUDP, approved: true, grant: true, grantFail: true, asks: 1, reason: ask.ReasonUnavailable},
		{name: "root exact single datagram", tier: backend.TierCgroup, raw: "udp://93.184.216.34:53", proto: agent.ProtoUDP, approved: true, grant: true, asks: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, f, sink := udpAskLoop(t, tc.tier, tc.raw, tc.proto, agent.AskHoldConnect)
			asked, granted, revoked := 0, 0, 0
			var req ask.Request
			l.ask = func(_ context.Context, r ask.Request) (ask.Decision, error) {
				asked++
				req = r
				f.put(dgramAddr, sockaddrIn4("203.0.113.99", 8443))
				f.put(dgramPayload, []byte("pong"))
				return ask.Decision{Approved: tc.approved, Reason: ask.ReasonDenied}, nil
			}
			if tc.grant {
				l.grantDatagram = func(_ <-chan struct{}, cookie uint64, domain int, ap netip.AddrPort) (Revoke, error) {
					granted++
					if ap != dgramDst || cookie != 77 || domain != unix.AF_INET {
						t.Fatalf("grant for cookie %d domain %d %s, want the socket's 77, AF_INET, %s", cookie, domain, ap, dgramDst)
					}
					if tc.grantFail {
						return nil, errors.New("unavailable")
					}
					return func() (bool, error) { revoked++; return false, nil }, nil
				}
			}
			sendDatagram(l, 0)
			response, _ := f.lastResp()
			if asked != tc.asks {
				t.Fatalf("asks %d, want %d; response %+v lines %+v", asked, tc.asks, response, netLines(sink))
			}
			if asked > 0 && (req.Op != "send" || req.Target != "udp://93.184.216.34:53" || req.Rule != "net["+tc.raw+"]" || req.Hold != "connect") {
				t.Fatalf("request %+v", req)
			}
			lines := netLines(sink)
			if tc.reason == "" {
				if response.Error != 0 || response.Val != 4 || len(f.sends) != 1 {
					t.Fatalf("response %+v sends %d", response, len(f.sends))
				}
				if string(f.sends[0].payload) != "ping" || string(f.sends[0].addr) != string(sockaddrIn4(dgramDst.Addr().String(), dgramDst.Port())) {
					t.Fatalf("relay sent %q to %x: a copy the target rewrote during the wait", f.sends[0].payload, f.sends[0].addr)
				}
				if len(lines) != 1 || lines[0].Verdict != record.VerdictAllow || lines[0].Authority != record.AuthorityHuman {
					t.Fatalf("lines %+v, want one allow by a person", lines)
				}
			} else {
				if response.Error != -int32(unix.EACCES) || len(f.sends) != 0 {
					t.Fatalf("refusal %+v sends %d", response, len(f.sends))
				}
				if len(lines) != 1 || lines[0].Verdict != record.VerdictRefused || string(lines[0].Reason) != tc.reason {
					t.Fatalf("lines %+v, want one refusal %s", lines, tc.reason)
				}
			}
			for _, ev := range lines {
				if err := ev.Validate(); err != nil {
					t.Errorf("event does not validate: %v", err)
				}
			}
			if tc.grant && granted != 1 {
				t.Fatalf("grants %d", granted)
			}
			if tc.grant && !tc.grantFail && revoked != 1 {
				t.Fatalf("revokes %d", revoked)
			}
		})
	}
}

// TestAskDatagramApprovalCoversTheSocketOnly (R13d): an approval covers the socket's later datagrams to that destination
// under that scope, each relayed from its own copies (and at a root tier granted one at a time), so a person is asked
// once per socket, as for the stream a TCP approval opens; another socket, whose SO_COOKIE differs, is asked again,
// and a denial is remembered nowhere.
func TestAskDatagramApprovalCoversTheSocketOnly(t *testing.T) {
	l, f, sink := udpAskLoop(t, backend.TierCgroup, "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect)
	asked, granted := 0, 0
	approve := true
	l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
		asked++
		return ask.Decision{Approved: approve, Reason: ask.ReasonDenied}, nil
	}
	l.grantDatagram = func(<-chan struct{}, uint64, int, netip.AddrPort) (Revoke, error) {
		granted++
		return revokedTaken, nil
	}
	f.sockID = sockID{ino: 1, cookie: 100}
	for range 3 {
		sendDatagram(l, 0)
	}
	if asked != 1 || granted != 3 || len(f.sends) != 3 {
		t.Fatalf("one socket: asks %d grants %d sends %d, want 1, 3, 3", asked, granted, len(f.sends))
	}
	f.sockID = sockID{ino: 2, cookie: 101}
	approve = false
	sendDatagram(l, 0)
	sendDatagram(l, 0)
	if asked != 3 || len(f.sends) != 3 {
		t.Fatalf("another socket: asks %d sends %d, want each datagram asked and none sent", asked, len(f.sends))
	}
	for _, ev := range netLines(sink) {
		if ev.Verdict == record.VerdictAllow && ev.Authority != record.AuthorityHuman {
			t.Fatalf("an approved datagram's line has authority %q", ev.Authority)
		}
	}
}

// TestAskDatagramRefusesWhatItCannotRelayBeforeAsking (R13d, relayDatagram): a tcp:// scope holds no datagram (the
// ordinary refusal stands), a hold other than connect has nothing to hold a datagram with, and MSG_ZEROCOPY, which a
// relay cannot honour, is refused before anyone is asked; so are MSG_MORE and a corked socket,
// where the relayed datagram would join a pending frame to another destination; nothing is sent.
func TestAskDatagramRefusesWhatItCannotRelayBeforeAsking(t *testing.T) {
	for _, tc := range []struct {
		name, raw, proto string
		hold             agent.AskHold
		flags            uint64
		rule, reason     string
		corked           bool
	}{
		{"tcp scope", "tcp://93.184.216.34:53", agent.ProtoTCP, agent.AskHoldConnect, 0, ruleUnmatched, string(record.ReasonNetNotAllowed), false},
		{"first_write hold", "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldFirstWrite, 0, "net[udp://93.184.216.34:53]", ask.ReasonUnavailable, false},
		{"zero copy", "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect, unix.MSG_ZEROCOPY, ruleZeroCopy, "", false},
		{"more", "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect, unix.MSG_MORE, ruleCorked, "", false},
		{"corked socket", "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect, 0, ruleCorked, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, f, sink := udpAskLoop(t, backend.TierLandlock, tc.raw, tc.proto, tc.hold)
			f.udpCorked = tc.corked
			asked := 0
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
				asked++
				return ask.Decision{Approved: true}, nil
			}
			sendDatagram(l, tc.flags)
			response, _ := f.lastResp()
			lines := netLines(sink)
			if asked != 0 || len(f.sends) != 0 || response.Error != -int32(unix.EACCES) || len(lines) != 1 || lines[0].Verdict != record.VerdictRefused || lines[0].Rule != tc.rule {
				t.Fatalf("asks %d sends %d response %+v lines %+v", asked, len(f.sends), response, lines)
			}
			if tc.reason != "" && string(lines[0].Reason) != tc.reason {
				t.Fatalf("reason %q, want %q", lines[0].Reason, tc.reason)
			}
		})
	}
}

// TestAskDatagramCorkedDuringTheWaitIsNotRelayed (R13d): a socket corked while a person decides
// (by a process outside the run that shares it: the run itself can set no cork, R13's pending frames) would make the
// relay join the frame it then holds; the approved datagram is refused datagram-corked once the approval comes,
// granted and sent nowhere, and the socket's approval is still kept.
func TestAskDatagramCorkedDuringTheWaitIsNotRelayed(t *testing.T) {
	l, f, sink := udpAskLoop(t, backend.TierCgroup, "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect)
	asked := 0
	l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
		asked++
		f.mu.Lock()
		f.udpCorked = true
		f.mu.Unlock()
		return ask.Decision{Approved: true}, nil
	}
	l.grantDatagram = func(<-chan struct{}, uint64, int, netip.AddrPort) (Revoke, error) { return revokedTaken, nil }
	sendDatagram(l, 0)
	response, _ := f.lastResp()
	lines := netLines(sink)
	if asked != 1 || len(f.sends) != 0 || response.Error != -int32(unix.EACCES) || len(lines) != 1 || lines[0].Rule != ruleCorked {
		t.Fatalf("asks %d sends %d response %+v lines %+v", asked, len(f.sends), response, lines)
	}
	f.mu.Lock()
	f.udpCorked = false
	f.mu.Unlock()
	sendDatagram(l, 0)
	if asked != 1 || len(f.sends) != 1 {
		t.Fatalf("after the uncork: asks %d sends %d, want the kept approval to relay the datagram", asked, len(f.sends))
	}
}

// TestAskUDPConnectIsHeldAndGranted (R13d): a UDP socket's connect to a destination a udp:// or bare host:port scope
// reaches is held as a TCP connect is, under op connect and target udp://ip:port, and an approval at a root tier
// grants that one UDP connect (connect4/6) before the relay connects the copied address.
func TestAskUDPConnectIsHeldAndGranted(t *testing.T) {
	l, f, sink := udpAskLoop(t, backend.TierCgroup, "93.184.216.34:53", agent.ProtoInet, agent.AskHoldConnect)
	var req ask.Request
	l.ask = func(_ context.Context, r ask.Request) (ask.Decision, error) {
		req = r
		f.put(dgramAddr, sockaddrIn4("203.0.113.99", 8443))
		return ask.Decision{Approved: true}, nil
	}
	var grantedProto string
	l.grantConnect = func(_ <-chan struct{}, _ int, ap netip.AddrPort, proto string) (Revoke, error) {
		if ap != dgramDst {
			t.Fatalf("grant for %s", ap)
		}
		grantedProto = proto
		return revokedTaken, nil
	}
	l.handle(notifFor(connectNR(), 42, 5, dgramAddr, 16))
	response, _ := f.lastResp()
	if req.Op != "connect" || req.Target != "udp://93.184.216.34:53" || grantedProto != agent.ProtoUDP {
		t.Fatalf("request %+v grant %q", req, grantedProto)
	}
	if response.Error != 0 || len(f.connects) != 1 || string(f.connects[0]) != string(sockaddrIn4(dgramDst.Addr().String(), dgramDst.Port())) {
		t.Fatalf("response %+v connects %d", response, len(f.connects))
	}
	if lines := netLines(sink); len(lines) != 1 || lines[0].Authority != record.AuthorityHuman || lines[0].Verdict != record.VerdictAllow {
		t.Fatalf("lines %+v", lines)
	}
}

// TestAskUDPConnectOfAnIPv6SocketToIPv4IsUnavailableAtRootTiers (R13d): an AF_INET6 UDP socket connected to an IPv4
// peer has the run's sendmsg4 decide each later send (udpv6_sendmsg; TestDatagramApprovalOnRealKernel's udp6-mapped
// cell), which no row admits, so at a root tier its connect is refused ask-unavailable before anyone is asked, in
// either spelling of the peer; at tier landlock nothing in the kernel decides the sends, and the connect is asked.
func TestAskUDPConnectOfAnIPv6SocketToIPv4IsUnavailableAtRootTiers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tier   backend.Tier
		sa     []byte
		asks   int
		reason string
	}{
		{"mapped at cgroup", backend.TierCgroup, sockaddrIn6("::ffff:93.184.216.34", 53), 0, ask.ReasonUnavailable},
		{"AF_INET at bpflsm", backend.TierBPFLSM, sockaddrIn4("93.184.216.34", 53), 0, ask.ReasonUnavailable},
		{"mapped at landlock", backend.TierLandlock, sockaddrIn6("::ffff:93.184.216.34", 53), 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, f, sink := udpAskLoop(t, tc.tier, "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect)
			f.sockDomain = unix.AF_INET6
			f.put(0x50000, tc.sa)
			asked := 0
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
				asked++
				return ask.Decision{Approved: true}, nil
			}
			l.grantConnect = func(<-chan struct{}, int, netip.AddrPort, string) (Revoke, error) { return revokedTaken, nil }
			l.handle(notifFor(connectNR(), 42, 5, 0x50000, uint64(len(tc.sa))))
			response, _ := f.lastResp()
			if asked != tc.asks {
				t.Fatalf("asks %d, want %d; response %+v lines %+v", asked, tc.asks, response, netLines(sink))
			}
			if tc.reason == "" {
				if response.Error != 0 || len(f.connects) != 1 {
					t.Fatalf("response %+v connects %d", response, len(f.connects))
				}
				return
			}
			lines := netLines(sink)
			if response.Error != -int32(unix.EACCES) || len(f.connects) != 0 || len(lines) != 1 || string(lines[0].Reason) != tc.reason {
				t.Fatalf("response %+v connects %d lines %+v", response, len(f.connects), lines)
			}
		})
	}
}

// TestAskDatagramApprovalIsKeptAtTheScoreAPersonSaw (R13d): under a net gate the approval a person
// gave a socket's datagram covers its later datagrams to that destination only while the gate scores them as it
// scored the one the person saw (the request carried that score); a datagram the gate scores otherwise, here after
// its rule changed weight, is asked again and never relayed unasked.
func TestAskDatagramApprovalIsKeptAtTheScoreAPersonSaw(t *testing.T) {
	l, f, _ := udpAskLoop(t, backend.TierLandlock, "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect)
	pol := l.table.Load().pol
	pol.Rules.Gate = testGate(t, gate.NetTo, dgramDst.String(), 60)
	var scores []int
	l.ask = func(_ context.Context, r ask.Request) (ask.Decision, error) {
		if r.Score == nil {
			t.Fatalf("a gated datagram's request carries no score: %+v", r)
		}
		scores = append(scores, *r.Score)
		return ask.Decision{Approved: true}, nil
	}
	sendDatagram(l, 0)
	sendDatagram(l, 0)
	if len(scores) != 1 || len(f.sends) != 2 {
		t.Fatalf("same score: asks %v sends %d, want one ask covering both datagrams", scores, len(f.sends))
	}
	pol.Rules.Gate = testGate(t, gate.NetTo, dgramDst.String(), 70)
	sendDatagram(l, 0)
	if len(scores) != 2 || scores[1] != 70 || len(f.sends) != 3 {
		t.Fatalf("another score: asks %v sends %d, want the datagram scored 70 asked again", scores, len(f.sends))
	}
}

// TestAnApprovedDatagramWhoseCreditTheKernelLeftIsNotAPersonsAllow (R13d, R13's pending frames): at tiers 2 and 3 an
// approved datagram's credit is taken by the run's sendmsg4/6 only for that socket's datagram to that destination, so
// a relay the kernel answered with success whose credit is still in the map when it is withdrawn never passed the hook
// with it: it joined a frame pending on the socket (one the run was handed, or one a sibling raced the supervisor's
// read on), its bytes going to that frame's destination, or a row admitted the destination meanwhile. Its line is
// observed, the person's, under the scope's rule, never an allow of a destination its bytes may not have reached,
// whatever a breadcrumb says (the kernel recorder names connects); a taken credit is the allow it always was.
func TestAnApprovedDatagramWhoseCreditTheKernelLeftIsNotAPersonsAllow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		untaken bool
		crumb   record.Verdict
		want    record.Verdict
	}{
		{"the hook took the credit", false, "", record.VerdictAllow},
		{"the credit was left", true, "", record.VerdictObserved},
		{"the credit was left, whatever a breadcrumb says", true, record.VerdictAllow, record.VerdictObserved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, f, sink := udpAskLoop(t, backend.TierCgroup, "udp://93.184.216.34:53", agent.ProtoUDP, agent.AskHoldConnect)
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) { return ask.Decision{Approved: true}, nil }
			revokes := 0
			l.grantDatagram = func(<-chan struct{}, uint64, int, netip.AddrPort) (Revoke, error) {
				return func() (bool, error) { revokes++; return tc.untaken, nil }, nil
			}
			if tc.crumb != "" {
				l.kernelNet = func(netip.AddrPort, string, time.Time) (record.Verdict, string, record.Reason) {
					return tc.crumb, "", ""
				}
			}
			sendDatagram(l, 0)
			response, _ := f.lastResp()
			if len(f.sends) != 1 || response.Error != 0 || response.Val != 4 {
				t.Fatalf("sends %d response %+v; want the relayed datagram's own answer", len(f.sends), response)
			}
			if revokes != 1 {
				t.Fatalf("the credit was withdrawn %d times; want once", revokes)
			}
			lines := netLines(sink)
			if len(lines) != 1 {
				t.Fatalf("lines %+v; want one", lines)
			}
			ev := lines[0]
			if ev.Verdict != tc.want || ev.Rule != "net[udp://93.184.216.34:53]" || ev.Authority != record.AuthorityHuman {
				t.Errorf("line %s rule %s authority %s; want %s, the scope's rule, the person's", ev.Verdict, ev.Rule, ev.Authority, tc.want)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("line does not validate: %v", err)
			}
		})
	}
}
