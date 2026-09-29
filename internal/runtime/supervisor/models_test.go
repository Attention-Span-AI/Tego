// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// guardPolicy is a contract with no net: section, capture: forwarder and the given models[] entries, at
// tier, with rules (the capture listener's, say) in the resolver set as admitLoopback leaves them.
func guardPolicy(tier backend.Tier, rules []agent.NetRule, models ...agent.ModelEndpoint) *Policy {
	// host_sockets: true, so the guard alone decides what these tests ask: the unix-only state (ADR 0070) relays every
	// connect of its own (TestConnectInTheUnixOnlyState).
	pol := contractPolicy(&agent.Contract{Models: models, HostSockets: true}, rules, nil)
	pol.Rules.Tier = tier
	pol.Rules.Capture = agent.CaptureForwarder
	return pol
}

// stubLookup answers a guarded name's lookup: a fixed set of addresses, or err.
type stubLookup struct {
	mu    sync.Mutex
	addrs []netip.Addr
	err   error
	asked []string
}

func (s *stubLookup) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, host)
	return s.addrs, s.err
}

// guardLoop is newTestLoop with the guard's lookup injected.
func guardLoop(t *testing.T, f *fakeKernel, pol *Policy, lookup agent.Resolver) (*Loop, *testSink) {
	t.Helper()
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 1, lookup: lookup})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, sink
}

// netLine decodes a net event's payload.
func netLine(t *testing.T, ev *record.Event) netPayload {
	t.Helper()
	var p netPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestModelEndpointIsRefusedWithNoNetSection is SEMANTICS §1's exception to "no net: — deny nothing" at the
// supervisor (R7): under capture: forwarder a direct connect to a declared models[] endpoint is refused, at
// tier 1 and at tier 2 alike, since tier 2 attaches no network program for such a contract and this loop is
// what decides there too. The C9 acceptance run's kt2 forwarder half connected straight to the model stand-in
// with no net: section: the connect was answered CONTINUE and recorded allow/unmatched, so the model traffic
// went around the forwarder and its capture. Every other IP destination stays admitted, and is relayed on the
// duplicate rather than continued, because a CONTINUE lets a sibling thread swap the guarded endpoint in
// after the decision.
func TestModelEndpointIsRefusedWithNoNetSection(t *testing.T) {
	const addr = 0x40000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	model6 := agent.ModelEndpoint{Provider: "local", Host: "::1", Port: 9443}
	listener := agent.NetRule{Raw: "127.0.0.1:39001", Host: "127.0.0.1", Port: 39001, Proto: agent.ProtoInet,
		Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true, Runtime: agent.CaptureGrant}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		t.Run(string(tier), func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				sa      []byte
				dst     string
				refused bool
				rule    string
				host    string
			}{
				{"the model endpoint", sockaddrIn4("127.0.0.1", 8443), "127.0.0.1:8443", true, "models[127.0.0.1:8443]", "127.0.0.1"},
				{"the model endpoint, v4-mapped", sockaddrIn6("::ffff:127.0.0.1", 8443), "127.0.0.1:8443", true, "models[127.0.0.1:8443]", "127.0.0.1"},
				// The kernel sends a connect to the unspecified address to loopback (ip_route_connect,
				// tcp_v6_connect): 0.0.0.0:8443 reached a server on 127.0.0.1:8443 around the guard, recorded
				// allow/unmatched, which a copy of kt2 whose agent connected to 0.0.0.0:$port showed (the shipped
				// kt2 connects to 127.0.0.1:$port; supervisor.md's corrections name the copy).
				{"the unspecified address", sockaddrIn4("0.0.0.0", 8443), "0.0.0.0:8443", true, "models[127.0.0.1:8443]", "127.0.0.1"},
				{"the unspecified address, v4-mapped", sockaddrIn6("::ffff:0.0.0.0", 8443), "0.0.0.0:8443", true, "models[127.0.0.1:8443]", "127.0.0.1"},
				{"the IPv6 unspecified address", sockaddrIn6("::", 9443), "[::]:9443", true, "models[[::1]:9443]", "::1"},
				// A server bound to all interfaces answers on every loopback address.
				{"another loopback address", sockaddrIn4("127.0.0.2", 8443), "127.0.0.2:8443", true, "models[127.0.0.1:8443]", "127.0.0.1"},
				{"IPv6 loopback on the IPv4 endpoint's port", sockaddrIn6("::1", 8443), "[::1]:8443", true, "models[127.0.0.1:8443]", "127.0.0.1"},
				{"IPv4 loopback on the IPv6 endpoint's port", sockaddrIn4("127.0.0.1", 9443), "127.0.0.1:9443", true, "models[[::1]:9443]", "::1"},
				{"the forwarder's listener", sockaddrIn4("127.0.0.1", 39001), "127.0.0.1:39001", false, "net.capture[127.0.0.1:39001]", ""},
				{"the model address on another port", sockaddrIn4("127.0.0.1", 8080), "127.0.0.1:8080", false, ruleUnmatched, ""},
				{"the unspecified address on another port", sockaddrIn4("0.0.0.0", 8080), "0.0.0.0:8080", false, ruleUnmatched, ""},
				{"another host", sockaddrIn4("203.0.113.9", 443), "203.0.113.9:443", false, ruleUnmatched, ""},
				{"another host on the model's port", sockaddrIn4("203.0.113.9", 8443), "203.0.113.9:8443", false, ruleUnmatched, ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := newFake()
					f.put(addr, tc.sa)
					l, sink := newTestLoop(t, f, guardPolicy(tier, []agent.NetRule{listener}, model, model6))
					l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(tc.sa))))
					got, _ := f.lastResp()
					if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
						t.Fatalf("response = %+v: continued, so the kernel re-reads an address a sibling can have swapped", got)
					}
					ev := sink.one(t)
					p := netLine(t, ev)
					if tc.refused {
						if got.Error != -int32(refusalErrno) || len(f.connects) != 0 {
							t.Fatalf("response = %+v connects %d, want R10's errno and no connect", got, len(f.connects))
						}
						if ev.Verdict != record.VerdictRefused || ev.Rule != tc.rule || ev.Reason != record.ReasonNetNotAllowed ||
							p.Dst != tc.dst || p.Host != tc.host || p.BestEffort {
							t.Errorf("event = %s/%s/%s dst %s host %q best_effort=%v, want refused/%s/net-not-allowed dst %s, enforced",
								ev.Verdict, ev.Rule, ev.Reason, p.Dst, p.Host, p.BestEffort, tc.rule, tc.dst)
						}
						return
					}
					if got.Error != 0 || len(f.connects) != 1 {
						t.Fatalf("response = %+v connects %d, want the relayed result of one connect", got, len(f.connects))
					}
					if ev.Verdict != record.VerdictAllow || ev.Rule != tc.rule || p.Dst != tc.dst || p.BestEffort {
						t.Errorf("event = %s/%s dst %s best_effort=%v, want allow/%s dst %s, performed here",
							ev.Verdict, ev.Rule, p.Dst, p.BestEffort, tc.rule, tc.dst)
					}
				})
			}
		})
	}

	// A socket that cannot reach an IP destination is left to the kernel as before: the guard has nothing
	// on it to hold. On an IP socket, an address of any other form is refused, whatever the kernel would
	// have answered it, since continued it is re-read after the decision.
	netlink := make([]byte, 12)
	netlink[0] = unix.AF_NETLINK
	for _, tc := range []struct {
		name    string
		domain  int
		domErr  error
		sa      []byte
		cont    bool
		verdict record.Verdict
	}{
		{"a unix socket", unix.AF_UNIX, nil, sockaddrUn("/run/user/1000/bus"), true, record.VerdictAllow},
		{"a unix address on an IP socket", unix.AF_INET, nil, sockaddrUn("/run/user/1000/bus"), false, record.VerdictRefused},
		{"an unparsed family on an IP socket", unix.AF_INET6, nil, netlink, false, record.VerdictRefused},
		{"an unparsed family on a netlink socket", unix.AF_NETLINK, nil, netlink, true, record.VerdictAllow},
		{"a socket whose domain cannot be read", 0, unix.EBADF, sockaddrUn("/run/user/1000/bus"), false, record.VerdictRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockDomain, f.sockDomainErr = tc.domain, tc.domErr
			f.put(addr, tc.sa)
			l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(tc.sa))))
			got, _ := f.lastResp()
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != tc.cont {
				t.Fatalf("response = %+v, want CONTINUE=%v", got, tc.cont)
			}
			if !tc.cont && got.Error != -int32(refusalErrno) {
				t.Errorf("response = %+v, want R10's errno", got)
			}
			if ev := sink.one(t); ev.Verdict != tc.verdict || len(f.connects) != 0 || len(f.unixConnects) != 0 {
				t.Errorf("event %s, connects %d, unix relays %d; want %s and nothing performed here", ev.Verdict, len(f.connects), len(f.unixConnects), tc.verdict)
			}
		})
	}

	// connect(2)'s AF_UNSPEC is still the disassociation, relayed rather than continued.
	t.Run("AF_UNSPEC connect", func(t *testing.T) {
		f := newFake()
		sa := unspecSockaddr("127.0.0.1", 8443)
		f.put(addr, sa)
		l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || len(f.connects) != 1 {
			t.Fatalf("response = %+v connects %d, want the disassociation relayed", got, len(f.connects))
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictObserved || ev.Rule != ruleUnspec {
			t.Errorf("event = %s/%s, want observed/%s", ev.Verdict, ev.Rule, ruleUnspec)
		}
	})

	// No guard without capture: forwarder, and none under a net: section, which decides on its own.
	t.Run("capture: uprobe is not guarded", func(t *testing.T) {
		f := newFake()
		sa := sockaddrIn4("127.0.0.1", 8443)
		f.put(addr, sa)
		pol := guardPolicy(backend.TierCgroup, nil, model)
		pol.Rules.Capture = agent.CaptureUprobe
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(f.connects) != 0 {
			t.Fatalf("response = %+v, want CONTINUE: the uprobes record a direct connection's TLS", got)
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictAllow || !netLine(t, ev).BestEffort {
			t.Errorf("event = %s, want allow best_effort", ev.Verdict)
		}
	})
}

// TestModelEndpointSendsWithNoNetSection is the guard on the send forms. A Fast-Open send is a connect
// (R12): refused to the model endpoint and relayed elsewhere. A datagram to it is refused too, with R10's
// errno and a line with no best_effort: continued under R13b, it reached the model around the forwarder —
// QUIC over an unconnected socket sends just this way — at tier 2 as well, whose network programs stay
// detached for such a contract, so the guard's verdict is the only one there is. A datagram elsewhere is
// relayed on the duplicate, to the address this loop read and with the payload it read, and answered with
// the real byte count: continued, the kernel read the address again, and a sibling that rewrote it to the
// model endpoint in between sent the datagram there under an allow line. One that cannot be relayed whole —
// ancillary data, a payload past sendBytes, one that could not be read — is refused. A batch cannot be
// relayed (R13c), so on an IP socket under the guard every addressed batch is refused whole, the model
// endpoint's message named by its rule and the others batch-send.
func TestModelEndpointSendsWithNoNetSection(t *testing.T) {
	const saAddr, bufAddr, arrayAddr, hdrAddr, otherAddr = 0x40000, 0x50000, 0x100000, 0x60000, 0x70000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	payload := []byte("POST /v1/messages HTTP/1.1\r\n")
	netlink := make([]byte, 12)
	netlink[0] = unix.AF_NETLINK
	t.Run("Fast Open to the model endpoint", func(t *testing.T) {
		f := newFake()
		f.put(saAddr, sockaddrIn4("127.0.0.1", 8443))
		f.put(bufAddr, payload)
		l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
		l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), unix.MSG_FASTOPEN, saAddr, 16))
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) || len(f.sends) != 0 {
			t.Fatalf("response = %+v sends %d, want R10's errno and nothing sent", got, len(f.sends))
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != "models[127.0.0.1:8443]" {
			t.Errorf("event = %s/%s, want refused/models[127.0.0.1:8443]", ev.Verdict, ev.Rule)
		}
	})
	t.Run("Fast Open elsewhere is relayed", func(t *testing.T) {
		f := newFake()
		f.put(saAddr, sockaddrIn4("203.0.113.9", 443))
		f.put(bufAddr, payload)
		l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
		l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), unix.MSG_FASTOPEN, saAddr, 16))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || len(f.sends) != 1 || got.Val != int64(len(payload)) {
			t.Fatalf("response = %+v sends %d, want the relayed byte count", got, len(f.sends))
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictAllow || ev.Rule != ruleUnmatched || netLine(t, ev).BestEffort {
			t.Errorf("event = %s/%s, want allow/unmatched, performed here", ev.Verdict, ev.Rule)
		}
	})

	// One datagram, by sendto and by sendmsg. send issues the call and returns the answer and its one line.
	type datagram struct {
		name string
		send func(t *testing.T, f *fakeKernel, l *Loop, sa []byte)
	}
	const iovAddr = 0x80000
	dgram := []byte("dgrm")
	forms := []datagram{
		{"sendto", func(t *testing.T, f *fakeKernel, l *Loop, sa []byte) {
			f.put(saAddr, sa)
			f.put(bufAddr, dgram)
			l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(dgram)), 0, saAddr, uint64(len(sa))))
		}},
		{"sendmsg", func(t *testing.T, f *fakeKernel, l *Loop, sa []byte) {
			f.put(saAddr, sa)
			f.put(bufAddr, dgram)
			hdr := namedMsgHdr(saAddr, uint32(len(sa)))
			putU64(hdr[msgIovOff:], iovAddr)
			putU64(hdr[msgIovLenOff:], 1)
			iov := make([]byte, iovecSize)
			putU64(iov[iovecBaseOff:], bufAddr)
			putU64(iov[iovecLenOff:], uint64(len(dgram)))
			f.put(iovAddr, iov)
			f.put(hdrAddr, hdr)
			l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0))
		}},
	}
	for _, form := range forms {
		for _, tc := range []struct {
			name     string
			sockType int
			sa       []byte
			refused  bool
			rule     string
		}{
			{"a datagram to the model endpoint", unix.SOCK_DGRAM, sockaddrIn4("127.0.0.1", 8443), true, "models[127.0.0.1:8443]"},
			{"a datagram to the unspecified address on its port", unix.SOCK_DGRAM, sockaddrIn4("0.0.0.0", 8443), true, "models[127.0.0.1:8443]"},
			{"a raw datagram to the model endpoint", unix.SOCK_RAW, sockaddrIn4("127.0.0.1", 8443), true, "models[127.0.0.1:8443]"},
			// E4 under the guard: an address of a family this tier does not parse, on an IP socket, is
			// refused as under a net: section. Continued, the kernel re-reads it after this decision.
			{"a datagram with an unparsed family", unix.SOCK_DGRAM, netlink, true, ruleUnmatched},
			{"a datagram elsewhere", unix.SOCK_DGRAM, sockaddrIn4("203.0.113.9", 443), false, ruleUnmatched},
		} {
			t.Run(form.name+": "+tc.name, func(t *testing.T) {
				f := newFake()
				f.sockType = tc.sockType
				l, sink := newTestLoop(t, f, guardPolicy(backend.TierCgroup, nil, model))
				form.send(t, f, l, tc.sa)
				got, _ := f.lastResp()
				ev := sink.one(t)
				p := netLine(t, ev)
				if tc.refused {
					if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
						t.Fatalf("response = %+v, want R10's errno and no CONTINUE", got)
					}
					if ev.Verdict != record.VerdictRefused || ev.Rule != tc.rule || p.BestEffort {
						t.Errorf("event = %s/%s best_effort=%v, want refused/%s, enforced", ev.Verdict, ev.Rule, p.BestEffort, tc.rule)
					}
					return
				}
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || len(f.sends) != 1 || got.Val != int64(len(dgram)) {
					t.Fatalf("response = %+v sends %d, want the datagram relayed and its real byte count", got, len(f.sends))
				}
				if sent := f.sends[0]; !bytes.Equal(sent.addr, tc.sa) || !bytes.Equal(sent.payload, dgram) {
					t.Errorf("relayed %q to %x, want %q to the address as read, %x", sent.payload, sent.addr, dgram, tc.sa)
				}
				if ev.Verdict != record.VerdictAllow || ev.Rule != tc.rule || p.BestEffort || p.Proto != protoUDP {
					t.Errorf("event = %s/%s %s best_effort=%v, want allow/%s udp, performed here", ev.Verdict, ev.Rule, p.Proto, p.BestEffort, tc.rule)
				}
			})
		}
		// A connected stream socket ignores the address a send carries, and the send is continued
		// undecided (R13a) — but not one this tier cannot parse, on an IP socket under the guard (E4): it
		// is refused before the peer is looked at, as under a net: section.
		t.Run(form.name+": an unparsed family on a connected stream socket", func(t *testing.T) {
			f := newFake()
			f.connected = true
			l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
			form.send(t, f, l, netlink)
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v, want R10's errno and no CONTINUE", got)
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched {
				t.Errorf("event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleUnmatched)
			}
		})
	}

	t.Run("a stream batch on an IP socket", func(t *testing.T) {
		f := newFake()
		f.put(arrayAddr, mmsgArray(1, func(int) uint64 { return saAddr }))
		f.put(saAddr, sockaddrIn4("203.0.113.9", 443))
		l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, unix.MSG_FASTOPEN))
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno: a batch cannot be relayed (R13c)", got)
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleBatchSend {
			t.Errorf("event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleBatchSend)
		}
	})

	// A datagram batch: the model endpoint as its first message, or as a message past the 64 the ledger
	// records one line each, refuses the whole batch; the admitted messages are recorded batch-send, the
	// batch and not their host being what refused them, and the tail's one line names the model message.
	for _, at := range []int{0, mmsgMessages + 3} {
		t.Run("a datagram batch carrying the model endpoint at "+strconv.Itoa(at), func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_DGRAM
			vlen := mmsgMessages + 5
			f.put(arrayAddr, mmsgArray(vlen, func(i int) uint64 {
				if i == at {
					return saAddr
				}
				return otherAddr
			}))
			f.put(saAddr, sockaddrIn4("127.0.0.1", 8443))
			f.put(otherAddr, sockaddrIn4("203.0.113.9", 443))
			l, sink := newTestLoop(t, f, guardPolicy(backend.TierCgroup, nil, model))
			l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, uint64(vlen), 0))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v, want R10's errno for the whole batch", got)
			}
			evs := sink.all()
			if len(evs) != mmsgMessages+1 {
				t.Fatalf("%d lines, want %d: one per recorded message and one past them", len(evs), mmsgMessages+1)
			}
			models := 0
			for i, ev := range evs {
				p := netLine(t, ev)
				if ev.Verdict != record.VerdictRefused || p.BestEffort {
					t.Errorf("line %d = %s best_effort=%v, want refused, enforced", i, ev.Verdict, p.BestEffort)
				}
				switch {
				case ev.Rule == "models[127.0.0.1:8443]" && p.Dst == "127.0.0.1:8443":
					models++
				case ev.Rule != ruleBatchSend || p.Dst != "203.0.113.9:443":
					t.Errorf("line %d = %s dst %s, want %s for an admitted message", i, ev.Rule, p.Dst, ruleBatchSend)
				}
			}
			if models != 1 {
				t.Errorf("%d lines name the model endpoint, want exactly one", models)
			}
		})
	}
	t.Run("a datagram batch elsewhere is refused whole", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		f.put(arrayAddr, mmsgArray(mmsgMessages+2, func(int) uint64 { return otherAddr }))
		f.put(otherAddr, sockaddrIn4("203.0.113.9", 8443))
		l, sink := newTestLoop(t, f, guardPolicy(backend.TierCgroup, nil, model))
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgMessages+2, 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno: continued, the kernel reads every address again (R7)", got)
		}
		evs := sink.all()
		if len(evs) == 0 {
			t.Fatal("no line for a refused batch")
		}
		for _, ev := range evs {
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleBatchSend || netLine(t, ev).BestEffort {
				t.Errorf("line = %s/%s best_effort=%v, want refused/%s, enforced", ev.Verdict, ev.Rule, netLine(t, ev).BestEffort, ruleBatchSend)
			}
		}
	})

	// A datagram a relay cannot reproduce whole is refused, never sent altered and never continued.
	t.Run("a datagram with ancillary data", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		sa := sockaddrIn4("203.0.113.9", 443)
		f.put(saAddr, sa)
		hdr := namedMsgHdr(saAddr, uint32(len(sa)))
		putU64(hdr[msgControlLenOff:], 24)
		f.put(hdrAddr, hdr)
		l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
		l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0))
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) || len(f.sends) != 0 {
			t.Fatalf("response = %+v sends %d, want R10's errno and nothing sent", got, len(f.sends))
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleAncillary {
			t.Errorf("event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleAncillary)
		}
	})
	for _, tc := range []struct {
		name string
		len  uint64
		put  bool
	}{
		{"a datagram past sendBytes", sendBytes + 1, true},
		{"a datagram whose payload cannot be read", 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_DGRAM
			sa := sockaddrIn4("203.0.113.9", 443)
			f.put(saAddr, sa)
			if tc.put {
				f.put(bufAddr, make([]byte, sendBytes+1))
			}
			l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
			l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, tc.len, 0, saAddr, uint64(len(sa))))
			if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) || len(f.sends) != 0 {
				t.Fatalf("response = %+v sends %d, want R10's errno and nothing sent", got, len(f.sends))
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleDatagramSize {
				t.Errorf("event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleDatagramSize)
			}
		})
	}
	// The same through sendmsg's gather: a datagram whose iovecs total more than sendBytes, whose iovlen is
	// past msgIovs, whose iovec array or one of whose buffers cannot be read, one of whose iovecs has a NULL
	// base, whose buffer is cut short by the end of its mapping, or whose iovecs are left unread once
	// sendBytes is reached, is refused. Relayed, gather's partial read would have left as a shorter datagram
	// (I3).
	for _, tc := range gatherShapes() {
		t.Run("sendmsg: a datagram "+tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_DGRAM
			sa := sockaddrIn4("203.0.113.9", 443)
			f.put(saAddr, sa)
			tc.put(f, hdrAddr, saAddr, uint32(len(sa)))
			l, sink := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
			l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0))
			if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) || len(f.sends) != 0 {
				t.Fatalf("response = %+v sends %d, want R10's errno and nothing sent", got, len(f.sends))
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleDatagramSize {
				t.Errorf("event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleDatagramSize)
			}
		})
	}
}

// gatherShape is one msghdr whose payload gather cannot read whole. put writes the header at hdrAddr, naming
// the address at nameAddr (0 for none), and whatever iovec array and buffers the shape needs.
type gatherShape struct {
	name string
	put  func(f *fakeKernel, hdrAddr, nameAddr uint64, namelen uint32)
}

// gatherShapes are the datagrams a relay cannot reproduce whole (relayDatagram, sendUnaddressed).
func gatherShapes() []gatherShape {
	const iovAddr, bufAddr, unmapped = 0x80000, 0x200000, 0x7000000
	hdrWith := func(f *fakeKernel, hdrAddr, nameAddr uint64, namelen uint32, iovs [][2]uint64, iovlen uint64) {
		hdr := namedMsgHdr(nameAddr, namelen)
		if nameAddr == 0 {
			hdr = make([]byte, msgHdrSize)
		}
		putU64(hdr[msgIovOff:], iovAddr)
		putU64(hdr[msgIovLenOff:], iovlen)
		f.put(hdrAddr, hdr)
		arr := make([]byte, len(iovs)*iovecSize)
		for i, v := range iovs {
			putU64(arr[i*iovecSize+iovecBaseOff:], v[0])
			putU64(arr[i*iovecSize+iovecLenOff:], v[1])
		}
		f.put(iovAddr, arr)
	}
	return []gatherShape{
		{"whose iovecs total more than sendBytes", func(f *fakeKernel, h, n uint64, nl uint32) {
			half := uint64(sendBytes/2 + 1)
			f.put(bufAddr, make([]byte, 2*half))
			hdrWith(f, h, n, nl, [][2]uint64{{bufAddr, half}, {bufAddr + half, half}}, 2)
		}},
		{"whose iovlen is past msgIovs", func(f *fakeKernel, h, n uint64, nl uint32) {
			f.put(bufAddr, make([]byte, msgIovs+1))
			iovs := make([][2]uint64, msgIovs+1)
			for i := range iovs {
				iovs[i] = [2]uint64{bufAddr + uint64(i), 1}
			}
			hdrWith(f, h, n, nl, iovs, msgIovs+1)
		}},
		{"whose iovec array cannot be read", func(f *fakeKernel, h, n uint64, nl uint32) {
			hdrWith(f, h, n, nl, nil, 1)
		}},
		{"whose buffer cannot be read", func(f *fakeKernel, h, n uint64, nl uint32) {
			hdrWith(f, h, n, nl, [][2]uint64{{unmapped, 4}}, 1)
		}},
		{"with an iovec whose base is NULL", func(f *fakeKernel, h, n uint64, nl uint32) {
			f.put(bufAddr, []byte("dgrm"))
			hdrWith(f, h, n, nl, [][2]uint64{{bufAddr, 4}, {0, 4}}, 2)
		}},
		// A buffer that runs past the end of its mapping reads short without failing, so only gather's
		// length check keeps the relay from sending the first two bytes as the whole datagram.
		{"whose buffer is cut short", func(f *fakeKernel, h, n uint64, nl uint32) {
			f.put(bufAddr, []byte("dg"))
			hdrWith(f, h, n, nl, [][2]uint64{{bufAddr, 4}}, 1)
		}},
		{"whose sendBytes is reached with an iovec left", func(f *fakeKernel, h, n uint64, nl uint32) {
			f.put(bufAddr, make([]byte, sendBytes+4))
			hdrWith(f, h, n, nl, [][2]uint64{{bufAddr, sendBytes}, {bufAddr + sendBytes, 4}}, 2)
		}},
	}
}

// TestModelEndpointByName is the guard for a models[] host given by name: its addresses are resolved when the
// loop is built and refused. Another address on its port is refused too, rule models.port, under a net: section
// unless a net.allow entry names it (ADR 0040 (2)); with no net: section, as guardPolicy has, the port is not
// reserved and that connect is allowed unmatched (SEMANTICS §1, amended 2026-10-05), though the
// guard's own match still names the reservation. A name that has not resolved refuses every address on its
// port, rule unresolved, because any of them could be it — never admits them.
func TestModelEndpointByName(t *testing.T) {
	const addr = 0x40000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "API.anthropic.com", Port: 443}
	connect := func(t *testing.T, lookup *stubLookup, ip string, port uint16) *record.Event {
		t.Helper()
		f := newFake()
		sa := sockaddrIn4(ip, port)
		f.put(addr, sa)
		l, sink := guardLoop(t, f, guardPolicy(backend.TierLandlock, nil, model), lookup)
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		return sink.one(t)
	}
	resolved := &stubLookup{addrs: []netip.Addr{netip.MustParseAddr("160.79.104.10")}}
	if ev := connect(t, resolved, "160.79.104.10", 443); ev.Verdict != record.VerdictRefused || ev.Rule != "models[api.anthropic.com:443]" ||
		netLine(t, ev).Host != "api.anthropic.com" {
		t.Errorf("a resolved model address = %s/%s host %q, want refused/models[api.anthropic.com:443]", ev.Verdict, ev.Rule, netLine(t, ev).Host)
	}
	if len(resolved.asked) == 0 || resolved.asked[0] != "api.anthropic.com" {
		t.Errorf("lookups = %q, want the model host resolved when the loop was built", resolved.asked)
	}
	// guardPolicy has no net: section, which reserves no port (SEMANTICS §1, amended 2026-10-05): from
	// 2026-10-01 to then this connect, any HTTPS host's, was refused models.port[api.anthropic.com:443].
	if ev := connect(t, resolved, "203.0.113.9", 443); ev.Verdict != record.VerdictAllow || ev.Rule != ruleUnmatched {
		t.Errorf("another address on the model's port = %s/%s, want allow/unmatched", ev.Verdict, ev.Rule)
	}
	failing := &stubLookup{err: errors.New("no route to the resolver")}
	if ev := connect(t, failing, "203.0.113.9", 443); ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnresolved {
		t.Errorf("an address on an unresolved model's port = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleUnresolved)
	}
	if ev := connect(t, failing, "203.0.113.9", 80); ev.Verdict != record.VerdictAllow {
		t.Errorf("another port while the model host is unresolved = %s, want allow", ev.Verdict)
	}

	// A later refresh publishes the model addresses; other addresses still require explicit allowance.
	g := newModelGuard([]agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}}, dns.Options{Lookup: failing})
	if _, ok := g.match(netip.MustParseAddrPort("203.0.113.9:443")); !ok {
		t.Fatal("an unresolved guard admitted an address on its port")
	}
	failing.mu.Lock()
	failing.err, failing.addrs = nil, []netip.Addr{netip.MustParseAddr("160.79.104.10")}
	failing.mu.Unlock()
	g.refresh(context.Background())
	if dec, ok := g.match(netip.MustParseAddrPort("203.0.113.9:443")); !ok || dec.rule != "models.port[api.anthropic.com:443]" {
		t.Error("after the name resolved, its port admitted an undeclared address")
	}
	if dec, ok := g.match(netip.MustParseAddrPort("160.79.104.10:443")); !ok || dec.rule != "models[api.anthropic.com:443]" {
		t.Errorf("after the name resolved, its address = %+v %v, want refused", dec, ok)
	}
}

// TestModelGuardInAnObserveRun: an observe run enforces nothing (R30), the guard included, but its line says
// what the contract would have done.
func TestModelGuardInAnObserveRun(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	sa := sockaddrIn4("127.0.0.1", 8443)
	f.put(addr, sa)
	pol := guardPolicy(backend.TierLandlock, nil, agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443})
	pol.Observe = true
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE in an observe run", got)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictObserved || ev.Rule != "models[127.0.0.1:8443]" {
		t.Errorf("event = %s/%s, want observed/models[127.0.0.1:8443]", ev.Verdict, ev.Rule)
	}
}

// TestModelGuardKeepsEveryAddressANameResolvedTo: a successful lookup adds to what a guarded name matches
// rather than replacing it. dns.Set.Refresh replaces, so a deny list built on it forgot an address the name
// stopped returning while the agent could still hold it in its resolver cache or connection pool.
func TestModelGuardKeepsEveryAddressANameResolvedTo(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	lookup := &stubLookup{addrs: []netip.Addr{netip.MustParseAddr("160.79.104.10")}}
	g := newModelGuard([]agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}},
		dns.Options{Lookup: lookup, Now: clock})
	lookup.mu.Lock()
	lookup.addrs = []netip.Addr{netip.MustParseAddr("160.79.104.11"), netip.MustParseAddr("::ffff:160.79.104.12")}
	lookup.mu.Unlock()
	mu.Lock()
	now = now.Add(dns.DefaultMinTTL + time.Second)
	mu.Unlock()
	g.refresh(context.Background())
	if n := len(lookup.asked); n != 2 {
		t.Fatalf("%d lookups, want the name looked up again once its TTL passed", n)
	}
	for _, a := range []string{"160.79.104.10", "160.79.104.11", "160.79.104.12"} {
		if dec, ok := g.match(netip.MustParseAddrPort(a + ":443")); !ok || dec.rule != "models[api.anthropic.com:443]" {
			t.Errorf("%s = %+v %v, want refused: the name resolved to it during the run", a, dec, ok)
		}
	}
	if _, ok := g.matchAllowed(netip.MustParseAddrPort("203.0.113.9:443"), true); ok {
		t.Error("an explicitly allowed unrelated address was refused")
	}

	// The latest answer comes first and is never dropped; the oldest go once the bound is reached.
	had := make([]netip.Addr, maxGuardAddrs)
	for i := range had {
		had[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
	}
	latest := []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1"), had[5]}
	got := union(latest, had)
	if len(got) != maxGuardAddrs || got[0] != netip.MustParseAddr("192.0.2.1") || got[1] != had[5] ||
		got[2] != had[0] || got[len(got)-1] != had[maxGuardAddrs-2] {
		t.Errorf("union = %d addresses starting %v, want %d: the latest answer, then the newest of the rest", len(got), got[:3], maxGuardAddrs)
	}
}

// TestModelGuardByLocalhostName: a localhost name is loopback by RFC 6761 §6.3 whatever a lookup says, so
// it guards every loopback and unspecified address on its port from the start, even when its lookup fails,
// and never refuses another host's address on that port as unresolved. agent.Evaluate reads it the same way.
func TestModelGuardByLocalhostName(t *testing.T) {
	failing := &stubLookup{err: errors.New("no route to the resolver")}
	g := newModelGuard([]agent.ModelEndpoint{{Provider: "local", Host: "localhost", Port: 8000}}, dns.Options{Lookup: failing})
	for _, a := range []string{"127.0.0.1:8000", "0.0.0.0:8000", "[::1]:8000", "[::]:8000", "127.9.9.9:8000"} {
		if dec, ok := g.match(netip.MustParseAddrPort(a)); !ok || dec.rule != "models[localhost:8000]" {
			t.Errorf("%s = %+v %v, want refused models[localhost:8000]", a, dec, ok)
		}
	}
	if dec, ok := g.match(netip.MustParseAddrPort("203.0.113.9:8000")); ok {
		t.Errorf("another host on the port = %+v, want admitted: a localhost name is never unresolved", dec)
	}
}

// TestModelGuardResolvesOnTheRunRefresher: a name whose lookup failed when the loop was built refuses its
// whole port only until Run's refresher resolves it; then its addresses are refused and every other address
// on the port is admitted. Without the refresher the port stayed refused for the whole run.
func TestModelGuardResolvesOnTheRunRefresher(t *testing.T) {
	lookup := &stubLookup{err: errors.New("no route to the resolver")}
	pol := guardPolicy(backend.TierLandlock, nil, agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443})
	l, err := New(testListener(), pol, &testSink{}, Options{kernel: newFake(), Workers: 1, lookup: lookup, modelRefresh: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	other := netip.MustParseAddrPort("203.0.113.9:443")
	if dec, ok := l.table.Load().guard.match(other); !ok || dec.rule != ruleUnresolved {
		t.Fatalf("before the name resolved, %s = %+v %v; want refused %s", other, dec, ok, ruleUnresolved)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	lookup.mu.Lock()
	lookup.err, lookup.addrs = nil, []netip.Addr{netip.MustParseAddr("160.79.104.10")}
	lookup.mu.Unlock()
	waitFor(t, func() bool {
		_, ok := l.table.Load().guard.matchAllowed(other, true)
		return !ok
	})
	if dec, ok := l.table.Load().guard.match(netip.MustParseAddrPort("160.79.104.10:443")); !ok || dec.rule != "models[api.anthropic.com:443]" {
		t.Errorf("after the refresher resolved the name, its address = %+v %v, want refused", dec, ok)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}
