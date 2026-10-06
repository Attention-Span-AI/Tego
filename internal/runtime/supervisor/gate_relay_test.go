// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gateRelayCall is one addressed syscall of the relay tests: a connect, a Fast-Open sendto on a stream socket,
// or a sendto on a datagram socket, naming the sockaddr at 0x40000.
type gateRelayCall struct {
	name     string
	sockType int
	n        func(l *Loop, sa []byte)
}

var gateRelayCalls = []gateRelayCall{
	{"connect", unix.SOCK_STREAM, func(l *Loop, sa []byte) {
		l.handle(notifFor(connectNR(), 42, 5, 0x40000, uint64(len(sa))))
	}},
	{"fastopen", unix.SOCK_STREAM, func(l *Loop, sa []byte) {
		l.handle(notifFor(sendToNR(), 42, 5, 0x50000, 1, unix.MSG_FASTOPEN, 0x40000, uint64(len(sa))))
	}},
	{"sendto", unix.SOCK_DGRAM, func(l *Loop, sa []byte) {
		l.handle(notifFor(sendToNR(), 42, 5, 0x50000, 1, 0, 0x40000, uint64(len(sa))))
	}},
}

// gateRelayLoop is a loop over a contract with no net: section, host_sockets: true (so the gate's relay alone is
// asked: the unix-only state relays every connect, ADR 0070) and a `net to` gate refusing 203.0.113.5:443, with the
// call's socket and the copied address sa in the fake's memory.
func gateRelayLoop(t *testing.T, call gateRelayCall, sa []byte) (*fakeKernel, *Loop, *testSink) {
	t.Helper()
	f := newFake()
	f.sockType = call.sockType
	f.put(0x40000, sa)
	f.put(0x50000, []byte("x"))
	pol := contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
	pol.Rules.Gate = testGate(t, gate.NetTo, "203.0.113.5:443", 90)
	l, sink := newTestLoop(t, f, pol)
	return f, l, sink
}

// relayedWith reports whether the call was performed on the duplicate with exactly the copied address sa.
func relayedWith(f *fakeKernel, call gateRelayCall, sa []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.unixConnects) != 0 {
		return false
	}
	if call.name == "connect" {
		return len(f.connects) == 1 && bytes.Equal(f.connects[0], sa) && len(f.sends) == 0
	}
	return len(f.sends) == 1 && bytes.Equal(f.sends[0].addr, sa) && len(f.connects) == 0
}

// TestGateRelayKeysOnSocketDomain is ADR 0041 D6 (findings failopen-1, supervisor-2's net half): under a `net`
// gate, a connect, Fast-Open send or addressed datagram on an IP-domain socket is performed on the duplicate
// with the copy the gate scored, whatever family that copy spells, so the kernel never reads the address
// again. Before, a contract with no net: section answered a gate-allowed connect or Fast-Open send CONTINUE,
// and a sibling that rewrote the address afterwards (to the gated host, or from a unix-spelled copy, which
// `net to host:port` scores 0, to AF_INET) reached the gated destination. A unix-spelled copy on an IP socket
// gets the kernel's own answer from the relayed call (EAFNOSUPPORT). The socket's domain is SO_DOMAIN of the
// duplicate, never the copied family word; one that cannot be read is IP, the side that decides. A unix-domain
// socket cannot reach an IP destination, and keeps D1's best-effort CONTINUE with no net: section.
func TestGateRelayKeysOnSocketDomain(t *testing.T) {
	benign := sockaddrIn4("198.51.100.1", 443)
	unixSpelled := sockaddrUn("gated.sock")
	for _, call := range gateRelayCalls {
		for _, tc := range []struct {
			name    string
			domain  int
			domErr  error
			sa      []byte
			relayed bool
		}{
			{"inet socket, benign copy", unix.AF_INET, nil, benign, true},
			{"inet socket, unix-spelled copy", unix.AF_INET, nil, unixSpelled, true},
			{"inet6 socket, unix-spelled copy", unix.AF_INET6, nil, unixSpelled, true},
			{"unreadable domain, unix-spelled copy", unix.AF_INET, unix.EBADF, unixSpelled, true},
			{"unix socket, unix copy", unix.AF_UNIX, nil, unixSpelled, false},
		} {
			t.Run(call.name+"/"+tc.name, func(t *testing.T) {
				f, l, _ := gateRelayLoop(t, call, tc.sa)
				f.sockDomain, f.sockDomainErr = tc.domain, tc.domErr
				call.n(l, tc.sa)
				r, ok := f.lastResp()
				if !ok {
					t.Fatal("unanswered")
				}
				if !tc.relayed {
					if r.Flags == 0 {
						t.Fatalf("response %+v; a unix socket's gate-allowed send stays continued (D1)", r)
					}
					return
				}
				if r.Flags != 0 || !relayedWith(f, call, tc.sa) {
					t.Fatalf("response %+v connects %q sends %+v unix %q; want the copy performed on the duplicate, no CONTINUE",
						r, f.connects, f.sends, f.unixConnects)
				}
			})
		}
	}
}

// TestGateRelayRefusesSourceRoute is ADR 0041 D6's source-route refusal: a relayed IP socket under a `net` gate
// that carries a source route (IP_OPTIONS LSRR/SSRR, IPV6_RTHDR) sends its first hop to an address the gate
// never scored, so it is refused, rule relay-source-routed, and so is one whose options cannot be read. A
// socket without one is relayed (TestGateRelayKeysOnSocketDomain).
func TestGateRelayRefusesSourceRoute(t *testing.T) {
	benign := sockaddrIn4("198.51.100.1", 443)
	for _, call := range gateRelayCalls {
		for _, tc := range []struct {
			name   string
			routed bool
			err    error
		}{
			{"routed", true, nil},
			{"unreadable", false, errors.New("getsockopt: EBADF")},
		} {
			t.Run(call.name+"/"+tc.name, func(t *testing.T) {
				f, l, sink := gateRelayLoop(t, call, benign)
				f.sourceRouted, f.sourceRoutedErr = tc.routed, tc.err
				call.n(l, benign)
				r, _ := f.lastResp()
				if r.Flags != 0 || r.Error != -int32(refusalErrno) || len(f.connects) != 0 || len(f.sends) != 0 {
					t.Fatalf("response %+v connects %d sends %d; want the refusal and nothing performed", r, len(f.connects), len(f.sends))
				}
				ev := sink.one(t)
				if ev.Verdict != record.VerdictRefused || ev.Rule != ruleSourceRouted {
					t.Fatalf("line %+v; want refused %s", ev, ruleSourceRouted)
				}
			})
		}
	}
}
