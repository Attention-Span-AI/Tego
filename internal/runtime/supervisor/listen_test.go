// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

type listenerFake struct {
	*bindFake
	name      []byte
	cookie    uint64
	listens   int
	listenErr error
}

func (f *listenerFake) SocketNameRaw(int) ([]byte, error) { return bytes.Clone(f.name), nil }
func (f *listenerFake) SocketCookie(int) (uint64, error)  { return f.cookie, nil }
func (f *listenerFake) ListenRaw(int, int) error          { f.listens++; return f.listenErr }

func TestListenUsesSuccessfulEphemeralBindProof(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bindErr error
		mutate  string
		want    bool
	}{
		{"successful ephemeral bind", nil, "", true},
		{"failed bind", unix.EADDRINUSE, "", false},
		{"reused descriptor different socket", nil, "cookie", false},
		{"different bound address", nil, "address", false},
		{"different protocol", nil, "protocol", false},
		{"withdrawn declaration", nil, "policy", false},
		{"failed rebind preserves successful proof", nil, "failedrebind", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			raw := sockaddrIn4("127.0.0.1", 0)
			f.put(0x40000, raw)
			policy := testPolicy(nil, nil, nil)
			policy.Rules.Listen = []agent.ListenRule{{Raw: "tcp://127.0.0.1:0", Proto: agent.ProtoTCP, Address: netip.MustParseAddr("127.0.0.1")}}
			l, _ := newTestLoop(t, f, policy)
			k := &listenerFake{bindFake: &bindFake{fakeKernel: f, err: tc.bindErr}, name: sockaddrIn4("127.0.0.1", 34567), cookie: 77}
			l.k = k
			handleBind(l, notifFor(connectNR(), 4242, 5, 0x40000, uint64(len(raw))))
			switch tc.mutate {
			case "failedrebind":
				k.err = unix.EADDRINUSE
				handleBind(l, notifFor(connectNR(), 4242, 5, 0x40000, uint64(len(raw))))
			case "cookie":
				k.cookie++
			case "address":
				k.name = sockaddrIn4("127.0.0.2", 34567)
			case "protocol":
				f.sockType = unix.SOCK_DGRAM
			case "policy":
				l.table.Load().pol.Rules.Listen = []agent.ListenRule{}
			}
			handleListen(l, notifFor(connectNR(), 4242, 5, 8))
			resp, ok := f.lastResp()
			if !ok || resp.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("listen did not relay: %+v", resp)
			}
			if (k.listens == 1) != tc.want || (resp.Error == 0) != tc.want {
				t.Fatalf("listen calls=%d response=%+v", k.listens, resp)
			}
			if f.fdBalance() != 0 {
				t.Fatalf("duplicate leaked: %d", f.fdBalance())
			}
		})
	}
}

// TestListenUnderANetSectionWithNoListenerPolicy is enforce-landlock R6: such a contract grants no TCP listener, and
// BIND_TCP stops only an explicit bind, so a listen is refused here and recorded. The socket's port is no reason to
// let one through: "a connect's port" is a sibling's connect in flight, whose failure takes the port back between
// getsockname and ListenRaw, and the listen then autobinds. A unix listener and a UDP socket's kernel answer stay, with
// no line, as when the kernel took them.
func TestListenUnderANetSectionWithNoListenerPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     int
		addr    []byte
		listens int
	}{
		{"IPv4 autobind", unix.SOCK_STREAM, sockaddrIn4("0.0.0.0", 0), 0},
		{"IPv6 autobind", unix.SOCK_STREAM, sockaddrIn6("::", 0), 0},
		{"a connect's port", unix.SOCK_STREAM, sockaddrIn4("127.0.0.1", 41234), 0},
		{"UDP keeps the kernel's answer", unix.SOCK_DGRAM, sockaddrIn4("0.0.0.0", 0), 1},
		{"unix pathname listener", unix.SOCK_STREAM, sockaddrUn("/work/app.sock"), 1},
		{"unix abstract listener", unix.SOCK_STREAM, sockaddrUn("@app"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.typ
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			k := &listenerFake{bindFake: &bindFake{fakeKernel: f}, name: tc.addr, cookie: 55}
			l.k = k
			handleListen(l, notifFor(connectNR(), 4242, 5, 8))
			resp, ok := f.lastResp()
			if !ok || resp.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("listen was not answered on the duplicate: %+v", resp)
			}
			if k.listens != tc.listens {
				t.Fatalf("listen calls = %d, want %d", k.listens, tc.listens)
			}
			if tc.listens == 0 {
				ev := sink.one(t)
				if resp.Error != -int32(refusalErrno) || ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched {
					t.Fatalf("response %+v, line %s %s, want a recorded refusal", resp, ev.Verdict, ev.Rule)
				}
			} else if resp.Error != 0 || len(sink.all()) != 0 {
				t.Fatalf("response %+v, lines %d, want the listen made with no line: no rule decided it", resp, len(sink.all()))
			}
			if f.fdBalance() != 0 {
				t.Fatalf("duplicate leaked: %d", f.fdBalance())
			}
		})
	}
}

func TestListenUnboundNeedsEphemeralWildcardAndReturnsRealError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		port  uint16
		empty bool
		want  bool
	}{
		{"explicit ephemeral", 0, false, true},
		{"fixed port is not autobind", 8080, false, false},
		{"empty denies autobind", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			p := testPolicy(nil, nil, nil)
			p.Rules.Listen = []agent.ListenRule{}
			if !tc.empty {
				p.Rules.Listen = []agent.ListenRule{{Raw: "listener", Proto: agent.ProtoTCP, Address: netip.IPv4Unspecified(), Port: tc.port}}
			}
			l, _ := newTestLoop(t, f, p)
			k := &listenerFake{bindFake: &bindFake{fakeKernel: f}, name: sockaddrIn4("0.0.0.0", 0), cookie: 55, listenErr: unix.EADDRINUSE}
			l.k = k
			handleListen(l, notifFor(connectNR(), 4242, 5, 8))
			resp, _ := f.lastResp()
			if (k.listens == 1) != tc.want {
				t.Fatalf("implicit admission: %d", k.listens)
			}
			if tc.want && resp.Error != -int32(unix.EADDRINUSE) {
				t.Fatalf("real errno lost: %+v", resp)
			}
		})
	}
}

func TestListenerBindingCacheBoundAndCleanup(t *testing.T) {
	var b listenerBindings
	ap := netip.MustParseAddrPort("127.0.0.1:12345")
	for i := uint64(1); i <= maxListenerBindings; i++ {
		b.remember(i, ap, agent.ProtoTCP, "rule")
	}
	b.remember(2, ap, agent.ProtoTCP, "rule") // a proof remembered again keeps its place
	b.remember(maxListenerBindings+1, ap, agent.ProtoTCP, "newest")
	b.remember(maxListenerBindings+2, ap, agent.ProtoTCP, "newest")
	if len(b.byCookie) != maxListenerBindings || len(b.order) != maxListenerBindings {
		t.Fatalf("cache holds %d proofs in %d slots, want the cap %d", len(b.byCookie), len(b.order), maxListenerBindings)
	}
	for _, cookie := range []uint64{1, 2} {
		if _, ok := b.match(cookie, ap, agent.ProtoTCP); ok {
			t.Fatalf("a full cache kept its oldest proof %d", cookie)
		}
	}
	for _, cookie := range []uint64{3, maxListenerBindings, maxListenerBindings + 1, maxListenerBindings + 2} {
		if _, ok := b.match(cookie, ap, agent.ProtoTCP); !ok {
			t.Fatalf("a full cache lost proof %d, not its oldest", cookie)
		}
	}
	b.clear()
	if _, ok := b.match(3, ap, agent.ProtoTCP); ok {
		t.Fatal("ended loop retained authority")
	}
}

// TestListenAfterTheProofCacheFilledWithClosedSockets pins that the port-zero proof cache is bounded by
// the sockets still bound, not by every bind the run made (races-1): a cookie is never reused, so a proof
// whose socket closed is never matched again, and a full cache that dropped the newest proof refused every
// later bind(port 0)+listen() the contract grants, for the rest of the run. The oldest proof makes room
// now; a second listen on the same socket (a backlog update the kernel allows) is still admitted.
func TestListenAfterTheProofCacheFilledWithClosedSockets(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	raw := sockaddrIn4("127.0.0.1", 0)
	f.put(0x40000, raw)
	policy := testPolicy(nil, nil, nil)
	policy.Rules.Listen = []agent.ListenRule{{Raw: "tcp://127.0.0.1:0", Proto: agent.ProtoTCP, Address: netip.MustParseAddr("127.0.0.1")}}
	l, _ := newTestLoop(t, f, policy)
	actual := netip.MustParseAddrPort("127.0.0.1:34567")
	rule := policy.Rules.Listen[0].RuleName()
	for cookie := uint64(1); cookie <= maxListenerBindings; cookie++ { // earlier sockets, all since closed
		l.listenerBindings.remember(cookie, actual, agent.ProtoTCP, rule)
	}
	k := &listenerFake{bindFake: &bindFake{fakeKernel: f}, name: sockaddrIn4("127.0.0.1", 34567), cookie: maxListenerBindings + 1}
	l.k = k
	handleBind(l, notifFor(connectNR(), 4242, 5, 0x40000, uint64(len(raw))))
	for i := 1; i <= 2; i++ {
		handleListen(l, notifFor(connectNR(), 4242, 5, 8))
		resp, _ := f.lastResp()
		if k.listens != i || resp.Error != 0 {
			t.Fatalf("listen %d after %d earlier port-0 binds: calls=%d response=%+v, want relayed", i, maxListenerBindings, k.listens, resp)
		}
	}
}
