// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const netAskAddr = 0x40000

var netAskDst = netip.MustParseAddrPort("93.184.216.34:443")

// netAskScope is one net.ask scope, raw as declared, for host, resolved to netAskDst's address, of proto.
func netAskScope(raw, host, proto string) agent.NetRule {
	r := netRule(raw, host, int(netAskDst.Port()), netAskDst.Addr().String())
	r.Proto, r.Verdict = proto, agent.VerdictAsk
	return r
}

// netAskLive is a loop under one net.ask scope whose live blocks are cur's: a TCP socket connecting to netAskDst, or
// with udp a UDP socket sending a datagram there.
func netAskLive(t *testing.T, scope agent.NetRule, udp bool, cur *atomic.Pointer[liveblock.Set]) (*Loop, *fakeKernel, *testSink) {
	t.Helper()
	f := newFake()
	f.put(netAskAddr, sockaddrIn4(netAskDst.Addr().String(), netAskDst.Port()))
	f.sockType, f.sockProto, f.sockDomain = unix.SOCK_STREAM, unix.IPPROTO_TCP, unix.AF_INET
	if udp {
		f.put(dgramPayload, []byte("ping"))
		f.sockType, f.sockProto = unix.SOCK_DGRAM, unix.IPPROTO_UDP
	}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Record = agent.RecordFull
	pol.Rules.Contract = &agent.Contract{Net: &agent.NetSection{}}
	pol.Rules.NetAsk = []agent.NetRule{scope}
	pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
	l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: cur.Load})
	l.askResolver = staticResolver{set: dns.NewSet(pol.Rules.NetAsk, nil, dns.Options{})}
	return l, f, sink
}

// netAskNotif is the held notification: the connect, or the datagram's sendto.
func netAskNotif(udp bool) *notif {
	if udp {
		return notifFor(sendToNR(), 42, 5, dgramPayload, 4, 0, netAskAddr, uint64(unix.SizeofSockaddrInet4))
	}
	return notifFor(connectNR(), 42, 5, netAskAddr, uint64(unix.SizeofSockaddrInet4))
}

// netLiveRefusal judges the answer and the one line of a held connect or datagram a live block refused after it was
// asked about: EACCES, nothing connected or sent, one net line refused net-not-allowed under the block's rule (never
// the ask's, never a person's).
func netLiveRefusal(t *testing.T, f *fakeKernel, sink *testSink, rule string) {
	t.Helper()
	res, _ := f.lastResp()
	if res.Error != -int32(unix.EACCES) || res.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
		t.Fatalf("answer %+v: want EACCES", res)
	}
	if len(f.connects) != 0 || len(f.sends) != 0 {
		t.Fatalf("connects %d sends %d: want nothing reached under the block", len(f.connects), len(f.sends))
	}
	lines := sink.all()
	if len(lines) != 1 || lines[0].Kind != record.KindNet || lines[0].Verdict != record.VerdictRefused ||
		lines[0].Reason != record.ReasonNetNotAllowed || lines[0].Rule != rule || lines[0].Authority == record.AuthorityHuman {
		t.Fatalf("lines %+v: want one net line refused net-not-allowed by %s", lines, rule)
	}
}

// gateAskLive is a loop where a declared entry admits netAskDst under the host api.example.com and a net gate scores
// the connect inside its ask range, so the gate raises an ask on an admitted destination (performAskConnect, scoped
// false): the host the block is matched by comes from the entry's admission (t.dec.host), not from a net.ask scope.
func gateAskLive(t *testing.T, cur *atomic.Pointer[liveblock.Set]) (*Loop, *fakeKernel, *testSink) {
	t.Helper()
	f := newFake()
	f.put(netAskAddr, sockaddrIn4(netAskDst.Addr().String(), netAskDst.Port()))
	f.sockType, f.sockProto, f.sockDomain = unix.SOCK_STREAM, unix.IPPROTO_TCP, unix.AF_INET
	pol := testPolicy([]agent.NetRule{netRule("api.example.com:443", "api.example.com", 443, netAskDst.Addr().String())}, nil, nil)
	pol.Rules.Record = agent.RecordFull
	pol.Rules.Gate = testGate(t, gate.NetTo, netAskDst.String(), 70)
	pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
	l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: cur.Load})
	return l, f, sink
}

// TestApprovedNetAskAfterALiveBlockIsRefused is the net half: a connect (or an addressed UDP datagram)
// held for a net.ask scope, and approved after a live block naming its destination landed while the person decided,
// is refused when the answer comes back, under the block's rule, and nothing is connected or sent. Before, the
// approval was relayed: the agent reached the host the dashboard had just blocked. A block names the destination by
// its address (with or without the port) or by the scope's declared host; a block of another port leaves the
// approval standing. The same holds for a connect a net gate raised an ask on, whose host is the declared entry's,
// and for a UDP socket's connect held for a udp:// scope.
func TestApprovedNetAskAfterALiveBlockIsRefused(t *testing.T) {
	byAddr := netAskScope("tcp://93.184.216.34:443", "93.184.216.34", agent.ProtoTCP)
	byHost := netAskScope("tcp://api.example.com:443", "api.example.com", agent.ProtoTCP)
	udpByHost := netAskScope("udp://api.example.com:443", "api.example.com", agent.ProtoUDP)
	for _, tc := range []struct {
		name       string
		scope      agent.NetRule
		udp        bool
		block      string
		refuses    bool
		gate       bool // a gate ask on an admitted host (gateAskLive), not a net.ask scope
		udpConnect bool // the UDP socket connects rather than sending a datagram
	}{
		{"an address and port block", byAddr, false, "93.184.216.34:443", true, false, false},
		{"an address block", byAddr, false, "93.184.216.34", true, false, false},
		{"a host block of a scope declared by host", byHost, false, "api.example.com", true, false, false},
		{"an address block of a scope declared by host", byHost, false, "93.184.216.34:443", true, false, false},
		{"a block of another port", byHost, false, "93.184.216.34:80", false, false, false},
		{"a host block of a UDP scope, for the datagram", udpByHost, true, "api.example.com", true, false, false},
		{"an address block of a UDP scope, for the datagram", udpByHost, true, "93.184.216.34", true, false, false},
		{"a host block of a gate ask on an admitted host", agent.NetRule{}, false, "api.example.com", true, true, false},
		{"a host block of a UDP scope, for the socket's connect", udpByHost, true, "api.example.com", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cur atomic.Pointer[liveblock.Set]
			var (
				l    *Loop
				f    *fakeKernel
				sink *testSink
			)
			if tc.gate {
				l, f, sink = gateAskLive(t, &cur)
			} else {
				l, f, sink = netAskLive(t, tc.scope, tc.udp, &cur)
			}
			n := netAskNotif(tc.udp && !tc.udpConnect)
			asked := 0
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
				asked++
				cur.Store(liveSet(t, "net", tc.block)) // lands while the person decides
				return ask.Decision{Approved: true, By: "uid:1 pid:2"}, nil
			}
			l.handle(n)
			if asked != 1 {
				t.Fatalf("asked %d times, want once", asked)
			}
			if !tc.refuses {
				res, _ := f.lastResp()
				if res.Error != 0 || len(f.connects) != 1 {
					t.Fatalf("answer %+v connects %d: a block of another port leaves the approval standing", res, len(f.connects))
				}
				return
			}
			netLiveRefusal(t, f, sink, liveblock.Rule(liveblock.KindNet, tc.block))
		})
	}
}

// TestPendingNetAskWithdrawnWhenALiveBlockLands: a live block naming the destination of a connect that waits for its
// person takes the request back at the hold's next tick, so the dashboard's card and `tego ask` drop it (its answer
// line says ask-unavailable by cancelled, which the dashboard reads "Withdrawn: a live block now refuses this"), and
// the connect is refused under the block. Before, the card stayed answerable until the timeout. Through the real
// broker, by the destination's address and by the scope's host; and a unix connect held for a net.ask unix: scope,
// whose approval the relay's walk already matched again (liveUnixLanded), is withdrawn too.
func TestPendingNetAskWithdrawnWhenALiveBlockLands(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope agent.NetRule
		udp   bool
		block string
	}{
		{"an address block", netAskScope("tcp://93.184.216.34:443", "93.184.216.34", agent.ProtoTCP), false, "93.184.216.34"},
		{"a host block", netAskScope("tcp://api.example.com:443", "api.example.com", agent.ProtoTCP), false, "api.example.com"},
		{"a host block, for a datagram", netAskScope("udp://api.example.com:443", "api.example.com", agent.ProtoUDP), true, "api.example.com"},
	} {
		t.Run(tc.name+", the real broker", func(t *testing.T) {
			var cur atomic.Pointer[liveblock.Set]
			l, f, sink := netAskLive(t, tc.scope, tc.udp, &cur)
			var mu sync.Mutex
			var lines []ask.Event
			runDir := t.TempDir()
			broker, err := ask.New(runDir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Minute,
				Authorize: func(ask.Peer) error { return nil },
				Emit: func(e ask.Event) error {
					mu.Lock()
					defer mu.Unlock()
					lines = append(lines, e)
					return nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			defer broker.Close()
			l.ask = broker.Request
			done := make(chan struct{})
			go func() { l.handle(netAskNotif(tc.udp)); close(done) }()
			var items []ask.Summary
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && len(items) == 0; time.Sleep(5 * time.Millisecond) {
				if items, err = ask.ListFor(context.Background(), runDir, os.Getpid()); err != nil {
					t.Fatal(err)
				}
			}
			if len(items) != 1 {
				t.Fatalf("pending %+v: want the held request", items)
			}
			cur.Store(liveSet(t, "net", tc.block))
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the held request was still asked about 5 s after a block of its destination landed")
			}
			if items, err = ask.ListFor(context.Background(), runDir, os.Getpid()); err != nil || len(items) != 0 {
				t.Fatalf("pending after the block: %+v %v, want none", items, err)
			}
			mu.Lock()
			got := append([]ask.Event(nil), lines...)
			mu.Unlock()
			if len(got) != 2 || got[1].Kind != "answer" || got[1].Decision.Approved || got[1].Decision.Reason != ask.ReasonUnavailable ||
				got[1].Decision.By != "cancelled" {
				t.Fatalf("broker lines %+v: want the ask and its answer ask-unavailable by cancelled", got)
			}
			netLiveRefusal(t, f, sink, liveblock.Rule(liveblock.KindNet, tc.block))
		})
	}
	t.Run("a unix connect held for a net.ask unix: scope", func(t *testing.T) {
		for _, path := range []string{"/run/app.sock", "@bus"} {
			t.Run(path, func(t *testing.T) {
				f := newFake()
				sa := sockaddrUn(path)
				f.put(netAskAddr, sa)
				f.sockType, f.sockDomain = unix.SOCK_STREAM, unix.AF_UNIX
				askPath := unixRuleOf("unix:/run/app.sock", "/run/app.sock", false)
				askAbs := unixRuleOf("unix:@bus", "bus", true)
				askPath.Verdict, askAbs.Verdict = agent.VerdictAsk, agent.VerdictAsk
				pol := testPolicy(nil, nil, nil)
				pol.Rules.NetAsk = []agent.NetRule{askPath, askAbs}
				pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
				var cur atomic.Pointer[liveblock.Set]
				l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: cur.Load})
				withdrawn := false
				l.ask = func(ctx context.Context, req ask.Request) (ask.Decision, error) {
					cur.Store(liveSet(t, "net", path))
					select {
					case <-ctx.Done(): // the broker's own answer to a request its owner took back
						withdrawn = true
						return ask.Decision{AskID: req.AskID, Reason: ask.ReasonUnavailable, By: "cancelled"}, nil
					case <-time.After(5 * time.Second): // the person, still shown the card, answers Allow once
						return ask.Decision{Approved: true, By: "uid:1 pid:2"}, nil
					}
				}
				l.handle(notifFor(connectNR(), 4242, 5, netAskAddr, uint64(len(sa))))
				if !withdrawn {
					t.Fatal("the request was never taken back after a block of its socket landed")
				}
				res, _ := f.lastResp()
				if res.Error != -int32(unix.EACCES) || len(f.unixConnects) != 0 {
					t.Fatalf("answer %+v, reached %q: want EACCES and no connect", res, f.unixConnects)
				}
				ev := sink.one(t)
				if ev.Verdict != record.VerdictRefused || ev.Rule != liveblock.Rule(liveblock.KindNet, path) || ev.Authority == record.AuthorityHuman {
					t.Fatalf("line %+v: want refused by the block", ev)
				}
			})
		}
	})
}

// TestRememberedDatagramAfterAHostBlockIsRefused: a UDP socket's datagrams to a destination a person approved are
// refused once a live block naming the scope's declared host lands, under the block's rule, and the approval is
// dropped, so a datagram after the block is lifted is asked about again. Before, only the first datagram was put to
// the live Set: liveNet knows no host for a destination nothing admits, so a host block whose lookup did not hold
// this address (a round-robin or CDN host, QUIC's usual traffic) let the remembered approval send on.
func TestRememberedDatagramAfterAHostBlockIsRefused(t *testing.T) {
	const block = "api.example.com"
	var cur atomic.Pointer[liveblock.Set]
	l, f, sink := netAskLive(t, netAskScope("udp://api.example.com:443", block, agent.ProtoUDP), true, &cur)
	asked := 0
	l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
		asked++
		return ask.Decision{Approved: true, By: "uid:1 pid:2"}, nil
	}
	l.handle(netAskNotif(true))
	if res, _ := f.lastResp(); res.Error != 0 || asked != 1 || len(f.sends) != 1 {
		t.Fatalf("first datagram: answer %+v asked %d sends %d, want approved and sent", res, asked, len(f.sends))
	}
	cur.Store(liveSet(t, "net", block))
	before := len(sink.all())
	l.handle(netAskNotif(true))
	res, _ := f.lastResp()
	if res.Error != -int32(unix.EACCES) || asked != 1 || len(f.sends) != 1 {
		t.Fatalf("datagram after the block: answer %+v asked %d sends %d, want EACCES, nobody asked, nothing sent", res, asked, len(f.sends))
	}
	lines := sink.all()
	if len(lines) != before+1 {
		t.Fatalf("lines %+v: want one more line for the refused datagram", lines[before:])
	}
	ev := lines[before]
	if ev.Verdict != record.VerdictRefused || ev.Rule != liveblock.Rule(liveblock.KindNet, block) || ev.Authority == record.AuthorityHuman {
		t.Fatalf("line %+v: want refused by the block", ev)
	}
	cur.Store(nil)
	l.handle(netAskNotif(true))
	if asked != 2 || len(f.sends) != 2 {
		t.Fatalf("datagram after the block was lifted: asked %d sends %d, want asked again", asked, len(f.sends))
	}
}

// TestNetAskHostBlockInForceAsksNobody: a live block naming the scope's declared host that is in force when the
// connect or datagram arrives refuses it before anyone is asked, and under first_write before a relay is reserved.
// Before, liveNet (which knows no host for an unmatched destination) let it through: the broker posted a card the
// hold's first tick took back, and a first-write connect to the relay was allowed and logged, its first write refused.
func TestNetAskHostBlockInForceAsksNobody(t *testing.T) {
	const block = "api.example.com"
	for _, tc := range []struct {
		name       string
		proto      string
		udp        bool
		firstWrite bool
	}{
		{"a TCP connect", agent.ProtoTCP, false, false},
		{"a TCP connect under first_write", agent.ProtoTCP, false, true},
		{"a UDP datagram", agent.ProtoUDP, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cur atomic.Pointer[liveblock.Set]
			cur.Store(liveSet(t, "net", block))
			l, f, sink := netAskLive(t, netAskScope(tc.proto+"://api.example.com:443", block, tc.proto), tc.udp, &cur)
			reserved := 0
			if tc.firstWrite {
				l.table.Load().pol.Rules.AskConfig.Hold = agent.AskHoldFirstWrite
				l.firstWrite = func(context.Context, ask.Request, netip.AddrPort, bool, int, func() string) (netip.AddrPort, func(), error) {
					reserved++
					return netip.MustParseAddrPort("127.0.0.1:1"), func() {}, nil
				}
			}
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
				t.Error("a person was asked about a destination a block in force names")
				return ask.Decision{Approved: true}, nil
			}
			l.handle(netAskNotif(tc.udp))
			if reserved != 0 {
				t.Fatalf("a first-write relay was reserved %d times for a blocked destination", reserved)
			}
			netLiveRefusal(t, f, sink, liveblock.Rule(liveblock.KindNet, block))
		})
	}
}

// TestUnixAskApprovedBeforeTheTickAfterABlock: a unix connect held for a net.ask unix: scope whose approval comes back
// after a live block landed but before the hold's next tick (a standing answer, or Allow clicked inside the 50 ms) is
// refused under the block, and nothing is connected, when the block names an abstract name or the name the agent
// spelled (a symlink to the scope's socket). Before, only where the relay's walk landed was matched again
// (liveUnixLanded), which names neither: the agent reached @bus, and /run/app.sock through /work/alias.sock.
func TestUnixAskApprovedBeforeTheTickAfterABlock(t *testing.T) {
	for _, tc := range []struct {
		name, path, block string
		symlinks          map[string]string
	}{
		{"an abstract name", "@bus", "@bus", nil},
		{"the name the agent spelled", "/work/alias.sock", "/work/alias.sock", map[string]string{"/work/alias.sock": "/run/app.sock"}},
		{"the scope's place", "/run/app.sock", "/run/app.sock", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			sa := sockaddrUn(tc.path)
			f.put(netAskAddr, sa)
			f.sockType, f.sockDomain = unix.SOCK_STREAM, unix.AF_UNIX
			askPath := unixRuleOf("unix:/run/app.sock", "/run/app.sock", false)
			askAbs := unixRuleOf("unix:@bus", "bus", true)
			askPath.Verdict, askAbs.Verdict = agent.VerdictAsk, agent.VerdictAsk
			pol := testPolicy(nil, nil, nil)
			pol.Rules.NetAsk = []agent.NetRule{askPath, askAbs}
			pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
			var cur atomic.Pointer[liveblock.Set]
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: cur.Load})
			for k, v := range tc.symlinks {
				f.symlinks[k] = v
				f.links[k] = v
			}
			asked := 0
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
				asked++
				cur.Store(liveSet(t, "net", tc.block)) // lands, and the answer is back before the hold's next tick
				return ask.Decision{Approved: true, By: "uid:1 pid:2"}, nil
			}
			l.handle(notifFor(connectNR(), 4242, 5, netAskAddr, uint64(len(sa))))
			if asked != 1 {
				t.Fatalf("asked %d times, want once", asked)
			}
			res, _ := f.lastResp()
			if res.Error != -int32(unix.EACCES) || len(f.unixConnects) != 0 {
				t.Fatalf("answer %+v, reached %q: want EACCES and no connect", res, f.unixConnects)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Rule != liveblock.Rule(liveblock.KindNet, tc.block) || ev.Authority == record.AuthorityHuman {
				t.Fatalf("line %+v: want refused by the block", ev)
			}
		})
	}
}
