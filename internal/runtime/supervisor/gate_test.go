//go:build amd64 || arm64

// SPDX-License-Identifier: Apache-2.0
package supervisor

import (
	"context"
	"errors"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testGate(t *testing.T, p gate.Predicate, arg string, score int) *gate.Policy {
	t.Helper()
	g, e := gate.New([]gate.Rule{{Predicate: p, Argument: arg, Score: score}}, 50, 80)
	if e != nil {
		t.Fatal(e)
	}
	return g
}

// TestGateNetToSeesThroughAnIPv6ScopeID: a net gate's literal rule refuses a connect that carries sin6_scope_id, under
// a contract with no net: section, where the gate is the only refusal. parseSockaddr keeps the scope as a zone for the
// ledger, and gate.go compared `::1%1` with the rule's `::1`, so a scope id reached the very address the rule names.
func TestGateNetToSeesThroughAnIPv6ScopeID(t *testing.T) {
	for _, scope := range []uint32{0, 1, 4242} {
		raw := sockaddrIn6("::1", 39512)
		putU32(raw[sin6ScopeOff:], scope)
		f := newFake()
		f.sockType = unix.SOCK_STREAM
		f.sockProto = unix.IPPROTO_TCP
		f.put(0x40000, raw)
		pol := contractPolicy(&agent.Contract{}, nil, nil)
		pol.Rules.Gate = testGate(t, gate.NetTo, "[::1]:39512", 90)
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(connectNR(), 42, 5, 0x40000, uint64(len(raw))))
		resp, _ := f.lastResp()
		if resp.Flags != 0 || resp.Error != -int32(unix.EACCES) || len(f.connects) != 0 {
			t.Fatalf("scope %d: response %+v, connects %d, want a refusal", scope, resp, len(f.connects))
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Authority != record.AuthorityGate {
			t.Fatalf("scope %d: line %s by %s, want refused by the gate", scope, ev.Verdict, ev.Authority)
		}
	}
}

// TestGateNetToReachesEverySpellingOfThisHost: a `net to` rule on a loopback literal refuses whatever reaches this host on
// its port, under a contract with no net: section, where the gate is the only refusal. Compared as written, 127.0.0.2:P,
// ::1:P and the host's LAN address wrote `allow unmatched` and reached a server on all interfaces, the alias a live block
// on the same address refuses, and 127.0.0.1:Q went through under a rule on [::1]:Q. While the host's addresses cannot
// be read, a destination on the rule's port is refused, as under a block.
func TestGateNetToReachesEverySpellingOfThisHost(t *testing.T) {
	const addr, port = 0x40000, 39513
	prev := thisHost
	t.Cleanup(func() { thisHost = prev })
	own := hostList("192.0.2.10")
	for _, c := range []struct {
		name    string
		rule    string
		sa      []byte
		list    func() ([]net.Addr, error)
		refused bool
	}{
		{"the rule's own", "127.0.0.1:39513", sockaddrIn4("127.0.0.1", port), own, true},
		{"another loopback address", "127.0.0.1:39513", sockaddrIn4("127.0.0.2", port), own, true},
		{"IPv6 loopback", "127.0.0.1:39513", sockaddrIn6("::1", port), own, true},
		{"mapped, another loopback address", "127.0.0.1:39513", sockaddrIn6("::ffff:127.0.0.2", port), own, true},
		{"this host's LAN address", "127.0.0.1:39513", sockaddrIn4("192.0.2.10", port), own, true},
		{"a rule on v6, the v4 spelling", "[::1]:39513", sockaddrIn4("127.0.0.1", port), own, true},
		{"a rule on the LAN address, loopback", "192.0.2.10:39513", sockaddrIn4("127.0.0.1", port), own, true},
		{"a group", "127.0.0.1:39513", sockaddrIn4("224.0.0.1", port), own, true},
		{"its subnet's broadcast", "127.0.0.1:39513", sockaddrIn4("192.0.2.255", port), own, true},
		{"another host", "127.0.0.1:39513", sockaddrIn4("203.0.113.7", port), own, false},
		{"a rule on another host, loopback", "203.0.113.7:39513", sockaddrIn4("127.0.0.1", port), own, false},
		{"another port", "127.0.0.1:39514", sockaddrIn4("127.0.0.1", port), own, false},
		{"the host unknown", "127.0.0.1:39513", sockaddrIn4("203.0.113.7", port), func() ([]net.Addr, error) { return nil, errors.New("no netlink") }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			thisHost = newHostAddrs(c.list, time.Now)
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			f.sockProto = unix.IPPROTO_TCP
			f.put(addr, c.sa)
			pol := contractPolicy(&agent.Contract{}, nil, nil)
			pol.Rules.Record = agent.RecordFull
			pol.Rules.Gate = testGate(t, gate.NetTo, c.rule, 90)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(connectNR(), 42, 5, addr, uint64(len(c.sa))))
			if connected := len(f.connects) > 0; connected == c.refused {
				t.Fatalf("connected = %v, want %v", connected, !c.refused)
			}
			ev := sink.one(t)
			if refused := ev.Verdict == record.VerdictRefused && ev.Authority == record.AuthorityGate; refused != c.refused {
				t.Errorf("line %s by %s, want refused by the gate: %v", ev.Verdict, ev.Authority, c.refused)
			}
		})
	}
}

func TestGateConnectPrecedesRelayAndNoNetRecordOffShortcut(t *testing.T) {
	for _, score := range []int{40, 49, 50, 51, 70, 80, 81, 90} {
		for _, ordinary := range []bool{false, true} {
			for _, approved := range []bool{false, true} {
				f := newFake()
				f.sockType = unix.SOCK_STREAM
				f.sockProto = unix.IPPROTO_TCP
				f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
				pol := contractPolicy(&agent.Contract{}, nil, nil)
				if ordinary {
					pol = testPolicy([]agent.NetRule{netRule("93.184.216.34:443", "", 443, "93.184.216.34")}, nil, nil)
				}
				pol.Rules.Record = agent.RecordOff
				pol.Rules.Gate = testGate(t, gate.NetTo, "93.184.216.34:443", score)
				pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
				if len(pol.Rules.NetAsk) != 0 {
					t.Fatal("gate-only approval fixture unexpectedly contains an ordinary ask scope")
				}
				l, sink := newTestLoop(t, f, pol)
				asked := 0
				l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
					asked++
					f.put(0x40000, sockaddrIn4("203.0.113.99", 8443))
					return ask.Decision{Approved: approved, Reason: ask.ReasonDenied}, nil
				}
				l.handle(notifFor(connectNR(), 42, 5, 0x40000, 16))
				resp, _ := f.lastResp()
				allowed := score < 50 || score <= 80 && approved
				if !allowed {
					if resp.Flags != 0 || resp.Error != -int32(unix.EACCES) || len(f.connects) != 0 {
						t.Fatalf("score%d ordinary%t approve%t response%+v connects%d", score, ordinary, approved, resp, len(f.connects))
					}
					evs := sink.all()
					if len(evs) != 1 {
						t.Fatal(evs)
					}
					if score > 80 && evs[0].Authority != record.AuthorityGate {
						t.Fatalf("denial authority%+v", evs[0])
					}
				} else if resp.Flags != 0 || resp.Error != 0 || len(f.connects) != 1 || string(f.connects[0]) != string(sockaddrIn4("93.184.216.34", 443)) {
					// Every admitted connect is performed on the duplicate with the scored copy, the no-net:
					// contract's included: a CONTINUE let the kernel read an address a sibling had rewritten
					// to a gated one (ADR 0041 D6, finding failopen-1).
					t.Fatalf("score%d ordinary%t approve%t: admitted frozen response%+v connects%v", score, ordinary, approved, resp, f.connects)
				}
				wantAsks := 0
				if score >= 50 && score <= 80 {
					wantAsks = 1
				}
				if asked != wantAsks {
					t.Fatalf("score%d asks%d want%d", score, asked, wantAsks)
				}
			}
		}
	}
}
func TestGateUDPAndFastOpenBeforeDelivery(t *testing.T) {
	for _, transport := range []int{unix.SOCK_DGRAM, unix.SOCK_STREAM} {
		for _, score := range []int{40, 49, 50, 51, 70, 80, 81, 90} {
			for _, msg := range []bool{false, true} {
				f := newFake()
				f.sockType = transport
				f.sockProto = unix.IPPROTO_UDP
				if transport == unix.SOCK_STREAM {
					f.sockProto = unix.IPPROTO_TCP
				}
				f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
				f.put(0x50000, []byte("hello"))
				hdr := namedMsgHdr(0x40000, 16)
				putU64(hdr[msgIovOff:], 0x70000)
				putU64(hdr[msgIovLenOff:], 1)
				iov := make([]byte, iovecSize)
				putU64(iov, 0x50000)
				putU64(iov[8:], 5)
				f.put(0x70000, iov)
				f.put(0x60000, hdr)
				pol := testPolicy([]agent.NetRule{netRule("93.184.216.34:443", "", 443, "93.184.216.34")}, nil, nil)
				pol.Rules.Gate = testGate(t, gate.NetTo, "93.184.216.34:443", score)
				l, sink := newTestLoop(t, f, pol)
				flags := uint64(0)
				if transport == unix.SOCK_STREAM {
					flags = unix.MSG_FASTOPEN
				}
				if msg {
					l.handle(notifFor(sendMsgNR(), 42, 5, 0x60000, flags))
				} else {
					l.handle(notifFor(sendToNR(), 42, 5, 0x50000, 5, flags, 0x40000, 16))
				}
				r, _ := f.lastResp()
				if score >= 50 {
					if r.Error != -int32(unix.EACCES) || r.Flags != 0 || len(f.sends) != 0 {
						t.Fatalf("gate send score%d response%+v sends%d", score, r, len(f.sends))
					}
					ev := sink.one(t)
					var payload netPayload
					_ = ev.DecodePayload(&payload)
					if ev.Authority != record.AuthorityGate || payload.Score == nil || *payload.Score != score || payload.CompletionUnsupported != (score <= 80) {
						t.Fatalf("scored refusal%+v payload%+v", ev, payload)
					}
				} else if r.Flags != 0 || r.Val != 5 || len(f.sends) != 1 {
					t.Fatalf("bounded frozen send response%+v sends%d", r, len(f.sends))
				}
			}
		}
	}
}
func TestGateBatchRefusesWithoutReadingOrSendingPayload(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	f.sockProto = unix.IPPROTO_UDP
	f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
	f.put(0x50000, mmsgBatch(0x40000, 16))
	pol := testPolicy([]agent.NetRule{netRule("93.184.216.34:443", "", 443, "93.184.216.34")}, nil, nil)
	pol.Rules.Gate = testGate(t, gate.NetTo, "93.184.216.34:443", 90)
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(sendMMsgNR(), 42, 5, 0x50000, 1, 0))
	r, _ := f.lastResp()
	if r.Flags != 0 || r.Error != -int32(unix.ENOSYS) || len(f.sends) != 0 {
		t.Fatalf("batch%+v sends%d", r, len(f.sends))
	}
	var p netPayload
	ev := sink.one(t)
	_ = ev.DecodePayload(&p)
	if p.Score == nil || *p.Score != 90 || ev.Authority != record.AuthorityGate {
		t.Fatalf("batch gate%+v %+v", ev, p)
	}
}
func TestGateExecCopiedArgsBoundsAndFastHandover(t *testing.T) {
	for _, score := range []int{40, 49, 50, 51, 70, 80, 81, 90} {
		for _, off := range []bool{false, true} {
			f := newFake()
			f.put(0x10000, cstr("/usr/bin/rm"))
			execFixture(f, 0x20000, []string{"spoofed", "-rf", "/tmp/file"})
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/rm", Source: agent.ExecSourceAllow}}
			pol.Rules.Gate = testGate(t, gate.ExecMatches, "rm -rf", score)
			if off {
				pol.Rules.Record = agent.RecordOff
			}
			l, sink := newTestLoop(t, f, pol)
			l.kernelExecHandoff = func() bool { return true }
			l.kernelExecs = func() bool { return true }
			l.handle(notifFor(nrFor(t, "execve"), 4242, 0x10000, 0x20000))
			v := record.VerdictAllow
			if score >= 50 {
				v = record.VerdictRefused
			}
			wantExecAnswer(t, f, v)
			if score >= 50 {
				ev := sink.one(t)
				var p execPayload
				_ = ev.DecodePayload(&p)
				if ev.Authority != record.AuthorityGate || p.Score == nil || *p.Score != score || p.CompletionUnsupported != (score <= 80) {
					t.Fatalf("execgate%+v %+v", ev, p)
				}
			} else {
				if len(sink.all()) != 0 {
					t.Fatal("duplicated kernel line")
				}
				_, naming := l.execHanded.find(4242, 4242, 0, ^uint64(0))
				_ = naming
				found := false
				for _, e := range l.execHanded.ring {
					if e.tid == 4242 {
						found = true
						if e.naming.SupervisorOwned || e.naming.Score == nil || *e.naming.Score != score {
							t.Fatalf("kernel naming lost score%+v", e.naming)
						}
					}
				}
				if !found {
					t.Fatal("no kernel outcome metadata")
				}
			}
		}
	}
	f := newFake()
	f.put(0x10000, cstr("/usr/bin/rm"))
	args := make([]string, gate.MaxArgs+1)
	for i := range args {
		args[i] = "a"
	}
	execFixture(f, 0x20000, args)
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/rm", Source: agent.ExecSourceAllow}}
	pol.Rules.Gate = testGate(t, gate.ExecMatches, "rm", 40)
	l, s := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "execve"), 42, 0x10000, 0x20000))
	wantExecAnswer(t, f, record.VerdictRefused)
	if ev := s.one(t); ev.Rule != "gate.unreadable" {
		t.Fatalf("argv bounds%+v", ev)
	}
}
func TestGateSafeReadAsksCannotOverrideProtectedFloor(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if e := os.WriteFile(p, []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := (sysKernel{}).PrepareAskOpen(pathQuery{tid: selfTask(t), dirfd: atFDCWD, path: p, joined: p}, unix.O_RDONLY)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(h.fd)
	for _, deny := range []bool{false, true} {
		f := newFake()
		k := &heldTestKernel{fakeKernel: f, held: h}
		pol := testPolicy(nil, []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSImplicit}}, nil)
		if deny {
			pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Path: p, Resolved: p, Kind: agent.FSDenyRead})
		}
		pol.Rules.Workdir = dir
		pol.Rules.Gate = testGate(t, gate.ReadMatches, "secret", 70)
		pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
		asked := 0
		sink := &testSink{}
		l, e := New(testListener(), pol, sink, Options{kernel: k, Ask: func(context.Context, ask.Request) (ask.Decision, error) {
			asked++
			return ask.Decision{Approved: true}, nil
		}})
		if e != nil {
			t.Fatal(e)
		}
		f.put(0x10000, cstr(p))
		n := notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000, unix.O_RDONLY)
		l.handle(n)
		if deny {
			if asked != 0 || k.completed != 0 {
				t.Fatal("protected read overridden")
			}
		} else if asked != 1 || k.completed != 1 {
			t.Fatalf("safe read ask%d complete%d events%v", asked, k.completed, sink.all())
		}
	}
}
func TestGateHostnameAliasesRespectProtocol(t *testing.T) {
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	rules := []agent.NetRule{netRule("first.example:443", "first.example", 443, "93.184.216.34"), netRule("second.example:443", "second.example", 443, "93.184.216.34")}
	rules[0].Proto = agent.ProtoTCP
	rules[1].Proto = agent.ProtoUDP
	pol := testPolicy(rules, nil, nil)
	pol.Resolver = dns.NewSet(rules, nil, dns.Options{})
	pol.Rules.Gate = testGate(t, gate.NetTo, "second.example:443", 90)
	f := newFake()
	l, _ := newTestLoop(t, f, pol)
	n := notifFor(connectNR(), 42)
	r := l.newReader(n)
	d := parseSockaddr(sockaddrIn4(dst.Addr().String(), dst.Port()))
	_, g := l.gateNet(l.table.Load(), r, d, protoTCP, verdictOf{allowed: true, rule: "net[first]"}, gate.Allow)
	if g == nil || g.Score != 0 {
		t.Fatalf("opposite protocol leaked%+v", g)
	}
	_, g = l.gateNet(l.table.Load(), r, d, protoUDP, verdictOf{allowed: true, rule: "net[second]"}, gate.Allow)
	if g == nil || g.Score != 90 {
		t.Fatalf("matching alias omitted%+v", g)
	}
}

func TestGateBatchKeepsStrongestHeadOrTailDecision(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	f.sockProto = unix.IPPROTO_UDP
	f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
	f.put(0x41000, sockaddrIn4("203.0.113.9", 443))
	batch := make([]byte, (mmsgMessages+1)*mmsgHdrSize)
	copy(batch, mmsgBatch(0x40000, 16))
	copy(batch[mmsgMessages*mmsgHdrSize:], mmsgBatch(0x41000, 16))
	f.put(0x50000, batch)
	pol := testPolicy([]agent.NetRule{netRule("93.184.216.34:443", "", 443, "93.184.216.34"), netRule("203.0.113.9:443", "", 443, "203.0.113.9")}, nil, nil)
	var e error
	pol.Rules.Gate, e = gate.New([]gate.Rule{{Predicate: gate.NetTo, Argument: "93.184.216.34:443", Score: 90}, {Predicate: gate.NetTo, Argument: "203.0.113.9:443", Score: 70}}, 50, 80)
	if e != nil {
		t.Fatal(e)
	}
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(sendMMsgNR(), 42, 5, 0x50000, mmsgMessages+1, 0))
	r, _ := f.lastResp()
	if r.Error != -int32(unix.ENOSYS) || r.Flags != 0 || len(f.sends) != 0 {
		t.Fatalf("batch response%+v sends%d", r, len(f.sends))
	}
	ev := sink.one(t)
	var p netPayload
	if e := ev.DecodePayload(&p); e != nil {
		t.Fatal(e)
	}
	if p.Score == nil || *p.Score != 90 || p.GateRule != "gate.rules[0]" || p.GateOutcome != "refused" || p.CompletionUnsupported || ev.Authority != record.AuthorityGate {
		t.Fatalf("strongest batch attribution lost: event%+v payload%+v", ev, p)
	}
}

func TestGateExecOutcomeOwnershipUsesOneReadinessSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		terminal, plane, toggle, noExec bool
	}{
		{"fallback", false, false, false, false}, {"terminal-without-plane", true, false, false, false}, {"terminal-and-plane", true, true, false, false}, {"terminal-readiness-changes", true, true, true, false}, {"no-exec-section", true, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.stats[4242] = procStat{ppid: 1, start: 1234}
			pol := contractPolicy(&agent.Contract{MCP: []agent.MCPServer{{Name: "server", Command: []string{"/usr/bin/rm", "--server"}}}}, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/rm", Source: "mcp:server", Verdict: agent.VerdictAllow}}
			if tc.noExec {
				pol.Rules.Exec = nil
				pol.Rules.Contract.MCP = nil
			}
			pol.Rules.Gate = testGate(t, gate.ExecMatches, "rm", 40)
			l, sink := newTestLoop(t, f, pol)
			l.mono = func() uint64 { return 100 }
			calls := 0
			l.kernelExecHandoff = func() bool {
				calls++
				if tc.toggle && calls > 1 {
					return false
				}
				return tc.terminal
			}
			if tc.plane {
				l.kernelExecs = func() bool { return true }
			}
			execAt(l, f, nrFor(t, "execve"), 4242, 0, "/usr/bin/rm", "rm", "--server")
			wantExecAnswer(t, f, record.VerdictAllow)
			if calls != 1 {
				t.Errorf("terminal readiness calls%d, want one post-score snapshot", calls)
			}
			naming, ok := l.ContinuedExec(4242, 4242, 1234*proc.NanosPerTick, 110)
			if !ok {
				t.Fatal("no final outcome marker")
			}
			if tc.terminal {
				if len(sink.all()) != 0 || naming.SupervisorOwned || naming.Score == nil || *naming.Score != 40 {
					t.Fatalf("terminal owner line%v marker%+v", sink.all(), naming)
				}
				if !tc.noExec && (naming.MCPName != "server" || naming.MCPPath != "/usr/bin/rm") {
					t.Fatalf("success-only MCP proof omitted%+v", naming)
				}
			} else {
				if len(sink.all()) != 1 || !naming.SupervisorOwned {
					t.Fatalf("fallback owner lines%v marker%+v", sink.all(), naming)
				}
			}
		})
	}
}

func TestGateRuntimeGrantsAreFloorWithoutDeclaredFacts(t *testing.T) {
	g := testGate(t, gate.NetUndeclared, "", 70)
	for _, rule := range []string{agent.ResolverRule, "net.capture[127.0.0.1:1234]", "net.dns-broker[unix:/run/runtime.sock]", "net.allow[tcp://127.0.0.1:443]", "models[declared]"} {
		pol := testPolicy(nil, nil, nil)
		pol.Rules.Gate = g
		f := newFake()
		l, _ := newTestLoop(t, f, pol)
		n := notifFor(connectNR(), 42)
		d := parseSockaddr(sockaddrIn4("127.0.0.1", 443))
		a := agent.Action{Kind: agent.ActionNetConnect, Host: "127.0.0.1", Port: 443, Proto: agent.ProtoTCP}
		if rule == "net.dns-broker[unix:/run/runtime.sock]" {
			d = parseSockaddr(sockaddrUn("/run/runtime.sock"))
			a.Host = ""
			a.Port = 0
			a.Proto = agent.ProtoUnix
			a.Path = "unix:/run/runtime.sock"
		}
		_, live := l.gateNet(l.table.Load(), l.newReader(n), d, a.Proto, verdictOf{allowed: true, rule: rule}, gate.Allow)
		hypothetical := agent.EvaluateGateRow(pol.Rules, a, agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rule})
		want := 0
		if agent.IsRuntimeRule(rule) {
			want = 70
		}
		if live == nil || live.Score != want || hypothetical.Score == nil || *hypothetical.Score != want {
			t.Fatalf("runtime fact parity %s live%+v table%+v", rule, live, hypothetical)
		}
		if a.Proto == agent.ProtoUnix && (!hypothetical.CompletionUnsupported || hypothetical.Verdict != agent.VerdictRefused) {
			t.Fatalf("Unix hypothetical completion%+v", hypothetical)
		}
	}
}

func TestGateUDPConnectAskRefusesUnsupportedWithoutPrompt(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	f.sockProto = unix.IPPROTO_UDP
	f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
	pol := contractPolicy(&agent.Contract{}, nil, nil)
	pol.Rules.Gate = testGate(t, gate.NetUndeclared, "", 70)
	pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
	l, sink := newTestLoop(t, f, pol)
	l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
		t.Fatal("unsupported UDP prompted")
		return ask.Decision{}, nil
	}
	l.handle(notifFor(connectNR(), 42, 5, 0x40000, 16))
	r, _ := f.lastResp()
	if r.Flags != 0 || r.Error != -int32(unix.EACCES) || len(f.connects) != 0 {
		t.Fatalf("UDP delivery%+v connects%v", r, f.connects)
	}
	ev := sink.one(t)
	var p netPayload
	if e := ev.DecodePayload(&p); e != nil {
		t.Fatal(e)
	}
	if p.Score == nil || *p.Score != 70 || !p.CompletionUnsupported || p.GateOutcome != "ask" || ev.Authority != record.AuthorityGate || ev.Reason != record.ReasonNetGate {
		t.Fatalf("unsupported UDP attribution%+v payload%+v", ev, p)
	}
}

func TestGateBatchRetainsOriginalStaticRefusalFloor(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	f.sockProto = unix.IPPROTO_UDP
	f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
	f.put(0x41000, sockaddrIn4("203.0.113.9", 443))
	f.put(0x50000, append(mmsgBatch(0x40000, 16), mmsgBatch(0x41000, 16)...))
	pol := testPolicy([]agent.NetRule{netRule("93.184.216.34:443", "", 443, "93.184.216.34")}, nil, nil)
	pol.Rules.Gate = testGate(t, gate.NetTo, "93.184.216.34:443", 90)
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(sendMMsgNR(), 42, 5, 0x50000, 2, 0))
	r, _ := f.lastResp()
	ev := sink.one(t)
	var p netPayload
	if e := ev.DecodePayload(&p); e != nil {
		t.Fatal(e)
	}
	if r.Flags != 0 || r.Error != -int32(unix.EACCES) || len(f.sends) != 0 || ev.Rule != ruleUnmatched || ev.Authority != record.AuthorityRule || ev.Reason != record.ReasonNetNotAllowed || p.Score != nil || p.GateRule != "" || p.CompletionUnsupported {
		t.Fatalf("ordinary floor changed: response%+v event%+v payload%+v", r, ev, p)
	}
}
