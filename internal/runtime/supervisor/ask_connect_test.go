// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func TestAskConnectNoScopesPreservesOrdinaryRefusalWithTypedNilResolver(t *testing.T) {
	f := newFake()
	f.put(0x40000, sockaddrIn4("10.255.255.1", 443))
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	var absent *dns.Set
	l.askResolver = absent // Same interface conversion as the original runtime wiring.
	l.handle(notifFor(connectNR(), 42, 5, 0x40000, 16))
	response, _ := f.lastResp()
	events := sink.all()
	if response.Error != -int32(unix.EACCES) || response.Flags != 0 || len(events) != 1 || events[0].Kind != record.KindNet || events[0].Verdict != record.VerdictRefused || events[0].Rule != ruleUnmatched {
		t.Fatalf("ordinary refusal response=%+v events=%+v", response, events)
	}
}

func TestAskConnectFrozenDestinationApprovalDenialAndRootCredit(t *testing.T) {
	const addr = 0x40000
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	for _, tc := range []struct {
		name                                 string
		tier                                 backend.Tier
		approved, ordinary, grant, grantFail bool
		reason                               string
	}{{name: "approved landlock", approved: true}, {name: "denied", reason: ask.ReasonDenied}, {name: "ordinary allow first", ordinary: true}, {name: "root missing grant", tier: backend.TierCgroup, approved: true, reason: ask.ReasonUnavailable}, {name: "root grant fails", tier: backend.TierBPFLSM, approved: true, grant: true, grantFail: true, reason: ask.ReasonUnavailable}, {name: "root exact single connect", tier: backend.TierCgroup, approved: true, grant: true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, sockaddrIn4(dst.Addr().String(), dst.Port()))
			f.sockType = unix.SOCK_STREAM
			f.sockProto = unix.IPPROTO_TCP
			r := netRule("tcp://93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")
			r.Proto, r.Verdict = agent.ProtoTCP, agent.VerdictAsk
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Tier = tc.tier
			pol.Rules.Contract = &agent.Contract{Net: &agent.NetSection{}}
			pol.Rules.NetAsk = []agent.NetRule{r}
			pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
			if tc.ordinary {
				a := r
				a.Verdict = agent.VerdictAllow
				pol = testPolicy([]agent.NetRule{a}, nil, nil)
				pol.Rules.NetAsk = []agent.NetRule{r}
				pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect}
			}
			l, sink := newTestLoop(t, f, pol)
			l.askResolver = staticResolver{set: dns.NewSet(pol.Rules.NetAsk, nil, dns.Options{})}
			asked, granted, revoked := 0, 0, 0
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
				asked++
				f.put(addr, sockaddrIn4("203.0.113.99", 8443))
				return ask.Decision{Approved: tc.approved, Reason: ask.ReasonDenied}, nil
			}
			if tc.grant {
				l.grantConnect = func(_ <-chan struct{}, fd int, ap netip.AddrPort, proto string) (Revoke, error) {
					granted++
					if ap != dst || proto != agent.ProtoTCP {
						t.Fatalf("credit %s %s", ap, proto)
					}
					if tc.grantFail {
						return nil, errors.New("unavailable")
					}
					return func() (bool, error) { revoked++; return false, nil }, nil
				}
			}
			l.handle(notifFor(connectNR(), 42, 5, addr, 16))
			response, _ := f.lastResp()
			connected := tc.reason == ""
			if connected {
				if response.Error != 0 || response.Flags != 0 || len(f.connects) != 1 {
					t.Fatalf("connect response %+v calls=%d", response, len(f.connects))
				}
				if string(f.connects[0]) != string(sockaddrIn4(dst.Addr().String(), dst.Port())) {
					t.Fatal("mutable target destination used after approval")
				}
			} else {
				if response.Error != -int32(unix.EACCES) || response.Flags != 0 || len(f.connects) != 0 {
					t.Fatalf("refusal %+v calls=%d", response, len(f.connects))
				}
				events := sink.all()
				if len(events) != 1 || string(events[0].Reason) != tc.reason {
					t.Fatalf("refusal events %+v", events)
				}
			}
			if tc.ordinary {
				if asked != 0 {
					t.Fatal("ordinary allow prompted")
				}
			} else if asked != 1 {
				t.Fatalf("asks %d", asked)
			}
			if tc.grant && granted != 1 {
				t.Fatalf("grant calls%d", granted)
			}
			if tc.grant && !tc.grantFail && revoked != 1 {
				t.Fatalf("revokes%d", revoked)
			}
		})
	}
}

// TestApprovedAskConnectCarriesTheKernelsRefusal: at a root tier an approved TCP connect is admitted in the kernel by a
// one-connect grant that lapses after a second, and connect4/6 refuses a relayed connect it no longer covers with
// EPERM. The line then says what the kernel did, as kernelDecided says it for every relayed connect: the kernel's
// refusal its breadcrumb names, or observed when none names it; it said allow with authority human for a connect that
// never happened (the same class as the unix grant). An allow breadcrumb, or another errno, which
// is the connect's own result, keeps the person's allow.
func TestApprovedAskConnectCarriesTheKernelsRefusal(t *testing.T) {
	const addr = 0x40000
	const kernelRule = "net[kernel-row]"
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	for _, tc := range []struct {
		name       string
		connectErr unix.Errno
		kernel     record.Verdict
		verdict    record.Verdict
		rule       string
		human      bool
	}{
		{"kernel refused", unix.EPERM, record.VerdictRefused, record.VerdictRefused, kernelRule, false},
		{"no fresh breadcrumb names it", unix.EPERM, "", record.VerdictObserved, "net[tcp://93.184.216.34:443]", true},
		{"kernel allowed, EPERM from elsewhere", unix.EPERM, record.VerdictAllow, record.VerdictAllow, "net[tcp://93.184.216.34:443]", true},
		{"another errno is the connect's own", unix.ECONNREFUSED, record.VerdictRefused, record.VerdictAllow, "net[tcp://93.184.216.34:443]", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, sockaddrIn4(dst.Addr().String(), dst.Port()))
			f.sockType, f.sockProto = unix.SOCK_STREAM, unix.IPPROTO_TCP
			f.connectErr = tc.connectErr
			r := netRule("tcp://93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")
			r.Proto, r.Verdict = agent.ProtoTCP, agent.VerdictAsk
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Tier = backend.TierCgroup
			pol.Rules.Contract = &agent.Contract{Net: &agent.NetSection{}}
			pol.Rules.NetAsk = []agent.NetRule{r}
			pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
			l, sink := newTestLoop(t, f, pol)
			l.askResolver = staticResolver{set: dns.NewSet(pol.Rules.NetAsk, nil, dns.Options{})}
			l.ask = func(context.Context, ask.Request) (ask.Decision, error) { return ask.Decision{Approved: true}, nil }
			l.grantConnect = func(<-chan struct{}, int, netip.AddrPort, string) (Revoke, error) { return revokedTaken, nil }
			l.kernelNet = func(netip.AddrPort, string, time.Time) (record.Verdict, string, record.Reason) {
				if tc.kernel == record.VerdictRefused {
					return tc.kernel, kernelRule, record.ReasonNetNotAllowed
				}
				return tc.kernel, "", ""
			}
			l.handle(notifFor(connectNR(), 42, 5, addr, 16))
			if got, _ := f.lastResp(); got.Error != -int32(tc.connectErr) || len(f.connects) != 1 {
				t.Fatalf("response %+v after %d connects, want the relayed errno %v (I3)", got, len(f.connects), tc.connectErr)
			}
			var net []*record.Event
			for _, ev := range sink.all() {
				if ev.Kind == record.KindNet {
					net = append(net, ev)
				}
			}
			if len(net) != 1 {
				t.Fatalf("%d net lines, want one", len(net))
			}
			ev := net[0]
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule || (ev.Authority == record.AuthorityHuman) != tc.human {
				t.Errorf("line %s %s authority %q, want %s %s human %v", ev.Verdict, ev.Rule, ev.Authority, tc.verdict, tc.rule, tc.human)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
		})
	}
}

func TestAskConnectRejectsUnprovenAndMPTCPBeforePrompt(t *testing.T) {
	for _, hold := range []agent.AskHold{agent.AskHoldConnect, agent.AskHoldFirstWrite} {
		for _, protocol := range []int{0, unix.IPPROTO_MPTCP} {
			t.Run(string(hold)+"/"+strconv.Itoa(protocol), func(t *testing.T) {
				f := newFake()
				f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
				f.sockType, f.sockProto = unix.SOCK_STREAM, protocol
				r := netRule("tcp://93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")
				r.Proto, r.Verdict = agent.ProtoTCP, agent.VerdictAsk
				pol := testPolicy(nil, nil, nil)
				pol.Rules.Tier = backend.TierLandlock
				pol.Rules.Contract = &agent.Contract{Net: &agent.NetSection{}}
				pol.Rules.NetAsk = []agent.NetRule{r}
				pol.Rules.AskConfig = &agent.AskConfig{Hold: hold, Timeout: agent.Duration(time.Second), MaxPending: 4}
				l, sink := newTestLoop(t, f, pol)
				l.askResolver = staticResolver{set: dns.NewSet(pol.Rules.NetAsk, nil, dns.Options{})}
				asked, relayed := 0, 0
				l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
					asked++
					return ask.Decision{Approved: true}, nil
				}
				l.firstWrite = func(context.Context, ask.Request, netip.AddrPort, bool, int, func() string) (netip.AddrPort, func(), error) {
					relayed++
					return netip.MustParseAddrPort("127.0.0.1:12345"), func() {}, nil
				}
				l.handle(notifFor(connectNR(), 42, 5, 0x40000, 16))
				response, _ := f.lastResp()
				events := sink.all()
				if response.Error != -int32(unix.EACCES) || response.Flags != 0 || len(f.connects) != 0 || asked != 0 || relayed != 0 || len(events) != 1 || string(events[0].Reason) != ask.ReasonUnavailable {
					t.Fatalf("unsupported protocol%d hold%s response%+v connects%d asks%d relays%d events%+v", protocol, hold, response, len(f.connects), asked, relayed, events)
				}
			})
		}
	}
}

// TestAskConnectAnswersEFAULTForAShortAddress is the ask half of TestRelayAnswersEFAULTForAShortAddress
// (R3, R9, I3): the target's own connect copies all min(addrlen, 128) address bytes and faults EFAULT when
// any of them cannot be read, before any prompt, so an ask-scoped connect whose address read came up short
// is answered that, unprompted, and nothing is connected with the readable prefix.
func TestAskConnectAnswersEFAULTForAShortAddress(t *testing.T) {
	for _, hold := range []agent.AskHold{agent.AskHoldConnect, agent.AskHoldFirstWrite} {
		for _, tc := range []struct {
			addrlen uint64
			want    unix.Errno
		}{{sockaddrMax, unix.EFAULT}, {4096, unix.EINVAL}} {
			t.Run(string(hold)+"/"+strconv.FormatUint(tc.addrlen, 10), func(t *testing.T) {
				f := newFake()
				f.put(0x40000, sockaddrIn4("93.184.216.34", 443)) // mapped alone: the bytes past it fault
				f.sockType, f.sockProto = unix.SOCK_STREAM, unix.IPPROTO_TCP
				r := netRule("tcp://93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")
				r.Proto, r.Verdict = agent.ProtoTCP, agent.VerdictAsk
				pol := testPolicy(nil, nil, nil)
				pol.Rules.Tier = backend.TierLandlock
				pol.Rules.Contract = &agent.Contract{Net: &agent.NetSection{}}
				pol.Rules.NetAsk = []agent.NetRule{r}
				pol.Rules.AskConfig = &agent.AskConfig{Hold: hold, Timeout: agent.Duration(time.Second), MaxPending: 4}
				l, _ := newTestLoop(t, f, pol)
				l.askResolver = staticResolver{set: dns.NewSet(pol.Rules.NetAsk, nil, dns.Options{})}
				asked, relayed := 0, 0
				l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
					asked++
					return ask.Decision{Approved: true}, nil
				}
				l.firstWrite = func(context.Context, ask.Request, netip.AddrPort, bool, int, func() string) (netip.AddrPort, func(), error) {
					relayed++
					return netip.MustParseAddrPort("127.0.0.1:12345"), func() {}, nil
				}
				l.handle(notifFor(connectNR(), 42, 5, 0x40000, tc.addrlen))
				response, _ := f.lastResp()
				if response.Error != -int32(tc.want) || response.Flags != 0 || len(f.connects) != 0 || asked != 0 || relayed != 0 {
					t.Fatalf("response %+v connects %d asks %d relays %d: want the kernel's own %v, unprompted", response, len(f.connects), asked, relayed, tc.want)
				}
			})
		}
	}
}
