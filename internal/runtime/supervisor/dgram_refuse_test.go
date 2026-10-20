// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// lookupForm is one way a resolver lookup reaches the machine resolver: a connect of a UDP socket, then a send
// with no address (glibc's connected resolver), or a send that carries the address itself (an unconnected one).
type lookupForm struct {
	name string
	run  func(l *Loop, f *fakeKernel)
}

// lookupForms are the four syscalls that carry a resolver address, each on a UDP socket.
func lookupForms() []lookupForm {
	const saAt, bufAt, hdrAt, iovAt, arrAt = 0x40000, 0x50000, 0x60000, 0x70000, 0x90000
	sa := sockaddrIn4("127.0.0.53", 53)
	setup := func(f *fakeKernel) {
		f.sockType, f.sockDomain, f.sockProto = unix.SOCK_DGRAM, unix.AF_INET, unix.IPPROTO_UDP
		f.put(saAt, sa)
		f.put(bufAt, []byte("query"))
		hdr := namedMsgHdr(saAt, uint32(len(sa)))
		putU64(hdr[msgIovOff:], iovAt)
		putU64(hdr[msgIovLenOff:], 1)
		f.put(hdrAt, hdr)
		iov := make([]byte, iovecSize)
		putU64(iov, bufAt)
		putU64(iov[8:], 5)
		f.put(iovAt, iov)
		arr := make([]byte, mmsgHdrSize)
		copy(arr, hdr)
		f.put(arrAt, arr)
	}
	return []lookupForm{
		{"connect", func(l *Loop, f *fakeKernel) {
			setup(f)
			l.handle(notifFor(connectNR(), 42, 5, saAt, uint64(len(sa))))
		}},
		{"sendto", func(l *Loop, f *fakeKernel) {
			setup(f)
			l.handle(notifFor(sendToNR(), 42, 5, bufAt, 5, 0, saAt, uint64(len(sa))))
		}},
		{"sendmsg", func(l *Loop, f *fakeKernel) {
			setup(f)
			l.handle(notifFor(sendMsgNR(), 42, 5, hdrAt, 0))
		}},
		{"sendmmsg", func(l *Loop, f *fakeKernel) {
			setup(f)
			l.handle(notifFor(sendMMsgNR(), 42, 5, arrAt, 1, 0))
		}},
	}
}

// TestDNSOffRefusesEveryLookupForm is finding F1 of the interactive-codex POC at the supervisor: under
// net.dns.mode: off the run has no resolver exception (agent.DNSPolicy.SystemResolvers), so the machine resolver
// is a destination like any other the contract does not name. A connected lookup was refused at its connect, and
// an unconnected one — sendto, sendmsg or sendmmsg carrying the resolver's address — was continued under a refused
// line marked best_effort, so the query left and the answer came back. Every form is refused now, with R10's
// errno, by one enforced line (R13b as amended 2026-10-16), and nothing is sent from this process either.
func TestDNSOffRefusesEveryLookupForm(t *testing.T) {
	for _, form := range lookupForms() {
		t.Run(form.name, func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, []netip.AddrPort{}))
			form.run(l, f)
			got, _ := f.lastResp()
			if got.Flags != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("answer %+v, want R10's errno: under dns off the resolver is not admitted", got)
			}
			if len(f.sends) != 0 || len(f.connects) != 0 {
				t.Fatalf("the loop sent or connected for a refused lookup: sends %d, connects %d", len(f.sends), len(f.connects))
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed || ev.Rule != ruleUnmatched ||
				p.BestEffort || p.Dst != "127.0.0.53:53" || p.Proto != protoUDP {
				t.Fatalf("line %s/%s/%s %+v, want one enforced udp refused/net-not-allowed/unmatched for 127.0.0.53:53",
					ev.Verdict, ev.Reason, ev.Rule, p)
			}
		})
	}
}

// TestSystemDNSAdmitsEveryLookupForm is the control: with the resolver exception (net.dns.mode: system), the same
// four syscalls are admitted under net.resolver (R14). The connect is relayed; a datagram is continued, its line
// best_effort because the kernel sends to its own copy of the address.
func TestSystemDNSAdmitsEveryLookupForm(t *testing.T) {
	resolvers := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}
	for _, form := range lookupForms() {
		t.Run(form.name, func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, resolvers))
			form.run(l, f)
			got, _ := f.lastResp()
			if got.Error != 0 {
				t.Fatalf("answer %+v, want the lookup admitted", got)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictAllow || ev.Rule != ruleResolver {
				t.Fatalf("line %s/%s, want allow/%s", ev.Verdict, ev.Rule, ruleResolver)
			}
			if datagram := form.name != "connect"; p.BestEffort != datagram {
				t.Fatalf("best_effort = %t, want %t: only a continued datagram carries it", p.BestEffort, datagram)
			}
		})
	}
}
