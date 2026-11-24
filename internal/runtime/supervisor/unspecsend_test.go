// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAnObserveRunNamesAnUnspecSendForWhatItIs is GAPS C61. An observe run continues a send whose address is
// AF_UNSPEC (R30): an attempted send whose destination and result were not established. IPv4 UDP or raw sockets can
// use the sockaddr_in behind the family word; IPv6 UDP can use its existing peer. The line
// used to say rule "unmatched", dst "unspec", the same words a connect(2) disassociation had under rule
// "net.unspec", so a reader could not tell an attempted send with an unread destination from a reset. It now carries
// ruleUnspecSend. The enforcing tiers' refusal is the same as before: EACCES, refused, rule "unmatched".
func TestAnObserveRunNamesAnUnspecSendForWhatItIs(t *testing.T) {
	const saAddr, bufAddr, hdrAddr, arrayAddr = 0x40000, 0x50000, 0x60000, 0x90000
	drive := map[string]func(l *Loop){
		"sendto":   func(l *Loop) { l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, 4, 0, saAddr, 16)) },
		"sendmsg":  func(l *Loop) { l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0)) },
		"sendmmsg": func(l *Loop) { l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, 0)) },
	}
	for name, send := range drive {
		for _, observe := range []bool{true, false} {
			t.Run(name+map[bool]string{true: ", observe", false: ", enforcing"}[observe], func(t *testing.T) {
				f := newFake()
				f.sockType = unix.SOCK_DGRAM
				f.put(saAddr, unspecSockaddr("203.0.113.9", 8080))
				f.put(bufAddr, []byte("leak"))
				f.put(hdrAddr, namedMsgHdr(saAddr, 16))
				f.put(arrayAddr, mmsgBatch(saAddr, 16))
				pol := observePolicy()
				pol.Observe = observe
				l, sink := newTestLoop(t, f, pol)

				send(l)

				ev := sink.one(t)
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatalf("payload: %v", err)
				}
				if p.Dst != "unspec" || p.Proto != protoUDP {
					t.Errorf("dst %q proto %q, want unspec on udp", p.Dst, p.Proto)
				}
				if observe {
					wantContinue(t, f)
					wantObserved(t, ev, record.KindNet, ruleUnspecSend)
					return
				}
				got, ok := f.lastResp()
				if !ok || f.respCount() != 1 || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
					t.Fatalf("response = %+v, want R10's errno", got)
				}
				if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed || ev.Rule != ruleUnmatched {
					t.Errorf("event = %s/%s rule %q, want refused/net-not-allowed rule %q: the enforcing refusal is unchanged",
						ev.Verdict, ev.Reason, ev.Rule, ruleUnmatched)
				}
			})
		}
	}
}

// TestAnObserveRunKeepsAConnectDisassociationUnspec: the other half. connect(fd, {AF_UNSPEC}) is a disassociation, and
// its line keeps ruleUnspec in an observe run, so the two stay apart by rule.
func TestAnObserveRunKeepsAConnectDisassociationUnspec(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	f.put(addr, make([]byte, 16))
	l, sink := newTestLoop(t, f, observePolicy())
	l.handle(notifFor(connectNR(), 4242, 5, addr, 16))
	if ev := sink.one(t); ev.Rule != ruleUnspec || ev.Verdict != record.VerdictObserved {
		t.Errorf("event = %s rule %q, want observed %q", ev.Verdict, ev.Rule, ruleUnspec)
	}
}
