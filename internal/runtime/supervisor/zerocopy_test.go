// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRelayedSendRefusesZeroCopy is zeroCopy: a send this loop would relay on the duplicate — R12's Fast-Open
// send, and a datagram on a guarded IP socket, addressed or not (R7, R13b) — is refused, rule zerocopy, when
// its flags carry MSG_ZEROCOPY, and nothing is sent. Relayed, the kernel could have transmitted from this
// process's heap after the call returned. A send the loop continues keeps the flag: the kernel then pins the
// agent's own pages, as it would with no supervisor at all.
func TestRelayedSendRefusesZeroCopy(t *testing.T) {
	const saAddr, bufAddr, hdrAddr, iovAddr = 0x40000, 0x50000, 0x60000, 0x80000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	guard := func() *Policy { return guardPolicy(backend.TierCgroup, nil, model) }
	declared := func() *Policy {
		return testPolicy([]agent.NetRule{netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil)
	}
	payload := []byte("dgrm")
	sa := sockaddrIn4("203.0.113.9", 443)
	sendto := func(f *fakeKernel, flags uint64) *notif {
		f.put(saAddr, sa)
		f.put(bufAddr, payload)
		return notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), flags, saAddr, uint64(len(sa)))
	}
	sendmsg := func(named bool) func(f *fakeKernel, flags uint64) *notif {
		return func(f *fakeKernel, flags uint64) *notif {
			hdr := make([]byte, msgHdrSize)
			if named {
				f.put(saAddr, sa)
				hdr = namedMsgHdr(saAddr, uint32(len(sa)))
			}
			putU64(hdr[msgIovOff:], iovAddr)
			putU64(hdr[msgIovLenOff:], 1)
			iov := make([]byte, iovecSize)
			putU64(iov[iovecBaseOff:], bufAddr)
			putU64(iov[iovecLenOff:], uint64(len(payload)))
			f.put(iovAddr, iov)
			f.put(bufAddr, payload)
			f.put(hdrAddr, hdr)
			return notifFor(sendMsgNR(), 4242, 5, hdrAddr, flags)
		}
	}
	const zc, fo = unix.MSG_ZEROCOPY, unix.MSG_FASTOPEN
	for _, tc := range []struct {
		name      string
		pol       func() *Policy
		sockType  int
		connected bool
		flags     uint64
		send      func(*fakeKernel, uint64) *notif
		refused   bool
	}{
		{name: "a guarded datagram by sendto", pol: guard, sockType: unix.SOCK_DGRAM, flags: zc, send: sendto, refused: true},
		{name: "a guarded datagram by sendmsg", pol: guard, sockType: unix.SOCK_DGRAM, flags: zc, send: sendmsg(true), refused: true},
		{name: "an unaddressed guarded datagram", pol: guard, sockType: unix.SOCK_DGRAM, flags: zc, send: sendmsg(false), refused: true},
		{name: "a Fast-Open sendto under the guard", pol: guard, sockType: unix.SOCK_STREAM, flags: zc | fo, send: sendto, refused: true},
		{name: "a declared Fast-Open sendto", pol: declared, sockType: unix.SOCK_STREAM, flags: zc | fo, send: sendto, refused: true},
		{name: "a declared Fast-Open sendmsg", pol: declared, sockType: unix.SOCK_STREAM, flags: zc | fo, send: sendmsg(true), refused: true},
		{name: "an unaddressed Fast-Open sendmsg", pol: declared, sockType: unix.SOCK_STREAM, flags: zc | fo, send: sendmsg(false), refused: true},
		// Continued: the kernel runs these as the agent, from the agent's pages.
		{name: "a datagram under a net: section", pol: declared, sockType: unix.SOCK_DGRAM, flags: zc, send: sendto},
		{name: "an unaddressed datagram under a net: section", pol: declared, sockType: unix.SOCK_DGRAM, flags: zc, send: sendmsg(false)},
		{name: "a stream send to a connected peer under the guard", pol: guard, sockType: unix.SOCK_STREAM, connected: true, flags: zc, send: sendto},
		{name: "an unaddressed stream send under the guard", pol: guard, sockType: unix.SOCK_STREAM, flags: zc, send: sendmsg(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.sockType
			f.connected = tc.connected
			l, sink := newTestLoop(t, f, tc.pol())
			l.handle(tc.send(f, tc.flags))
			got, _ := f.lastResp()
			if len(f.sends) != 0 {
				t.Fatalf("%d sends; want nothing relayed", len(f.sends))
			}
			if !tc.refused {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v; want CONTINUE", got)
				}
				for _, ev := range sink.all() {
					if ev.Rule == ruleZeroCopy {
						t.Errorf("line %s/%s; a continued send is not refused for its flags", ev.Verdict, ev.Rule)
					}
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v; want R10's errno", got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleZeroCopy || netLine(t, ev).BestEffort {
				t.Errorf("event = %s/%s best_effort=%v; want refused/%s, enforced", ev.Verdict, ev.Rule, netLine(t, ev).BestEffort, ruleZeroCopy)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("line does not validate: %v", err)
			}
			if b := f.fdBalance(); b != 0 {
				t.Errorf("fd balance %d; want every duplicate closed", b)
			}
		})
	}
}
