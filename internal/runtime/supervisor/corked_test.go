// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDatagramThatCouldJoinAPendingFrameIsRefused (R13b, R7): a UDP socket holding a pending frame
// (MSG_MORE, UDP_CORK) appends every later datagram to it, before udp_sendmsg reads the address and before the run's
// sendmsg4/6 runs, so the bytes go to the frame's destination, not the one this loop read and records. A datagram this
// loop relays is therefore refused, rule datagram-corked, when it carries MSG_MORE (it would leave a frame pending on
// the agent's socket) or the socket is corked or its cork cannot be read; and under a net: section an addressed UDP
// datagram, continued or relayed, or a sendmmsg batch, carrying MSG_MORE is refused, so no frame the next relay could
// join forms from a send this loop sees. A continued datagram on a corked socket is left to the kernel: its line is
// R13b's best effort. With no net: section nothing is decided, and MSG_MORE is continued. An unaddressed sendmsg or
// sendmmsg with MSG_MORE under a net: section is refused too: it leaves a frame pending to the
// socket's peer. A UDP-Lite socket keeps UDP's frames and is decided the same way.
func TestDatagramThatCouldJoinAPendingFrameIsRefused(t *testing.T) {
	const saAddr, bufAddr, hdrAddr, iovAddr, arrAddr = 0x40000, 0x50000, 0x60000, 0x80000, 0x90000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	guard := func() *Policy { return guardPolicy(backend.TierCgroup, nil, model) }
	declared := func() *Policy {
		return testPolicy([]agent.NetRule{netRule("udp://203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil)
	}
	open := func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }
	payload := []byte("dgrm")
	sa := sockaddrIn4("203.0.113.9", 443)
	sendto := func(f *fakeKernel, flags uint64) *notif {
		f.put(saAddr, sa)
		f.put(bufAddr, payload)
		return notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), flags, saAddr, uint64(len(sa)))
	}
	msghdr := func(f *fakeKernel, named bool) []byte {
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
		return hdr
	}
	sendmsg := func(named bool) func(f *fakeKernel, flags uint64) *notif {
		return func(f *fakeKernel, flags uint64) *notif {
			f.put(hdrAddr, msghdr(f, named))
			return notifFor(sendMsgNR(), 4242, 5, hdrAddr, flags)
		}
	}
	batch := func(named bool) func(f *fakeKernel, flags uint64) *notif {
		return func(f *fakeKernel, flags uint64) *notif {
			arr := make([]byte, mmsgHdrSize)
			copy(arr, msghdr(f, named))
			f.put(arrAddr, arr)
			return notifFor(sendMMsgNR(), 4242, 5, arrAddr, 1, flags)
		}
	}
	sendmmsg := batch(true)
	// A UDP-Lite socket (SOCK_DGRAM, IPPROTO_UDPLITE) sends through udp_sendmsg and keeps the same pending frames;
	// its proto is raw (protoOf), which a udp:// rule does not match, so its net: section names a bare host:port.
	declaredAny := func() *Policy {
		return testPolicy([]agent.NetRule{netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil)
	}
	const lite = unix.IPPROTO_UDPLITE
	const more = unix.MSG_MORE
	for _, tc := range []struct {
		name      string
		pol       func() *Policy
		flags     uint64
		corked    bool
		corkedErr error
		send      func(*fakeKernel, uint64) *notif
		proto     int
		refused   bool
		relayed   bool
	}{
		{name: "a relayed datagram with MSG_MORE", pol: guard, flags: more, send: sendto, refused: true},
		{name: "a relayed datagram on a corked socket", pol: guard, corked: true, send: sendto, refused: true},
		{name: "a relayed datagram whose cork cannot be read", pol: guard, corkedErr: errors.New("EBADF"), send: sendto, refused: true},
		{name: "a relayed sendmsg on a corked socket", pol: guard, corked: true, send: sendmsg(true), refused: true},
		{name: "an unaddressed relayed datagram with MSG_MORE", pol: guard, flags: more, send: sendmsg(false), refused: true},
		{name: "an unaddressed relayed datagram on a corked socket", pol: guard, corked: true, send: sendmsg(false), refused: true},
		{name: "a relayed datagram", pol: guard, send: sendto, relayed: true},
		{name: "a continued datagram with MSG_MORE under a net: section", pol: declared, flags: more, send: sendto, refused: true},
		{name: "a continued sendmsg with MSG_MORE under a net: section", pol: declared, flags: more, send: sendmsg(true), refused: true},
		{name: "a sendmmsg batch with MSG_MORE under a net: section", pol: declared, flags: more, send: sendmmsg, refused: true},
		// Unaddressed, the kernel sends to the socket's peer, and MSG_MORE leaves a frame pending there all the same: a
		// sendmsg or sendmmsg the filter notifies is refused under a net: section, gate
		// or guard or none; without MSG_MORE it is continued as before.
		{name: "an unaddressed sendmsg with MSG_MORE under a net: section", pol: declared, flags: more, send: sendmsg(false), refused: true},
		{name: "an unaddressed sendmmsg batch with MSG_MORE under a net: section", pol: declared, flags: more, send: batch(false), refused: true},
		{name: "an unaddressed sendmsg under a net: section", pol: declared, send: sendmsg(false)},
		{name: "an unaddressed sendmmsg batch under a net: section", pol: declared, send: batch(false)},
		{name: "an unaddressed sendmsg with MSG_MORE and no net: section", pol: open, flags: more, send: sendmsg(false)},
		{name: "an unaddressed sendmmsg batch with MSG_MORE and no net: section", pol: open, flags: more, send: batch(false)},
		// UDP-Lite keeps udp_sendmsg's pending frames.
		{name: "a relayed UDP-Lite datagram with MSG_MORE", pol: guard, flags: more, send: sendto, proto: lite, refused: true},
		{name: "a relayed UDP-Lite datagram on a corked socket", pol: guard, corked: true, send: sendto, proto: lite, refused: true},
		{name: "a relayed UDP-Lite datagram whose cork cannot be read", pol: guard, corkedErr: errors.New("EBADF"), send: sendto, proto: lite, refused: true},
		{name: "an unaddressed relayed UDP-Lite datagram with MSG_MORE", pol: guard, flags: more, send: sendmsg(false), proto: lite, refused: true},
		{name: "a relayed UDP-Lite datagram", pol: guard, send: sendto, proto: lite, relayed: true},
		{name: "a continued UDP-Lite datagram with MSG_MORE under a net: section", pol: declaredAny, flags: more, send: sendto, proto: lite, refused: true},
		{name: "a continued UDP-Lite sendmsg with MSG_MORE under a net: section", pol: declaredAny, flags: more, send: sendmsg(true), proto: lite, refused: true},
		{name: "a UDP-Lite sendmmsg batch with MSG_MORE under a net: section", pol: declaredAny, flags: more, send: sendmmsg, proto: lite, refused: true},
		{name: "an unaddressed UDP-Lite sendmsg with MSG_MORE under a net: section", pol: declaredAny, flags: more, send: sendmsg(false), proto: lite, refused: true},
		{name: "a continued UDP-Lite datagram under a net: section", pol: declaredAny, send: sendto, proto: lite},
		{name: "a UDP-Lite datagram with MSG_MORE and no net: section", pol: open, flags: more, send: sendto, proto: lite},
		// Continued: the kernel runs these as the agent, and the line says best_effort.
		{name: "a continued datagram on a corked socket", pol: declared, corked: true, send: sendto},
		{name: "a datagram with MSG_MORE and no net: section", pol: open, flags: more, send: sendto},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.sockProto = unix.SOCK_DGRAM, unix.AF_INET, unix.IPPROTO_UDP
			if tc.proto != 0 {
				f.sockProto = tc.proto
			}
			f.udpCorked, f.udpCorkedErr = tc.corked, tc.corkedErr
			pol := tc.pol()
			pol.Rules.Record = agent.RecordFull
			l, sink := newTestLoop(t, f, pol)
			l.handle(tc.send(f, tc.flags))
			got, _ := f.lastResp()
			if b := f.fdBalance(); b != 0 {
				t.Errorf("fd balance %d; want every duplicate closed", b)
			}
			if tc.relayed {
				if len(f.sends) != 1 || got.Error != 0 {
					t.Fatalf("response %+v sends %d; want the datagram relayed", got, len(f.sends))
				}
				return
			}
			if len(f.sends) != 0 {
				t.Fatalf("%d sends; want nothing relayed", len(f.sends))
			}
			if !tc.refused {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response = %+v; want CONTINUE", got)
				}
				for _, ev := range sink.all() {
					if ev.Rule == ruleCorked {
						t.Errorf("line %s/%s; a continued send is not refused for a pending frame", ev.Verdict, ev.Rule)
					}
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v; want R10's errno", got)
			}
			found := false
			for _, ev := range sink.all() {
				if ev.Kind != record.KindNet {
					continue
				}
				if ev.Verdict != record.VerdictRefused || ev.Rule != ruleCorked || netLine(t, ev).BestEffort {
					t.Errorf("line %s/%s best_effort=%v; want refused/%s, enforced", ev.Verdict, ev.Rule, netLine(t, ev).BestEffort, ruleCorked)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("line does not validate: %v", err)
				}
				found = true
			}
			if !found {
				t.Fatalf("no net line; want refused/%s", ruleCorked)
			}
		})
	}
}
