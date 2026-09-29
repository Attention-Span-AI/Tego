// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUnaddressedSendMsg is sendUnaddressed: a sendmsg whose header names no destination. After a CONTINUE
// the kernel copies the msghdr again, so a sibling that writes an address into msg_name in between sends
// there. On an IP datagram, raw or seqpacket socket under the models[] guard (R7) that reached the model
// around the forwarder with no line, and MSG_FASTOPEN on an IP stream socket whose connects are decided had
// tcp_sendmsg_fastopen connect to a host nothing decided (R12). Both are relayed on the duplicate with no
// address, as read, answered with the relay's result and recorded nothing, as the continued send did not;
// one a relay cannot reproduce whole is refused. Everything else keeps the old answer: CONTINUE, and no
// duplicate where nothing about the socket needs reading.
func TestUnaddressedSendMsg(t *testing.T) {
	const hdrAddr, iovAddr, bufAddr, nameAddr = 0x60000, 0x80000, 0x50000, 0x40000
	dgram := []byte("dgrm")
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	guard := func() *Policy { return guardPolicy(backend.TierCgroup, nil, model) }
	declared := func() *Policy {
		return testPolicy([]agent.NetRule{netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil)
	}
	noNet := func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }
	// header is an unaddressed msghdr carrying dgram in one iovec: msg_name NULL, or set with a zero
	// length, which __copy_msghdr treats the same way.
	header := func(f *fakeKernel, zeroLenName bool, control uint64) {
		hdr := make([]byte, msgHdrSize)
		if zeroLenName {
			putU64(hdr[msgNameOff:], nameAddr)
			f.put(nameAddr, sockaddrIn4("127.0.0.1", 8443))
		}
		putU64(hdr[msgIovOff:], iovAddr)
		putU64(hdr[msgIovLenOff:], 1)
		putU64(hdr[msgControlLenOff:], control)
		iov := make([]byte, iovecSize)
		putU64(iov[iovecBaseOff:], bufAddr)
		putU64(iov[iovecLenOff:], uint64(len(dgram)))
		f.put(iovAddr, iov)
		f.put(bufAddr, dgram)
		f.put(hdrAddr, hdr)
	}
	const (
		continued = iota
		relayed
		refused
	)
	for _, tc := range []struct {
		name     string
		pol      func() *Policy
		sockType int
		domain   int
		flags    uint64
		zeroLen  bool
		control  uint64
		sendErr  error
		want     int
		rule     string // a refusal's
		noDup    bool   // nothing about the socket needs reading
	}{
		{name: "a datagram on a guarded IP socket", pol: guard, sockType: unix.SOCK_DGRAM, want: relayed},
		{name: "a datagram on a guarded IP socket, msg_name set with a zero length", pol: guard, sockType: unix.SOCK_DGRAM, zeroLen: true, want: relayed},
		{name: "a datagram on a guarded, unconnected IP socket", pol: guard, sockType: unix.SOCK_DGRAM, sendErr: unix.EDESTADDRREQ, want: relayed},
		{name: "a raw datagram on a guarded IP socket", pol: guard, sockType: unix.SOCK_RAW, want: relayed},
		{name: "a seqpacket send on a guarded IP socket", pol: guard, sockType: unix.SOCK_SEQPACKET, want: relayed},
		{name: "a datagram with ancillary data on a guarded IP socket", pol: guard, sockType: unix.SOCK_DGRAM, control: 24, want: refused, rule: ruleAncillary},
		{name: "a stream send on a guarded IP socket", pol: guard, sockType: unix.SOCK_STREAM, want: continued},
		{name: "a Fast-Open send on a guarded IP socket", pol: guard, sockType: unix.SOCK_STREAM, flags: unix.MSG_FASTOPEN, sendErr: unix.EINVAL, want: relayed},
		{name: "a Fast-Open send with ancillary data on a guarded IP socket", pol: guard, sockType: unix.SOCK_STREAM, flags: unix.MSG_FASTOPEN, control: 24, want: refused, rule: ruleAncillary},
		{name: "a datagram on a unix socket under the guard", pol: guard, sockType: unix.SOCK_DGRAM, domain: unix.AF_UNIX, want: continued},
		{name: "a datagram under a net: section", pol: declared, sockType: unix.SOCK_DGRAM, want: continued, noDup: true},
		{name: "a Fast-Open send under a net: section", pol: declared, sockType: unix.SOCK_STREAM, flags: unix.MSG_FASTOPEN, sendErr: unix.EISCONN, want: relayed},
		{name: "a Fast-Open send on a unix stream socket under a net: section", pol: declared, sockType: unix.SOCK_STREAM, domain: unix.AF_UNIX, flags: unix.MSG_FASTOPEN, want: continued},
		{name: "a Fast-Open send with no net: section", pol: noNet, sockType: unix.SOCK_STREAM, flags: unix.MSG_FASTOPEN, want: continued, noDup: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.sockType
			if tc.domain != 0 {
				f.sockDomain = tc.domain
			}
			f.sendErr = tc.sendErr
			header(f, tc.zeroLen, tc.control)
			l, sink := newTestLoop(t, f, tc.pol())
			l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, tc.flags))
			got, _ := f.lastResp()
			evs := sink.all()
			switch tc.want {
			case continued:
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(f.sends) != 0 || len(evs) != 0 {
					t.Fatalf("response = %+v, %d sends, %d lines; want CONTINUE, nothing relayed, no line", got, len(f.sends), len(evs))
				}
			case relayed:
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || len(f.sends) != 1 {
					t.Fatalf("response = %+v, %d sends; want the send relayed", got, len(f.sends))
				}
				if s := f.sends[0]; len(s.addr) != 0 || !bytes.Equal(s.payload, dgram) || s.flags != int(tc.flags) {
					t.Errorf("relayed %q flags %#x to %x; want %q flags %#x to no address, as read", s.payload, s.flags, s.addr, dgram, tc.flags)
				}
				want := respResult(len(dgram), tc.sendErr)
				if got.Error != want.errno || got.Val != want.val {
					t.Errorf("response = %+v; want the relay's own result %+v", got, want)
				}
				if len(evs) != 0 {
					t.Errorf("%d lines; want none, as for the continued send to the peer connect decided", len(evs))
				}
			case refused:
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) || len(f.sends) != 0 {
					t.Fatalf("response = %+v, %d sends; want R10's errno and nothing sent", got, len(f.sends))
				}
				if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != tc.rule {
					t.Fatalf("lines = %+v; want one refused/%s", evs, tc.rule)
				}
				if err := evs[0].Validate(); err != nil {
					t.Errorf("line does not validate: %v", err)
				}
			}
			if tc.noDup && f.openFDs != 0 {
				t.Errorf("%d descriptors taken; want none, nothing about the socket is read", f.openFDs)
			}
			if b := f.fdBalance(); b != 0 {
				t.Errorf("fd balance %d; want every duplicate closed", b)
			}
		})
	}
	// A datagram a relay cannot reproduce whole is refused on the unaddressed path as on the addressed one.
	for _, shape := range gatherShapes() {
		t.Run("a guarded datagram "+shape.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_DGRAM
			shape.put(f, hdrAddr, 0, 0)
			l, sink := newTestLoop(t, f, guard())
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

// TestUnaddressedFastOpenBatch is unaddressedBatch: a sendmmsg with MSG_FASTOPEN whose messages carry no
// address. Continued, a sibling that wrote an address into the first msg_name had tcp_sendmsg_fastopen
// connect there (R12), and a batch cannot be relayed (R13c), so on an IP stream socket whose connects are
// decided it is refused whole, rule batch-send. Guarded IP datagram, raw and seqpacket batches return
// ENOSYS for individual-send fallback. Unix sockets, ordinary stream batches and a contract without
// a net section or model guard keep CONTINUE.
func TestUnaddressedFastOpenBatch(t *testing.T) {
	const arrayAddr = 0x100000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	guard := func() *Policy { return guardPolicy(backend.TierLandlock, nil, model) }
	declared := func() *Policy {
		return testPolicy([]agent.NetRule{netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil)
	}
	noNet := func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }
	for _, tc := range []struct {
		name     string
		pol      func() *Policy
		sockType int
		domain   int
		flags    uint64
		refused  bool
		noDup    bool
		errno    unix.Errno
	}{
		{name: "under the guard", pol: guard, sockType: unix.SOCK_STREAM, flags: unix.MSG_FASTOPEN, refused: true},
		{name: "under a net: section", pol: declared, sockType: unix.SOCK_STREAM, flags: unix.MSG_FASTOPEN, refused: true},
		{name: "on a unix stream socket", pol: declared, sockType: unix.SOCK_STREAM, domain: unix.AF_UNIX, flags: unix.MSG_FASTOPEN},
		{name: "on a datagram socket", pol: declared, sockType: unix.SOCK_DGRAM, flags: unix.MSG_FASTOPEN},
		{name: "without MSG_FASTOPEN", pol: guard, sockType: unix.SOCK_STREAM},
		{name: "guarded IPv4 datagram", pol: guard, sockType: unix.SOCK_DGRAM, refused: true, errno: unix.ENOSYS},
		{name: "guarded IPv6 datagram", pol: guard, sockType: unix.SOCK_DGRAM, domain: unix.AF_INET6, refused: true, errno: unix.ENOSYS},
		{name: "guarded raw socket", pol: guard, sockType: unix.SOCK_RAW, refused: true, errno: unix.ENOSYS},
		{name: "guarded seqpacket socket", pol: guard, sockType: unix.SOCK_SEQPACKET, refused: true, errno: unix.ENOSYS},
		{name: "guarded unix datagram", pol: guard, sockType: unix.SOCK_DGRAM, domain: unix.AF_UNIX},
		{name: "with no net: section", pol: noNet, sockType: unix.SOCK_STREAM, flags: unix.MSG_FASTOPEN, noDup: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.sockType
			if tc.domain != 0 {
				f.sockDomain = tc.domain
			}
			f.put(arrayAddr, mmsgArray(3, func(int) uint64 { return 0 }))
			l, sink := newTestLoop(t, f, tc.pol())
			l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 3, tc.flags))
			got, _ := f.lastResp()
			evs := sink.all()
			if tc.refused {
				wantErrno := tc.errno
				if wantErrno == 0 {
					wantErrno = refusalErrno
				}
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(wantErrno) {
					t.Fatalf("response = %+v; want %v", got, wantErrno)
				}
				if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != ruleBatchSend || netLine(t, evs[0]).BestEffort {
					t.Fatalf("lines = %+v; want one refused/%s, enforced", evs, ruleBatchSend)
				}
				if err := evs[0].Validate(); err != nil {
					t.Errorf("line does not validate: %v", err)
				}
			} else if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(evs) != 0 {
				t.Fatalf("response = %+v, %d lines; want CONTINUE and no line", got, len(evs))
			}
			if tc.noDup && f.openFDs != 0 {
				t.Errorf("%d descriptors taken; want none", f.openFDs)
			}
			if b := f.fdBalance(); b != 0 {
				t.Errorf("fd balance %d; want every duplicate closed", b)
			}
		})
	}
}
