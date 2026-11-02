// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// cmsgOf lays out one control message as this architecture's libc does, through x/sys's own struct cmsghdr and
// CMSG_LEN/CMSG_SPACE, so the parser's constants are checked against the platform's layout, not against
// themselves.
func cmsgOf(level, typ int, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = int32(level), int32(typ)
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

var (
	// An IPOPT_NOOP, then IPOPT_LSRR of length 7, pointer 4, one hop: 198.51.100.7.
	lsrrOpts = []byte{1, 0x83, 7, 4, 198, 51, 100, 7}
	// A type 2 routing header (RFC 6275): next header, length 2, type 2, segments left 1, reserved, one address.
	rthdr2 = func() []byte {
		b := make([]byte, 24)
		b[1], b[2], b[3] = 2, 2, 1
		b[8], b[9], b[23] = 0x20, 0x01, 7
		return b
	}()
	// UDP_SEGMENT's GSO size, the message QUIC sends most.
	gsoSize = []byte{0xc8, 0x05}
)

// TestCmsgLayout pins the parser's struct cmsghdr to this architecture's: the header's size and field offsets and
// CMSG_ALIGN's unit (amd64 and arm64 share the LP64 layout; CI runs this on both).
func TestCmsgLayout(t *testing.T) {
	var h unix.Cmsghdr
	if unix.SizeofCmsghdr != cmsgHdrLen || unsafe.Offsetof(h.Level) != cmsgLevelOff || unsafe.Offsetof(h.Type) != cmsgTypeOff {
		t.Fatalf("struct cmsghdr: size %d, level at %d, type at %d; the parser reads %d, %d, %d",
			unix.SizeofCmsghdr, unsafe.Offsetof(h.Level), unsafe.Offsetof(h.Type), cmsgHdrLen, cmsgLevelOff, cmsgTypeOff)
	}
	if unix.CmsgSpace(1) != cmsgHdrLen+cmsgAlignTo || unix.CmsgSpace(cmsgAlignTo) != cmsgHdrLen+cmsgAlignTo {
		t.Fatalf("CMSG_SPACE(1) = %d, CMSG_SPACE(%d) = %d: CMSG_ALIGN is not %d", unix.CmsgSpace(1), cmsgAlignTo,
			unix.CmsgSpace(cmsgAlignTo), cmsgAlignTo)
	}
	var m unix.Msghdr
	if unsafe.Offsetof(m.Control) != msgControlOff || unsafe.Offsetof(m.Controllen) != msgControlLenOff {
		t.Fatalf("struct msghdr: msg_control at %d, msg_controllen at %d; the handlers read %d, %d",
			unsafe.Offsetof(m.Control), unsafe.Offsetof(m.Controllen), msgControlOff, msgControlLenOff)
	}
}

// TestControlRoutesParse is controlRoutes' walk of a control buffer, as the kernel's for_each_cmsghdr walks it: a
// message of SOL_IP's IP_RETOPTS or IP_OPTIONS, or of SOL_IPV6's IPV6_RTHDR or IPV6_2292RTHDR, routes, wherever it
// lies among others; the same numbers at another level do not; a message CMSG_OK refuses ends the walk with no route,
// since the kernel then fails the whole send EINVAL; bytes too few for a header after the last message are not one;
// and a buffer read short of its length, walked to the end of what was read, is taken as a route.
func TestControlRoutesParse(t *testing.T) {
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	retopts := cmsgOf(unix.SOL_IP, unix.IP_RETOPTS, lsrrOpts)
	gso := cmsgOf(unix.SOL_UDP, unix.UDP_SEGMENT, gsoSize)
	tos := cmsgOf(unix.SOL_IP, unix.IP_TOS, []byte{0x10, 0, 0, 0})
	short := cmsgOf(unix.SOL_IP, unix.IP_TTL, []byte{9, 0, 0, 0})
	putU64(short, 8) // a cmsg_len shorter than the header: CMSG_OK fails
	past := cmsgOf(unix.SOL_IP, unix.IP_TTL, []byte{9, 0, 0, 0})
	putU64(past, 4096) // a cmsg_len past the buffer's end
	for _, tc := range []struct {
		name string
		buf  []byte
		cut  int // read only this much of buf, when set
		want bool
	}{
		{name: "empty", buf: nil},
		{name: "shorter than a header", buf: make([]byte, cmsgHdrLen-1)},
		{name: "UDP_SEGMENT", buf: gso},
		{name: "SCM_RIGHTS", buf: unix.UnixRights(3, 4, 5, 6, 7)},
		{name: "IP_RETOPTS", buf: retopts, want: true},
		{name: "IP_OPTIONS", buf: cmsgOf(unix.SOL_IP, unix.IP_OPTIONS, lsrrOpts), want: true},
		{name: "IPV6_RTHDR", buf: cmsgOf(unix.SOL_IPV6, unix.IPV6_RTHDR, rthdr2), want: true},
		{name: "IPV6_2292RTHDR", buf: cmsgOf(unix.SOL_IPV6, unix.IPV6_2292RTHDR, rthdr2), want: true},
		{name: "IPV6_RTHDR's number at SOL_IP", buf: cmsgOf(unix.SOL_IP, unix.IPV6_RTHDR, rthdr2)},
		{name: "IP_RETOPTS's number at SOL_IPV6", buf: cmsgOf(unix.SOL_IPV6, unix.IP_RETOPTS, lsrrOpts)},
		{name: "IPV6_RTHDR's number at SOL_UDP", buf: cmsgOf(unix.SOL_UDP, unix.IPV6_RTHDR, rthdr2)},
		{name: "several benign messages", buf: cat(gso, tos, unix.UnixRights(3))},
		{name: "a route behind two benign messages", buf: cat(gso, tos, retopts), want: true},
		{name: "a route before benign ones", buf: cat(retopts, gso, tos), want: true},
		{name: "a malformed message before a route", buf: cat(gso, short, retopts)},
		{name: "a route before a malformed message", buf: cat(retopts, short)},
		{name: "a cmsg_len past the buffer", buf: cat(gso, past)},
		{name: "trailing bytes too few for a header", buf: cat(gso, make([]byte, cmsgHdrLen-1))},
		{name: "a zeroed header after a message", buf: cat(gso, make([]byte, cmsgHdrLen), retopts)},
		{name: "read short, walked past what was read", buf: cat(gso, tos, retopts), cut: len(gso) + 4, want: true},
		{name: "read short, a route within what was read", buf: cat(retopts, gso), cut: len(retopts), want: true},
		{name: "read short on a message boundary", buf: cat(gso, tos), cut: len(gso), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.buf
			if tc.cut != 0 {
				b = b[:tc.cut]
			}
			if got := controlRoutes(b, uint64(len(tc.buf))); got != tc.want {
				t.Fatalf("controlRoutes(%x, %d) = %t, want %t", b, len(tc.buf), got, tc.want)
			}
		})
	}
}

// routeSendCase is one sendmsg of TestSendMsgRoutingControl.
type routeSendCase struct {
	name      string
	noNet     bool   // a contract with no net: section
	sockType  int    // SOCK_DGRAM unless set
	domain    int    // AF_INET unless set
	connected bool   // the socket has a peer (a stream socket's R13a)
	addressed bool   // msg_name names the admitted 203.0.113.9:53
	ctl       []byte // the control buffer, at ctlAt
	ctlLen    uint64 // msg_controllen, when it is not len(ctl)
	nullCtl   bool   // msg_control is NULL
	refused   bool   // refused relay-source-routed, nothing sent
}

// TestSendMsgRoutingControl is GAPS C34's control-message half (R13b): under a net: section with no gate an admitted
// datagram is continued, and the kernel sent it with whatever route its own control messages carried, connected or
// not (udp_sendmsg takes the first hop from an IP_RETOPTS LSRR or SSRR, fl6_update_dst from an IPV6_RTHDR), so it
// went to an address in the route, which no entry admits and no decision saw. The handler never read msg_control,
// only tested its length. Now a route among the messages is refused with R10's errno and rule relay-source-routed,
// on an IP socket that is not a stream one, and nothing is sent; benign messages (GSO, TOS) keep the old answer; a
// stream socket, which reads no such message, and a unix socket go on as before; a malformed buffer the kernel would
// refuse EINVAL is the kernel's to answer; one this loop cannot read whole (NULL, faulting part-way) or longer than
// the read is refused (R5); and a contract with no net: section admits every IP destination and is not read.
func TestSendMsgRoutingControl(t *testing.T) {
	const hdrAt, saAt, iovAt, bufAt, ctlAt = 0x60000, 0x40000, 0x70000, 0x80000, 0xa0000
	retopts := cmsgOf(unix.SOL_IP, unix.IP_RETOPTS, lsrrOpts)
	gso := cmsgOf(unix.SOL_UDP, unix.UDP_SEGMENT, gsoSize)
	tos := cmsgOf(unix.SOL_IP, unix.IP_TOS, []byte{0x10, 0, 0, 0})
	short := cmsgOf(unix.SOL_IP, unix.IP_TTL, []byte{9, 0, 0, 0})
	putU64(short, 8)
	// msgControlMax bytes of GSO messages and a route past them, which the read does not reach.
	var long []byte
	for len(long) < msgControlMax {
		long = append(long, gso...)
	}
	long = append(long, retopts...)
	for _, tc := range []routeSendCase{
		{name: "UDP_SEGMENT", addressed: true, ctl: gso},
		{name: "UDP_SEGMENT and IP_TOS", addressed: true, ctl: append(append([]byte{}, gso...), tos...)},
		{name: "IP_RETOPTS", addressed: true, ctl: retopts, refused: true},
		{name: "IP_OPTIONS", addressed: true, ctl: cmsgOf(unix.SOL_IP, unix.IP_OPTIONS, lsrrOpts), refused: true},
		{name: "IPV6_RTHDR", domain: unix.AF_INET6, addressed: true, ctl: cmsgOf(unix.SOL_IPV6, unix.IPV6_RTHDR, rthdr2), refused: true},
		{name: "IPV6_2292RTHDR", domain: unix.AF_INET6, addressed: true, ctl: cmsgOf(unix.SOL_IPV6, unix.IPV6_2292RTHDR, rthdr2), refused: true},
		{name: "a route behind GSO", addressed: true, ctl: append(append([]byte{}, gso...), retopts...), refused: true},
		{name: "a connected socket's unaddressed send", ctl: retopts, refused: true},
		{name: "a raw socket", sockType: unix.SOCK_RAW, addressed: true, ctl: retopts, refused: true},
		{name: "a socket whose domain cannot be read", domain: -1, ctl: retopts, refused: true},
		{name: "a buffer longer than the read", addressed: true, ctl: long, refused: true},
		{name: "a connected TCP socket", sockType: unix.SOCK_STREAM, connected: true, addressed: true, ctl: retopts},
		{name: "a unix datagram socket", domain: unix.AF_UNIX, ctl: retopts},
		{name: "a NULL buffer", addressed: true, ctlLen: 24, nullCtl: true, refused: true},
		{name: "a buffer that faults part-way", addressed: true, ctl: retopts, ctlLen: uint64(len(retopts)) + 64, refused: true},
		{name: "a malformed message before a route", addressed: true, ctl: append(append([]byte{}, short...), retopts...)},
		{name: "a buffer shorter than a header", addressed: true, ctl: retopts[:cmsgHdrLen-1]},
		{name: "no net: section", noNet: true, addressed: true, ctl: retopts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.connected = unix.SOCK_DGRAM, unix.AF_INET, tc.connected
			if tc.sockType != 0 {
				f.sockType = tc.sockType
			}
			switch {
			case tc.domain == -1:
				f.sockDomainErr = unix.EBADF
			case tc.domain != 0:
				f.sockDomain = tc.domain
			}
			hdr := make([]byte, msgHdrSize)
			if tc.addressed {
				putU64(hdr[msgNameOff:], saAt)
				putU32(hdr[msgNameLenOff:], 16)
				f.put(saAt, sockaddrIn4("203.0.113.9", 53))
			}
			putU64(hdr[msgIovOff:], iovAt)
			putU64(hdr[msgIovLenOff:], 1)
			if !tc.nullCtl {
				putU64(hdr[msgControlOff:], ctlAt)
				f.put(ctlAt, tc.ctl)
			}
			ctlLen := uint64(len(tc.ctl))
			if tc.ctlLen != 0 {
				ctlLen = tc.ctlLen
			}
			putU64(hdr[msgControlLenOff:], ctlLen)
			iov := make([]byte, iovecSize)
			putU64(iov[iovecBaseOff:], bufAt)
			putU64(iov[iovecLenOff:], 5)
			f.put(hdrAt, hdr)
			f.put(iovAt, iov)
			f.put(bufAt, []byte("query"))
			// The host on UDP 53, and on port 0, which a raw or ping socket's datagram matches (SEMANTICS §5).
			pol := contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, []agent.NetRule{
				netRule("ns.example.com:53", "ns.example.com", 53, "203.0.113.9"),
				netRule("ns.example.com:0", "ns.example.com", 0, "203.0.113.9"),
			}, nil)
			if tc.noNet {
				pol = contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
			}
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(sendMsgNR(), 42, 5, hdrAt, 0))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("unanswered")
			}
			var routed *record.Event
			for _, ev := range sink.all() {
				if ev.Rule == ruleSourceRouted {
					routed = ev
				}
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open", f.fdBalance())
			}
			if !tc.refused {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || routed != nil {
					t.Fatalf("response %+v, line %+v; want the send continued as before, no %s line", got, routed, ruleSourceRouted)
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) || len(f.sends) != 0 {
				t.Fatalf("response %+v, sends %d; want R10's errno and nothing sent", got, len(f.sends))
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleSourceRouted {
				t.Fatalf("line %+v; want refused %s", ev, ruleSourceRouted)
			}
		})
	}
}

// TestSendMMsgRoutingControl is the control-message check over a batch: a message's route refuses the whole batch,
// wherever it lies and whether or not the message is addressed, as a batch with a refused destination is refused
// whole (R13b); a batch whose messages carry only benign control data is continued as before.
func TestSendMMsgRoutingControl(t *testing.T) {
	const arrAt, saAt, ctlAt, benignAt = 0x90000, 0x40000, 0xa0000, 0xb0000
	retopts := cmsgOf(unix.SOL_IP, unix.IP_RETOPTS, lsrrOpts)
	gso := cmsgOf(unix.SOL_UDP, unix.UDP_SEGMENT, gsoSize)
	for _, tc := range []struct {
		name      string
		addressed bool
		routeAt   int // the message carrying the route, -1 for none
		refused   bool
	}{
		{name: "addressed, benign control", addressed: true, routeAt: -1},
		{name: "addressed, a route in the first message", addressed: true, routeAt: 0, refused: true},
		{name: "addressed, a route in the third message", addressed: true, routeAt: 2, refused: true},
		{name: "unaddressed, a route in the last message", routeAt: 3, refused: true},
		{name: "unaddressed, benign control", routeAt: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.sockProto = unix.SOCK_DGRAM, unix.AF_INET, unix.IPPROTO_UDP
			f.put(saAt, sockaddrIn4("203.0.113.9", 53))
			f.put(ctlAt, retopts)
			f.put(benignAt, gso)
			const vlen = 4
			arr := make([]byte, vlen*mmsgHdrSize)
			for i := 0; i < vlen; i++ {
				m := arr[i*mmsgHdrSize:]
				if tc.addressed {
					putU64(m[msgNameOff:], saAt)
					putU32(m[msgNameLenOff:], 16)
				}
				if i == tc.routeAt {
					putU64(m[msgControlOff:], ctlAt)
					putU64(m[msgControlLenOff:], uint64(len(retopts)))
				} else {
					putU64(m[msgControlOff:], benignAt)
					putU64(m[msgControlLenOff:], uint64(len(gso)))
				}
			}
			f.put(arrAt, arr)
			pol := contractPolicy(&agent.Contract{Net: &agent.NetSection{}},
				[]agent.NetRule{netRule("ns.example.com:53", "ns.example.com", 53, "203.0.113.9")}, nil)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(sendMMsgNR(), 42, 5, arrAt, vlen, 0))
			got, _ := f.lastResp()
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open", f.fdBalance())
			}
			if !tc.refused {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response %+v; want the batch continued as before", got)
				}
				for _, ev := range sink.all() {
					if ev.Rule == ruleSourceRouted {
						t.Fatalf("line %+v for a batch with no route", ev)
					}
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response %+v; want the batch refused with R10's errno", got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleSourceRouted {
				t.Fatalf("line %+v; want refused %s", ev, ruleSourceRouted)
			}
		})
	}
}
