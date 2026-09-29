// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRelayAnswersTheKernelsAddrlenError pins that an allowed relay gives the target the answer its own call
// would have had for an address length the kernel refuses (I3, R9, R12). The read is clamped to
// sockaddr_storage, so a relay made with those bytes connected or sent where move_addr_to_kernel fails the
// call EINVAL (connect, sendto past 128 bytes or negative) and __copy_msghdr fails a negative msg_namelen.
// A sendmsg name longer than 128 bytes is one the kernel clamps too, so that one is still relayed.
func TestRelayAnswersTheKernelsAddrlenError(t *testing.T) {
	const saAddr, bufAddr, hdrAddr = 0x40000, 0x50000, 0x60000
	rules := []agent.NetRule{netRule("93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")}
	storage := make([]byte, sockaddrMax)
	copy(storage, sockaddrIn4("93.184.216.34", 443))
	payload := []byte("hi")
	msghdr := func(namelen uint32) []byte {
		hdr := make([]byte, msgHdrSize)
		putU64(hdr[msgNameOff:], saAddr)
		putU32(hdr[msgNameLenOff:], namelen)
		return hdr
	}
	for _, tc := range []struct {
		name     string
		notif    func() *notif
		hdr      []byte
		relayed  bool
		wantErrn unix.Errno
	}{
		{"connect addrlen 4096", func() *notif { return notifFor(connectNR(), 4242, 5, saAddr, 4096) }, nil, false, unix.EINVAL},
		{"connect addrlen -1", func() *notif { return notifFor(connectNR(), 4242, 5, saAddr, 0xffffffff) }, nil, false, unix.EINVAL},
		{"connect addrlen 128", func() *notif { return notifFor(connectNR(), 4242, 5, saAddr, sockaddrMax) }, nil, true, 0},
		{"sendto addrlen 129", func() *notif {
			return notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), unix.MSG_FASTOPEN, saAddr, sockaddrMax+1)
		}, nil, false, unix.EINVAL},
		{"sendmsg namelen -1", func() *notif { return notifFor(sendMsgNR(), 4242, 5, hdrAddr, unix.MSG_FASTOPEN) }, msghdr(0xffffffff), false, unix.EINVAL},
		{"sendmsg namelen 4096", func() *notif { return notifFor(sendMsgNR(), 4242, 5, hdrAddr, unix.MSG_FASTOPEN) }, msghdr(4096), true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			f.put(saAddr, storage)
			f.put(bufAddr, payload)
			if tc.hdr != nil {
				f.put(hdrAddr, tc.hdr)
			}
			l, _ := newTestLoop(t, f, testPolicy(rules, nil, nil))
			l.handle(tc.notif())
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			performed := len(f.connects) + len(f.sends)
			if tc.relayed {
				if performed != 1 || got.Error != 0 {
					t.Errorf("performed %d, response %+v: want the length the kernel takes relayed", performed, got)
				}
				return
			}
			if performed != 0 {
				t.Errorf("performed %d relayed syscalls for a length the kernel refuses", performed)
			}
			if got.Error != -int32(tc.wantErrn) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Errorf("response = %+v, want the kernel's own %v", got, tc.wantErrn)
			}
		})
	}
}

// TestRelayAnswersEFAULTForAShortAddress pins that an allowed relay does not connect or send with the
// readable prefix of an address the target's own call could not copy (R9, R12, I3): move_addr_to_kernel
// copies all min(addrlen, 128) bytes and fails EFAULT when any faults, while sockaddr kept the prefix and
// the relay used to connect or send with it, answering success.
func TestRelayAnswersEFAULTForAShortAddress(t *testing.T) {
	const saAddr, bufAddr, hdrAddr = 0x40000, 0x50000, 0x60000
	rules := []agent.NetRule{netRule("93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")}
	sa := sockaddrIn4("93.184.216.34", 443) // mapped alone: the bytes past it fault
	salen := uint64(len(sa))
	payload := []byte("hi")
	msghdr := func(namelen uint32) []byte {
		hdr := make([]byte, msgHdrSize)
		putU64(hdr[msgNameOff:], saAddr)
		putU32(hdr[msgNameLenOff:], namelen)
		return hdr
	}
	sendTo := func(addrlen uint64) func() *notif {
		return func() *notif {
			return notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), unix.MSG_FASTOPEN, saAddr, addrlen)
		}
	}
	sendMsg := func() *notif { return notifFor(sendMsgNR(), 4242, 5, hdrAddr, unix.MSG_FASTOPEN) }
	for _, tc := range []struct {
		name     string
		notif    func() *notif
		hdr      []byte
		wantErrn unix.Errno
	}{
		{"connect addrlen 128", func() *notif { return notifFor(connectNR(), 4242, 5, saAddr, sockaddrMax) }, nil, unix.EFAULT},
		{"connect exact addrlen", func() *notif { return notifFor(connectNR(), 4242, 5, saAddr, salen) }, nil, 0},
		{"connect addrlen 4096", func() *notif { return notifFor(connectNR(), 4242, 5, saAddr, 4096) }, nil, unix.EINVAL},
		{"sendto addrlen 128", sendTo(sockaddrMax), nil, unix.EFAULT},
		{"sendto exact addrlen", sendTo(salen), nil, 0},
		{"sendmsg namelen 128", sendMsg, msghdr(sockaddrMax), unix.EFAULT},
		{"sendmsg namelen 4096", sendMsg, msghdr(4096), unix.EFAULT},
		{"sendmsg namelen -1", sendMsg, msghdr(0xffffffff), unix.EINVAL},
		{"sendmsg exact namelen", sendMsg, msghdr(uint32(salen)), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			f.put(saAddr, sa)
			f.put(bufAddr, payload)
			if tc.hdr != nil {
				f.put(hdrAddr, tc.hdr)
			}
			l, _ := newTestLoop(t, f, testPolicy(rules, nil, nil))
			l.handle(tc.notif())
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			performed := len(f.connects) + len(f.sends)
			if tc.wantErrn == 0 {
				if performed != 1 || got.Error != 0 {
					t.Errorf("performed %d, response %+v: want the fully read address relayed", performed, got)
				}
				return
			}
			if performed != 0 {
				t.Errorf("performed %d relayed syscalls with an address the kernel could not copy", performed)
			}
			if got.Error != -int32(tc.wantErrn) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Errorf("response = %+v, want the kernel's own %v", got, tc.wantErrn)
			}
		})
	}
}

// TestRelayedUnixConnectAnswersTheKernelsAddrlenError is the unix half of the test above (R3, R9, R11, I3):
// relayUnix used to connect with the clamped name whatever addrlen the call carried, so an admitted unix
// connect with an addrlen past 128 connected, as the task, where the task's own call fails EINVAL in
// move_addr_to_kernel before the socket is touched.
func TestRelayedUnixConnectAnswersTheKernelsAddrlenError(t *testing.T) {
	const addr = 0x40000
	write := []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite, Resolved: "/work"}}
	for _, tc := range []struct {
		name     string
		addrlen  uint64
		wantErrn unix.Errno
	}{
		{"addrlen 4096", 4096, unix.EINVAL},
		{"addrlen -1", 0xffffffff, unix.EINVAL},
		{"addrlen 128", sockaddrMax, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			storage := make([]byte, sockaddrMax)
			copy(storage, sockaddrUn("/work/real.sock"))
			f.put(addr, storage)
			l, sink := newTestLoop(t, f, testPolicy(nil, write, nil))
			f.bindsSocket(t, l, sockID{ino: 9000, cookie: 1}, "/work/real.sock") // the run's own socket (R11a)
			l.handle(notifFor(connectNR(), 4242, 5, addr, tc.addrlen))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if got.Error != -int32(tc.wantErrn) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Errorf("response = %+v, want error %v", got, tc.wantErrn)
			}
			if wantConnects := map[bool]int{true: 0, false: 1}[tc.wantErrn != 0]; len(f.unixConnects) != wantConnects {
				t.Errorf("unix connects %q, want %d", f.unixConnects, wantConnects)
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictAllow {
				t.Errorf("verdict %s, want the admitted name's allow", ev.Verdict)
			}
		})
	}
}

// TestSendToWithAZeroAddrlenIsUnaddressed pins that sendto(fd, buf, len, flags, ptr, 0) is the unaddressed
// send the kernel takes it for, as sendmsg's unaddressed already does for a zero msg_namelen: it goes to the
// peer connect decided, or the kernel fails the short name EINVAL, so it is continued with no line. The read
// of a zero-length address failed as args-unreadable and refused a send the kernel delivers.
func TestSendToWithAZeroAddrlenIsUnaddressed(t *testing.T) {
	const saAddr, bufAddr = 0x40000, 0x50000
	rules := []agent.NetRule{netRule("93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")}
	for _, tc := range []struct {
		name  string
		flags uint64
		typ   int
	}{
		{"connected stream", 0, unix.SOCK_STREAM},
		{"stream with MSG_FASTOPEN", unix.MSG_FASTOPEN, unix.SOCK_STREAM},
		{"datagram", 0, unix.SOCK_DGRAM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.typ
			f.put(saAddr, sockaddrIn4("93.184.216.34", 443))
			f.put(bufAddr, []byte("hi"))
			l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
			l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, 2, tc.flags, saAddr, 0))
			got, ok := f.lastResp()
			if !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Errorf("response = %+v, want CONTINUE", got)
			}
			if evs := sink.all(); len(evs) != 0 {
				t.Errorf("%d events (first rule=%s), want none for an unaddressed send", len(evs), evs[0].Rule)
			}
			if len(f.sends) != 0 {
				t.Errorf("relayed %d sends, want none", len(f.sends))
			}
		})
	}
}
