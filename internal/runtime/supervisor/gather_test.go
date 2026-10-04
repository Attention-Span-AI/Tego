// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestRelayedStreamSendIsTheKernelsPrefix pins that a relayed Fast-Open sendmsg sends what the target's own
// call would have sent and answers what it would have answered (R12, I3). gather used to read on past a
// buffer that faulted, so the relay sent the bytes after the fault too, out of the order the kernel copies
// them, and answered a count the kernel never gives; an iovlen past UIO_MAXIOV was cut to 1024 iovecs and
// sent as a short write where __copy_msghdr fails the call EMSGSIZE before anything is sent. Each shape runs
// addressed (relaySend) and with no address (sendUnaddressed).
func TestRelayedStreamSendIsTheKernelsPrefix(t *testing.T) {
	const hdrAddr, nameAddr, iovAddr, bufAddr, buf2Addr, unmapped = 0x60000, 0x40000, 0x80000, 0x200000, 0x300000, 0x7000000
	sa := sockaddrIn4("203.0.113.9", 443)
	put := func(f *fakeKernel, named bool, iovs [][2]uint64, iovlen uint64) {
		hdr := make([]byte, msgHdrSize)
		if named {
			hdr = namedMsgHdr(nameAddr, uint32(len(sa)))
			f.put(nameAddr, sa)
		}
		putU64(hdr[msgIovOff:], iovAddr)
		putU64(hdr[msgIovLenOff:], iovlen)
		f.put(hdrAddr, hdr)
		arr := make([]byte, len(iovs)*iovecSize)
		for i, v := range iovs {
			putU64(arr[i*iovecSize+iovecBaseOff:], v[0])
			putU64(arr[i*iovecSize+iovecLenOff:], v[1])
		}
		f.put(iovAddr, arr)
		f.put(bufAddr, []byte("ab"))
		f.put(buf2Addr, []byte("XY"))
	}
	past := make([][2]uint64, msgIovs+1)
	for i := range past {
		past[i] = [2]uint64{buf2Addr, 1}
	}
	for _, tc := range []struct {
		name   string
		iovs   [][2]uint64
		iovlen uint64
		sent   string // "" with errno set: nothing sent
		errno  unix.Errno
	}{
		{"a buffer that reads short", [][2]uint64{{bufAddr, 4}, {buf2Addr, 2}}, 2, "ab", 0},
		{"a NULL base between two buffers", [][2]uint64{{bufAddr, 2}, {0, 4}, {buf2Addr, 2}}, 3, "ab", 0},
		{"a first buffer that cannot be read", [][2]uint64{{unmapped, 4}, {buf2Addr, 2}}, 2, "", unix.EFAULT},
		{"a NULL first base", [][2]uint64{{0, 4}, {buf2Addr, 2}}, 2, "", unix.EFAULT},
		{"an iovec array that cannot be read whole", [][2]uint64{{buf2Addr, 2}}, 2, "", unix.EFAULT},
		{"an iovlen past UIO_MAXIOV", past, msgIovs + 1, "", unix.EMSGSIZE},
		{"whole buffers", [][2]uint64{{bufAddr, 2}, {buf2Addr, 2}}, 2, "abXY", 0},
	} {
		for _, named := range []bool{true, false} {
			form := "addressed"
			if !named {
				form = "unaddressed"
			}
			t.Run(form+": "+tc.name, func(t *testing.T) {
				f := newFake()
				f.sockType = unix.SOCK_STREAM
				put(f, named, tc.iovs, tc.iovlen)
				l, _ := newTestLoop(t, f, testPolicy([]agent.NetRule{netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil))
				l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, unix.MSG_FASTOPEN))
				got, ok := f.lastResp()
				if !ok {
					t.Fatal("no response")
				}
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
					t.Fatalf("response = %+v, want the relay's answer", got)
				}
				if tc.errno != 0 {
					if len(f.sends) != 0 || got.Error != -int32(tc.errno) {
						t.Errorf("sends %d, response %+v: want nothing sent and the kernel's %v", len(f.sends), got, tc.errno)
					}
					return
				}
				if len(f.sends) != 1 || string(f.sends[0].payload) != tc.sent {
					t.Fatalf("sends = %+v, want one send of %q", f.sends, tc.sent)
				}
				if got.Error != 0 || got.Val != int64(len(tc.sent)) {
					t.Errorf("response = %+v, want the %d bytes the kernel would have sent", got, len(tc.sent))
				}
			})
		}
	}
}
