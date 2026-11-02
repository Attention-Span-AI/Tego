// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"
)

// FuzzSendMMsg drives the sendmmsg path over an mmsghdr array the agent controls whole:
// vlen, every msg_name and msg_namelen, the bytes at the one address the fuzzer maps, the socket's type and
// whether it has a peer, and a policy with or without a net: section. Whatever they say, the handler answers
// exactly once (I11), closes every descriptor it opened, and writes at most R13b's 65 lines: one per addressed
// message up to mmsgMessages and one more past them. mmsgDests, asked on its own with nothing stopping it,
// keeps at most mmsgMessages destinations in its head and never more in all than the kernel sends.
func FuzzSendMMsg(f *testing.F) {
	const arrayAddr, saAddr = 0x90000, 0x40000
	f.Add(mmsgBatch(saAddr, 16), sockaddrIn4("203.0.113.9", 443), uint32(1), uint8(0))
	f.Add(mmsgBatch(saAddr, 16), sockaddrIn4("93.184.216.34", 443), uint32(1), uint8(1))
	f.Add(mmsgArray(70, func(int) uint64 { return saAddr }), sockaddrIn4("203.0.113.9", 53), uint32(70), uint8(0))
	f.Add(mmsgArray(3, func(i int) uint64 { return uint64(i%2) * saAddr }), sockaddrIn4("10.0.0.1", 53), uint32(3), uint8(2))
	f.Add([]byte{}, []byte{}, uint32(0xffffffff), uint8(4))
	f.Fuzz(func(t *testing.T, arr, sa []byte, vlen uint32, mode uint8) {
		setup := func() *fakeKernel {
			fk := newFake()
			fk.sockType = unix.SOCK_DGRAM
			if mode&1 != 0 {
				fk.sockType = unix.SOCK_STREAM
			}
			fk.connected = mode&2 != 0
			if len(arr) > 0 {
				fk.put(arrayAddr, arr)
			}
			if len(sa) > 0 {
				fk.put(saAddr, sa)
			}
			return fk
		}
		pol := fastOpenPolicy()
		if mode&4 != 0 {
			pol = testPolicy(nil, nil, nil)
		}

		fk := setup()
		l, sink := newTestLoop(t, fk, pol)
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, uint64(vlen), 0))
		if got := fk.respCount(); got != 1 {
			t.Fatalf("responses = %d, want exactly one (I11)", got)
		}
		if fk.fdBalance() != 0 {
			t.Fatalf("%d descriptors left open", fk.fdBalance())
		}
		if n := len(sink.all()); n > mmsgMessages+1 {
			t.Fatalf("%d lines for one sendmmsg, want at most %d (R13b)", n, mmsgMessages+1)
		}

		fk = setup()
		l, _ = newTestLoop(t, fk, pol)
		n := notifFor(sendMMsgNR(), 4242, 5, arrayAddr, uint64(vlen), 0)
		head, tail, _ := l.mmsgDests(l.newReader(n), n, func(dest) bool { return false })
		if len(head) > mmsgMessages {
			t.Fatalf("%d destinations in the head, want at most %d", len(head), mmsgMessages)
		}
		if sent := min(int(vlen), mmsgKernelMax); len(head)+len(tail) > sent || len(tail) > max(sent-mmsgMessages, 0) {
			t.Fatalf("%d head and %d tail destinations from a batch the kernel sends %d messages of",
				len(head), len(tail), sent)
		}
	})
}
