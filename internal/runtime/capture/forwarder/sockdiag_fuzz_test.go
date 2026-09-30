// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// FuzzParseSockDiagReply feeds the sock_diag parser arbitrary netlink bytes. It must never panic, and it returns
// an inode only alongside a nil error and never 0.
func FuzzParseSockDiagReply(f *testing.F) {
	peer := netip.MustParseAddrPort("127.0.0.1:8080")
	local := netip.MustParseAddrPort("127.0.0.1:50000")
	ne := binary.NativeEndian
	hdr := func(typ uint16, body []byte) []byte {
		m := make([]byte, nlmsgHdrLen+len(body))
		ne.PutUint32(m, uint32(len(m)))
		ne.PutUint16(m[4:], typ)
		copy(m[nlmsgHdrLen:], body)
		return m
	}
	body := make([]byte, inetDiagMsgLen)
	body[0] = unix.AF_INET
	putSockID(body[4:], unix.AF_INET, peer, local)
	ne.PutUint32(body[inetDiagInodeOff:], 4242)
	f.Add(hdr(unix.SOCK_DIAG_BY_FAMILY, body), uint8(unix.AF_INET))
	f.Add(hdr(nlmsgErrorType, []byte{0xfe, 0xff, 0xff, 0xff}), uint8(unix.AF_INET))
	f.Add(hdr(nlmsgErrorType, nil), uint8(unix.AF_INET))
	f.Add(hdr(unix.SOCK_DIAG_BY_FAMILY, body[:10]), uint8(unix.AF_INET6))
	f.Add([]byte{1, 2, 3}, uint8(0))
	f.Fuzz(func(t *testing.T, msg []byte, family uint8) {
		ino, err := parseSockDiagReply(msg, family, peer, local)
		if err == nil && ino == 0 {
			t.Fatal("nil error with inode 0")
		}
		if err != nil && ino != 0 {
			t.Fatalf("error %v with inode %d", err, ino)
		}
	})
}
