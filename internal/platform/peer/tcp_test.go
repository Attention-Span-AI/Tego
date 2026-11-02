// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// TestTCPSocketCgroupIsTheMakersCgroup: the cgroup id sock_diag reports for a loopback client socket this test made
// is the inode of this process's own cgroup directory under the cgroup2 mount, so a caller can compare it with run
// scopes' directories; a tuple no socket has is ErrNoSocket.
func TestTCPSocketCgroupIsTheMakersCgroup(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := netip.MustParseAddrPort(c.LocalAddr().String())
	server := netip.MustParseAddrPort(c.RemoteAddr().String())
	id, err := TCPSocketCgroup(client, server)
	if errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.ENOENT) || errors.Is(err, ErrNoCgroupID) || errors.Is(err, ErrNoTCPDiag) {
		t.Skipf("this kernel answers no socket cgroup over sock_diag: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	cg, err := runscope.Unified(b)
	if err != nil || runscope.OutsideNamespace(cg) {
		t.Skipf("no cgroup v2 path to compare with: %q %v", cg, err)
	}
	fi, err := os.Stat(filepath.Join("/sys/fs/cgroup", cg))
	if err != nil {
		t.Skipf("the cgroup2 mount is not at /sys/fs/cgroup here: %v", err)
	}
	if ino := fi.Sys().(*syscall.Stat_t).Ino; ino != id {
		t.Errorf("sock_diag cgroup id %d, the directory of %s is inode %d", id, cg, ino)
	}
	if _, err := TCPSocketCgroup(netip.MustParseAddrPort("127.0.0.1:1"), server); !errors.Is(err, ErrNoSocket) {
		t.Errorf("a tuple with no socket: %v, want ErrNoSocket", err)
	}
}

// TestParseDiagCgroup: the reply's tuple must be the question's, the cgroup id attribute must be whole, and an error
// reply's ENOENT is ErrNoSocket.
func TestParseDiagCgroup(t *testing.T) {
	client, server := netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:8000")
	ne := binary.NativeEndian
	reply := func(tupleFrom netip.AddrPort, attrs ...[]byte) []byte {
		body := make([]byte, diagMsgLen)
		body[0] = unix.AF_INET
		putDiagTuple(body[4:], unix.AF_INET, tupleFrom, server)
		for _, a := range attrs {
			body = append(body, a...)
		}
		msg := make([]byte, diagHdrLen, diagHdrLen+len(body))
		msg = append(msg, body...)
		ne.PutUint32(msg[0:], uint32(len(msg)))
		ne.PutUint16(msg[4:], unix.SOCK_DIAG_BY_FAMILY)
		return msg
	}
	attr := func(typ uint16, val []byte) []byte {
		a := make([]byte, 4, 4+len(val)+3)
		ne.PutUint16(a[0:], uint16(4+len(val)))
		ne.PutUint16(a[2:], typ)
		a = append(a, val...)
		for len(a)%4 != 0 {
			a = append(a, 0)
		}
		return a
	}
	idv := make([]byte, 8)
	ne.PutUint64(idv, 4242)
	if id, err := parseDiagCgroup(reply(client, attr(8, []byte{3}), attr(diagAttrCgroupID, idv)), unix.AF_INET, client, server); err != nil || id != 4242 {
		t.Errorf("a reply with the id after another attribute: %d %v", id, err)
	}
	if _, err := parseDiagCgroup(reply(netip.MustParseAddrPort("127.0.0.1:40001"), attr(diagAttrCgroupID, idv)), unix.AF_INET, client, server); err == nil ||
		!strings.Contains(err.Error(), "another socket") {
		t.Errorf("a reply about another socket: %v", err)
	}
	if _, err := parseDiagCgroup(reply(client, attr(8, []byte{3})), unix.AF_INET, client, server); !errors.Is(err, ErrNoCgroupID) {
		t.Errorf("a reply with no cgroup id: %v", err)
	}
	if _, err := parseDiagCgroup(reply(client, attr(diagAttrCgroupID, idv[:4])), unix.AF_INET, client, server); err == nil {
		t.Error("a short cgroup id was taken")
	}
	bad := reply(client, attr(diagAttrCgroupID, idv))
	ne.PutUint16(bad[diagHdrLen+diagMsgLen:], 200) // an attribute longer than the message
	if _, err := parseDiagCgroup(bad, unix.AF_INET, client, server); err == nil {
		t.Error("an attribute past the message's end was read")
	}
	e := make([]byte, diagHdrLen+4)
	ne.PutUint32(e[0:], uint32(len(e)))
	ne.PutUint16(e[4:], diagErrorType)
	errno := -int32(unix.ENOENT)
	ne.PutUint32(e[diagHdrLen:], uint32(errno))
	if _, err := parseDiagCgroup(e, unix.AF_INET, client, server); !errors.Is(err, ErrNoSocket) {
		t.Errorf("ENOENT: %v", err)
	}
	if _, err := parseDiagCgroup(e[:10], unix.AF_INET, client, server); err == nil {
		t.Error("a short reply was taken")
	}
}

// TestDiagProbeENOENT: tcpDiagMissing's empty dump says the kernel has no TCP socket diagnostics only when its answer
// carries ENOENT, as an NLMSG_ERROR or an NLMSG_DONE's status; a plain NLMSG_DONE, a listed socket, another errno or a
// short answer leaves the miss ErrNoSocket.
func TestDiagProbeENOENT(t *testing.T) {
	ne := binary.NativeEndian
	answer := func(typ uint16, status int32) []byte {
		m := make([]byte, diagHdrLen+4)
		ne.PutUint32(m[0:], uint32(len(m)))
		ne.PutUint16(m[4:], typ)
		ne.PutUint32(m[diagHdrLen:], uint32(status))
		return m
	}
	for _, tc := range []struct {
		name string
		msg  []byte
		want bool
	}{
		{"error ENOENT", answer(diagErrorType, -int32(unix.ENOENT)), true},
		{"done ENOENT", answer(unix.NLMSG_DONE, -int32(unix.ENOENT)), true},
		{"done", answer(unix.NLMSG_DONE, 0), false},
		{"error EPERM", answer(diagErrorType, -int32(unix.EPERM)), false},
		{"a socket listed", answer(unix.SOCK_DIAG_BY_FAMILY, -int32(unix.ENOENT)), false},
		{"short", answer(diagErrorType, -int32(unix.ENOENT))[:diagHdrLen+2], false},
	} {
		if got := diagProbeENOENT(tc.msg); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	// On this machine: the kernel either answers TCP lookups or does not; a lookup of no socket says which.
	_, err := TCPSocketCgroup(netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2"))
	if !errors.Is(err, ErrNoSocket) && !errors.Is(err, ErrNoTCPDiag) && !errors.Is(err, unix.EPROTONOSUPPORT) {
		t.Errorf("a tuple with no socket: %v, want ErrNoSocket or ErrNoTCPDiag", err)
	}
}
