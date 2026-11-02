// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// TCPSocketCgroup is the loopback half of the peer check, for the dashboard's TCP listener: the id of
// the cgroup a TCP client socket was made in. A unix socket's peer is identified by SO_PEERCRED (Identify); a TCP
// peer has no such credential, so the kernel's socket-diagnostics netlink family (sock_diag(7)) is asked for the
// client's own socket by its exact tuple: a SOCK_DIAG_BY_FAMILY request that names the 4-tuple and omits NLM_F_DUMP
// is one lookup in the established hash (inet_diag_find_one_icsk), and its answer carries INET_DIAG_CGROUP_ID, the id
// of the cgroup v2 directory the socket was made in (sk_cgrp_data, set when the socket is made, from the making
// task's cgroup, and never moved after). That id is the inode number of the cgroup's directory under the cgroup2
// mount, which a caller compares with the directories of the runs it knows (internal/control/web governed.go).
//
// The socket's cgroup, not its holder's: a scan of a run's processes' /proc/<pid>/fd would miss every non-dumpable
// process (prctl PR_SET_DUMPABLE 0, which hardened agent CLIs set), since /proc hides its descriptors from its own
// uid; the cgroup a socket was made in is the kernel's record and no process can hide it. A process that left its
// run's cgroup before making the socket is outside this check, as it is outside every cgroup-based one
// (docs/adr/0123-dashboard-threat-model.md).
//
// It needs no privilege for a socket in this network namespace, which is where a loopback client's is. Anything it
// cannot read or match is an error: a caller that refuses on the error fails closed. A miss on a kernel that has no
// TCP socket diagnostics loaded is ErrNoTCPDiag, not ErrNoSocket, so the refusal names what the machine lacks.
func TCPSocketCgroup(client, server netip.AddrPort) (uint64, error) {
	id, err := tcpSocketCgroup(client, server)
	if errors.Is(err, ErrNoSocket) && tcpDiagMissing() {
		return 0, ErrNoTCPDiag
	}
	return id, err
}

// tcpSocketCgroup is TCPSocketCgroup's lookup: the v4 family, then the v4-mapped v6 one, or the v6 family.
func tcpSocketCgroup(client, server netip.AddrPort) (uint64, error) {
	client, server = unmapAP(client), unmapAP(server)
	if client.Addr().Is4() && server.Addr().Is4() {
		id, err := sockDiagCgroup(unix.AF_INET, client, server)
		if err == nil {
			return id, nil
		}
		// A dual-stack client socket carries a v4 connection in AF_INET6, with v4-mapped addresses.
		if id, err6 := sockDiagCgroup(unix.AF_INET6, mapAP(client), mapAP(server)); err6 == nil {
			return id, nil
		}
		return 0, err
	}
	return sockDiagCgroup(unix.AF_INET6, client, server)
}

// ErrNoSocket is a lookup the kernel answered with no socket for the tuple (the client closed it already).
var ErrNoSocket = errors.New("sock_diag: no socket for the tuple")

// ErrNoTCPDiag is a kernel that answers no TCP socket lookup at all: inet_diag or tcp_diag (CONFIG_INET_DIAG,
// CONFIG_INET_TCP_DIAG) is a module that is not loaded and could not be loaded on demand, on a host that forbids module
// loading or in a guest with no modprobe (test/vm/root-suites.sh's guests, which load them by name). sock_diag answers
// that lookup ENOENT, as it answers a tuple no socket has, so tcpDiagMissing tells the two apart.
var ErrNoTCPDiag = errors.New("sock_diag: the kernel answers no TCP socket lookup (the inet_diag and tcp_diag modules are not loaded)")

// ErrNoCgroupID is an answer without INET_DIAG_CGROUP_ID: a kernel built without CONFIG_SOCK_CGROUP_DATA, or older
// than the attribute (Linux 5.10).
var ErrNoCgroupID = errors.New("sock_diag: the kernel's answer names no cgroup")

// Sizes of the structures in linux/inet_diag.h and linux/netlink.h; golang.org/x/sys defines the constants but not
// these structures (internal/runtime/capture/forwarder sockdiag.go reads the same; the dashboard may not import
// the runtime).
const (
	diagHdrLen       = 16                     // struct nlmsghdr
	diagSockIDLen    = 48                     // struct inet_diag_sockid: sport, dport, src[4], dst[4], if, cookie[2]
	diagReqV2Len     = 8 + diagSockIDLen      // struct inet_diag_req_v2: family, protocol, ext, pad, states, id
	diagMsgLen       = 4 + diagSockIDLen + 20 // struct inet_diag_msg: ..., id, expires, rqueue, wqueue, uid, inode
	diagTupleLen     = 36                     // sport, dport, src[4], dst[4]: the part of the id a reply echoes
	diagErrorType    = 2                      // NLMSG_ERROR
	diagAttrCgroupID = 21                     // INET_DIAG_CGROUP_ID (linux/inet_diag.h, Linux 5.10)
	diagReplyMax     = 8 << 10                // one answer: the message and its few attributes
	diagMaxAttrs     = 64                     // attributes read before an answer is refused as malformed
)

// sockDiagCgroup is one exact lookup in one address family.
func sockDiagCgroup(family uint8, client, server netip.AddrPort) (uint64, error) {
	reply, err := diagExchange(diagRequest(family, client, server))
	if err != nil {
		return 0, err
	}
	return parseDiagCgroup(reply, family, client, server)
}

// tcpDiagMissing reports whether the kernel has no TCP socket diagnostics: asked for a dump of the TCP sockets in no
// state, which lists nothing, a kernel with inet_diag and tcp_diag answers NLMSG_DONE, and one without them ENOENT, the
// answer its exact lookup gave. Any other answer, or none, is not taken for a missing module: the miss stays
// ErrNoSocket.
func tcpDiagMissing() bool {
	req := diagRequest(unix.AF_INET, netip.AddrPortFrom(netip.IPv4Unspecified(), 0), netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[diagHdrLen+4:], 0) // no state: the dump lists no socket
	reply, err := diagExchange(req)
	return err == nil && diagProbeENOENT(reply)
}

// diagProbeENOENT reads tcpDiagMissing's answer: true for an NLMSG_ERROR, or an NLMSG_DONE whose status is set, carrying
// ENOENT.
func diagProbeENOENT(msg []byte) bool {
	ne := binary.NativeEndian
	if len(msg) < diagHdrLen+4 || int(ne.Uint32(msg[0:])) < diagHdrLen+4 || int(ne.Uint32(msg[0:])) > len(msg) {
		return false
	}
	switch ne.Uint16(msg[4:]) {
	case diagErrorType, unix.NLMSG_DONE:
		return unix.Errno(-int32(ne.Uint32(msg[diagHdrLen:]))) == unix.ENOENT
	}
	return false
}

// diagExchange sends one sock_diag request on a socket of its own and returns the first datagram of the answer.
func diagExchange(req []byte) ([]byte, error) {
	fd, err := sys.Own(unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG))
	if err != nil {
		return nil, fmt.Errorf("sock_diag: socket: %w", err)
	}
	defer func() { _ = fd.Close() }() // a receive-only netlink socket: closing it loses nothing
	var reply []byte
	err = fd.Borrow(func(n int) error {
		// The kernel answers an exact lookup inside the send that asks it; the timeout is for one that does not.
		if err := unix.SetsockoptTimeval(n, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
			return fmt.Errorf("sock_diag: timeout: %w", err)
		}
		if err := unix.Sendto(n, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return fmt.Errorf("sock_diag: send: %w", err)
		}
		buf := make([]byte, diagReplyMax)
		got, _, err := unix.Recvfrom(n, buf, 0)
		if err != nil {
			return fmt.Errorf("sock_diag: receive: %w", err)
		}
		reply = buf[:got]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// diagRequest is an nlmsghdr and an inet_diag_req_v2 naming one TCP socket by its tuple, in any state, with no cookie
// (INET_DIAG_NOCOOKIE). Ports and addresses are in network order; the header is in host order.
func diagRequest(family uint8, client, server netip.AddrPort) []byte {
	req := make([]byte, diagHdrLen+diagReqV2Len)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST)
	ne.PutUint32(req[8:], 1) // sequence
	body := req[diagHdrLen:]
	body[0], body[1] = family, unix.IPPROTO_TCP
	ne.PutUint32(body[4:], 0xffffffff) // every TCP state
	putDiagTuple(body[8:], family, client, server)
	ne.PutUint64(body[8+40:], 0xffffffffffffffff) // the cookie: INET_DIAG_NOCOOKIE
	return req
}

// putDiagTuple writes the tuple part of an inet_diag_sockid: the socket's own end as source, the far end as
// destination, an AF_INET address in the first four bytes of its sixteen.
func putDiagTuple(id []byte, family uint8, src, dst netip.AddrPort) {
	binary.BigEndian.PutUint16(id[0:], src.Port())
	binary.BigEndian.PutUint16(id[2:], dst.Port())
	if family == unix.AF_INET {
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(id[4:], s[:])
		copy(id[20:], d[:])
		return
	}
	s, d := src.Addr().As16(), dst.Addr().As16()
	copy(id[4:], s[:])
	copy(id[20:], d[:])
}

// parseDiagCgroup reads the kernel's answer: an inet_diag_msg for the socket with its attributes, or an NLMSG_ERROR
// whose errno is ENOENT for a tuple no socket has. The reply's own tuple is checked against the question, so an
// answer about any other socket is never taken for this connection's.
func parseDiagCgroup(msg []byte, family uint8, client, server netip.AddrPort) (uint64, error) {
	ne := binary.NativeEndian
	if len(msg) < diagHdrLen {
		return 0, fmt.Errorf("sock_diag: short reply of %d bytes", len(msg))
	}
	total := int(ne.Uint32(msg[0:]))
	if total < diagHdrLen || total > len(msg) {
		return 0, fmt.Errorf("sock_diag: reply length %d of %d bytes", total, len(msg))
	}
	msg = msg[:total]
	switch typ := ne.Uint16(msg[4:]); typ {
	case diagErrorType:
		if len(msg) < diagHdrLen+4 {
			return 0, errors.New("sock_diag: short error reply")
		}
		errno := unix.Errno(-int32(ne.Uint32(msg[diagHdrLen:])))
		if errno == unix.ENOENT {
			return 0, ErrNoSocket
		}
		return 0, fmt.Errorf("sock_diag: %w", errno)
	case unix.SOCK_DIAG_BY_FAMILY:
	default:
		return 0, fmt.Errorf("sock_diag: reply of type %d", typ)
	}
	body := msg[diagHdrLen:]
	if len(body) < diagMsgLen || body[0] != family {
		return 0, errors.New("sock_diag: reply is not an inet_diag_msg of the family asked")
	}
	want := make([]byte, diagTupleLen)
	putDiagTuple(want, family, client, server)
	for i := range diagTupleLen {
		if body[4+i] != want[i] {
			return 0, errors.New("sock_diag: reply names another socket")
		}
	}
	attrs := body[diagMsgLen:]
	for range diagMaxAttrs {
		if len(attrs) < 4 {
			return 0, ErrNoCgroupID
		}
		l, t := int(ne.Uint16(attrs[0:])), ne.Uint16(attrs[2:]) // struct rtattr: len (header included), type
		if l < 4 || l > len(attrs) {
			return 0, fmt.Errorf("sock_diag: attribute length %d of %d bytes", l, len(attrs))
		}
		if t == diagAttrCgroupID {
			if l != 4+8 {
				return 0, fmt.Errorf("sock_diag: cgroup id of %d bytes", l-4)
			}
			id := ne.Uint64(attrs[4:])
			if id == 0 {
				return 0, errors.New("sock_diag: cgroup id 0")
			}
			return id, nil
		}
		step := (l + 3) &^ 3 // RTA_ALIGN
		if step >= len(attrs) {
			return 0, ErrNoCgroupID
		}
		attrs = attrs[step:]
	}
	return 0, errors.New("sock_diag: too many attributes")
}

func unmapAP(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func mapAP(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port())
}
