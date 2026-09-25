// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// The peer's socket inode by exact tuple, from the kernel's socket-diagnostics netlink family (sock_diag(7),
// R19a). /proc/net/tcp answers the same question by printing every TCP socket in the namespace, which
// peerSocketInode then reads row by row: its cost grows with every connection open on the host, the run's own
// included, and the forwarder pays it once per connection. A SOCK_DIAG_BY_FAMILY request that names the full
// 4-tuple and omits NLM_F_DUMP is a single lookup in the kernel's established hash (inet_diag_find_one_icsk),
// so its cost does not depend on how many sockets exist. It needs no privilege for a socket in this network
// namespace, which is where a loopback peer's is. peerSocketInode stays as the fallback for a kernel built
// without inet_diag, or one that refuses the request; a kernel that answers no TCP socket lookup at all is found
// once and the run goes straight to it after that (tcpDiag).

// Sizes and offsets of the structures in linux/inet_diag.h and linux/netlink.h. golang.org/x/sys defines the
// constants but not these structures.
const (
	nlmsgHdrLen      = 16                      // struct nlmsghdr
	inetDiagSockID   = 48                      // struct inet_diag_sockid: sport, dport, src[4], dst[4], if, cookie[2]
	inetDiagReqV2Len = 8 + inetDiagSockID      // struct inet_diag_req_v2: family, protocol, ext, pad, states, id
	inetDiagMsgLen   = 4 + inetDiagSockID + 20 // struct inet_diag_msg: ..., id, expires, rqueue, wqueue, uid, inode
	inetDiagInodeOff = 4 + inetDiagSockID + 16
	nlmsgErrorType   = 2 // NLMSG_ERROR
)

// errSockDiagMiss is a lookup the kernel answered with no socket for the tuple.
var errSockDiagMiss = errors.New("sock_diag: no socket for the tuple")

// errSockDiagUnsupported is a kernel that answers no TCP socket lookup at all: one whose socket(2) refuses the
// NETLINK_SOCK_DIAG protocol, or one where inet_diag or tcp_diag (CONFIG_INET_DIAG, CONFIG_INET_TCP_DIAG) is a module
// that is not loaded and could not be loaded on demand (a host that forbids module loading, a guest with no
// modprobe). sock_diag answers the second ENOENT, as it answers a tuple no socket has, so tcpDiagMissing tells the
// two apart, as internal/platform/peer's does for the dashboard (the runtime may not import the dashboard's
// packages, nor they the runtime's, so each reads the answer itself).
var errSockDiagUnsupported = errors.New("sock_diag: the kernel answers no TCP socket lookup (the inet_diag and " +
	"tcp_diag modules are not loaded)")

// tcpDiag is a run's exact socket lookup (sockDiagInode) and what it learned of the kernel. The first lookup that
// shows the kernel answers no TCP socket lookup at all (errSockDiagUnsupported, or a miss the probe tcpDiagMissing
// confirms is the kernel's) turns it off for the rest of the run and says so once in the run's own log: every later
// connection then goes straight to the tcp tables (peerSocketInode), the fallback it reached anyway, without the two
// netlink round trips that cannot answer and the probe before it. A miss on a kernel that has the modules (a peer
// that closed its socket already) stays a miss, and the next connection asks again. The run's listeners share one
// (Manager), so the run's log says it once.
type tcpDiag struct {
	// lookup is the exact lookup and missing the probe that tells a kernel without TCP sock_diag from a miss
	// (sockDiagInode, tcpDiagMissing); a test replaces both before the first connection.
	lookup  func(peer, local netip.AddrPort) (uint64, error)
	missing func() bool
	logger  *slog.Logger
	// off is set once the kernel showed it has no TCP sock_diag, and once says so in the log the first time.
	off  atomic.Bool
	once sync.Once
}

// newTCPDiag is a run's lookup, logging to logger (nil discards).
func newTCPDiag(logger *slog.Logger) *tcpDiag {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &tcpDiag{lookup: sockDiagInode, missing: tcpDiagMissing, logger: logger}
}

// inode is the peer's socket inode by the exact lookup. errSockDiagUnsupported says the kernel has no TCP sock_diag
// (the caller's fallback answers, as it answers any error); any other error is the lookup's own, the miss among them.
func (d *tcpDiag) inode(peer, local netip.AddrPort) (uint64, error) {
	if d.off.Load() {
		return 0, errSockDiagUnsupported
	}
	ino, err := d.lookup(peer, local)
	switch {
	case err == nil:
		return ino, nil
	case errors.Is(err, errSockDiagUnsupported):
	case errors.Is(err, errSockDiagMiss) && d.missing():
		err = fmt.Errorf("%w (a dump of no TCP socket was answered ENOENT, as the lookup was)", errSockDiagUnsupported)
	default:
		return 0, err
	}
	d.off.Store(true)
	d.once.Do(func() {
		d.logger.Warn("forwarder: the kernel answers no TCP socket lookup, so each connection's peer is looked for in "+
			"/proc/net/tcp for the rest of the run, at a cost that grows with the host's connections; load the modules "+
			"(sudo modprobe tcp_diag) for the exact lookup", "err", err)
	})
	return 0, errSockDiagUnsupported
}

// sockDiagInode is the inode of the socket whose local end is peer and whose remote end is local: the peer's side
// of this connection, as scanTCPTable's row order has it. A v4 connection is asked of AF_INET and then of AF_INET6
// with v4-mapped addresses, since a dual-stack peer socket carries a v4 connection in the second family.
func sockDiagInode(peer, local netip.AddrPort) (uint64, error) {
	if peer.Addr().Is4() && local.Addr().Is4() {
		ino, err := sockDiagQuery(unix.AF_INET, peer, local)
		if err == nil {
			return ino, nil
		}
		mapped := func(ap netip.AddrPort) netip.AddrPort {
			return netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port())
		}
		if ino, err6 := sockDiagQuery(unix.AF_INET6, mapped(peer), mapped(local)); err6 == nil {
			return ino, nil
		}
		return 0, err
	}
	return sockDiagQuery(unix.AF_INET6, peer, local)
}

// sockDiagQuery is one exact lookup in one address family.
func sockDiagQuery(family uint8, peer, local netip.AddrPort) (uint64, error) {
	reply, err := sockDiagExchange(sockDiagRequest(family, peer, local))
	if err != nil {
		return 0, err
	}
	return parseSockDiagReply(reply, family, peer, local)
}

// sockDiagExchange sends one sock_diag request on a socket of its own and returns the first datagram of the answer.
// A socket(2) that refuses the protocol or the family is errSockDiagUnsupported: the kernel has no sock_diag.
func sockDiagExchange(req []byte) ([]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		if errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.EAFNOSUPPORT) {
			return nil, fmt.Errorf("%w: socket: %w", errSockDiagUnsupported, err)
		}
		return nil, fmt.Errorf("sock_diag: socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	// The kernel answers an exact lookup inside the sendmsg that asks it, so the receive below finds the answer
	// already queued; the timeout is for a kernel that somehow does not, which is then the fallback's to answer.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return nil, fmt.Errorf("sock_diag: timeout: %w", err)
	}
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag: send: %w", err)
	}
	buf := make([]byte, 1024)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("sock_diag: receive: %w", err)
	}
	return buf[:n], nil
}

// tcpDiagMissing reports whether the kernel has no TCP socket diagnostics: asked for a dump of the TCP sockets in no
// state, which lists nothing, a kernel with inet_diag and tcp_diag answers NLMSG_DONE, and one without them ENOENT,
// the answer its exact lookup gave. Any other answer, or none, is not taken for a missing module: the miss stays one.
func tcpDiagMissing() bool {
	any4 := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	req := sockDiagRequest(unix.AF_INET, any4, any4)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[nlmsgHdrLen+4:], 0) // no state: the dump lists no socket
	reply, err := sockDiagExchange(req)
	return err == nil && probeAnsweredENOENT(reply)
}

// probeAnsweredENOENT reads tcpDiagMissing's answer: true for an NLMSG_ERROR, or an NLMSG_DONE whose status is set,
// carrying ENOENT.
func probeAnsweredENOENT(msg []byte) bool {
	ne := binary.NativeEndian
	if len(msg) < nlmsgHdrLen+4 || int(ne.Uint32(msg[0:])) < nlmsgHdrLen+4 || int(ne.Uint32(msg[0:])) > len(msg) {
		return false
	}
	switch ne.Uint16(msg[4:]) {
	case nlmsgErrorType, unix.NLMSG_DONE:
		return unix.Errno(-int32(ne.Uint32(msg[nlmsgHdrLen:]))) == unix.ENOENT
	}
	return false
}

// sockDiagRequest is an nlmsghdr and an inet_diag_req_v2 naming one TCP socket by its tuple, in any state, with
// no cookie (INET_DIAG_NOCOOKIE). Ports and addresses are in network order; the header is in host order.
func sockDiagRequest(family uint8, peer, local netip.AddrPort) []byte {
	req := make([]byte, nlmsgHdrLen+inetDiagReqV2Len)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST)
	ne.PutUint32(req[8:], 1) // sequence
	body := req[nlmsgHdrLen:]
	body[0], body[1] = family, unix.IPPROTO_TCP
	ne.PutUint32(body[4:], 0xffffffff) // every TCP state
	putSockID(body[8:], family, peer, local)
	binary.NativeEndian.PutUint64(body[8+40:], 0xffffffffffffffff) // cookie: INET_DIAG_NOCOOKIE
	return req
}

// putSockID writes the tuple part of an inet_diag_sockid: the socket's own end as source, the far end as
// destination, an AF_INET address in the first four bytes of its sixteen.
func putSockID(id []byte, family uint8, src, dst netip.AddrPort) {
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

// parseSockDiagReply reads the kernel's answer: an inet_diag_msg for the socket, or an NLMSG_ERROR whose errno is
// ENOENT for a tuple no socket has. The reply's own tuple is checked against the question, so a reply to anything
// else is never taken for this connection's.
func parseSockDiagReply(msg []byte, family uint8, peer, local netip.AddrPort) (uint64, error) {
	ne := binary.NativeEndian
	if len(msg) < nlmsgHdrLen {
		return 0, fmt.Errorf("sock_diag: short reply of %d bytes", len(msg))
	}
	switch typ := ne.Uint16(msg[4:]); typ {
	case nlmsgErrorType:
		if len(msg) < nlmsgHdrLen+4 {
			return 0, errors.New("sock_diag: short error reply")
		}
		errno := unix.Errno(-int32(ne.Uint32(msg[nlmsgHdrLen:])))
		if errno == unix.ENOENT {
			return 0, errSockDiagMiss
		}
		return 0, fmt.Errorf("sock_diag: %w", errno)
	case unix.SOCK_DIAG_BY_FAMILY:
	default:
		return 0, fmt.Errorf("sock_diag: reply of type %d", typ)
	}
	body := msg[nlmsgHdrLen:]
	if len(body) < inetDiagMsgLen || body[0] != family {
		return 0, errors.New("sock_diag: reply is not an inet_diag_msg of the family asked")
	}
	want := make([]byte, 36)
	putSockID(want, family, peer, local)
	for i := range 36 {
		if body[4+i] != want[i] {
			return 0, errors.New("sock_diag: reply names another socket")
		}
	}
	ino := uint64(ne.Uint32(body[inetDiagInodeOff:]))
	if ino == 0 {
		// A socket no file holds any more (TIME_WAIT, or closed and not yet gone) has no inode to look for.
		return 0, errSockDiagMiss
	}
	return ino, nil
}
