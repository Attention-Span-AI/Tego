// SPDX-License-Identifier: Apache-2.0

package hostaddr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// LocalTable is what the kernel's routing tables send to this host, which no address list says: the destinations of
// their routes of three types, both families, in the tables the kernel's default policy rules look up (`ip rule`:
// local, then main, then default). The kernel writes its own in table local (`ip route show table local`) as addresses
// come and go: a `local` route for each address and for the whole subnet of one on a loopback interface
// (127.0.0.0/8), a `broadcast` route for an IPv4 subnet's broadcast address and for one set by hand (`ip addr ...
// brd`), and an `anycast` route for each IPv6 anycast address the host joins, as a forwarding host joins each of its
// subnets' router anycast address. A person adds a `local` route to make a whole range this host's own (`ip route add
// local 192.0.2.0/24 dev lo`, AnyIP), in table local unless the command names another table. One in main or default
// (`... table main`) delivers here every destination in it that table local, or a more specific route of its own
// table, does not take first, with no rule of anyone's; it is read whole, which can only count more as this host's
// than the kernel delivers here. A route of these types in any other table is not read: only a policy rule a person
// adds, or a VRF, sends lookups there, as TPROXY's `local 0.0.0.0/0 dev lo table 100` takes the packets its rule marks
// and no others.
type LocalTable struct {
	// Local is the destinations of `local` routes, which the kernel delivers here as addresses of its own: a server
	// bound to all interfaces answers on every address in them.
	Local []netip.Prefix
	// Broadcast is the destinations of `broadcast` routes: a datagram sent to one is delivered here as well as to the
	// link.
	Broadcast []netip.Prefix
	// Anycast is the destinations of `anycast` routes, the IPv6 anycast addresses this host joined: a datagram sent to
	// one from here is delivered here.
	Anycast []netip.Prefix
}

const (
	// localTableRecvBytes is one datagram of a dump: the kernel fills at most 32 KiB for a reader whose buffer is that
	// large (netlink_recvmsg's max_recvmsg_len), so none is cut short.
	localTableRecvBytes = 32 << 10
	// localTableMaxDatagrams bounds each dump: a filtered dump of one type's routes is a datagram or two on a host, and
	// one a kernel sends whole, every table, is still far below this unless the host carries a router's tables.
	localTableMaxDatagrams = 4096
)

// localTableTypes are the route types ReadLocalTable reads, one dump each, in this order: the dump of the i-th has
// sequence number i+1, so a message of another number is not its answer.
var localTableTypes = [...]uint8{unix.RTN_LOCAL, unix.RTN_BROADCAST, unix.RTN_ANYCAST}

// ReadLocalTable reads the `local`, `broadcast` and `anycast` routes of both families in the tables the kernel's default
// policy rules look up (LocalTable), with one RTM_GETROUTE dump per type over one NETLINK_ROUTE socket, which needs no
// privilege and no cgo. Each request names its type, which a kernel that checks dump requests strictly
// (NETLINK_GET_STRICT_CHK, Linux 4.20) reads as a filter (ip_valid_fib_dump_req), so each answer holds that type's
// routes of every table and nothing else; one that does not sends every route of every table, and what was not asked
// for is left out here (parseLocalTable). It takes three small answers, where reading tables main and default whole
// would take as many routes as they hold. A route of these types in a table no default rule looks up is not read.
func ReadLocalTable() (LocalTable, error) {
	fd, err := sys.Own(unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE))
	if err != nil {
		return LocalTable{}, fmt.Errorf("hostaddr: local table: socket: %w", err)
	}
	defer func() { _ = fd.Close() }() // a socket only read from: closing it loses nothing
	var t LocalTable
	err = fd.Borrow(func(n int) error {
		// A kernel without strict checking refuses the option and sends every route, which the parse filters, so its
		// error changes nothing.
		_ = unix.SetsockoptInt(n, unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1)
		// The kernel fills each datagram of a dump as it is read; the timeout is for one that does not, since the
		// caller decides under its snapshot's lock.
		if err := unix.SetsockoptTimeval(n, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
			return fmt.Errorf("timeout: %w", err)
		}
		// Bound before the send, as Go's own dump binds its socket (syscall.NetlinkRIB): the kernel picks the port id.
		if err := unix.Bind(n, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return fmt.Errorf("bind: %w", err)
		}
		buf := make([]byte, localTableRecvBytes)
		for i, typ := range localTableTypes {
			if err := readDump(n, buf, uint32(i+1), typ, &t); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return LocalTable{}, fmt.Errorf("hostaddr: local table: %w", err)
	}
	return t, nil
}

// readDump sends the dump of route type typ under sequence number seq on netlink socket n, and reads its answer into t
// through buf. The socket has one dump in flight at a time: the next is sent once this one's end was read.
func readDump(n int, buf []byte, seq uint32, typ uint8, t *LocalTable) error {
	if err := unix.Sendto(n, localTableRequest(seq, typ), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	for range localTableMaxDatagrams {
		got, flags, from, err := recvDatagram(n, buf)
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}
		if sa, ok := from.(*unix.SockaddrNetlink); !ok || sa.Pid != 0 {
			return errors.New("a datagram not from the kernel")
		}
		if flags&unix.MSG_TRUNC != 0 {
			return fmt.Errorf("a datagram longer than %d bytes", len(buf))
		}
		done, err := parseLocalTable(buf[:got], seq, typ, t)
		if err != nil || done {
			return err
		}
	}
	return fmt.Errorf("the dump did not end within %d datagrams", localTableMaxDatagrams)
}

// recvDatagram is one recvmsg, taken again when a signal interrupts it: with a receive timeout set the kernel does not
// restart the call itself, and the Go runtime signals its threads to preempt them.
func recvDatagram(n int, buf []byte) (int, int, unix.Sockaddr, error) {
	for {
		got, _, flags, from, err := unix.Recvmsg(n, buf, nil, 0)
		if err != unix.EINTR {
			return got, flags, from, err
		}
	}
}

// localTableRequest is an RTM_GETROUTE dump of both families (AF_UNSPEC) under sequence number seq whose struct rtmsg
// names route type typ and no table: a kernel that checks dump requests strictly reads the type as a filter in each
// family's dump (ip_valid_fib_dump_req), walks every table and marks each route it sends NLM_F_DUMP_FILTERED. The
// other families that answer an AF_UNSPEC dump take the filter too (MPLS sends nothing for a type other than unicast)
// or send routes of their own family, which the parse leaves out.
func localTableRequest(seq uint32, typ uint8) []byte {
	req := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofRtMsg)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], unix.RTM_GETROUTE)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], seq)
	req[unix.NLMSG_HDRLEN+7] = typ // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
	return req
}

// parseLocalTable reads one datagram of the dump of route type typ, sequence number seq, into t, and done says the dump
// ended. A message that is no route adds nothing, nor does a route of another family or type, of a table no default
// policy rule looks up, or a cached one (addLocalRoute), so a kernel that sends every route to each dump adds each
// route once, in the dump of its type. An error message, an end that carries an error, a message of another sequence
// number, a message the kernel marks interrupted (a table changed while it was read, so a route may be missing) and a
// malformed message are errors, and the caller keeps what it read before.
func parseLocalTable(b []byte, seq uint32, typ uint8, t *LocalTable) (done bool, err error) {
	ne := binary.NativeEndian
	for len(b) > 0 {
		if len(b) < unix.NLMSG_HDRLEN {
			return false, fmt.Errorf("%d bytes after the last message", len(b))
		}
		l := int(ne.Uint32(b[0:]))
		if l < unix.NLMSG_HDRLEN || l > len(b) {
			return false, fmt.Errorf("message length %d of %d bytes", l, len(b))
		}
		mtype, flags, mseq := ne.Uint16(b[4:]), ne.Uint16(b[6:]), ne.Uint32(b[8:])
		body := b[unix.NLMSG_HDRLEN:l]
		if mseq != seq {
			return false, fmt.Errorf("a message of sequence %d in the answer to %d", mseq, seq)
		}
		if flags&unix.NLM_F_DUMP_INTR != 0 {
			return false, errors.New("a table changed while it was read")
		}
		switch mtype {
		case unix.NLMSG_DONE:
			if len(body) >= 4 {
				if e := int32(ne.Uint32(body)); e < 0 {
					return false, unix.Errno(-e)
				}
			}
			return true, nil
		case unix.NLMSG_ERROR:
			if len(body) < 4 {
				return false, errors.New("a short error message")
			}
			if e := int32(ne.Uint32(body)); e < 0 {
				return false, unix.Errno(-e)
			}
			return false, errors.New("an acknowledgement in place of the dump")
		case unix.RTM_NEWROUTE:
			if err := addLocalRoute(body, typ, t); err != nil {
				return false, err
			}
		}
		b = b[min(align4(l), len(b)):]
	}
	return false, nil
}

// lookedUp reports whether the kernel's default policy rules look up table: local, main and default (`ip rule`'s 0,
// 32766 and 32767). IPv6 has no default rule for table default, which stays empty unless a person fills it, so reading
// it there can only count more as this host's; a kernel built without IPv6 policy routing keeps every IPv6 route,
// local ones included, in main.
func lookedUp(table uint32) bool {
	return table == unix.RT_TABLE_LOCAL || table == unix.RT_TABLE_MAIN || table == unix.RT_TABLE_DEFAULT
}

// addLocalRoute adds one route message's destination to t when it is a route of type typ, `local`, `broadcast` or
// `anycast`, in a table the default policy rules look up (parseLocalTable). A route with no RTA_DST is its family's
// default route.
func addLocalRoute(m []byte, typ uint8, t *LocalTable) error {
	ne := binary.NativeEndian
	if len(m) < unix.SizeofRtMsg {
		return fmt.Errorf("a route message of %d bytes", len(m))
	}
	family, bits, table, rtype := m[0], int(m[1]), uint32(m[4]), m[7]
	var size int
	switch family {
	case unix.AF_INET:
		size = 4
	case unix.AF_INET6:
		size = 16
	default:
		return nil // a multicast routing table's or an MPLS route: it names no address of this host
	}
	var dst []byte
	for attrs := m[unix.SizeofRtMsg:]; len(attrs) > 0; {
		if len(attrs) < unix.SizeofRtAttr {
			return fmt.Errorf("%d bytes after the last attribute", len(attrs))
		}
		l, at := int(ne.Uint16(attrs[0:])), ne.Uint16(attrs[2:])&^(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER)
		if l < unix.SizeofRtAttr || l > len(attrs) {
			return fmt.Errorf("attribute length %d of %d bytes", l, len(attrs))
		}
		switch at {
		case unix.RTA_DST:
			dst = attrs[unix.SizeofRtAttr:l]
		case unix.RTA_TABLE:
			if l != unix.SizeofRtAttr+4 {
				return fmt.Errorf("a table attribute of %d bytes", l)
			}
			table = ne.Uint32(attrs[unix.SizeofRtAttr:])
		}
		attrs = attrs[min(align4(l), len(attrs)):]
	}
	if ne.Uint32(m[8:])&unix.RTM_F_CLONED != 0 || rtype != typ || !lookedUp(table) {
		return nil
	}
	var to *[]netip.Prefix
	switch typ {
	case unix.RTN_LOCAL:
		to = &t.Local
	case unix.RTN_BROADCAST:
		to = &t.Broadcast
	case unix.RTN_ANYCAST:
		to = &t.Anycast
	default:
		return nil
	}
	addr := netip.IPv4Unspecified()
	if family == unix.AF_INET6 {
		addr = netip.IPv6Unspecified()
	}
	if dst != nil {
		if len(dst) != size {
			return fmt.Errorf("a destination of %d bytes in family %d", len(dst), family)
		}
		addr, _ = netip.AddrFromSlice(dst)
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return fmt.Errorf("a destination of prefix length %d in family %d", bits, family)
	}
	*to = append(*to, p)
	return nil
}

// align4 is a netlink length rounded up to the 4-byte alignment messages and attributes keep (NLMSG_ALIGN, RTA_ALIGN).
func align4(n int) int { return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1) }

// prefixSet is a set of destinations, the single addresses in a map and the ranges in a list, since a host's local
// table holds a route for each address and few for ranges.
type prefixSet struct {
	addrs  map[netip.Addr]bool
	ranges []netip.Prefix
}

func newPrefixSet(ps []netip.Prefix) prefixSet {
	s := prefixSet{addrs: make(map[netip.Addr]bool, len(ps))}
	for _, p := range ps {
		switch p = p.Masked(); {
		case !p.IsValid():
		case p.IsSingleIP():
			s.addrs[p.Addr()] = true
		default:
			s.ranges = append(s.ranges, p)
		}
	}
	return s
}

// contains reports whether a lies in one of the set's destinations. a is unmapped and has no zone (Snapshot.answer makes
// it so): an IPv4 address matches the IPv4 routes alone, since the kernel routes a v4-mapped destination by its IPv4
// table.
func (s prefixSet) contains(a netip.Addr) bool {
	if s.addrs[a] {
		return true
	}
	for _, p := range s.ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// routeIndex is a LocalTable made ready for lookups.
type routeIndex struct{ local, broadcast, anycast prefixSet }

func indexLocalTable(t LocalTable) routeIndex {
	return routeIndex{newPrefixSet(t.Local), newPrefixSet(t.Broadcast), newPrefixSet(t.Anycast)}
}
