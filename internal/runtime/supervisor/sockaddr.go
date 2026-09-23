// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Offsets and sizes inside a sockaddr, as the kernel lays them out (R4).
const (
	sinPortOff   = 2  // sockaddr_in.sin_port, network byte order
	sinAddrOff   = 4  // sockaddr_in.sin_addr
	sinMin       = 8  // the bytes of sockaddr_in that carry the destination
	sin6PortOff  = 2  // sockaddr_in6.sin6_port
	sin6AddrOff  = 8  // sockaddr_in6.sin6_addr, after sin6_flowinfo
	sin6ScopeOff = 24 // sockaddr_in6.sin6_scope_id
	sin6Min      = 24
	sunPathOff   = 2   // sockaddr_un.sun_path
	sunPathMax   = 108 // sizeof(sockaddr_un.sun_path)
)

// dest is a destination address parsed out of a sockaddr the target passed. Only one of the address forms
// is set; ok is false for a family this tier does not understand or a buffer too short to carry one (E4).
type dest struct {
	// family is the raw ss_family value, kept even when ok is false so the event and the log can name it.
	family uint16
	// ap is the destination for AF_INET and AF_INET6, with an IPv4-mapped IPv6 address unmapped.
	ap netip.AddrPort
	// unixPath is a pathname socket's sun_path exactly as the target wrote it: possibly relative, to be
	// resolved against /proc/<pid>/cwd (R11).
	unixPath string
	// abstract is an abstract socket's name: the raw bytes after the leading NUL, never NUL-scanned (E5).
	abstract []byte
	// unnamed is an AF_UNIX address with an empty sun_path (an autobound socket).
	unnamed bool
	// ok reports whether the address was understood.
	ok bool
}

// isInet reports whether the destination is an IP address.
func (d dest) isInet() bool { return d.family == unix.AF_INET || d.family == unix.AF_INET6 }

// isUnix reports whether the destination is a unix socket.
func (d dest) isUnix() bool { return d.family == unix.AF_UNIX }

// isUnspec reports whether the address really carried the family AF_UNSPEC. ok is part of the test because
// a buffer too short to carry a family reads as family 0 without being an AF_UNSPEC address; that one is
// unreadable (E4). What an AF_UNSPEC address means depends on the syscall it arrived in: see decidable.
func (d dest) isUnspec() bool { return d.family == unix.AF_UNSPEC && d.ok }

// decidable reports whether the policy can be matched against this address in the syscall it arrived in.
// An unrecognised family never can (R4, E4). AF_UNSPEC can only in connect(2), where the kernel routes it
// straight to the protocol's disconnect (__inet_dgram_connect, __inet_stream_connect) and it names nowhere
// (R4's carve-out). A send reads the same bytes as an address, and which address depends on a socket
// domain this tier never reads: udp_sendmsg and raw_sendmsg take them as a sockaddr_in, rawv6_sendmsg as a
// sockaddr_in6, udpv6_sendmsg as "no address, use the peer". So outside connect(2) it is one more family
// this tier does not parse, and it takes that family's fail-closed answer (R4).
func (d dest) decidable(connectOp bool) bool { return d.ok && (connectOp || !d.isUnspec()) }

// String renders the destination for the event's dst field: "ip:port" for inet, "unix:<path>",
// "unix:@<name>" for abstract, "unspec" for an AF_UNSPEC address, and "family(<n>)" for anything else.
func (d dest) String() string {
	switch {
	case d.isInet() && d.ap.IsValid():
		return d.ap.String()
	case d.isUnix() && len(d.abstract) > 0:
		return "unix:@" + printable(string(d.abstract))
	case d.isUnix() && d.unixPath != "":
		return "unix:" + d.unixPath
	case d.isUnix():
		return "unix:"
	case d.isUnspec():
		return "unspec"
	}
	return "family(" + strconv.Itoa(int(d.family)) + ")"
}

// unzoned is d without the IPv6 scope id: the destination as the kernel recorder's copy of the address names it.
func (d dest) unzoned() dest {
	if d.ap.IsValid() {
		d.ap = netip.AddrPortFrom(d.ap.Addr().WithZone(""), d.ap.Port())
	}
	return d
}

// parseSockaddr decodes the bytes read out of the target. It never reads past what it was given, never
// trusts a length field inside the buffer, and never allocates on a length the target supplied (R3, R4).
func parseSockaddr(b []byte) dest {
	if len(b) > sockaddrMax {
		b = b[:sockaddrMax]
	}
	if len(b) < 2 {
		return dest{}
	}
	d := dest{family: uint16(leU16(b))}
	switch d.family {
	case unix.AF_UNSPEC:
		// Understood, but carrying nothing this parse can name: in connect(2) it is the defined request to
		// dissolve a socket's association, and in a send it is an address whose layout depends on the
		// socket's domain. Which of the two it is belongs to the syscall, so decidable answers it, not this.
		d.ok = true
	case unix.AF_INET:
		if len(b) < sinMin {
			return d
		}
		var a [4]byte
		copy(a[:], b[sinAddrOff:sinAddrOff+4])
		d.ap = netip.AddrPortFrom(netip.AddrFrom4(a), beU16(b[sinPortOff:]))
		d.ok = true
	case unix.AF_INET6:
		if len(b) < sin6Min {
			return d
		}
		var a [16]byte
		copy(a[:], b[sin6AddrOff:sin6AddrOff+16])
		addr := netip.AddrFrom16(a).Unmap()
		if len(b) >= sin6ScopeOff+4 {
			if zone := leU32(b[sin6ScopeOff:]); zone != 0 && addr.Is6() {
				addr = addr.WithZone(strconv.FormatUint(uint64(zone), 10))
			}
		}
		d.ap = netip.AddrPortFrom(addr, beU16(b[sin6PortOff:]))
		d.ok = true
	case unix.AF_UNIX:
		p := b[min(len(b), sunPathOff):]
		if len(p) > sunPathMax {
			p = p[:sunPathMax]
		}
		switch {
		case len(p) == 0:
			d.unnamed = true
		case p[0] == 0:
			// Abstract: the name is exactly the bytes the caller passed after the leading NUL, bounded by
			// the addrlen the read already clamped to, embedded and trailing NULs included. The kernel
			// takes it the same way — @bus and @bus\0\0 are two different sockets — so nothing is
			// trimmed or NUL-scanned here (E5). A name of no bytes at all is an unnamed socket.
			if len(p) == 1 {
				d.unnamed = true
				break
			}
			d.abstract = append([]byte(nil), p[1:]...)
		default:
			if i := indexNUL(p); i >= 0 {
				p = p[:i]
			}
			d.unixPath = string(p)
		}
		d.ok = true
	}
	return d
}

// indexNUL is bytes.IndexByte(b, 0) without the import.
func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// leU16 decodes a host-order (little-endian) 16-bit field such as ss_family.
func leU16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

// beU16 decodes a network-order 16-bit field such as a port.
func beU16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

// printable replaces the bytes of an abstract name that would not survive a log line or a JSON string.
func printable(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c < 0x20 || c == 0x7f {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
