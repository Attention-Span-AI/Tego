// SPDX-License-Identifier: Apache-2.0

package thishost

import (
	"net/netip"
	"strings"
)

// Addrs is what only the running host can tell about an address.
type Addrs interface {
	// Own reports whether a is one of this host's addresses: one assigned to an interface, or one in a range the
	// kernel's local routing table delivers here as its own (a `local` route: 127.0.0.0/8, an AnyIP range).
	Own(a netip.Addr) bool
	// Broadcast reports whether a is a broadcast address of this host: a subnet's, from its mask, or one a `broadcast`
	// route of the local table names, such as one set by hand.
	Broadcast(a netip.Addr) bool
	// Anycast reports whether a is an IPv6 anycast address this host joined, an `anycast` route of the local table, as
	// a forwarding host joins each of its subnets' router anycast address.
	Anycast(a netip.Addr) bool
}

// limitedBroadcast is 255.255.255.255, which the kernel delivers to this host as well as to its link.
var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Names reports whether a names this host, as a block or a rule can: a connection to it stays here. A server bound to
// all interfaces answers on every loopback address and on each of the host's own, and the kernel sends a connection to
// an unspecified address to loopback or to the socket's bound source. a is read unmapped and with no zone.
func Names(a netip.Addr, h Addrs) bool {
	a = a.Unmap().WithZone("")
	return a.IsLoopback() || a.IsUnspecified() || h != nil && h.Own(a)
}

// Reaches reports whether a send to destination a reaches this host. That is every address Names, and the group
// addresses, which name no host at all and so count on the destination's side only: a datagram to a multicast group,
// the limited broadcast or a broadcast address of this host is delivered to a local UDP socket bound to all interfaces
// as well as to the link, and one to an IPv6 anycast address this host joined is delivered to that socket. A block or
// rule on one of them says nothing about this host.
func Reaches(a netip.Addr, h Addrs) bool {
	a = a.Unmap().WithZone("")
	return Names(a, h) || a.IsMulticast() || a == limitedBroadcast || h != nil && (h.Broadcast(a) || h.Anycast(a))
}

// Name reports whether host is a name RFC 6761 §6.3 reserves for loopback, localhost or a name under .localhost, which
// needs no lookup to name this host. A trailing dot and the case of the name mean nothing.
func Name(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}
