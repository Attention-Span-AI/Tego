// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net"
	"net/netip"
	"strings"
)

// CanonicalHost is a host in the one spelling every comparison of a Host header, a request authority and a
// models[] host uses: lower case, without a port, an IPv6 literal without its brackets, and without the trailing
// dot of a fully qualified name, which names the same host (R33). A value that is
// already a bare host comes back lower-cased and otherwise as it was; an unbracketed IPv6 literal keeps every
// colon, since no port can be told apart from it. An IP literal comes back in one spelling of its address
// (netip's, IPv4-mapped IPv6 as IPv4).
//
// It is the one normalization: derive's step and dispatch tables, the uprobe source's provider
// and endpoint lookup and this package's models[] guard each had their own, and they disagreed on case, on an
// IPv6 literal's brackets and on the trailing dot, so a host matched one table and not the next.
func CanonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		// An IP literal has many spellings of one address (0:0::1 and ::1, ::ffff:127.0.0.1 and ::ffff:7f00:1):
		// it is compared in netip's, an IPv4-mapped IPv6 address as the IPv4 address it maps.
		return a.Unmap().String()
	}
	return strings.TrimSuffix(h, ".")
}
