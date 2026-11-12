// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net/netip"
	"strings"
)

// A host name in net.allow admits whatever addresses the name resolves to, at compile and again on every
// TTL refresh in the run (SEMANTICS §5), and the resolver's answer is not the contract author's: a name the
// author trusts can be re-pointed, rebound between two lookups (DNS rebinding) or answered by a hostile
// resolver. A few address classes are never the remote service a name in a contract stands for, and
// reaching one through a name is the server-side request forgery shape of cloud credential theft (the
// instance metadata service at 169.254.169.254 hands the machine's role credentials to anything on the
// host that asks). So a host entry never admits an address in these classes
// (docs/p0/agent-contract.md R18): compile drops it from the addresses it resolved and warns, and the
// supervisor refuses a connect or send to one that a refresh brought in (docs/p0/supervisor.md R7). The
// explicit way to admit one is to declare it: a literal address or a CIDR entry is never filtered, because
// the author wrote the address itself. The machine config can add ranges (denied_resolved_addresses), such
// as the private ranges on a host whose internal network no contract should reach by name; it cannot
// remove a built-in class.
//
// Private ranges (10/8, 172.16/12, 192.168/16, the shared 100.64/10, fc00::/7) are refused by what the name
// resolved to first. Split-horizon DNS answers an internal registry or git server with one, so a name whose
// compile-time answer held a private address keeps them. A name whose compile-time answer was public only
// (NetRule.PublicAnswer) stands for a service on the internet, and a later answer that brings a private
// address in is DNS rebinding's other target, the services on the host's own network (a router's admin page,
// an internal API): that address is refused, class private.

// Resolved-address classes, the words a diagnostic and a rule name use.
const (
	ResolvedLoopback  = "loopback"
	ResolvedLinkLocal = "link-local"
	ResolvedMetadata  = "cloud metadata"
	ResolvedMachine   = "machine config"
	ResolvedPrivate   = "private"
	ResolvedMulticast = "multicast"
)

// DeniedResolvedRule is the rule a refused connect or send carries when the address was one a host
// entry's name resolved to but that entry may not admit (DeniedResolvedClass): "net.denied_resolved[<entry>]",
// naming the declared entry whose resolution was refused. It is not a runtime grant (IsRuntimeRule is false),
// so `tego drift` counts the refusal.
func DeniedResolvedRule(entry string) string { return "net.denied_resolved[" + entry + "]" }

// metadataAddrs are cloud instance-metadata and host-agent endpoints outside the link-local range, which
// the link-local class already covers for the 169.254.169.254 endpoint AWS, GCP, Azure and OCI share (and
// for EKS Pod Identity's 169.254.170.23): AWS's IPv6 IMDS (fd00:ec2::254, a ULA), the EKS Pod Identity
// Agent's IPv6 credential endpoint (fd00:ec2::23), GCE's IPv6 metadata server (fd20:ce::254, a ULA that
// the private class refuses only for a name whose first answer was public), Alibaba Cloud's metadata service (100.100.100.200, in the
// shared address space) and Azure's WireServer (168.63.129.16, a public address the platform answers on
// every VM).
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd00:ec2::23"),
	netip.MustParseAddr("fd20:ce::254"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("168.63.129.16"),
}

// privateRanges are the ranges a name whose compile-time answer was public only may not come to resolve to
// (ResolvedDenied): RFC 1918, the RFC 6598 shared address space carrier-grade NAT and tailnets use, and
// RFC 4193 unique local IPv6.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// nat64 is the well-known NAT64 prefix (RFC 6052): a DNS64 resolver on an IPv6-only network answers a
// name whose A record is 169.254.169.254 with 64:ff9b::a9fe:a9fe, so the embedded address is classified
// as the address it stands for.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// DeniedResolvedClass reports whether a is an address no host entry may admit by name, and its class:
// loopback (127/8, ::1) and the unspecified addresses (the kernel sends a connect to 0.0.0.0 or :: to
// loopback, see GuardAddrMatches), link-local (169.254/16, fe80::/10), the cloud metadata endpoints outside
// link-local, multicast (224/4, ff00::/8), and any range in extra (the machine config's
// denied_resolved_addresses). Built-in classes use the address an IPv4-mapped or NAT64 spelling stands
// for. Machine prefixes also match the actual transport address, so an IPv6 deny cannot be bypassed by
// a NAT64 answer whose embedded IPv4 lies outside it. Pure: no lookup, no syscall.
//
// Multicast is never the remote service a name stands for. A datagram sent to a group reaches listeners
// bound to its port on this host (ff01::/16 is interface-local, and the kernel loops multicast back to the
// sending host by default) and on the link (224.0.0.0/24, ff02::/16): a name the author allowed that a
// refresh rebinds to one reaches the local and on-link services the loopback and link-local classes keep a
// name from reaching.
func DeniedResolvedClass(a netip.Addr, extra []netip.Prefix) (class string, denied bool) {
	transport := a.WithZone("").Unmap()
	a = canonicalResolved(a)
	if !a.IsValid() {
		return "", false
	}
	switch {
	case a.IsLoopback() || a.IsUnspecified():
		return ResolvedLoopback, true
	case a.IsLinkLocalUnicast():
		if a == netip.MustParseAddr("169.254.169.254") {
			return ResolvedMetadata, true
		}
		return ResolvedLinkLocal, true
	case a.IsMulticast():
		return ResolvedMulticast, true
	}
	for _, m := range metadataAddrs {
		if a == m {
			return ResolvedMetadata, true
		}
	}
	for _, p := range extra {
		if p.Contains(a) || p.Contains(transport) {
			return ResolvedMachine, true
		}
	}
	return "", false
}

// canonicalResolved is the address a resolver's answer stands for: without a zone, unmapped from its
// IPv4-mapped form, and the IPv4 address a NAT64 one embeds.
func canonicalResolved(a netip.Addr) netip.Addr {
	a = a.WithZone("").Unmap()
	if a.IsValid() && nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return a
}

// privateAddr reports whether a lies in one of privateRanges.
func privateAddr(a netip.Addr) bool {
	a = canonicalResolved(a)
	for _, p := range privateRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// publicAddr reports whether a is neither private nor in a built-in class: an address on the internet, which
// is what a name answered with only such addresses stands for (NetRule.PublicAnswer). A localhost name's
// loopback answer is not one.
func publicAddr(a netip.Addr) bool {
	_, denied := DeniedResolvedClass(a, nil)
	return !denied && !privateAddr(a)
}

// ResolvedDenied is DeniedResolvedClass for an address a, which r, one of this table's host entries,
// resolved to, against the table's own machine ranges (RuleTable.DeniedResolved). A localhost name
// (LocalhostName) stands for loopback, so the loopback class is admitted for it and every other class is
// still refused. An entry whose compile-time answer was public only (PublicAnswer) also refuses a private
// address. A nil table refuses the built-in classes.
func (rt *RuleTable) ResolvedDenied(r NetRule, a netip.Addr) (class string, denied bool) {
	var extra []netip.Prefix
	if rt != nil {
		extra = rt.DeniedResolved
	}
	class, denied = DeniedResolvedClass(a, extra)
	switch {
	case denied && class == ResolvedLoopback && LocalhostName(r.Host):
		return "", false
	case !denied && r.PublicAnswer && privateAddr(a):
		return ResolvedPrivate, true
	}
	return class, denied
}

// FiltersResolved reports whether r is an entry whose addresses came from a lookup and are therefore
// filtered (ResolvedDenied): a host name. A literal address, a CIDR and a unix entry are never filtered,
// because the author wrote the destination itself; a grant the runtime added (Runtime) is not the
// contract's and is not filtered either.
func (r NetRule) FiltersResolved() bool {
	return IsIPProtocol(r.Proto) && r.CIDR == nil && r.Runtime == "" && HostFiltered(r.Host)
}

// HostFiltered reports whether a net entry's host field is a name, whose addresses came from a lookup,
// rather than an address the author wrote, with or without the brackets of an IPv6 literal. The supervisor
// asks it of the host a resolver match carries (dns.Match.Host).
func HostFiltered(h string) bool {
	if h == "" {
		return false
	}
	_, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
	return err != nil
}

// PrivateAddr reports whether a lies in a private range (RFC 1918, the RFC 6598 shared address space, RFC 4193 unique
// local IPv6), by the address an IPv4-mapped or NAT64 spelling stands for: the class an entry by host name keeps for a
// whole run when its answer at run start held one (NetRule.PublicAnswer). tego learn --allow-host refuses a name whose
// answer holds one the run did not reach.
func PrivateAddr(a netip.Addr) bool { return privateAddr(a) }
