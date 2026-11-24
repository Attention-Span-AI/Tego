// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"net/netip"
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func canonicalIPs(in []netip.Addr) []netip.Addr {
	out := slices.Clone(in)
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

func compareNetwork(a, b []agent.NetRule, name func(agent.NetRule) string) Result {
	var added, removed []string
	for _, r := range b {
		if !netCovered(r, a) {
			added = append(added, name(r))
		}
	}
	for _, r := range a {
		if !netCovered(r, b) {
			removed = append(removed, name(r))
		}
	}
	return order(added, removed)
}

func netCovered(target agent.NetRule, old []agent.NetRule) bool {
	if slices.ContainsFunc(old, func(r agent.NetRule) bool { return netCovers(r, target) }) {
		return true
	}
	if target.CIDR == nil {
		return false
	}
	var prefixes []netip.Prefix
	for _, r := range old {
		if r.CIDR == nil {
			continue
		}
		// Replacing only the target prefix asks whether all other authority
		// facts permit this fragment to participate in the union.
		fragment := target
		fragment.CIDR = r.CIDR
		if netCovers(r, fragment) {
			prefixes = append(prefixes, r.CIDR.Masked())
		}
	}
	return prefixCovered(target.CIDR.Masked(), prefixes)
}

// Compare complete address sets, rather than sampling endpoints or requiring
// one old entry to cover the new prefix. The recursion follows only prefixes
// containing an old fragment and is bounded by the address width and row count.
func prefixCovered(target netip.Prefix, old []netip.Prefix) bool {
	hasFragment := false
	for _, p := range old {
		if p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			return true
		}
		hasFragment = hasFragment || target.Contains(p.Addr())
	}
	if !hasFragment || target.Bits() >= target.Addr().BitLen() {
		return false
	}
	bits := target.Bits()
	addr := target.Addr()
	var high netip.Addr
	if addr.Is4() {
		v := addr.As4()
		v[bits/8] |= 1 << (7 - bits%8)
		high = netip.AddrFrom4(v)
	} else {
		v := addr.As16()
		v[bits/8] |= 1 << (7 - bits%8)
		high = netip.AddrFrom16(v)
	}
	return prefixCovered(netip.PrefixFrom(addr, bits+1), old) && prefixCovered(netip.PrefixFrom(high, bits+1), old)
}
