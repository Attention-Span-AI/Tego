// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Sentinel errors of key construction.
var (
	// ErrFamily is returned for an address that is neither IPv4 nor IPv6.
	ErrFamily = errors.New("bpf: unsupported address family")
	// ErrPrefix is returned for a prefix whose bit count does not fit its address family.
	ErrPrefix = errors.New("bpf: invalid prefix")
	// ErrSlot is returned for a run_idx outside [0, MaxSlots).
	ErrSlot = errors.New("bpf: run_idx out of range")
)

// v4MappedBits is the prefix width of ::ffff:0:0/96, the IPv6 form of an IPv4 address.
const v4MappedBits = 96

// Addr16 returns the 16-byte form of an address as the kernel keys it: an IPv4 address occupies the first
// four bytes and the rest are zero, an IPv6 address is copied whole. The second result is the address family
// the hook that sees this address reports.
func Addr16(a netip.Addr) ([16]byte, uint8, error) {
	var out [16]byte
	switch {
	case !a.IsValid():
		return out, 0, fmt.Errorf("%w: invalid address", ErrFamily)
	case a.Is4():
		copy(out[:4], a.AsSlice())
		return out, AFInet, nil
	case a.Is4In6():
		// An AF_INET6 socket reaching an IPv4 host sees the mapped form; keep it verbatim.
		out = a.As16()
		return out, AFInet6, nil
	case a.Is6():
		out = a.As16()
		return out, AFInet6, nil
	default:
		return out, 0, fmt.Errorf("%w: %s", ErrFamily, a)
	}
}

// AddrFrom rebuilds an address from a key's family and 16-byte slot, the inverse of Addr16.
func AddrFrom(family uint8, b [16]byte) (netip.Addr, error) {
	switch family {
	case AFInet:
		return netip.AddrFrom4([4]byte(b[:4])), nil
	case AFInet6:
		return netip.AddrFrom16(b), nil
	default:
		return netip.Addr{}, fmt.Errorf("%w: %d", ErrFamily, family)
	}
}

// NewNetKey builds the exact verdict key for one destination. Port is host byte order, as the hook reports it.
func NewNetKey(runIdx uint32, proto uint8, addr netip.Addr, port uint16) (NetKey, error) {
	if runIdx >= MaxSlots {
		return NetKey{}, fmt.Errorf("%w: %d", ErrSlot, runIdx)
	}
	raw, family, err := Addr16(addr)
	if err != nil {
		return NetKey{}, err
	}
	return NetKey{RunIdx: runIdx, Family: family, Proto: proto, Port: port, Addr: raw}, nil
}

// NetKeys returns every exact key a destination must be inserted under. An IPv4 rule yields two: the AF_INET
// key the connect4/sendmsg4 hooks build, and the IPv4-mapped AF_INET6 key the connect6/sendmsg6 hooks build
// when a dual-stack socket reaches the same host (the kernel dispatches by socket family, not by address
// family, so a rule inserted only as AF_INET would silently miss a Python or Go dual-stack connect).
func NetKeys(runIdx uint32, proto uint8, addr netip.Addr, port uint16) ([]NetKey, error) {
	k, err := NewNetKey(runIdx, proto, addr, port)
	if err != nil {
		return nil, err
	}
	if !addr.Is4() {
		return []NetKey{k}, nil
	}
	mapped, err := NewNetKey(runIdx, proto, netip.AddrFrom16(addr.As16()), port)
	if err != nil {
		return nil, err
	}
	return []NetKey{k, mapped}, nil
}

// LPMPrefixLen converts a CIDR bit count into the trie's prefixlen: the fixed run_idx/family/proto/port
// header is always matched whole, so the stored width is LPMHeaderBits plus the address bits (§2.2).
func LPMPrefixLen(addrBits int) (uint32, error) {
	if addrBits < 0 || addrBits > 128 {
		return 0, fmt.Errorf("%w: %d address bits", ErrPrefix, addrBits)
	}
	return uint32(LPMHeaderBits + addrBits), nil
}

// NewNetLPMKey builds the CIDR verdict key for one declared prefix. The prefix is masked first, so two
// spellings of the same network produce the same key.
func NewNetLPMKey(runIdx uint32, proto uint8, p netip.Prefix, port uint16) (NetLPMKey, error) {
	if runIdx >= MaxSlots {
		return NetLPMKey{}, fmt.Errorf("%w: %d", ErrSlot, runIdx)
	}
	if !p.IsValid() {
		return NetLPMKey{}, fmt.Errorf("%w: %s", ErrPrefix, p)
	}
	m := p.Masked()
	raw, family, err := Addr16(m.Addr())
	if err != nil {
		return NetLPMKey{}, err
	}
	plen, err := LPMPrefixLen(m.Bits())
	if err != nil {
		return NetLPMKey{}, err
	}
	return NetLPMKey{PrefixLen: plen, RunIdx: runIdx, Family: family, Proto: proto, Port: port, Addr: raw}, nil
}

// NetLPMKeys returns every CIDR key a prefix must be inserted under, for the reason NetKeys documents: an
// IPv4 prefix also gets its IPv4-mapped IPv6 form, ::ffff:0:0/96 widened by the prefix's own bits.
func NetLPMKeys(runIdx uint32, proto uint8, p netip.Prefix, port uint16) ([]NetLPMKey, error) {
	k, err := NewNetLPMKey(runIdx, proto, p, port)
	if err != nil {
		return nil, err
	}
	if !p.Addr().Is4() {
		return []NetLPMKey{k}, nil
	}
	m := p.Masked()
	mapped, err := NewNetLPMKey(runIdx, proto, netip.PrefixFrom(netip.AddrFrom16(m.Addr().As16()), m.Bits()+v4MappedBits), port)
	if err != nil {
		return nil, err
	}
	return []NetLPMKey{k, mapped}, nil
}

// LookupLPMKey builds the key a lookup uses: the full width, so the trie answers with the longest stored
// prefix that matches. It is what the C side builds and exists here so tests can exercise the same shape.
func LookupLPMKey(runIdx uint32, proto uint8, addr netip.Addr, port uint16) (NetLPMKey, error) {
	k, err := NewNetKey(runIdx, proto, addr, port)
	if err != nil {
		return NetLPMKey{}, err
	}
	return NetLPMKey{PrefixLen: LPMMaxBits, RunIdx: k.RunIdx, Family: k.Family, Proto: k.Proto, Port: k.Port, Addr: k.Addr}, nil
}

// Matches reports whether a stored CIDR key covers a lookup key, applying the trie's own rule: the fixed
// header must be equal and the first PrefixLen-LPMHeaderBits address bits must agree. It never consults the
// kernel; it is the userspace model the precedence tests check the C side's behaviour against (§5 R3).
func (k NetLPMKey) Matches(lookup NetLPMKey) bool {
	if k.RunIdx != lookup.RunIdx || k.Family != lookup.Family || k.Proto != lookup.Proto || k.Port != lookup.Port {
		return false
	}
	if k.PrefixLen < LPMHeaderBits || k.PrefixLen > LPMMaxBits {
		return false
	}
	bits := int(k.PrefixLen) - LPMHeaderBits
	full := bits / 8
	for i := 0; i < full; i++ {
		if k.Addr[i] != lookup.Addr[i] {
			return false
		}
	}
	if rem := bits % 8; rem != 0 {
		mask := byte(0xff) << (8 - rem)
		if k.Addr[full]&mask != lookup.Addr[full]&mask {
			return false
		}
	}
	return true
}

// ErrUnixName is returned for a unix name no sun_path can carry, or one no row can be built for.
var ErrUnixName = errors.New("bpf: unix name does not fit sun_path")

// unixKey fills the fixed header of a name-trie key and copies the name bytes it is to match.
func unixKey(runIdx uint32, kind, length uint8, name []byte, bytes int) (UnixKey, error) {
	if runIdx >= MaxSlots {
		return UnixKey{}, fmt.Errorf("%w: %d", ErrSlot, runIdx)
	}
	if len(name) > UnixNameMax || bytes > UnixNameMax {
		return UnixKey{}, fmt.Errorf("%w: %d bytes", ErrUnixName, bytes)
	}
	k := UnixKey{PrefixLen: uint32(UnixHeaderBits + 8*bytes), RunIdx: runIdx, Kind: kind, Len: length}
	copy(k.Name[:], name)
	return k, nil
}

// UnixPathKey builds the row for one absolute path. An exact row matches the name that is this path and
// nothing longer: the path's bytes and the NUL connect_unix and sendmsg_unix find after them, or the bytes
// alone for a path that fills sun_path, since no name is longer. A subtree row matches every name beneath
// the path, at a component boundary only: the path's bytes and a "/" ("/" alone for the root, which is its
// own separator), so "/tmp/work" never covers "/tmp/workshop" (§5 R7). A row that cannot fit is ErrUnixName:
// no name reaches it.
func UnixPathKey(runIdx uint32, path string, subtree bool) (UnixKey, error) {
	if !strings.HasPrefix(path, "/") || strings.IndexByte(path, 0) >= 0 {
		return UnixKey{}, fmt.Errorf("%w: %q is not an absolute path", ErrUnixName, path)
	}
	name := []byte(path)
	switch {
	case subtree && path != "/":
		name = append(name, '/')
	case !subtree && len(name) < UnixNameMax:
		name = append(name, 0)
	}
	return unixKey(runIdx, UnixPath, 0, name, len(name))
}

// UnixAbstractKey builds the row for one abstract name: the NUL that marks it abstract, then its bytes, with
// the whole sun_path length in the header so that only a name of exactly this length matches (supervisor.md
// E5: an abstract name is never NUL-scanned).
func UnixAbstractKey(runIdx uint32, name []byte) (UnixKey, error) {
	if len(name) == 0 || len(name)+1 > UnixNameMax {
		return UnixKey{}, fmt.Errorf("%w: abstract name of %d bytes", ErrUnixName, len(name))
	}
	raw := append([]byte{0}, name...)
	return unixKey(runIdx, UnixAbstract, uint8(len(raw)), raw, len(raw))
}

// UnixApproval builds the one-connect grant of the abstract name name (its bytes after the NUL that marks it
// abstract) for the socket whose cookie is cookie, in the run of slot runIdx at gen, live until deadlineNS
// (CLOCK_MONOTONIC): MapUnixApprovals' row, which tego_unix_approved matches by the name's kind, length and bytes.
func UnixApproval(runIdx, gen uint32, cookie uint64, name []byte, deadlineNS uint64) (UnixApprovalKey, UnixCredit, error) {
	if runIdx >= MaxSlots || gen == 0 || cookie == 0 {
		return UnixApprovalKey{}, UnixCredit{}, fmt.Errorf("%w: approval of slot %d gen %d cookie %d", ErrUnixName, runIdx, gen, cookie)
	}
	k, err := UnixAbstractKey(runIdx, name)
	if err != nil {
		return UnixApprovalKey{}, UnixCredit{}, err
	}
	return UnixApprovalKey{RunIdx: runIdx, Gen: gen, Cookie: cookie}, UnixCredit{
		Credit: 1, DeadlineNS: deadlineNS, PrefixLen: k.PrefixLen, RunIdx: runIdx, Kind: k.Kind, Len: k.Len, Name: k.Name,
	}, nil
}

// LookupUnixKey builds the key connect_unix and sendmsg_unix build from an address's sun_path bytes (addrlen
// minus the family word), for tests of the same shape: the full width, an abstract name's length in the
// header, and a pathname ended at its first NUL or the address's end.
func LookupUnixKey(runIdx uint32, sunPath []byte) (UnixKey, error) {
	if len(sunPath) == 0 || len(sunPath) > UnixNameMax {
		return UnixKey{}, fmt.Errorf("%w: %d bytes", ErrUnixName, len(sunPath))
	}
	if sunPath[0] == 0 {
		k, err := unixKey(runIdx, UnixAbstract, uint8(len(sunPath)), sunPath, UnixNameMax)
		return k, err
	}
	if i := bytes.IndexByte(sunPath, 0); i >= 0 {
		sunPath = sunPath[:i]
	}
	return unixKey(runIdx, UnixPath, 0, sunPath, UnixNameMax)
}

// Matches reports whether a stored name-trie row covers a lookup key, applying the trie's own rule: the
// header must be equal and the row's first PrefixLen-UnixHeaderBits name bits must agree. It never consults
// the kernel; it is the userspace model the rule tests check BuildRuleMaps' rows against (§5 R7).
func (k UnixKey) Matches(lookup UnixKey) bool {
	if k.RunIdx != lookup.RunIdx || k.Kind != lookup.Kind || k.Len != lookup.Len {
		return false
	}
	if k.PrefixLen < UnixHeaderBits || k.PrefixLen > UnixMaxBits || (k.PrefixLen-UnixHeaderBits)%8 != 0 {
		return false
	}
	n := int(k.PrefixLen-UnixHeaderBits) / 8
	return bytes.Equal(k.Name[:n], lookup.Name[:n])
}
