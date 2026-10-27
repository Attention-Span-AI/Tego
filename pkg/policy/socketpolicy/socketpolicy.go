// SPDX-License-Identifier: Apache-2.0

// Package socketpolicy is ADR 0018 (1)'s socket allowlist in Go: the one spelling of the table that the decision
// core (compile --test's net.socket rows), internal/bpf (the recorder's reading of a cgroup/sock_create record) and
// the tests holding the seccomp filter's socket arm and the kernel's tego_socket_allowed to the table all read. It is
// the standard library only and makes no I/O (depguard socketpolicy-is-pure), so the decision core, which may not
// import internal/, and internal/bpf, which may not import pkg/spec, can both import it.
package socketpolicy

// The address families, socket types and protocols the allowlist names: Linux's stable ABI numbers, which
// bpf/include/common.h spells TEGO_AF_*, TEGO_SOCK_* and TEGO_IPPROTO_* (internal/bpf's
// TestSocketAllowedConstantsAreCommonH holds its own copy of them to the header).
const (
	afUnix        = 1
	afInet        = 2
	afInet6       = 10
	afNetlink     = 16
	netlinkRoute  = 0
	sockStream    = 1
	sockDgram     = 2
	sockTypeMask  = 0xf
	ipprotoICMP   = 1
	ipprotoTCP    = 6
	ipprotoUDP    = 17
	ipprotoICMPv6 = 58
)

// Allowed is bpf/include/socket_allow.h's tego_socket_allowed in Go: AF_UNIX of any type, AF_NETLINK as NETLINK_ROUTE
// alone (ADR 0128), and AF_INET or AF_INET6 as a stream socket with protocol 0 or TCP, a datagram socket with protocol
// 0 or UDP, or, with icmp (a port-0 net entry, RuleTable.NetSocketPolicy), a datagram socket with ICMP or ICMPv6. The
// type's flags (SOCK_NONBLOCK, SOCK_CLOEXEC) are masked off, and the protocol is compared whole, as the C function
// does. The plane's socket_create and cgroup/sock_create apply the C function in the kernel, and the seccomp
// filter's socket arm applies the same table to socket(2) (enforce/landlock socketAllowTest).
func Allowed(family, typ, protocol int32, icmp bool) bool {
	switch family {
	case afUnix:
		return true
	case afNetlink:
		return protocol == netlinkRoute
	case afInet, afInet6:
	default:
		return false
	}
	switch typ & sockTypeMask {
	case sockStream:
		return protocol == 0 || protocol == ipprotoTCP
	case sockDgram:
		return protocol == 0 || protocol == ipprotoUDP || (icmp && (protocol == ipprotoICMP || protocol == ipprotoICMPv6))
	}
	return false
}
