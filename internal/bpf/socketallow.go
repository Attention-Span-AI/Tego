// SPDX-License-Identifier: Apache-2.0

package bpf

import "github.com/attention-span-ai/tego/pkg/policy/socketpolicy"

// The address families, socket types and protocols ADR 0018 (1)'s allowlist names: bpf/include/common.h's
// TEGO_AF_*, TEGO_SOCK_* and TEGO_IPPROTO_*, the kernel's stable ABI numbers. TestSocketAllowedConstantsAreCommonH
// holds them to the header, and the table tests read them.
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

// SocketAllowed is bpf/include/socket_allow.h's tego_socket_allowed in Go: ADR 0018 (1)'s allowlist, which the
// plane's socket_create and cgroup/sock_create apply in the kernel and the seccomp filter's socket arm applies to
// socket(2) (enforce/landlock socketAllowTest). AF_UNIX of any type, AF_NETLINK as NETLINK_ROUTE alone (ADR 0128), and
// AF_INET or AF_INET6 as a stream socket with protocol 0 or TCP, a datagram socket with protocol 0 or UDP, or, with
// icmp, a datagram socket with ICMP or ICMPv6. The protocol is compared whole, as the C function does.
//
// It is pkg/policy/socketpolicy's Allowed, which the decision core answers compile --test's net.socket rows by
// (plans/adr0017 C9): one Go spelling of the table, in a leaf package both may import. The recorder reads it to tell a cgroup/sock_create record of a triple the
// program never refuses (observe.handleSockCreate). Tests hold it to the seccomp arm (enforce/landlock) and, as
// root, to the C function in the kernel (sockcreate_integration_test.go), so the three spellings cannot drift.
func SocketAllowed(family, typ, protocol int32, icmp bool) bool {
	return socketpolicy.Allowed(family, typ, protocol, icmp)
}
