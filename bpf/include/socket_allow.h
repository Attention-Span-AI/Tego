// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* ADR 0018 (1)'s socket allowlist, the one C spelling of it: the decision plane's socket_create (bpf/decide_stepb.h,
 * enforce-plane R14) and the cgroup/sock_create program (bpf/cgroup_net.bpf.c, enforce-cgroup-observe §5 R4) both
 * call tego_socket_allowed, so the two kernel layers that refuse a socket cannot disagree on one. The seccomp
 * filter's socketAllowTest (internal/runtime/enforce/landlock filter.go) is the same table for socket(2), and
 * internal/bpf SocketAllowed is its Go mirror, which a unit test holds to the filter and a root test to this
 * function in the kernel (internal/bpf socket_allow_test.go, sockcreate_integration_test.go).
 *
 * The family, type and protocol constants are common.h's, and NETLINK_ROUTE's is here, the one file that names it. */
#ifndef TEGO_SOCKET_ALLOW_H
#define TEGO_SOCKET_ALLOW_H

#include "common.h"

#define TEGO_NETLINK_ROUTE 0

/* AF_UNIX of any type, AF_NETLINK as NETLINK_ROUTE alone (ADR 0128), and AF_INET or AF_INET6 as a stream socket with
 * protocol 0 or TCP, a datagram socket with protocol 0 or UDP, or, when the net section names an ICMP destination, a
 * datagram socket with ICMP or ICMPv6. socketpair's sockets come here too, of their own family. protocol is compared
 * whole: a protocol number above 255 (IPPROTO_MPTCP 262, IPPROTO_SMC 256) is never read as its low byte, which would
 * make MPTCP TCP and SMC protocol 0. */
static __always_inline int tego_socket_allowed(int family, int type, int protocol, int icmp)
{
    int t = type & TEGO_SOCK_TYPE_MASK;

    if (family == TEGO_AF_UNIX)
        return 1;
    if (family == TEGO_AF_NETLINK)
        return protocol == TEGO_NETLINK_ROUTE;
    if (family != TEGO_AF_INET && family != TEGO_AF_INET6)
        return 0;
    if (t == TEGO_SOCK_STREAM)
        return protocol == 0 || protocol == TEGO_IPPROTO_TCP;
    if (t == TEGO_SOCK_DGRAM)
        return protocol == 0 || protocol == TEGO_IPPROTO_UDP ||
               (icmp && (protocol == TEGO_IPPROTO_ICMP || protocol == TEGO_IPPROTO_ICMPV6));
    return 0;
}

#endif /* TEGO_SOCKET_ALLOW_H */
