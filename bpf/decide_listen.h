// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef TEGO_DECIDE_LISTEN_H
#define TEGO_DECIDE_LISTEN_H

/* The cgroup bind policy also governs implicit listen autobinding. These are
 * the same three pinned maps; the plane replaces them with the run backend's
 * maps instead of creating a second source of listener authority. */
#define TEGO_NET_CONTROL_LISTEN_ONLY
#include "net_control.h"

static __always_inline struct tego_run *tego_listen_sock_run(struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct cgroup *cg;
    if (!sk || (sk->__sk_common.skc_family != TEGO_AF_INET && sk->__sk_common.skc_family != TEGO_AF_INET6 &&
                sk->__sk_common.skc_family != TEGO_AF_UNIX))
        return 0;
    /* An original governed task must also constrain sockets imported from an
     * outside creator. The socket's cgroup is the fallback for supervisor
     * relays, whose current task is outside the governed run. */
    struct tego_run *current = tego_current_run(&tego_run_set);
    if (current)
        return current;
    cg = sk->sk_cgrp_data.cgroup;
    return cg ? tego_run_lookup(&tego_run_set, cg->kn->id) : 0;
}

static __always_inline int tego_listen_refuse(struct tego_run *run, struct socket *sock, __u8 reason)
{
    struct tego_run *current = tego_current_run(&tego_run_set);
    struct tego_plane_sample_args a = {};
    struct sock *sk = sock->sk;
    if (!sk)
        return -EACCES;
    if (tego_unix_listen_marker(sock,run,reason,TEGO_PLANE_RULE_NONE))
        return -EACCES; // original Unix task's terminal syscall record owns the line
    // A duplicated-socket supervisor relay has no original agent task here;
    // its trapped syscall handler records the actual relay error instead.
    if (current && current->run_idx == run->run_idx && current->gen == run->gen) {
        a.kind = TEGO_EV_PLANE_SOCKET;
        a.hook = TEGO_HOOK_SOCKET_LISTEN;
        a.rule = TEGO_PLANE_RULE_NONE;
        a.reason = reason;
        a.family = sk->__sk_common.skc_family;
        a.type = sock->type;
        a.protocol = sk->sk_protocol;
        tego_plane_own_sample(run, &a);
    }
    return -EACCES;
}

TEGO_PLANE_HOOK(socket_listen, socket_listen, security_socket_listen,
                 (struct socket *sock, int backlog), (sock, backlog))
{
    struct tego_run *run = tego_listen_sock_run(sock);
    const struct tego_plane_slot *slot;
    struct tego_nc_config *config;
    struct tego_net_verdict *grant;
    struct tego_net_key key = {}, wildcard;
    struct tego_net_socket_key socket = {};
    struct sock *sk = sock->sk;
    struct tego_plane_decision *scratch;
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u8 reason = TEGO_R_NET_NOT_ALLOWED;
    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    /* The helper checked an earlier load; this fresh socket-field load needs
     * its own verifier-visible proof before any family/cookie dereference. */
    if (!sk)
        return tego_listen_refuse(run,sock,TEGO_R_PATH_UNRESOLVED);
    slot = tego_plane_slot_of(run);
    if (!slot) {
        tego_plane_unslotted(TEGO_HOOK_SOCKET_LISTEN, (__u64)sock);
        return tego_listen_refuse(run,sock,TEGO_R_PATH_UNRESOLVED);
    }
    if (!(slot->flags & TEGO_SLOT_LISTEN_DECIDES))
        return 0;
    if (sk->__sk_common.skc_family == TEGO_AF_UNIX) {
        reason = tego_unix_listen_reason(sock,run,&rule);
        goto decided;
    }
    config = bpf_map_lookup_elem(&tego_net_control, &run->run_idx);
    if (!config || config->gen != run->gen || !(config->flags & TEGO_NC_LISTEN))
        goto decided;
    socket.run_idx = run->run_idx;
    socket.gen = run->gen;
    socket.cookie = sk->__sk_common.skc_cookie.counter;
    // A successful explicit port-zero bind has already allocated its port.
    // Its admission row proves the original bind rule, without treating a
    // port-zero declaration as a grant for an arbitrary fixed-port request.
    if (sk->__sk_common.skc_num && socket.cookie && bpf_map_lookup_elem(&tego_net_binds, &socket)) {
        reason = 0;
        goto decided;
    }
    key.run_idx = run->run_idx;
    key.family = sk->__sk_common.skc_family;
    key.proto = sk->sk_protocol;
    key.port = sk->__sk_common.skc_num;
    if (key.proto != IPPROTO_TCP)
        goto decided;
    if (key.family == TEGO_AF_INET6) {
        tego_addr_v6(key.addr, sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0],
                     sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[1],
                     sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2],
                     sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3]);
    } else {
        tego_addr_v4(key.addr, sk->__sk_common.skc_rcv_saddr);
    }
    grant = bpf_map_lookup_elem(&tego_bind_exact, &key);
    if (!grant) {
        wildcard = key;
        if (wildcard.family == TEGO_AF_INET6 && tego_v4mapped(wildcard.addr))
            wildcard.family = TEGO_AF_INET;
        __builtin_memset(wildcard.addr,0,sizeof(wildcard.addr));
        grant = bpf_map_lookup_elem(&tego_bind_exact, &wildcard);
    }
    if (grant && grant->verdict == TEGO_V_ALLOW)
        reason = 0;
decided:
    scratch = tego_plane_scratch_get();
    if (!scratch) {
        TEGO_PLANE_COUNT(run->run_idx,unresolved);
        return tego_listen_refuse(run,sock,TEGO_R_PATH_UNRESOLVED);
    }
    // Listener rule indexes belong to the network table, not FS plane rows.
    // Do not mislabel a network decision with an unrelated FS rule index.
    int refused = tego_plane_record(scratch,TEGO_HOOK_SOCKET_LISTEN,(__u64)sock,rule,reason);
    if (tego_unix_listen_marker(sock,run,reason,rule))
        return refused ? -EACCES : 0;
    if (refused)
        return tego_listen_refuse(run,sock,reason);
    return 0;
}

#endif
