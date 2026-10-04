// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef TEGO_NET_BUDGET_H
#define TEGO_NET_BUDGET_H

/* Connection ceilings are conservative socket-lifetime reservations, not a
 * flow cache count. TCP establishment releases only its pending reservation;
 * TCP_CLOSE or inet socket release releases its total reservation exactly once.
 * All per-run counters share one lock; no helper is called while it is held.
 * The socket and pending maps are shared by every run of the build: a refused
 * reservation deletes its row, so a run holds rows only for what it admitted
 * (network-controls; bpf-1). */
static __always_inline int tego_reserve_socket(struct tego_net_owner *owner,
                                               struct tego_nc_config *control,
                                               __u64 cookie, int tcp)
{
    struct tego_net_socket_key key = {};
    struct tego_net_socket init = {};
    struct tego_net_socket *state;
    struct tego_nc_stats *stats;
    int admitted = 1;

    if (!(control->flags & (TEGO_NC_CONNECTIONS | TEGO_NC_PENDING)))
        return 1;
    if (!cookie)
        return 0;
    key.run_idx = owner->run_idx;
    key.gen = control->gen;
    key.cookie = cookie;
    state = bpf_map_lookup_elem(&tego_net_sockets, &key);
    if (state) {
        __u64 phase = state->phase;
        if (phase == 1 || phase == 2)
            return 1;
        /* A closed socket's released row may reserve again. A simultaneous
         * operation never widens a half-complete reservation. */
        if (phase != 3 || __sync_val_compare_and_swap(&state->phase, 3, 0) != 3)
            return 0;
    } else {
        if (bpf_map_update_elem(&tego_net_sockets, &key, &init, BPF_NOEXIST))
            return 0;
        state = bpf_map_lookup_elem(&tego_net_sockets, &key);
        if (!state)
            return 0;
    }
    stats = bpf_map_lookup_elem(&tego_net_stats, &owner->run_idx);
    if (!stats) {
        bpf_map_delete_elem(&tego_net_sockets, &key);
        return 0;
    }
    bpf_spin_lock(&stats->lock);
    if ((control->flags & TEGO_NC_CONNECTIONS) && stats->connections >= control->connections) {
        stats->denied_connections++;
        admitted = 0;
    } else if (tcp && (control->flags & TEGO_NC_PENDING) && stats->pending >= control->pending_connects) {
        stats->denied_pending++;
        admitted = 0;
    } else {
        stats->connections++;
        if (tcp)
            stats->pending++;
    }
    bpf_spin_unlock(&stats->lock);
    if (!admitted) {
        // A refused socket holds no row: a later attempt reserves afresh.
        bpf_map_delete_elem(&tego_net_sockets, &key);
        return 0;
    }
    state->phase = tcp ? 1 : 2;
    return 1;
}

static __always_inline void tego_release_socket(struct tego_net_owner *owner,
                                                 struct tego_nc_config *control,
                                                 __u64 cookie, int closing)
{
    struct tego_net_socket_key key = {};
    struct tego_net_socket *state;
    struct tego_nc_stats *stats;
    __u64 phase;

    key.run_idx = owner->run_idx;
    key.gen = control->gen;
    key.cookie = cookie;
    state = bpf_map_lookup_elem(&tego_net_sockets, &key);
    if (!state)
        return;
    phase = state->phase;
    if (phase != 1 && phase != 2)
        return;
    if (__sync_val_compare_and_swap(&state->phase, phase, closing ? 3 : 2) != phase)
        return;
    stats = bpf_map_lookup_elem(&tego_net_stats, &owner->run_idx);
    if (!stats)
        return;
    bpf_spin_lock(&stats->lock);
    if (phase == 1 && stats->pending)
        stats->pending--;
    if (closing && stats->connections)
        stats->connections--;
    bpf_spin_unlock(&stats->lock);
    if (closing && state->inbound)
        bpf_map_delete_elem(&tego_net_flows, &state->flow);
}

/* Releases an admitted inbound reservation that never reached establishment,
 * exactly once: the phase moves 2 -> 3 here or in tego_accept_reservation,
 * never both. The reply-cache row goes with it, so the handshake's late final
 * ACK, or a retransmitted SYN-ACK, finds no admitted tuple and is refused. */
static __always_inline void tego_pending_release(struct tego_net_reservation *pending,
                                                  const struct tego_net_flow_key *key)
{
    struct tego_nc_config *control;
    struct tego_nc_stats *stats;

    if (__sync_val_compare_and_swap(&pending->phase, 2, 3) != 2)
        return;
    control = bpf_map_lookup_elem(&tego_net_control, &key->run_idx);
    stats = bpf_map_lookup_elem(&tego_net_stats, &key->run_idx);
    if (control && control->gen == key->gen && stats) {
        bpf_spin_lock(&stats->lock);
        if (stats->pending)
            stats->pending--;
        if (stats->connections)
            stats->connections--;
        bpf_spin_unlock(&stats->lock);
    }
    bpf_map_delete_elem(&tego_net_flows, key);
    bpf_map_delete_elem(&tego_net_pending, key);
}

/* The reservation's timer: no callback reports a request socket the kernel
 * drops (SYN-ACK retries exhausted, a reset, a syncookie never answered). */
static int tego_pending_expire(void *map, struct tego_net_flow_key *key, struct tego_net_reservation *pending)
{
    tego_pending_release(pending, key);
    return 0;
}

/* The first admitted SYN reserves a bounded slot until actual establishment,
 * TEGO_NET_SYN_RESERVATION_NS or run teardown. A refused SYN keeps no row:
 * the pending map is shared by every run of the build (bpf-1). */
static __always_inline int tego_reserve_inbound(struct tego_net_owner *owner,
                                                struct tego_nc_config *control,
                                                const struct tego_net_flow_key *key,
                                                __u64 cookie)
{
    struct tego_net_reservation initial = {.cookie = cookie};
    struct tego_net_reservation *pending;
    struct tego_nc_stats *stats;
    int allowed = 1;
    if (!(control->flags & (TEGO_NC_CONNECTIONS | TEGO_NC_PENDING)))
        return 1;
    // A duplicate SYN on an already established tuple belongs to that actual
    // accepted socket. It must not reserve a second connection/pending slot.
    {
        struct tego_net_socket_key socket = {.run_idx = owner->run_idx, .gen = control->gen, .cookie = cookie};
        struct tego_net_socket *active = bpf_map_lookup_elem(&tego_net_sockets,&socket);
        if (active && active->phase == 2 && active->inbound &&
            !__builtin_memcmp(&active->flow,key,sizeof(*key)))
            return 1;
    }
    pending = bpf_map_lookup_elem(&tego_net_pending, key);
    if (!pending) {
        if (bpf_map_update_elem(&tego_net_pending, key, &initial, BPF_NOEXIST))
            return 0;
        pending = bpf_map_lookup_elem(&tego_net_pending, key);
        if (!pending)
            return 0;
    }
    if (pending->phase == 2)
        return 1;
    if (__sync_val_compare_and_swap(&pending->phase, 0, 1) != 0)
        return 0;
    stats = bpf_map_lookup_elem(&tego_net_stats, &owner->run_idx);
    if (!stats) {
        bpf_map_delete_elem(&tego_net_pending, key);
        return 0;
    }
    bpf_spin_lock(&stats->lock);
    if ((control->flags & TEGO_NC_CONNECTIONS) && stats->connections >= control->connections) {
        stats->denied_connections++;
        allowed = 0;
    } else if ((control->flags & TEGO_NC_PENDING) && stats->pending >= control->pending_connects) {
        stats->denied_pending++;
        allowed = 0;
    } else {
        stats->connections++;
        stats->pending++;
    }
    bpf_spin_unlock(&stats->lock);
    if (!allowed) {
        bpf_map_delete_elem(&tego_net_pending, key);
        return 0;
    }
    pending->phase = 2;
    // The SYN-ACK cannot leave before this program returns, so the timer is
    // armed before any transfer. One that cannot be armed refuses the SYN
    // rather than leave a reservation nothing would release.
    if (bpf_timer_init(&pending->timer, &tego_net_pending, TEGO_CLOCK_MONOTONIC) ||
        bpf_timer_set_callback(&pending->timer, tego_pending_expire) ||
        bpf_timer_start(&pending->timer, TEGO_NET_SYN_RESERVATION_NS, 0)) {
        tego_pending_release(pending, key);
        return 0;
    }
    return 1;
}

static __always_inline void tego_sockops_key(struct bpf_sock_ops *ctx,
                                             struct tego_net_owner *owner,
                                             struct tego_nc_config *control,
                                             struct tego_net_flow_key *key)
{
    key->run_idx = owner->run_idx;
    key->gen = control->gen;
    key->family = ctx->family;
    key->proto = IPPROTO_TCP;
    key->local_port = (__u16)ctx->local_port;
    key->remote_port = bpf_ntohl(ctx->remote_port);
    if (ctx->family == TEGO_AF_INET6) {
        tego_addr_v6(key->local, ctx->local_ip6[0], ctx->local_ip6[1], ctx->local_ip6[2], ctx->local_ip6[3]);
        tego_addr_v6(key->remote, ctx->remote_ip6[0], ctx->remote_ip6[1], ctx->remote_ip6[2], ctx->remote_ip6[3]);
        if (tego_v4mapped(key->local) && tego_v4mapped(key->remote)) {
            __builtin_memmove(key->local, key->local + 12, 4);
            __builtin_memmove(key->remote, key->remote + 12, 4);
            __builtin_memset(key->local + 4, 0, 12);
            __builtin_memset(key->remote + 4, 0, 12);
            key->family = TEGO_AF_INET;
        }
    } else {
        tego_addr_v4(key->local, ctx->local_ip4);
        tego_addr_v4(key->remote, ctx->remote_ip4);
    }
}

static __always_inline void tego_accept_reservation(struct bpf_sock_ops *ctx,
                                                     struct tego_net_owner *owner,
                                                     struct tego_nc_config *control,
                                                     __u64 cookie)
{
    struct tego_net_flow_key flow_key = {};
    struct tego_net_socket_key socket_key = {.run_idx = owner->run_idx, .gen = control->gen, .cookie = cookie};
    struct tego_net_socket initial = {.phase = 2, .inbound = 1};
    struct tego_net_reservation *pending;
    struct tego_net_flow *flow;
    struct tego_nc_stats *stats;
    int transferred;
    tego_sockops_key(ctx, owner, control, &flow_key);
    if (!(control->flags & (TEGO_NC_CONNECTIONS | TEGO_NC_PENDING))) {
        flow = bpf_map_lookup_elem(&tego_net_flows, &flow_key);
        if (flow && flow->inbound)
            flow->cookie = cookie;
        return;
    }
    pending = bpf_map_lookup_elem(&tego_net_pending, &flow_key);
    if (!pending || __sync_val_compare_and_swap(&pending->phase, 2, 3) != 2)
        return;
    initial.flow = flow_key;
    transferred = cookie && bpf_map_update_elem(&tego_net_sockets, &socket_key, &initial, BPF_NOEXIST) == 0;
    stats = bpf_map_lookup_elem(&tego_net_stats, &owner->run_idx);
    if (stats) {
        bpf_spin_lock(&stats->lock);
        if (stats->pending)
            stats->pending--;
        if (!transferred && stats->connections)
            stats->connections--;
        bpf_spin_unlock(&stats->lock);
    }
    flow = bpf_map_lookup_elem(&tego_net_flows, &flow_key);
    if (flow && transferred)
        flow->cookie = cookie;
    else if (!transferred)
        bpf_map_delete_elem(&tego_net_flows, &flow_key);
    bpf_map_delete_elem(&tego_net_pending, &flow_key);
}

/* Bytes count outgoing IP bytes, including IP/transport headers and TCP
 * retransmission. The datagram ceiling is a fixed monotonic one-second window.
 * Locally admitted attempts are charged even if a later downstream queue drops
 * them; admitted bytes never exceed an explicit cap. */
static __always_inline int tego_charge_packet(struct tego_net_owner *owner,
                                               struct tego_nc_config *control,
                                               __u64 bytes, int udp)
{
    struct tego_nc_stats *stats;
    __u64 now = bpf_ktime_get_ns();
    int allowed = 1;

    stats = bpf_map_lookup_elem(&tego_net_stats, &owner->run_idx);
    if (!stats)
        return 0;
    bpf_spin_lock(&stats->lock);
    if (!stats->window_ns || now - stats->window_ns >= 1000000000ULL) {
        stats->window_ns = now;
        stats->datagrams = 0;
    }
    if ((control->flags & TEGO_NC_BYTES) &&
        (stats->bytes > control->bytes || bytes > control->bytes - stats->bytes)) {
        stats->denied_bytes++;
        allowed = 0;
    } else if (udp && (control->flags & TEGO_NC_DATAGRAMS) &&
               stats->datagrams >= control->datagrams_per_second) {
        stats->denied_datagrams++;
        allowed = 0;
    } else {
        if (bytes <= ~0ULL - stats->bytes)
            stats->bytes += bytes;
        else
            stats->bytes = ~0ULL;
        if (udp && stats->datagrams != ~0ULL)
            stats->datagrams++;
        if (udp && stats->datagrams_out != ~0ULL)
            stats->datagrams_out++;
    }
    bpf_spin_unlock(&stats->lock);
    return allowed;
}

SEC("sockops")
int tego_cg_sockops(struct bpf_sock_ops *ctx)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_nc_config *control;
    __u64 cookie;

    if (!owner->cgroup_id)
        return 1;
    control = bpf_map_lookup_elem(&tego_net_control, &owner->run_idx);
    if (!control || !(control->flags & (TEGO_NC_LISTEN | TEGO_NC_INGRESS | TEGO_NC_CONNECTIONS | TEGO_NC_PENDING)))
        return 1;
    cookie = bpf_get_socket_cookie(ctx);
    if (ctx->op == BPF_SOCK_OPS_TCP_LISTEN_CB && (control->flags & TEGO_NC_LISTEN)) {
        struct tego_net_socket_key socket = {.run_idx = owner->run_idx, .gen = control->gen, .cookie = cookie};
        struct tego_net_key key = {.run_idx = owner->run_idx, .family = ctx->family, .proto = IPPROTO_TCP};
        struct tego_net_verdict *grant;
        __u32 rule;
        // Explicit successful bind attribution is already committed by the
        // post-bind hook. Only an implicit autobind needs a port-zero row;
        // socket_listen admitted its pre-operation copied kernel address.
        if (!cookie || bpf_map_lookup_elem(&tego_net_binds,&socket))
            return 1;
        if (ctx->family == TEGO_AF_INET6)
            tego_addr_v6(key.addr,ctx->local_ip6[0],ctx->local_ip6[1],ctx->local_ip6[2],ctx->local_ip6[3]);
        else
            tego_addr_v4(key.addr,ctx->local_ip4);
        grant = bpf_map_lookup_elem(&tego_bind_exact,&key);
        if (!grant) {
            if (key.family == TEGO_AF_INET6 && tego_v4mapped(key.addr))
                key.family = TEGO_AF_INET;
            __builtin_memset(key.addr,0,sizeof(key.addr));
            grant = bpf_map_lookup_elem(&tego_bind_exact,&key);
        }
        if (grant && grant->verdict == TEGO_V_ALLOW) {
            rule = grant->rule_idx;
            bpf_map_update_elem(&tego_net_binds,&socket,&rule,BPF_NOEXIST);
        }
        return 1;
    }
    if (ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        tego_accept_reservation(ctx, owner, control, cookie);
    if (ctx->op == BPF_SOCK_OPS_TCP_CONNECT_CB || ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        if (bpf_sock_ops_cb_flags_set(ctx, ctx->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG)) {
            tego_release_socket(owner, control, cookie, 1);
            return 1;
        }
    }
    if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        tego_release_socket(owner, control, cookie, 0);
    if (ctx->op == BPF_SOCK_OPS_STATE_CB && ctx->args[1] == BPF_TCP_CLOSE)
        tego_release_socket(owner, control, cookie, 1);
    return 1;
}

SEC("cgroup/sock_release")
int tego_cg_release(struct bpf_sock *ctx)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_nc_config *control;
    struct tego_net_socket_key key = {};

    if (!owner->cgroup_id)
        return 1;
    control = bpf_map_lookup_elem(&tego_net_control, &owner->run_idx);
    if (!control)
        return 1;
    key.run_idx = owner->run_idx;
    key.gen = control->gen;
    key.cookie = bpf_get_socket_cookie(ctx);
    tego_release_socket(owner, control, key.cookie, 1);
    bpf_map_delete_elem(&tego_net_sockets, &key);
    bpf_map_delete_elem(&tego_net_binds, &key);
    return 1;
}

#endif
