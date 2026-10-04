// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef TEGO_NET_PACKET_H
#define TEGO_NET_PACKET_H

/* Only complete, nonfragmented TCP/UDP IP packets are supported. IPv6 extension
 * chains and jumbograms fail closed under packet controls. No payload parsing. */
static __always_inline int tego_packet_key(struct __sk_buff *skb, struct tego_net_flow_key *key, int ingress, __u8 *tcp_flags)
{
    __u8 head[40] = {}, ports[4] = {};
    __u32 off, length;
    __u16 source, dest;

    if (bpf_skb_load_bytes(skb, 0, head, 20))
        return 0;
    if ((head[0] >> 4) == 4) {
        off = (head[0] & 15) * 4;
        length = ((__u32)head[2] << 8) | head[3];
        if (off < 20 || off > 60 || length < off || length > skb->len || (head[6] & 0xbf) || head[7])
            return 0;
        key->family = TEGO_AF_INET;
        key->proto = head[9];
        if (ingress) {
            __builtin_memcpy(key->remote, head + 12, 4);
            __builtin_memcpy(key->local, head + 16, 4);
        } else {
            __builtin_memcpy(key->local, head + 12, 4);
            __builtin_memcpy(key->remote, head + 16, 4);
        }
    } else if ((head[0] >> 4) == 6) {
        if (bpf_skb_load_bytes(skb, 0, head, 40))
            return 0;
        length = ((__u32)head[4] << 8) | head[5];
        if (!length || length + 40 > skb->len)
            return 0;
        length += 40;
        off = 40;
        key->family = TEGO_AF_INET6;
        key->proto = head[6];
        if (ingress) {
            __builtin_memcpy(key->remote, head + 8, 16);
            __builtin_memcpy(key->local, head + 24, 16);
        } else {
            __builtin_memcpy(key->local, head + 8, 16);
            __builtin_memcpy(key->remote, head + 24, 16);
        }
    } else {
        return 0;
    }
    if (key->proto == IPPROTO_TCP) {
        __u8 tcp[20];
        if (length < off + 20 || bpf_skb_load_bytes(skb, off, tcp, sizeof(tcp)) ||
            (tcp[12] >> 4) < 5 || length < off + (tcp[12] >> 4) * 4)
            return 0;
        __builtin_memcpy(ports, tcp, sizeof(ports));
        *tcp_flags = tcp[13];
    } else if (key->proto == IPPROTO_UDP) {
        __u8 udp[8];
        __u32 udp_len;
        if (length < off + 8 || bpf_skb_load_bytes(skb, off, udp, sizeof(udp)))
            return 0;
        udp_len = ((__u32)udp[4] << 8) | udp[5];
        if (udp_len < 8 || udp_len > length - off)
            return 0;
        __builtin_memcpy(ports, udp, sizeof(ports));
    } else {
        return 0;
    }
    source = ((__u16)ports[0] << 8) | ports[1];
    dest = ((__u16)ports[2] << 8) | ports[3];
    key->local_port = ingress ? dest : source;
    key->remote_port = ingress ? source : dest;
    return source != 0 && dest != 0;
}

static __always_inline int tego_flow_live(const struct tego_net_flow_key *key, __u64 now, __u64 cookie, int inbound_only)
{
    struct tego_net_flow *flow = bpf_map_lookup_elem(&tego_net_flows, key);
    return flow && cookie && flow->cookie == cookie && flow->expires_ns > now && (!inbound_only || flow->inbound);
}

static __always_inline int tego_flow_save(const struct tego_net_flow_key *key, __u64 now, __u64 cookie, int inbound)
{
    struct tego_net_flow val = {};
    val.expires_ns = now + (key->proto == IPPROTO_UDP ? 30000000000ULL : 1800000000000ULL);
    val.inbound = inbound;
    val.cookie = cookie;
    return bpf_map_update_elem(&tego_net_flows, key, &val, BPF_ANY) == 0;
}

static __always_inline int tego_packet_ingress(struct __sk_buff *skb, struct tego_net_owner *owner,
                                               struct tego_nc_config *control)
{
    struct tego_net_flow_key key = {};
    struct tego_net_socket_key socket = {};
    struct tego_ingress_key peer = {};
    struct tego_net_verdict *grant;
    struct tego_nc_stats *stats;
    __u32 *bind_rule;
    __u64 now = bpf_ktime_get_ns();
    __u64 cookie = bpf_get_socket_cookie(skb);
    __u8 tcp_flags = 0;
    int new_syn;

    if (!(control->flags & (TEGO_NC_INGRESS | TEGO_NC_CONNECTIONS | TEGO_NC_PENDING)))
        return 1;
    key.run_idx = owner->run_idx;
    key.gen = control->gen;
    if (!tego_packet_key(skb, &key, 1, &tcp_flags) || !cookie)
        goto refused;
    new_syn = key.proto == IPPROTO_TCP && (tcp_flags & 0x12) == 0x02;
    // A new SYN always rechecks source/listener admission, even when its tuple
    // equals an old outgoing flow. Every cached reply belongs to one socket.
    if (!new_syn && tego_flow_live(&key, now, cookie, 0)) {
        struct tego_net_flow *flow = bpf_map_lookup_elem(&tego_net_flows, &key);
        int inbound = flow && flow->inbound;
        return tego_flow_save(&key, now, cookie, inbound);
    }
    if (!new_syn && key.proto == IPPROTO_TCP) {
        struct tego_net_flow *flow = bpf_map_lookup_elem(&tego_net_flows, &key);
        // The final handshake ACK arrives before passive-established names
        // the child cookie. Only a previously admitted exact inbound tuple
        // can pass this transition; the TCP stack still checks sequence state.
        if (flow && flow->inbound && flow->expires_ns > now) {
            if (control->flags & (TEGO_NC_CONNECTIONS | TEGO_NC_PENDING)) {
                struct tego_net_reservation *pending = bpf_map_lookup_elem(&tego_net_pending, &key);
                if (!pending || pending->phase != 2)
                    goto refused;
            } else {
                struct tego_net_socket_key listener = {.run_idx = owner->run_idx, .gen = control->gen, .cookie = flow->cookie};
                if (!bpf_map_lookup_elem(&tego_net_binds, &listener))
                    goto refused;
            }
            return 1;
        }
    }
    if (!(control->flags & TEGO_NC_INGRESS))
        goto admitted;
    socket.run_idx = owner->run_idx;
    socket.gen = control->gen;
    socket.cookie = cookie;
    bind_rule = bpf_map_lookup_elem(&tego_net_binds, &socket);
    if (!bind_rule)
        goto refused;
    peer.prefixlen = TEGO_INGRESS_MAX_BITS;
    peer.run_idx = owner->run_idx;
    peer.bind_rule = *bind_rule;
    peer.family = key.family;
    peer.proto = key.proto;
    peer.port = key.local_port;
    __builtin_memcpy(peer.local, key.local, sizeof(peer.local));
    __builtin_memcpy(peer.addr, key.remote, sizeof(peer.addr));
    grant = bpf_map_lookup_elem(&tego_net_ingress, &peer);
    if (!grant) {
        __builtin_memset(peer.local, 0, sizeof(peer.local));
        grant = bpf_map_lookup_elem(&tego_net_ingress, &peer);
    }
    if (!grant) {
        peer.port = 0;
        __builtin_memcpy(peer.local, key.local, sizeof(peer.local));
        grant = bpf_map_lookup_elem(&tego_net_ingress, &peer);
    }
    if (!grant) {
        __builtin_memset(peer.local, 0, sizeof(peer.local));
        grant = bpf_map_lookup_elem(&tego_net_ingress, &peer);
    }
    if (!grant || grant->verdict != TEGO_V_ALLOW)
        goto refused;
admitted:
    if (key.proto == IPPROTO_TCP && !new_syn)
        goto refused; // Unsolicited established TCP traffic creates no grant.
    if (new_syn && !tego_reserve_inbound(owner, control, &key, cookie))
        goto refused;
    if (key.proto == IPPROTO_UDP && !tego_reserve_socket(owner, control, cookie, 0))
        goto refused;
    if (!tego_flow_save(&key, now, cookie, 1))
        goto refused;
    return 1;
refused:
    stats = bpf_map_lookup_elem(&tego_net_stats, &owner->run_idx);
    if (stats)
        __sync_fetch_and_add(&stats->denied_ingress, 1);
    return 0;
}

static __always_inline int tego_packet_egress(struct __sk_buff *skb, struct tego_net_owner *owner,
                                              struct tego_nc_config *control)
{
    struct tego_net_flow_key key = {};
    struct tego_net_key dest = {};
    struct tego_net_decision verdict = {};
    __u64 now = bpf_ktime_get_ns();
    __u64 cookie = bpf_get_socket_cookie(skb);
    __u8 tcp_flags = 0;
    struct tego_net_socket_key socket = {.run_idx = owner->run_idx, .gen = control->gen};
    struct tego_net_socket *state;
    struct tego_net_flow *flow;
    int inbound = 0;

    key.run_idx = owner->run_idx;
    key.gen = control->gen;
    if (!tego_packet_key(skb, &key, 0, &tcp_flags) || !cookie)
        return 0;
    flow = bpf_map_lookup_elem(&tego_net_flows, &key);
    inbound = tego_flow_live(&key, now, cookie, 1);
    // SYN-ACK may still belong to a request socket, before passive-established
    // transfers the exact tuple to the accepted cookie. No other fresh TCP
    // packet receives this listener-owned exception.
    if (!inbound && key.proto == IPPROTO_TCP && (tcp_flags & 0x12) == 0x12 && flow &&
        flow->inbound && flow->expires_ns > now)
        inbound = 1;
    if (control->flags & (TEGO_NC_CONNECTIONS | TEGO_NC_PENDING)) {
        socket.cookie = cookie;
        state = bpf_map_lookup_elem(&tego_net_sockets, &socket);
        if (!state || (state->phase != 1 && state->phase != 2)) {
            struct tego_net_reservation *pending = bpf_map_lookup_elem(&tego_net_pending, &key);
            if (!(inbound && key.proto == IPPROTO_TCP && (tcp_flags & 0x12) == 0x12 && pending && pending->phase == 2))
                return 0;
        }
    }
    if (control->flags & TEGO_NC_INGRESS) {
        if (!inbound) {
            dest.run_idx = owner->run_idx;
            dest.family = key.family;
            dest.proto = key.proto;
            dest.port = key.remote_port;
            __builtin_memcpy(dest.addr, key.remote, sizeof(dest.addr));
            if (!tego_net_match(&dest, &verdict) || verdict.verdict != TEGO_V_ALLOW)
                return 0;
        }
    }
    if (!tego_charge_packet(owner, control, skb->len, key.proto == IPPROTO_UDP))
        return 0;
    if (control->flags & (TEGO_NC_INGRESS | TEGO_NC_CONNECTIONS | TEGO_NC_PENDING)) {
        if (inbound && flow)
            flow->expires_ns = now + (key.proto == IPPROTO_UDP ? 30000000000ULL : 1800000000000ULL);
        else
            return tego_flow_save(&key, now, cookie, 0);
    }
    return 1;
}

SEC("cgroup_skb/ingress")
int tego_cg_ingress(struct __sk_buff *skb)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_nc_config *control;
    if (!owner->cgroup_id)
        return 0;
    control = bpf_map_lookup_elem(&tego_net_control, &owner->run_idx);
    if (!control)
        return 1;
    int admitted = tego_packet_ingress(skb, owner, control);
    if (admitted) {
        struct tego_nc_stats *stats = bpf_map_lookup_elem(&tego_net_stats,&owner->run_idx);
        __u8 version = 0, protocol = 0;
        if (!stats || bpf_skb_load_bytes(skb,0,&version,sizeof(version)))
            return 0;
        if ((version >> 4) == 4) {
            if (bpf_skb_load_bytes(skb,9,&protocol,sizeof(protocol)))
                return 0;
        } else if ((version >> 4) == 6) {
            if (bpf_skb_load_bytes(skb,6,&protocol,sizeof(protocol)))
                return 0;
        } else
            return 0;
        bpf_spin_lock(&stats->lock);
        if ((__u64)skb->len <= ~0ULL - stats->bytes_in)
            stats->bytes_in += skb->len;
        else
            stats->bytes_in = ~0ULL;
        if (protocol == IPPROTO_UDP && stats->datagrams_in != ~0ULL)
            stats->datagrams_in++;
        bpf_spin_unlock(&stats->lock);
    }
    return admitted;
}

SEC("cgroup_skb/egress")
int tego_cg_egress(struct __sk_buff *skb)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_nc_config *control;
    if (!owner->cgroup_id)
        return 0;
    control = bpf_map_lookup_elem(&tego_net_control, &owner->run_idx);
    if (!control)
        return 1;
    return tego_packet_egress(skb, owner, control);
}

#endif
