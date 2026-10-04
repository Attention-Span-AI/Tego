// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef TEGO_NET_CONTROL_H
#define TEGO_NET_CONTROL_H

#define TEGO_NC_LISTEN 1
#define TEGO_NC_INGRESS 2
#define TEGO_NC_BYTES 4
#define TEGO_NC_DATAGRAMS 8
#define TEGO_NC_CONNECTIONS 16
#define TEGO_NC_PENDING 32
#define TEGO_NET_FLOW_MAX 16384
#define TEGO_NET_SOCKET_MAX 65536
#define TEGO_INGRESS_HDR_BITS 224
#define TEGO_INGRESS_MAX_BITS 352
#define TEGO_NET_INTERVALS 16
/* An admitted inbound SYN's reservation lasts until its handshake completes or this long, whichever is first
 * (network-controls; bpf-1): nothing reports a request socket the kernel drops, and the pending map is shared by
 * every run of the build. Linux gives a request socket up after its SYN-ACK retries, 63 s at the default
 * tcp_synack_retries of 5; a handshake completing later finds no reservation and its ACK is refused. */
#define TEGO_NET_SYN_RESERVATION_NS 75000000000ULL
#define TEGO_CLOCK_MONOTONIC 1

struct tego_net_timeline_key { __u32 run_idx; __u32 index; };
struct tego_net_decision {
    __u8 verdict;
    __u8 reason;
    __u16 rule_idx;
    __u32 pad;
    __u64 deadline_ns;
};
struct tego_net_chain {
    __u32 count;
    __u32 pad;
    struct tego_net_decision steps[TEGO_NET_INTERVALS];
};

struct tego_nc_config {
    __u32 flags;
    __u32 gen;
    __u64 bytes;
    __u64 datagrams_per_second;
    __u64 connections;
    __u64 pending_connects;
};

struct tego_ingress_key {
    __u32 prefixlen;
    __u32 run_idx;
    __u32 bind_rule;
    __u8 family;
    __u8 proto;
    __u16 port;
    __u8 local[16];
    __u8 addr[16];
};

struct tego_net_flow_key {
    __u32 run_idx;
    __u32 gen;
    __u8 family;
    __u8 proto;
    __u16 local_port;
    __u16 remote_port;
    __u16 pad;
    __u8 local[16];
    __u8 remote[16];
};

struct tego_net_flow {
    __u64 expires_ns;
    __u64 cookie;
    __u64 phase; /* baseline BPF supports 64-bit atomic compare/exchange */
    __u8 inbound;
    __u8 pad[7];
};

/* An inbound SYN's reservation in tego_net_pending: 0 reserving, 2 admitted and charged, 3 released by the
 * handshake's transfer or by the timer's expiry, whichever moves 2 -> 3 first. Refused SYNs keep no row. */
struct tego_net_reservation {
    __u64 phase;
    __u64 cookie;
    struct bpf_timer timer;
};

struct tego_net_socket_key {
    __u32 run_idx;
    __u32 gen;
    __u64 cookie;
};

struct tego_net_socket {
    __u64 phase; /* 0 reserving, 1 pending, 2 established/UDP, 3 closed; a refused reservation keeps no row */
    __u32 inbound;
    __u32 pad;
    struct tego_net_flow_key flow;
};

struct tego_bind_attempt_key {
    struct tego_net_socket_key socket;
    __u64 task;
};

struct tego_connect_approval_key {
    __u32 run_idx;
    __u32 gen;
    __u64 cookie;
    __u8 family;
    __u8 proto;
    __u16 port;
    __u8 addr[16];
    __u32 pad;
};
struct tego_connect_credit {
    __u64 credit;
    __u64 deadline_ns;
};

struct tego_nc_stats {
    struct bpf_spin_lock lock;
    __u32 pad;
    __u64 bytes;
    __u64 window_ns;
    __u64 datagrams;
    __u64 connections;
    __u64 pending;
    __u64 denied_ingress;
    __u64 denied_bytes;
    __u64 denied_datagrams;
    __u64 denied_connections;
    __u64 denied_pending;
    __u64 bytes_in;
    __u64 datagrams_in;
    __u64 datagrams_out;
};

#define TEGO_NET_HASH(name, key_type, val_type, entries) \
struct { \
    __uint(type, BPF_MAP_TYPE_HASH); \
    __uint(max_entries, entries); \
    __uint(pinning, LIBBPF_PIN_BY_NAME); \
    __type(key, key_type); \
    __type(value, val_type); \
} name SEC(".maps")

TEGO_NET_HASH(tego_net_control, __u32, struct tego_nc_config, TEGO_MAX_SLOTS);
TEGO_NET_HASH(tego_bind_exact, struct tego_net_key, struct tego_net_verdict, TEGO_NET_ROWS_MAX);
TEGO_NET_HASH(tego_net_binds, struct tego_net_socket_key, __u32, TEGO_NET_SOCKET_MAX);
#ifndef TEGO_NET_CONTROL_LISTEN_ONLY
TEGO_NET_HASH(tego_net_timeline, struct tego_net_timeline_key, struct tego_net_chain, TEGO_NET_ROWS_MAX);
TEGO_NET_HASH(tego_net_stats, __u32, struct tego_nc_stats, TEGO_MAX_SLOTS);
TEGO_NET_HASH(tego_net_sockets, struct tego_net_socket_key, struct tego_net_socket, TEGO_NET_SOCKET_MAX);
TEGO_NET_HASH(tego_net_pending, struct tego_net_flow_key, struct tego_net_reservation, TEGO_NET_FLOW_MAX);
TEGO_NET_HASH(tego_connect_approvals, struct tego_connect_approval_key, struct tego_connect_credit, TEGO_NET_SOCKET_MAX);

/* Failed bind attempts never alter active listener attribution. Stale attempts
 * are bounded and only an exact socket+calling-task successful post-bind commits. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TEGO_NET_SOCKET_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_bind_attempt_key);
    __type(value, __u32);
} tego_bind_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, TEGO_NET_ROWS_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_ingress_key);
    __type(value, struct tego_net_verdict);
} tego_net_ingress SEC(".maps");

/* Reply-cache eviction narrows admission. Charged pending SYNs are kept in the
 * separate non-evicting pending map until transfer, expiry or run teardown. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TEGO_NET_FLOW_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_net_flow_key);
    __type(value, struct tego_net_flow);
} tego_net_flows SEC(".maps");
#endif

static __always_inline int tego_v4mapped(const __u8 addr[16])
{
    return addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
           addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
           addr[8] == 0 && addr[9] == 0 && addr[10] == 255 && addr[11] == 255;
}

#endif
