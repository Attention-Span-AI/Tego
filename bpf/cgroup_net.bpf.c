// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Tier 2 network enforcement: the eight BPF_PROG_TYPE_CGROUP_SOCK_ADDR programs that decide host:port, CIDR
 * and unix socket rules in-kernel, per cgroup, with no BPF LSM (docs/p0/enforce-cgroup-observe.md §1, §5
 * R1-R7).
 *
 * Shape of every decision (§5 R1, R2, R3, R5):
 *   1. the run is the one the attachment belongs to: bpf_get_local_storage(&tego_net_owners) hands the
 *      program the cgroup storage of the cgroup it was attached to, which Attach wrote. That is not a lookup
 *      and not keyed by the caller. The kernel runs this program because the *socket's* cgroup is the run's
 *      cgroup or beneath it, whoever calls connect(2) — including the seccomp supervisor, which relays every
 *      allowed connect of the agent from its own process on a duplicate of the agent's socket (supervisor.md
 *      R9, I2). A decision keyed by bpf_get_current_cgroup_id() named the supervisor's cgroup there, missed
 *      the run set and allowed, so no relayed connect was ever decided in the kernel (maps.h says more);
 *   2. an attachment whose storage userspace has not configured yet (cgroup_id 0) refuses: the window lies
 *      between the first link and Attach's storage write, before any process of the run exists (§5 R1);
 *   3. exact tego_net_exact hit wins; else longest-prefix tego_net_cidr hit; else refused (R3, E8);
 *   4. the decision is written to tego_reason_map under the run's cgroup id as a breadcrumb and no
 *      ring-buffer event is pushed (R5, I4);
 *   5. return 1 to allow, 0 to refuse — the only two values a CGROUP_SOCK_ADDR program of this component
 *      returns (§8 I3).
 *
 * cgroup/sock_create is ADR 0018 (5)'s backstop on socket creation (§5 R4): it refuses an inet socket outside ADR
 * 0018 (1)'s allowlist (bpf/include/socket_allow.h, the plane's socket_create's too) on whatever path reaches
 * inet_create, the seccomp filter's socket(2) arm or not. cgroup/setsockopt is ADR 0018 (7)'s: it refuses
 * setsockopt(SOL_TCP, TCP_ULP), the one way a socket the allowlist admitted becomes one of another family, on
 * whatever path reaches the protocol's setsockopt. Both take their run from the same storage (steps 1 and 2), and
 * they are the two programs here that push a ring-buffer event (R5 as amended): no recorder sees a socket's creation
 * or its options, so each refusal's one ledger line is the program's own record, on the run's ring, read by owner
 * storage alone.
 *
 * Coexisting builds (§5 R1, §6 E22) need no neutral branch any more: each build's programs read their own
 * build's pinned storage map and run only where that build attached them, and the kernel ANDs the verdicts
 * of every link on a cgroup, so neither build can widen or narrow the other's decision. A socket whose
 * protocol the contract cannot name returns 1 without deciding (R4).
 *
 * bind4/bind6 decide a declared net.listen (network-controls): a run with no listener control returns 1, as the
 * P0 placeholders did (R6); otherwise tego_bind_decide reads the run from tego_net_owners and refuses an
 * address without a tego_bind_exact grant.
 *
 * connect_unix and sendmsg_unix (6.7+, R7) decide unix destinations by name. The uapi struct bpf_sock_addr has
 * no path member, but bpf_cast_to_kern_ctx (6.2) turns the context into the kernel's struct
 * bpf_sock_addr_kern, whose uaddr is the kernel's own copy of the caller's sockaddr_un (move_addr_to_kernel,
 * or ____sys_sendmsg's copy of msg_name), read through bpf_rdonly_cast — the upstream selftest
 * connect_unix_prog.c does the same. Reading it is race-free, since no thread of the caller can rewrite that
 * copy, and needs CAP_PERFMON or CAP_SYS_ADMIN (untrusted BTF pointer loads), which tier 2 holds. These two
 * programs only ever narrow: the kernel ANDs them with the inherited tier-1 filter and supervisor, which stay
 * the primary decision. The name is all they see: the path lookup happens after the hook. For a connect, a
 * symlink or a daemon's socket moved under a listed name is the supervisor's resolved-socket check's to catch.
 * A datagram is continued, not relayed, so the agent's own send resolves the name under its inherited Landlock
 * domain: at Landlock ABI 9 (Linux 7.1) and above that domain's RESOLVE_UNIX backstop checks the socket it
 * resolves to (enforce-landlock R21); below ABI 9 nothing does, at this tier as at tier 1 (R7, supervisor R13b).
 */
#define TEGO_NET_MAPS
#include "maps.h"
#include "net_control.h"
#include "net_budget.h"
#include "socket_allow.h"

char _license[] SEC("license") = "Dual BSD/GPL";

/* BTF anchor (cgroup_track.bpf.c's convention): cgroup/sock_create's record is a local pointer into the ring, which
 * puts no struct in the object's BTF, so bpf2go's Go mirror of it (internal/bpf's parity test) needs this global.
 * Never read or written. */
const struct tego_ev_sock *tego_btf_ev_sock;
/* The same for cgroup/setsockopt's record. */
const struct tego_ev_sockopt *tego_btf_ev_sockopt;

/* The two values a CGROUP_SOCK_ADDR program may return: 1 lets the operation proceed, 0 refuses it with the
 * syscall's own EPERM. */
#define TEGO_SOCK_OK 1
#define TEGO_SOCK_REFUSE 0

/* Reads the destination port a sock_addr hook exposes. user_port is a 4-byte field holding the port in
 * network byte order (6.1 uapi, unchanged since); nothing past the 6.1 prototype is read (ARCHITECTURE §11.1). */
static __always_inline __u16 tego_user_port(const struct bpf_sock_addr *ctx)
{
    return bpf_ntohs((__u16)ctx->user_port);
}

/* Fills the exact-match key for this hook's destination. */
static __always_inline void tego_net_key_of(struct tego_net_key *k, const struct bpf_sock_addr *ctx,
                                             __u32 run_idx, __u8 family)
{
    __builtin_memset(k, 0, sizeof(*k));
    k->run_idx = run_idx;
    k->family = family;
    k->proto = (__u8)ctx->protocol;
    k->port = tego_user_port(ctx);
    if (family == TEGO_AF_INET6)
        tego_addr_v6(k->addr, ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3]);
    else
        tego_addr_v4(k->addr, ctx->user_ip4);
}

/* Reports whether the key names an unspecified destination: 0.0.0.0, :: or ::ffff:0.0.0.0. The kernel sends
 * such a connect or datagram to this host after the hook has returned (ip_route_output_key_hash_rcu for 0.0.0.0,
 * tcp_v6_connect and udpv6_sendmsg for ::, to ::1 or, from a socket bound to a v4-mapped address, to
 * ::ffff:127.0.0.1), so no row can name where it goes and it is refused. */
static __always_inline int tego_addr_unspecified(const struct tego_net_key *k)
{
    __u32 w0, w1, w2, w3;

    __builtin_memcpy(&w0, k->addr, 4);
    __builtin_memcpy(&w1, k->addr + 4, 4);
    __builtin_memcpy(&w2, k->addr + 8, 4);
    __builtin_memcpy(&w3, k->addr + 12, 4);
    if (k->family == TEGO_AF_INET)
        return w0 == 0;
    return w0 == 0 && w1 == 0 && (w2 == 0 || w2 == bpf_htonl(0xffff)) && w3 == 0;
}

/* Looks the destination up: exact first, then the longest matching CIDR prefix (§5 R3). Returns NULL when
 * neither names it, which is a refusal with net-not-allowed. */
static __always_inline int tego_net_match(const struct tego_net_key *k, struct tego_net_decision *out)
{
    struct tego_net_lpm_key lk;
    struct tego_net_verdict *v;

    v = bpf_map_lookup_elem(&tego_net_exact, k);
    if (!v) {
        __builtin_memset(&lk, 0, sizeof(lk));
        lk.prefixlen = TEGO_LPM_MAX_BITS;
        lk.run_idx = k->run_idx;
        lk.family = k->family;
        lk.proto = k->proto;
        lk.port = k->port;
        __builtin_memcpy(lk.addr, k->addr, sizeof(lk.addr));
        v = bpf_map_lookup_elem(&tego_net_cidr, &lk);
    }
    if (!v)
        return 0;
    if (v->timeline) {
        struct tego_net_timeline_key key = {.run_idx = k->run_idx, .index = v->timeline};
        struct tego_net_chain *chain = bpf_map_lookup_elem(&tego_net_timeline, &key);
        __u64 now = bpf_ktime_get_ns();
        if (!chain || !chain->count || chain->count > TEGO_NET_INTERVALS)
            return 0;
#pragma unroll
        for (__u32 i = 0; i < TEGO_NET_INTERVALS; i++) {
            if (i < chain->count && (!chain->steps[i].deadline_ns || now < chain->steps[i].deadline_ns)) {
                *out = chain->steps[i];
                return 1;
            }
        }
        return 0;
    }
    if (v->deadline_ns && bpf_ktime_get_ns() >= v->deadline_ns)
        return 0;
    out->verdict = v->verdict;
    out->reason = v->reason;
    out->rule_idx = v->rule_idx;
    return 1;
}

/* Records the decision for the network event's reader (§5 R5), under the run's own cgroup id, which is the
 * id the run's handle knows and removes at Detach (R15). Last write wins across the run; the reader discards a
 * breadcrumb whose mono_ns is older than its staleness window rather than misattribute (§6 E5). */
static __always_inline void tego_net_breadcrumb(__u64 cgroup_id, const struct tego_net_key *k, __u8 op,
                                                 __u8 verdict, __u8 reason, __u16 rule_idx)
{
    struct tego_reason br;

    __builtin_memset(&br, 0, sizeof(br));
    br.op = op;
    br.verdict = verdict;
    br.reason = reason;
    br.family = k->family;
    br.proto = k->proto;
    br.port = k->port;
    __builtin_memcpy(br.addr, k->addr, sizeof(br.addr));
    br.mono_ns = bpf_ktime_get_ns();
    br.run_idx = k->run_idx;
    br.rule_idx = rule_idx;
    bpf_map_update_elem(&tego_reason_map, &cgroup_id, &br, BPF_ANY);
}

/* An authenticated supervisor may approve exactly one frozen operation on this socket: a TCP connect, or a UDP
 * connect or addressed datagram (supervisor R13d), each to the one destination the key names. No run-wide destination
 * grant is installed. A TCP credit is a connect's alone: no addressed send consumes it (a Fast-Open send runs
 * connect4/6 itself). A UDP credit is taken by the first of the socket's connect or datagram to that destination,
 * which the supervisor's relay is, or an agent thread's own send there on that socket, which the approval admits
 * anyway. Normal policy allows leave credit untouched for revoke. */
static __always_inline int tego_connect_approved(struct bpf_sock_addr *ctx,
                                                 struct tego_net_owner *owner,
                                                 const struct tego_net_key *dest, __u8 op)
{
    struct tego_connect_approval_key key = {};
    struct tego_connect_credit *credit;
    struct tego_run *run;
    if (!(dest->proto == IPPROTO_TCP && op == TEGO_EV_CONNECT) && dest->proto != IPPROTO_UDP)
        return 0;
    run = bpf_map_lookup_elem(&tego_run_set, &owner->cgroup_id);
    if (!run || run->run_idx != owner->run_idx)
        return 0;
    key.run_idx = owner->run_idx;
    key.gen = run->gen;
    key.cookie = bpf_get_socket_cookie(ctx);
    key.family = dest->family;
    key.proto = dest->proto;
    key.port = dest->port;
    __builtin_memcpy(key.addr, dest->addr, sizeof(key.addr));
    credit = bpf_map_lookup_elem(&tego_connect_approvals, &key);
    if (!credit || credit->deadline_ns <= bpf_ktime_get_ns() ||
        __sync_val_compare_and_swap(&credit->credit, 1, 0) != 1)
        return 0;
    bpf_map_delete_elem(&tego_connect_approvals, &key);
    return 1;
}

/* The whole decision, shared by connect4/6 and sendmsg4/6. op distinguishes a connect from an unconnected
 * datagram send so the breadcrumb's reader knows which syscall it belongs to (§5 R4). */
static __always_inline int tego_net_decide(struct bpf_sock_addr *ctx, __u8 op, __u8 family)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_net_decision v = {};
    struct tego_net_key k;
    __u8 proto = (__u8)ctx->protocol;
    __u8 verdict = TEGO_V_REFUSED;
    __u8 reason = TEGO_R_NET_NOT_ALLOWED;
    __u16 rule_idx = 0;

    /* The contract names destinations as host:port, so only TCP and UDP are decided here. For connect4/6
     * nothing else arrives: __inet_stream_connect and inet_dgram_connect call the hook only when the
     * protocol's struct proto has a pre_connect, which tcp_prot, tcpv6_prot, udp_prot and udpv6_prot alone
     * have, so raw, ICMP, SCTP and UDP-Lite connects never reach it (§5 R4). sendmsg4/6 are different: they
     * run from udp_sendmsg and udpv6_sendmsg, which UDP-Lite's struct proto shares, so an unconnected UDP-Lite
     * datagram does reach this branch and is let through undecided. No UDP-Lite socket exists to send it under a
     * net: section: the seccomp filter refuses one at socket(2) (EPROTONOSUPPORT, ADR 0018 (1)), a plane mode's
     * socket_create on every path, and cgroup/sock_create below on any path to inet_create; this branch decides
     * none of it (R4). */
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return TEGO_SOCK_OK;

    /* An attachment Attach has not configured yet decides nothing and allows nothing (step 2 above). */
    if (owner->cgroup_id != 0) {
        tego_net_key_of(&k, ctx, owner->run_idx, family);

        if (!tego_addr_unspecified(&k) && tego_net_match(&k, &v)) {
            verdict = v.verdict;
            reason = v.verdict == TEGO_V_ALLOW ? TEGO_R_NONE : v.reason;
            rule_idx = v.rule_idx;
        }
        if (verdict != TEGO_V_ALLOW && tego_connect_approved(ctx, owner, &k, op)) {
            verdict = TEGO_V_ALLOW;
            reason = TEGO_R_NONE;
        }

        tego_net_breadcrumb(owner->cgroup_id, &k, op, verdict, reason, rule_idx);
    }

    if (verdict == TEGO_V_ALLOW) {
        struct tego_nc_config *control = bpf_map_lookup_elem(&tego_net_control, &owner->run_idx);
        if (control && !tego_reserve_socket(owner, control, bpf_get_socket_cookie(ctx),
                                             proto == IPPROTO_TCP)) {
            tego_net_breadcrumb(owner->cgroup_id, &k, op, TEGO_V_REFUSED, TEGO_R_NET_NOT_ALLOWED, rule_idx);
            return TEGO_SOCK_REFUSE;
        }
        return TEGO_SOCK_OK;
    }
    return TEGO_SOCK_REFUSE;
}

/* connect4 decides every AF_INET connect(2), TCP and UDP alike (§5 R4). */
SEC("cgroup/connect4")
int tego_cg_connect4(struct bpf_sock_addr *ctx)
{
    return tego_net_decide(ctx, TEGO_EV_CONNECT, TEGO_AF_INET);
}

/* connect6 decides every AF_INET6 connect(2). */
SEC("cgroup/connect6")
int tego_cg_connect6(struct bpf_sock_addr *ctx)
{
    return tego_net_decide(ctx, TEGO_EV_CONNECT, TEGO_AF_INET6);
}

/* sendmsg4 decides each unconnected IPv4 UDP datagram independently of any connect (§5 R4). */
SEC("cgroup/sendmsg4")
int tego_cg_sendmsg4(struct bpf_sock_addr *ctx)
{
    return tego_net_decide(ctx, TEGO_EV_SENDMSG, TEGO_AF_INET);
}

/* sendmsg6 decides each unconnected IPv6 UDP datagram. */
SEC("cgroup/sendmsg6")
int tego_cg_sendmsg6(struct bpf_sock_addr *ctx)
{
    return tego_net_decide(ctx, TEGO_EV_SENDMSG, TEGO_AF_INET6);
}

/* Bind grants decide the kernel-copied address. Missing listener controls retain
 * legacy behavior. Only successful post-bind commits listener attribution;
 * failed rebinding cannot replace a previously admitted socket's rule. */
static __always_inline int tego_bind_decide(struct bpf_sock_addr *ctx, __u8 family)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_nc_config *control;
    struct tego_net_key key;
    struct tego_net_key wildcard;
    struct tego_net_verdict *grant;
    struct tego_bind_attempt_key attempt = {};
    __u32 rule;

    if (!owner->cgroup_id)
        return TEGO_SOCK_REFUSE;
    control = bpf_map_lookup_elem(&tego_net_control, &owner->run_idx);
    if (!control || !(control->flags & TEGO_NC_LISTEN))
        return TEGO_SOCK_OK;
    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
        return TEGO_SOCK_REFUSE;
    tego_net_key_of(&key, ctx, owner->run_idx, family);
    grant = bpf_map_lookup_elem(&tego_bind_exact, &key);
    if (!grant) {
        wildcard = key;
        if (wildcard.family == TEGO_AF_INET6 && tego_v4mapped(wildcard.addr))
            wildcard.family = TEGO_AF_INET;
        __builtin_memset(wildcard.addr, 0, sizeof(wildcard.addr));
        grant = bpf_map_lookup_elem(&tego_bind_exact, &wildcard);
    }
    if (!grant || grant->verdict != TEGO_V_ALLOW) {
        tego_net_breadcrumb(owner->cgroup_id, &key, TEGO_EV_BIND,
                            TEGO_V_REFUSED, TEGO_R_NET_NOT_ALLOWED, 0);
        return TEGO_SOCK_REFUSE;
    }
    attempt.socket.run_idx = owner->run_idx;
    attempt.socket.gen = control->gen;
    attempt.socket.cookie = bpf_get_socket_cookie(ctx);
    attempt.task = bpf_get_current_pid_tgid();
    rule = grant->rule_idx;
    if (!attempt.socket.cookie || bpf_map_update_elem(&tego_bind_pending, &attempt, &rule, BPF_ANY))
        return TEGO_SOCK_REFUSE;
    tego_net_breadcrumb(owner->cgroup_id, &key, TEGO_EV_BIND, TEGO_V_ALLOW, TEGO_R_NONE, grant->rule_idx);
    return TEGO_SOCK_OK;
}

SEC("cgroup/bind4")
int tego_cg_bind4(struct bpf_sock_addr *ctx)
{
    return tego_bind_decide(ctx, TEGO_AF_INET);
}

/* bind6 is the IPv6 half of the same listener policy. */
SEC("cgroup/bind6")
int tego_cg_bind6(struct bpf_sock_addr *ctx)
{
    return tego_bind_decide(ctx, TEGO_AF_INET6);
}

static __always_inline int tego_commit_bind(struct bpf_sock *ctx)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_nc_config *control;
    struct tego_bind_attempt_key attempt = {};
    __u32 *rule;
    int err;
    if (!owner->cgroup_id)
        return 0;
    control = bpf_map_lookup_elem(&tego_net_control, &owner->run_idx);
    if (!control || !(control->flags & TEGO_NC_LISTEN))
        return 1;
    attempt.socket.run_idx = owner->run_idx;
    attempt.socket.gen = control->gen;
    attempt.socket.cookie = bpf_get_socket_cookie(ctx);
    attempt.task = bpf_get_current_pid_tgid();
    rule = bpf_map_lookup_elem(&tego_bind_pending, &attempt);
    if (!rule)
        return 0;
    err = bpf_map_update_elem(&tego_net_binds, &attempt.socket, rule, BPF_ANY);
    bpf_map_delete_elem(&tego_bind_pending, &attempt);
    return err == 0;
}

SEC("cgroup/post_bind4")
int tego_cg_post_bind4(struct bpf_sock *ctx) { return tego_commit_bind(ctx); }
SEC("cgroup/post_bind6")
int tego_cg_post_bind6(struct bpf_sock *ctx) { return tego_commit_bind(ctx); }

/* cgroup/sock_create (§5 R4; ADR 0018 (5), PR 2): the kernel runs it from inet_create and inet6_create, after the
 * protocol's own init and before the socket is handed back, for every socket of the run's cgroup or beneath it that
 * the caller asked for (kern == 0); it sees no other family, which is the residual ADR 0018 (5) names. It decides on
 * the socket's own family, sk_type and the whole protocol number, never the low byte tego_net_decide keys a
 * destination by, so MPTCP (262) is not TCP and IPPROTO_SMC (256) is not protocol 0 (ADR 0018 PR 2 condition: MPTCP
 * on this path is refused and recorded, since a runtime's MPTCP probe goes through socket(2), whose filter arm
 * answers it silently and never reaches here).
 *
 *   - an attachment Attach has not configured yet refuses, unrecorded, as the other programs do (§5 R1): no
 *     process of the run exists then, and no run is known to record for;
 *   - a triple the allowlist admits, ping sockets as the owner's TEGO_OWNER_NET_ICMP says, passes;
 *   - anything else is refused with the kernel's EPERM (return 0; §8 I3), and recorded first: the refusal's one
 *     ledger line is this program's own TEGO_EV_SOCK_CREATE on the run's ring, found by the owner's run_idx and
 *     stamped with the owner's gen and cgroup id, since no recorder sees a socket's creation (R5 as amended; ADR
 *     0015). Under record: off too, as every refusal is. A run with no ring, or a full one, counts the loss at
 *     the run's slot (§8 I7).
 *
 * The run is the attachment's (steps 1 and 2 above), never the caller's: no run-set lookup, so the record is
 * reserved after the storage read alone (bpf/tests TestRunSetLookupFirst names this program's exception). */
SEC("cgroup/sock_create")
int tego_cg_sock_create(struct bpf_sock *ctx)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_run r = {};
    const struct tego_run *run = &r;
    struct tego_ev_sock *e;
    void *ring;
    int family = ctx->family;
    int type = ctx->type;
    int protocol = ctx->protocol;

    if (owner->cgroup_id == 0)
        return TEGO_SOCK_REFUSE;
    if (tego_socket_allowed(family, type, protocol, (owner->flags & TEGO_OWNER_NET_ICMP) != 0))
        return TEGO_SOCK_OK;

    r.run_idx = owner->run_idx;
    r.gen = owner->gen;
    ring = tego_ring_of(&tego_events, run);
    e = ring ? bpf_ringbuf_reserve(ring, sizeof(*e), 0) : 0;
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return TEGO_SOCK_REFUSE;
    }
    tego_hdr_fill(&e->hdr, TEGO_EV_SOCK_CREATE, sizeof(*e), run, owner->cgroup_id);
    e->hdr.verdict = TEGO_V_REFUSED;
    e->hdr.reason = TEGO_R_NET_NOT_ALLOWED;
    e->family = family;
    e->type = type;
    e->protocol = protocol;
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
    return TEGO_SOCK_REFUSE;
}

#include "net_packet.h"

/* Builds the tego_unix_names lookup key for the destination the hook was handed, and returns its kind, or 0
 * for a length no valid address has (unix_validate_addr refused those before the hook ran; the check is here
 * so the offsets below are bounded for the verifier). The sun_path bytes are copied as they are, at constant
 * offsets, because an untrusted BTF pointer takes no variable offset:
 *   - an abstract name keeps its leading NUL, and the key's len is the address's whole sun_path length, so a
 *     row matches exactly that many bytes, NUL bytes included (never NUL-scanned, supervisor.md E5);
 *   - a pathname ends at its first NUL or at the address length, where unix_mkname_bsd ends it, and a NUL is
 *     written there when the address carries none.
 * What follows the name in the kernel's buffer is copied too and is never compared: every row's prefix ends
 * at or before the name's last byte (or its NUL), and the canonical and relay checks stop at the NUL. */
static __always_inline int tego_unix_key_of(struct tego_unix_key *k, struct bpf_sock_addr *ctx, __u32 run_idx)
{
    struct bpf_sock_addr_kern *sa = bpf_cast_to_kern_ctx(ctx);
    struct sockaddr_un *un;
    __u32 alen, n, i;
    int abstract;

    __builtin_memset(k, 0, sizeof(*k));
    k->prefixlen = TEGO_UNIX_MAX_BITS;
    k->run_idx = run_idx;

    alen = sa->uaddrlen;
    if (alen <= TEGO_SUN_PATH_OFF || alen > TEGO_SUN_PATH_OFF + TEGO_UNIX_NAME_MAX)
        return 0;
    n = alen - TEGO_SUN_PATH_OFF;
    un = bpf_core_cast(sa->uaddr, struct sockaddr_un);
    abstract = un->sun_path[0] == 0;
    /* The header goes in before the name, not after it. kind sits at the first byte of an 8-byte stack slot
     * that name[0..5] share, and the verifier tracks a lone byte stored there as a spilled register, then
     * refuses a one-byte read of its neighbours ("invalid size of register fill"); the name bytes written
     * after it turn the slot back into plain data. */
    k->kind = abstract ? TEGO_UNIX_ABSTRACT : TEGO_UNIX_PATH;
    k->len = abstract ? (__u8)n : 0;
#pragma unroll
    for (i = 0; i < TEGO_UNIX_NAME_MAX; i++)
        k->name[i] = un->sun_path[i];

    if (abstract)
        return TEGO_UNIX_ABSTRACT;
    if (n < TEGO_UNIX_NAME_MAX)
        k->name[n] = 0;
    return TEGO_UNIX_PATH;
}

/* Reports whether a pathname connect is the supervisor's relay of one it already decided (supervisor.md R11):
 * the relay walks the agent's name as the agent, admits the socket it resolves to, and connects on a duplicate
 * of the agent's socket by naming that inode as /proc/self/fd/<n>, so the decision and the connect cannot
 * name two sockets. That name means something only in the relaying process, so it is admitted only from the
 * launcher's own cgroup, which Attach wrote into the owner (0 admits it from no one); from anywhere else,
 * the agent included, it is an ordinary absolute name and is decided as one. The caller's cgroup identifies
 * the relay; the run is still the attachment's (§5 R1). */
static __always_inline int tego_unix_relayed(const struct tego_net_owner *owner, const __u8 *name)
{
    if (owner->relay_cgroup_id == 0 || bpf_get_current_cgroup_id() != owner->relay_cgroup_id)
        return 0;
    return tego_unix_relay_name(name);
}

/* Looks a built key up: a declared unix: entry or abstract name admits, and so does the nearest filesystem
 * entry above a pathname when it is a write entry; any other nearest entry, or none, refuses (SEMANTICS §5,
 * supervisor.md R11's name check). */
static __always_inline int tego_unix_listed(const struct tego_unix_key *k)
{
    struct tego_net_verdict *v = bpf_map_lookup_elem(&tego_unix_names, k);

    return v && v->verdict == TEGO_V_ALLOW;
}

/* Whether an abstract-name connect consumes the one-connect grant the supervisor made for this socket after a
 * person approved that name (supervisor R11c, tego_unix_approved): the run is the attachment's, at the gen its
 * slot holds now. */
static __always_inline int tego_unix_connect_approved(struct bpf_sock_addr *ctx, const struct tego_net_owner *owner,
                                                       const struct tego_unix_key *k)
{
    struct tego_run *run = bpf_map_lookup_elem(&tego_run_set, &owner->cgroup_id);

    if (!run || run->run_idx != owner->run_idx)
        return 0;
    return tego_unix_approved(owner->run_idx, run->gen, bpf_get_socket_cookie(ctx), k);
}

/* The whole unix decision, shared by connect_unix and sendmsg_unix; op says which (§5 R7):
 *   - an attachment Attach has not configured yet refuses, as the inet programs do (§5 R1);
 *   - an abstract name is admitted when a unix: entry names exactly its bytes, and a connect also when it consumes
 *     the one-connect grant of a person's approval (tego_unix_connect_approved);
 *   - an absolute name is admitted when it is the supervisor's relay (connect only), or when it is spelled
 *     canonically and a unix: entry or a write entry admits it;
 *   - a relative name resolves against the caller's cwd, which this program cannot read: a datagram's is left
 *     to tier 1, which records it (supervisor.md R13b), and a connect's is refused, because the supervisor
 *     relays every connect by the inode it resolved and never passes a relative name on, so one arriving
 *     here did not come through the supervisor.
 * No breadcrumb is written: tego_reason is shaped for an address and a port, and the supervisor reads none
 * yet (§5 R5). */
static __always_inline int tego_unix_decide(struct bpf_sock_addr *ctx, __u8 op)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_unix_key k;
    int kind, allow = 0;

    if (owner->cgroup_id != 0) {
        kind = tego_unix_key_of(&k, ctx, owner->run_idx);
        if (kind == TEGO_UNIX_ABSTRACT)
            allow = tego_unix_listed(&k) || (op == TEGO_EV_CONNECT && tego_unix_connect_approved(ctx, owner, &k));
        else if (kind == TEGO_UNIX_PATH && k.name[0] != '/')
            allow = op == TEGO_EV_SENDMSG;
        else if (kind == TEGO_UNIX_PATH && op == TEGO_EV_CONNECT && tego_unix_relayed(owner, k.name))
            allow = 1;
        else if (kind == TEGO_UNIX_PATH && tego_unix_canonical(k.name))
            allow = tego_unix_listed(&k);
    }

    if (allow)
        return TEGO_SOCK_OK;
    return TEGO_SOCK_REFUSE;
}

/* connect_unix decides every AF_UNIX connect(2) of the run's sockets, stream, seqpacket and datagram alike
 * (6.7+, §5 R7); below 6.7 the backend does not load it and the inherited tier-1 path decides alone (§6 E1). */
SEC("cgroup/connect_unix")
int tego_cg_connect_unix(struct bpf_sock_addr *ctx)
{
    return tego_unix_decide(ctx, TEGO_EV_CONNECT);
}

/* sendmsg_unix decides each addressed AF_UNIX datagram, which the supervisor records and continues, so the
 * kernel re-reads an address a sibling thread could rewrite after the supervisor read it (supervisor.md R13b).
 * This program reads the kernel's copy, so the verdict and the send name one destination (6.7+, §5 R7). */
SEC("cgroup/sendmsg_unix")
int tego_cg_sendmsg_unix(struct bpf_sock_addr *ctx)
{
    return tego_unix_decide(ctx, TEGO_EV_SENDMSG);
}

/* setsockopt(2)'s SOL_TCP (IPPROTO_TCP) and TCP_ULP: the uapi numbers, which vmlinux.h carries as no macro. */
#define TEGO_SOL_TCP 6
#define TEGO_TCP_ULP 31
/* The most of an option's value the kernel shows a cgroup/setsockopt program: PAGE_SIZE on 4 KiB pages
 * (kernel/bpf/cgroup.c sockopt_alloc_buf). A longer value is handed back with optlen 0 below. */
#define TEGO_SOCKOPT_SHOWN 4096

/* cgroup/setsockopt (ADR 0018 (7); §5 R4): the kernel runs it from do_sock_setsockopt, before the protocol's own
 * setsockopt, for every option set on a socket of the run's cgroup or beneath it, whoever sets it: setsockopt(2),
 * which the seccomp filter's socket arm already notifies for TCP_ULP and the supervisor refuses, and io_uring's
 * SOCKET_URING_OP_SETSOCKOPT (6.7+), which no seccomp filter sees. It decides one option, SOL_TCP's TCP_ULP, whatever
 * the name: an upper-layer protocol is how a TCP socket the allowlist admitted was turned into another family in
 * place (the smc module's "smc" ULP builds an AF_SMC socket as a kernel socket, which neither cgroup/sock_create nor
 * a plane's socket_create sees), and no ULP is something the network rules govern.
 *
 *   - an attachment Attach has not configured yet refuses, unrecorded, as the other programs do (§5 R1);
 *   - any other option passes (return 1) untouched, the value the kernel copied for this program included, so another
 *     program in the chain keeps what it rewrote; the one change is the documented one for a value longer than the
 *     kernel shows a program (TEGO_SOCKOPT_SHOWN): its optlen is set to 0, which tells the kernel to use the caller's
 *     own value, as it does with no program attached, where a 5.11 to 6.4 kernel would refuse the call with EFAULT;
 *   - TCP_ULP is refused with the kernel's EPERM (return 0; §8 I3), and recorded first, as cgroup/sock_create records:
 *     its own TEGO_EV_SOCKOPT on the run's ring, by the owner's run_idx, gen and cgroup id, under record: off too,
 *     with the caller's optlen and the first TEGO_ULP_NAME_MAX bytes of the kernel's copy of the value
 *     (optval..optval_end, checked against its end): the kernel copies min(optlen, its buffer) bytes into a zeroed
 *     buffer of at least 16, so the bytes past optlen are zero, and the reader cuts the name at optlen and the first
 *     NUL, the bytes the kernel itself would have read as the name (strncpy_from_sockptr, min(optlen, 15)). A run
 *     with no ring, or a full one, counts the loss at the run's slot (§8 I7).
 *
 * The run is the attachment's, never the caller's (bpf/tests TestRunSetLookupFirst names this program's exception, as
 * it names cgroup/sock_create's). */
SEC("cgroup/setsockopt")
int tego_cg_setsockopt(struct bpf_sockopt *ctx)
{
    struct tego_net_owner *owner = bpf_get_local_storage(&tego_net_owners, 0);
    struct tego_run r = {};
    const struct tego_run *run = &r;
    struct tego_ev_sockopt *e;
    __u8 *optval, *end;
    void *ring;

    if (owner->cgroup_id == 0)
        return TEGO_SOCK_REFUSE;
    if (ctx->level != TEGO_SOL_TCP || ctx->optname != TEGO_TCP_ULP) {
        if (ctx->optlen > TEGO_SOCKOPT_SHOWN)
            ctx->optlen = 0;
        return TEGO_SOCK_OK;
    }

    r.run_idx = owner->run_idx;
    r.gen = owner->gen;
    ring = tego_ring_of(&tego_events, run);
    e = ring ? bpf_ringbuf_reserve(ring, sizeof(*e), 0) : 0;
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return TEGO_SOCK_REFUSE;
    }
    tego_hdr_fill(&e->hdr, TEGO_EV_SOCKOPT, sizeof(*e), run, owner->cgroup_id);
    e->hdr.verdict = TEGO_V_REFUSED;
    e->hdr.reason = TEGO_R_NET_NOT_ALLOWED;
    e->level = ctx->level;
    e->optname = ctx->optname;
    e->optlen = ctx->optlen;
    e->pad = 0;
    __builtin_memset(e->name, 0, sizeof(e->name));
    optval = ctx->optval;
    end = ctx->optval_end;
    if (optval + TEGO_ULP_NAME_MAX <= end)
        __builtin_memcpy(e->name, optval, TEGO_ULP_NAME_MAX);
    bpf_ringbuf_submit(e, 0);
    return TEGO_SOCK_REFUSE;
}
