// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Common helpers for all Tego BPF programs. Every program declares its own SEC("license") = "Dual BSD/GPL".
 *
 * The libbpf headers are vendored under include/libbpf/ (bpf/README.md records the version) so a build needs
 * nothing but clang and this tree; vmlinux.h is generated from the running kernel's BTF.
 */
#ifndef TEGO_COMMON_H
#define TEGO_COMMON_H

#include "vmlinux.h"
#include "libbpf/bpf_helpers.h"
#include "libbpf/bpf_core_read.h"
#include "libbpf/bpf_tracing.h"
#include "libbpf/bpf_endian.h"
#include "events.h"

/* arm64's uprobe context. bpf_tracing.h reads a probed function's arguments on arm64 through struct
 * user_pt_regs, the userspace view arm64 exports instead of struct pt_regs, and vmlinux.h is an x86 dump
 * that does not carry it. The layout is uapi (arch/arm64/include/uapi/asm/ptrace.h) and so fixed, which is
 * what makes declaring it here safe; without it `make gen` cannot build uprobe_ssl for arm64, the second
 * architecture a release ships (internal/bpf/gen.go). */
#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#endif

/* vmlinux.h carries no uapi #defines, so the few errno values these programs compare against are named here.
 * They are the asm-generic values every architecture this project targets shares. */
#ifndef EPERM
#define EPERM 1
#endif
#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef E2BIG
#define E2BIG 7
#endif
#ifndef EACCES
#define EACCES 13
#endif
#ifndef EEXIST
#define EEXIST 17
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif

/* Address families, socket types and protocols: vmlinux.h carries no uapi #defines, so name the ones this project
 * decides on (cgroup_net's families, the plane's unix hooks and socket_create's allowlist). Stable ABI numbers,
 * defined here only. */
#define TEGO_AF_UNIX 1
#define TEGO_AF_INET 2
#define TEGO_AF_INET6 10
#define TEGO_AF_NETLINK 16
#define TEGO_SOCK_STREAM 1
#define TEGO_SOCK_DGRAM 2
#define TEGO_SOCK_TYPE_MASK 0xf
#define TEGO_IPPROTO_ICMP 1
#define TEGO_IPPROTO_TCP 6
#define TEGO_IPPROTO_UDP 17
#define TEGO_IPPROTO_ICMPV6 58

/* Returns the run entry for the current cgroup, or NULL: every program starts here and returns 0 on NULL.
 *
 * This is the one map lookup every hook is allowed before anything else (§8 I1) and the whole of the run's
 * membership test (§5 R2): cgroup_track materializes descendants ahead of time, so no hook ever walks
 * ancestors. A miss is never an error — it means "not one of my runs" (§5 R1).
 *
 * tego_run_lookup takes the cgroup id a caller already has, so a hook that needs the id again (to key the
 * reason breadcrumb, §5 R5) reads it once rather than calling the helper twice. */
static __always_inline struct tego_run *tego_run_lookup(void *run_set, __u64 cgroup_id)
{
    return bpf_map_lookup_elem(run_set, &cgroup_id);
}

static __always_inline struct tego_run *tego_current_run(void *run_set)
{
    __u64 cg = bpf_get_current_cgroup_id();
    return tego_run_lookup(run_set, cg);
}

/* Bumps a run's counter (tego_lost, tego_capture_lost, tego_capture_miss) at its run_idx, after a failed
 * bpf_ringbuf_reserve or a missing ring. Never retries and never blocks a producer (§8 I7); userspace diffs the
 * value per drain into a gap event.
 *
 * The add is atomic: every CPU shares the slot, and even a per-CPU one needs it, since a BPF program runs with
 * migration disabled, not preemption, so a second program on the same CPU can read the slot between this one's
 * load and store, and a plain `*slot += 1` then loses one of the two increments. A drop the counter misses is a
 * gap the ledger never reports. */
static __always_inline void tego_lost_inc(void *lost, __u32 run_idx)
{
    __u64 *slot = bpf_map_lookup_elem(lost, &run_idx);
    if (slot)
        __sync_fetch_and_add(slot, 1);
}

/* Returns the run's own ring from a ring outer (tego_events, tego_capture_events), or NULL when the run has none:
 * the caller then emits nothing and counts the miss at the run's slot, in tego_lost for the record ring and in
 * tego_capture_miss for the capture ring (ADR 0026 (1)). Looked up only after the run-set hit, by the run's slot. */
static __always_inline void *tego_ring_of(void *outer, const struct tego_run *run)
{
    __u32 idx = run->run_idx;

    return bpf_map_lookup_elem(outer, &idx);
}

/* Fills the common ring-buffer header. verdict/reason/rule_idx default to the record-only values; a caller
 * that decided something overwrites them afterwards. */
static __always_inline void tego_hdr_fill(struct tego_hdr *h, __u16 kind, __u32 size,
                                           const struct tego_run *run, __u64 cgroup_id)
{
    __u64 id = bpf_get_current_pid_tgid();

    h->version = TEGO_EVENTS_VERSION;
    h->kind = kind;
    h->size = size;
    h->ts_mono_ns = bpf_ktime_get_ns();
    h->cgroup_id = cgroup_id;
    h->pid = (__u32)(id >> 32);
    h->tid = (__u32)id;
    h->ppid = 0;
    h->run_idx = run ? run->run_idx : 0;
    h->verdict = TEGO_V_OBSERVED;
    h->reason = TEGO_R_NONE;
    h->rule_idx = 0;
    h->gen = run ? run->gen : 0;
}

/* Reports whether the run wants any ring-buffer traffic at all (§6 E23). */
static __always_inline int tego_recording(const struct tego_run *run)
{
    return run->record != TEGO_RECORD_OFF;
}

/* Stamps the run's activity (tego_activity, maps.h, passed as activity like tego_lost_inc's counter): the now of an
 * action the record keeps no line or sample for, which the run's stall check pulls once a tick (limits R4). Only a run
 * whose row carries TEGO_RUN_ACTIVITY is stamped, which userspace sets when a stall_after bounds the run, so a run
 * with no stall budget pays one test of a byte it has already loaded.
 *
 * The slot is written once a jiffy at most (struct tego_activity_slot): an action in the jiffy the slot already names
 * costs the jiffies read (bpf_jiffies64, a load of jiffies_64) and a compare, and only the first action of a new jiffy
 * reads the clock and stores, so the clock read (about 20 ns in a KVM guest) is paid once a jiffy and not once an
 * open, and the threads of a busy run read a shared cache line instead of bouncing it. Two CPUs that both see a new
 * jiffy both write, a nanosecond or so apart, and whichever pair of stores lands, mixed or not, names that jiffy and a
 * time in it: an aligned u64 store does not tear, and the stall check compares at a one-second grain. */
static __always_inline void tego_activity_stamp(void *activity, const struct tego_run *run)
{
    struct tego_activity_slot *slot;
    __u32 idx;
    __u64 j;

    if (!(run->flags & TEGO_RUN_ACTIVITY))
        return;
    idx = run->run_idx;
    slot = bpf_map_lookup_elem(activity, &idx);
    if (!slot)
        return;
    j = bpf_jiffies64();
    if (j == slot->jiffies)
        return;
    slot->jiffies = j;
    slot->mono_ns = bpf_ktime_get_ns();
}

/* Copies an IPv4 address (network byte order, as the hook exposes it) into a 16-byte key slot. */
static __always_inline void tego_addr_v4(__u8 *dst, __u32 be_ip4)
{
    __builtin_memset(dst, 0, 16);
    __builtin_memcpy(dst, &be_ip4, 4);
}

/* Copies an IPv6 address, given as the hook's four network-order words, into a 16-byte key slot.
 *
 * The words arrive by value, never as a pointer into the context. The verifier rewrites each load from a
 * CGROUP_SOCK_ADDR context into a load from the kernel's own struct, and it can do that only for a load
 * made directly off the context register at a constant offset. A memcpy through ctx->user_ip6 first adds
 * the member's offset to that register and then loads through the result, which the verifier refuses with
 * "dereference of modified ctx ptr", so connect6 and sendmsg6 did not load at all. Each ctx->user_ip6[i]
 * the caller passes is one such direct load. */
static __always_inline void tego_addr_v6(__u8 *dst, __u32 w0, __u32 w1, __u32 w2, __u32 w3)
{
    __builtin_memcpy(dst, &w0, 4);
    __builtin_memcpy(dst + 4, &w1, 4);
    __builtin_memcpy(dst + 8, &w2, 4);
    __builtin_memcpy(dst + 12, &w3, 4);
}

/* Unix socket names (enforce-cgroup-observe §5 R7): the checks on a name that connect_unix and sendmsg_unix
 * (bpf/cgroup_net.bpf.c, 6.7+) and the plane's socket_connect and socket_sendmsg (bpf/decide.bpf.c, below 6.7;
 * enforce-plane R14) share, so both decide one name the same way. Each reads a key's name, zero past its end. */

/* offsetof(struct sockaddr_un, sun_path): the family word in front of the name. */
#define TEGO_SUN_PATH_OFF 2

/* Reports whether an absolute name is spelled the way a contract entry is: no empty component ("//", a
 * trailing "/") and no "." or ".." component. The supervisor cleans a name lexically before matching it
 * (supervisor.md R11); a program cannot, and a byte match on an uncleaned name would let
 * "<write entry>/../x" or "<write entry>/.//<deny_read entry>/x" take the write entry's verdict for a
 * socket that lies elsewhere. Such a name is refused: fail-closed, and the kernel's own lookup of it
 * would reach the same socket as its clean spelling, which is how a caller should write it.
 *
 * st is what the current component holds so far: 0 nothing, 1 ".", 2 "..", 3 anything else. Four values
 * rather than two counters keep the verifier's state count per byte small.
 *
 * tego_unix_canon_byte is the rule, one byte c at position i (from 1; a NUL, or position TEGO_UNIX_NAME_MAX, ends
 * the name): 1 the name is canonical, -1 it is not, 0 read on. tego_unix_canonical runs it as a loop the verifier
 * walks (cgroup_net.bpf.c); the plane runs it through bpf_loop (decide.bpf.c tego_plane_unix_canonical), since a
 * walked loop took each of its socket hooks past 34,000 verified instructions. */
static __always_inline int tego_unix_canon_byte(__u32 *st, __u8 c, __u32 i)
{
    if (c == '/' || c == 0) {
        if (*st == 1 || *st == 2)
            return -1;
        if (*st == 0 && (c == '/' || i > 1))
            return -1;
        if (c == 0)
            return 1;
        *st = 0;
        return 0;
    }
    if (c == '.' && *st < 2)
        (*st)++;
    else
        *st = 3;
    return 0;
}

static __always_inline int tego_unix_canonical(const __u8 *name)
{
    __u32 st = 0, i;
    int r;

    for (i = 1; i <= TEGO_UNIX_NAME_MAX; i++) {
        r = tego_unix_canon_byte(&st, i < TEGO_UNIX_NAME_MAX ? name[i] : 0, i);
        if (r)
            return r > 0;
    }
    return 1;
}

/* Reports whether a pathname is the name the supervisor's relay connects under, /proc/self/fd/<digits>
 * (supervisor.md R11). It means something only in the relaying process, so each caller admits it only from the
 * launcher's own cgroup. */
static __always_inline int tego_unix_relay_name(const __u8 *name)
{
    __u32 i;
    __u8 c;

    if (name[0] != '/' || name[1] != 'p' || name[2] != 'r' || name[3] != 'o' || name[4] != 'c' ||
        name[5] != '/' || name[6] != 's' || name[7] != 'e' || name[8] != 'l' || name[9] != 'f' ||
        name[10] != '/' || name[11] != 'f' || name[12] != 'd' || name[13] != '/')
        return 0;
    for (i = 14; i < 25; i++) {
        c = name[i];
        if (c == 0)
            return i > 14;
        if (c < '0' || c > '9')
            return 0;
    }
    return 0;
}

#endif /* TEGO_COMMON_H */
