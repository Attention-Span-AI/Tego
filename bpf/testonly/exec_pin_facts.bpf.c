// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* ADR 0048 P2's K0 probe: the kernel facts exec pins rest on, measured on each matrix row before any pin code lands
 * (internal/bpf exec_pin_facts_integration_test.go). Compiled into a binding that builds with -tags
 * integration,tegobpf only and that no tego binary embeds, once per reader of kernel memory as the plane is
 * (TEGO_PLANE_RDONLY 1: direct BTF loads, which lockdown=confidentiality allows; 0: CO-RE probe reads).
 *
 * Every program watches the tasks of one cgroup (tego_pf_cfg.cgroup) and does nothing for any other task:
 * - tego_pf_exec_check (tp_btf/sched_process_exec) MACs the new image's own [arg_start, arg_end) with the pin MAC of
 *   bpf/include/exec_pin.h, reading it through bpf_probe_read_user in 256-byte chunks into task storage under a
 *   bpf_loop callback, as the plane will; with tego_pf_cfg.kill set it sends SIGKILL when the MAC differs from the
 *   expected one and counts every bpf_send_signal failure;
 * - tego_pf_bprm_lsm and tego_pf_bprm_fmod (bprm_check in each plane mode) record each binfmt stage: its file's
 *   identity, whether it is the first stage, bpf_get_ns_current_pid_tgid's answer for the namespace the test names,
 *   current->ptrace and current->start_boottime, and whether task storage could be had;
 * - tego_pf_sip (syscall) MACs a 0..64-byte input from its context, for the published SipHash vectors. */
#include "common.h"
#include "exec_pin.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#ifndef TEGO_PLANE_RDONLY
#error "internal/bpf/gen.go builds this file with -DTEGO_PLANE_RDONLY=1 (rd) and =0 (pr)"
#endif

/* TEGO_PF_READ is the plane's reader choice for typed pointers: a direct load in the rd build, a CO-RE probe read
 * in the pr build. */
#if TEGO_PLANE_RDONLY
#define TEGO_PF_READ(src, a, ...) ((src)->___arrow(a, ##__VA_ARGS__))
#else
#define TEGO_PF_READ(src, a, ...) BPF_CORE_READ(src, a, ##__VA_ARGS__)
#endif

#define TEGO_PF_SLOTS 64
#define TEGO_PF_SIGKILL 9
#define TEGO_PF_ENOMEM 12

/* What the test asks: the cgroup watched, the MAC key, the pid namespace asked about, and the exec check. */
struct tego_pf_cfg {
    __u64 cgroup;
    __u64 k0, k1;
    __u64 ns_dev, ns_ino;
    __u64 expect_mac;
    __u32 cov_len; /* bytes of the area the MAC covers; 0: all of it */
    __u8 domain;
    __u8 kill; /* 1: SIGKILL an exec whose MAC differs from expect_mac, or whose area could not be read */
    __u8 pad[2];
};

/* One sched_process_exec in the cgroup. */
struct tego_pf_exec {
    __u64 mac;
    __u64 span;     /* arg_end - arg_start */
    __u32 argc;     /* bprm->argc */
    __s32 read_err; /* the area's first read error, -E2BIG past the bound, or 0 */
    __s32 kill_ret; /* bpf_send_signal's answer; 1 when no kill was sent */
    __u32 tid;      /* the task, in the initial pid namespace */
    __u8 interpreted;
    __u8 pad[7];
};

/* One bprm_check in the cgroup: one binfmt stage. */
struct tego_pf_stage {
    __u64 ino;
    __u64 start_boottime;
    __u32 dev; /* the kernel's dev_t: major << 20 | minor */
    __u32 tid, tgid;
    __u32 ns_tid, ns_tgid;
    __s32 ns_ret;
    __u32 ptrace;
    __u8 first;   /* bprm->interp == bprm->filename */
    __u8 shebang; /* bprm->buf starts with #! */
    __u8 mode;    /* 0 lsm, 1 fmod_ret */
    __u8 storage; /* 1: task storage was had */
};

struct tego_pf_counts {
    __u64 execs;
    __u64 stages;
    __u64 kills;
    __u64 kill_failed;
    __s64 last_kill_err;
    __u64 mismatches;
    __u64 read_failed;
};

/* The syscall program's context: a framed MAC of len (at most 64) bytes of data. */
struct tego_pf_sip_ctx {
    __u64 k0, k1;
    __u32 len;
    __u8 domain;
    __u8 pad[3];
    __u64 data[8]; /* little-endian words: the verifier takes a context field at a constant offset only */
    __u64 mac;
};

struct tego_pf_buf {
    __u8 b[TEGO_PIN_CHUNK];
};

const struct tego_pf_cfg *tego_btf_pf_cfg;
const struct tego_pf_exec *tego_btf_pf_exec;
const struct tego_pf_stage *tego_btf_pf_stage;
const struct tego_pf_counts *tego_btf_pf_counts;
const struct tego_pf_sip_ctx *tego_btf_pf_sip_ctx;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tego_pf_cfg);
} tego_pf_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tego_pf_counts);
} tego_pf_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_PF_SLOTS);
    __type(key, __u32);
    __type(value, struct tego_pf_exec);
} tego_pf_execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_PF_SLOTS);
    __type(key, __u32);
    __type(value, struct tego_pf_stage);
} tego_pf_stages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct tego_pf_buf);
} tego_pf_bufs SEC(".maps");

/* The chunk loop's state. Only s and tail change across iterations, and the callback branches on neither. */
struct tego_pf_mac {
    struct tego_sip s;
    __u64 base;
    __u64 tail; /* the last partial word, read where the last chunk ends */
    __u32 len;
    __s32 err;
};

/* tego_pf_chunk absorbs chunk i of the area: one bpf_probe_read_user of at most 256 bytes into the task's own
 * storage (never a per-CPU buffer, which a preempted program would share), then its whole words. */
static long tego_pf_chunk(__u32 i, struct tego_pf_mac *c)
{
    struct tego_pf_buf *buf;
    __u32 off = i * TEGO_PIN_CHUNK, n;
    long r;
    int j;

    if (i >= TEGO_PIN_MAX_LEN / TEGO_PIN_CHUNK || off >= c->len)
        return 1;
    n = c->len - off;
    if (n > TEGO_PIN_CHUNK)
        n = TEGO_PIN_CHUNK;
    buf = bpf_task_storage_get(&tego_pf_bufs, bpf_get_current_task_btf(), 0, 0);
    if (!buf) {
        c->err = -TEGO_PF_ENOMEM;
        return 1;
    }
    r = bpf_probe_read_user(buf->b, n, (void *)(c->base + off));
    if (r) {
        c->err = (__s32)r;
        return 1;
    }
#pragma unroll
    for (j = 0; j < TEGO_PIN_CHUNK / 8; j++) {
        if ((__u32)(j + 1) * 8 > n) {
            c->tail = tego_sip_le64(&buf->b[j * 8]);
            break;
        }
        tego_sip_word(&c->s, tego_sip_le64(&buf->b[j * 8]));
    }
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(tego_pf_exec_check, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    __u32 zero = 0, idx;
    struct tego_pf_cfg *cfg = bpf_map_lookup_elem(&tego_pf_config, &zero);
    struct tego_pf_counts *cnt = bpf_map_lookup_elem(&tego_pf_counters, &zero);
    struct tego_pf_mac c = {};
    struct tego_pf_exec *rec;
    __u64 arg_start, arg_end, span, mac = 0;

    if (!cfg || !cnt || bpf_get_current_cgroup_id() != cfg->cgroup)
        return 0;
    /* The test runs one exec at a time, so the slot is the count before this one (bpf2go's CPU v1 has no
     * fetching atomics). */
    idx = (__u32)cnt->execs % TEGO_PF_SLOTS;
    __sync_fetch_and_add(&cnt->execs, 1);
    rec = bpf_map_lookup_elem(&tego_pf_execs, &idx);
    if (!rec)
        return 0;
    __builtin_memset(rec, 0, sizeof(*rec));
    rec->tid = (__u32)bpf_get_current_pid_tgid();
    rec->argc = TEGO_PF_READ(bprm, argc);
    rec->interpreted = TEGO_PF_READ(bprm, interp) != TEGO_PF_READ(bprm, filename);
    arg_start = TEGO_PF_READ(p, mm, arg_start);
    arg_end = TEGO_PF_READ(p, mm, arg_end);
    span = arg_end > arg_start ? arg_end - arg_start : 0;
    rec->span = span;
    c.len = cfg->cov_len ? cfg->cov_len : (__u32)span;
    c.base = arg_start;
    if (c.len > span || c.len > TEGO_PIN_MAX_LEN) {
        c.err = -E2BIG;
    } else if (!bpf_task_storage_get(&tego_pf_bufs, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE)) {
        c.err = -TEGO_PF_ENOMEM;
    } else {
        tego_sip_begin(&c.s, cfg->k0, cfg->k1, cfg->domain, c.len);
        bpf_loop((c.len + TEGO_PIN_CHUNK - 1) / TEGO_PIN_CHUNK, tego_pf_chunk, &c, 0);
        mac = tego_sip_end(&c.s, c.tail, c.len & 7);
    }
    rec->mac = mac;
    rec->read_err = c.err;
    rec->kill_ret = 1;
    if (c.err)
        __sync_fetch_and_add(&cnt->read_failed, 1);
    if (c.err || mac != cfg->expect_mac)
        __sync_fetch_and_add(&cnt->mismatches, 1);
    if (cfg->kill && (c.err || mac != cfg->expect_mac)) {
        long r = bpf_send_signal(TEGO_PF_SIGKILL);

        rec->kill_ret = (__s32)r;
        if (r) {
            __sync_fetch_and_add(&cnt->kill_failed, 1);
            cnt->last_kill_err = r;
        } else {
            __sync_fetch_and_add(&cnt->kills, 1);
        }
    }
    return 0;
}

static __always_inline int tego_pf_bprm(struct linux_binprm *bprm, __u8 mode)
{
    __u32 zero = 0, idx;
    struct tego_pf_cfg *cfg = bpf_map_lookup_elem(&tego_pf_config, &zero);
    struct tego_pf_counts *cnt = bpf_map_lookup_elem(&tego_pf_counters, &zero);
    struct task_struct *t = bpf_get_current_task_btf();
    struct bpf_pidns_info ns = {};
    struct tego_pf_stage *rec;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    char hdr[2] = {};

    if (!cfg || !cnt || bpf_get_current_cgroup_id() != cfg->cgroup)
        return 0;
    /* The test runs one exec at a time, so the slot is the count before this one (bpf2go's CPU v1 has no
     * fetching atomics). */
    idx = (__u32)cnt->stages % TEGO_PF_SLOTS;
    __sync_fetch_and_add(&cnt->stages, 1);
    rec = bpf_map_lookup_elem(&tego_pf_stages, &idx);
    if (!rec)
        return 0;
    __builtin_memset(rec, 0, sizeof(*rec));
    rec->mode = mode;
    rec->tid = (__u32)pid_tgid;
    rec->tgid = (__u32)(pid_tgid >> 32);
    rec->ns_ret = (__s32)bpf_get_ns_current_pid_tgid(cfg->ns_dev, cfg->ns_ino, &ns, sizeof(ns));
    rec->ns_tid = ns.pid;
    rec->ns_tgid = ns.tgid;
    rec->ptrace = TEGO_PF_READ(t, ptrace);
    rec->start_boottime = TEGO_PF_READ(t, start_boottime);
    rec->ino = TEGO_PF_READ(bprm, file, f_inode, i_ino);
    rec->dev = TEGO_PF_READ(bprm, file, f_inode, i_sb, s_dev);
    rec->first = TEGO_PF_READ(bprm, interp) == TEGO_PF_READ(bprm, filename);
#if TEGO_PLANE_RDONLY
    hdr[0] = bprm->buf[0];
    hdr[1] = bprm->buf[1];
#else
    bpf_core_read(&hdr, sizeof(hdr), &bprm->buf);
#endif
    rec->shebang = hdr[0] == '#' && hdr[1] == '!';
    rec->storage = bpf_task_storage_get(&tego_pf_bufs, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE) != 0;
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(tego_pf_bprm_lsm, struct linux_binprm *bprm)
{
    return tego_pf_bprm(bprm, 0);
}

SEC("fmod_ret/security_bprm_check")
int BPF_PROG(tego_pf_bprm_fmod, struct linux_binprm *bprm)
{
    return tego_pf_bprm(bprm, 1);
}

SEC("syscall")
int tego_pf_sip(struct tego_pf_sip_ctx *ctx)
{
    struct tego_sip s;
    __u32 len = ctx->len;
    __u64 tail = 0;
    int j;

    if (len > sizeof(ctx->data))
        return -E2BIG;
    tego_sip_begin(&s, ctx->k0, ctx->k1, ctx->domain, len);
#pragma unroll
    for (j = 0; j < 8; j++) {
        if ((__u32)(j + 1) * 8 > len) {
            tail = tego_sip_fix(ctx->data[j]);
            break;
        }
        tego_sip_word(&s, tego_sip_fix(ctx->data[j]));
    }
    ctx->mac = tego_sip_end(&s, tail, len & 7);
    return 0;
}
