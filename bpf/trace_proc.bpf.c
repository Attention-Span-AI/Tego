// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* The eBPF record: two scheduler tracepoints, ten fexit programs on the security_ functions where the run's
 * inherited Landlock domain can refuse, and one fentry program on security_socket_connect. They describe what a
 * run did, without deciding anything (docs/p0/enforce-cgroup-observe.md §1, §5 R8, R9, R10; ADR 0016).
 *
 * Every program is host-wide — tracepoints, fentry and fexit are global attach points, not per-cgroup — so the
 * whole of the filtering is one tego_run_set lookup keyed by the current cgroup id (§5 R2, §8 I1). A miss
 * returns 0 immediately, which is what makes two coexisting builds harmless to each other (§6 E22, E29).
 *
 * Path resolution follows R9/R10 exactly and depends on the kernel's fixed btf_allowlist_d_path BTF_SET, not
 * on the kernel version:
 *   - security_file_open is in that set on every supported kernel, so tego_file_open calls bpf_d_path and
 *     carries a resolved path string;
 *   - the security_path_* functions it records are in it on no kernel but security_path_truncate, so every file
 *     operation, truncate included for one layout, carries only what BPF_CORE_READ takes off the BTF arguments:
 *     the parent directory's (dev, inode) and the final component's raw bytes. Userspace names the rule from
 *     its own dirIndex; a miss is recorded unattributed rather than guessed. No kernel map here is ever keyed by
 *     (device, inode) (§8 I9).
 *
 * Verdicts: every record's header says TEGO_V_OBSERVED, since nothing here decides. The fs records carry the
 * LSM chain's own return instead (ret, ret_ok): an fexit program runs after the function returned, so it reads
 * what the chain answered — Landlock's refusal included, and on kernels up to 6.12 fanotify's — and userspace
 * maps that to the line's verdict (ADR 0016 (1), (3); §5 R9). security_socket_connect stays fentry: it returns
 * before connect4/6 decide, so its return never holds the cgroup verdict.
 *
 * Recording volume: exec and exit are emitted for every matched run even when record is off, because the
 * userspace process cache is built and evicted from them and enforcement attribution depends on it; the
 * high-volume open/fsop/connect records are skipped when the run records nothing (§6 E23), except an open or a
 * file operation the chain refused, which is recorded under record: off too (ADR 0016 (3)). What record: off skips is
 * still activity: each of those returns stamps the run's slot in tego_activity (tego_activity_stamp), one slot and no
 * ring, for a run whose row carries TEGO_RUN_ACTIVITY (a stall_after bounds it), so an agent busy with allowed
 * reads, writes and connects is not ended as stalled (limits R4). Under summary and full those actions are samples
 * the record keeps, and stamp nothing.
 *
 * Ring-buffer discipline: reserve, fill, submit — never a retry loop, never a blocked producer; a failed
 * reserve bumps the run's lost counter userspace diffs into a gap (§8 I7). Every record goes to the ring of the
 * run the process belongs to, looked up by the run's slot after the run-set hit, and a run with no ring gets
 * nothing (ADR 0026 (1)). Reserved memory is not zeroed by
 * the kernel, so every program clears its record before filling it: an unwritten tail would ship kernel stack
 * bytes to userspace.
 *
 * Wakeups (§9): the high-volume records submit with tego_quiet's flags, without waking the reader
 * (BPF_RB_NO_WAKEUP) unless the ring is filling, and the reader fetches them on its own short timer
 * (internal/runtime/observe DefaultReadInterval). Exec and exit always wake it (BPF_RB_FORCE_WAKEUP): the process
 * cache and the uprobe source's attach at exec are built from them, and behind a quiet record the kernel's
 * default would not wake it, since that default wakes only a reader that has consumed every record before.
 *
 * Two builds, one source (internal/bpf/gen.go; ADR 0024's 2026-09-29 tier-2 note). TEGO_TRACE_RDONLY=0, `trace`,
 * reads kernel objects through CO-RE bpf_probe_read_kernel and loads on every supported kernel without lockdown.
 * TEGO_TRACE_RDONLY=1, `tracerd`, makes no bpf_probe_read_kernel* call at all, since lockdown=confidentiality
 * refuses that helper at load on every kernel, 6.17 included: it reads an object's fields by direct loads off the
 * programs' BTF-typed arguments (TEGO_READ), and a kernel string byte by byte through bpf_rdonly_cast in a
 * bpf_loop (tego_kstr), which a kernel's BTF must carry (6.2+, RHEL 9.8's backport). bpf_probe_read_user, for
 * argv, is not refused by lockdown and stays in both. The loader picks tracerd where the kernel's BTF has the
 * kfunc and trace elsewhere (internal/bpf TraceObject). */
#ifndef TEGO_TRACE_RDONLY
#define TEGO_TRACE_RDONLY 0
#endif

#define TEGO_TRACE_MAPS
#include "maps.h"

char _license[] SEC("license") = "Dual BSD/GPL";

/* TEGO_READ(src, a, b, ...) is BPF_CORE_READ(src, a, b, ...) in the probe-read build and src->a->b in the rdonly
 * build: the same CO-RE relocated field chain, read by bpf_probe_read_kernel or by a direct load. */
#if TEGO_TRACE_RDONLY
#define TEGO_READ(src, a, ...) ((src)->___arrow(a, ##__VA_ARGS__))
#else
#define TEGO_READ(src, a, ...) BPF_CORE_READ(src, a, ##__VA_ARGS__)
#endif

#if TEGO_TRACE_RDONLY
/* TEGO_KSTR_MAX is the one buffer size tego_kstr fills, TEGO_PATH_MAX and TEGO_NAME_MAX both; a power of two,
 * so the callback's index is masked into the buffer. */
#define TEGO_KSTR_MAX 256
_Static_assert(TEGO_PATH_MAX == TEGO_KSTR_MAX && TEGO_NAME_MAX == TEGO_KSTR_MAX, "tego_kstr's one size");
#define TEGO_EFAULT 14

/* tego_kbyte reads one kernel byte through bpf_rdonly_cast: the address is cast to struct new_utsname, a type every
 * kernel's BTF has whose first member is a char array, and its first char is loaded. The load is a direct one the
 * verifier marks untrusted, so a fault reads 0 instead of oopsing, and a one-byte load never crosses a page. */
static __always_inline char tego_kbyte(__u64 addr)
{
    return bpf_core_cast((void *)addr, struct new_utsname)->sysname[0];
}

struct tego_kstr_ctx {
    char *dst;
    __u64 src;
    long n;
};

static long tego_kstr_step(__u64 i, void *arg)
{
    struct tego_kstr_ctx *s = arg;
    char c = tego_kbyte(s->src + i);

    s->dst[i & (TEGO_KSTR_MAX - 1)] = c;
    if (c == 0) {
        s->n = (long)i + 1;
        return 1;
    }
    return 0;
}

/* tego_kstr is bpf_probe_read_kernel_str(dst, TEGO_KSTR_MAX, src) without the helper: it copies up to the NUL and
 * returns the bytes copied with it, or TEGO_KSTR_MAX with dst's last byte made the NUL when none came first. A
 * fault reads as a zero byte, so a first byte of 0 is returned as the helper's -EFAULT: no string read here is empty
 * (an exec filename, a dentry's name, a symlink target). */
static __always_inline long tego_kstr(char *dst, const void *src)
{
    struct tego_kstr_ctx s = {.dst = dst, .src = (__u64)src, .n = TEGO_KSTR_MAX};

    if (bpf_loop(TEGO_KSTR_MAX, tego_kstr_step, &s, 0) < 0)
        return -TEGO_EFAULT;
    if (s.n == TEGO_KSTR_MAX)
        dst[TEGO_KSTR_MAX - 1] = 0;
    else if (s.n == 1)
        return -TEGO_EFAULT;
    return s.n;
}
#endif

/* BTF anchors: see bpf/cgroup_track.bpf.c. Every event struct this file writes is named once so bpf2go emits
 * a Go mirror of it and types.go's parity test can assert the layouts match. */
const struct tego_hdr *tego_btf_hdr;
const struct tego_ev_exec *tego_btf_ev_exec;
const struct tego_ev_exit *tego_btf_ev_exit;
const struct tego_ev_exec_result *tego_btf_ev_exec_result;
const struct tego_ev_bind_result *tego_btf_ev_bind_result;
const struct tego_ev_fs *tego_btf_ev_fs;
const struct tego_ev_fsop *tego_btf_ev_fsop;
const struct tego_ev_net *tego_btf_ev_net;

/* Zeroes a reserved ring-buffer record. Written as an explicit 8-byte store loop because clang lowers a
 * __builtin_memset of this size to a libcall BPF has no libc for; the stores are volatile and the loop unrolled,
 * since clang otherwise recognizes the loop as that memset again once the record passes 1 KiB (the fsop record's
 * directory paths). */
#define TEGO_ZERO(e)                                                        \
    do {                                                                     \
        volatile __u64 *_p = (volatile __u64 *)(e);                          \
        int _i;                                                              \
        _Static_assert(sizeof(*(e)) % 8 == 0, "record must be 8-byte sized"); \
        _Pragma("unroll")                                                    \
        for (_i = 0; _i < (int)(sizeof(*(e)) / 8); _i++)                     \
            _p[_i] = 0;                                                      \
    } while (0)

/* TEGO_WAKE_FRACTION: a quiet record still wakes the reader once the ring holds this fraction of its size, so a
 * burst never waits on the reader's timer while the ring fills toward a lost sample. */
#define TEGO_WAKE_FRACTION 8

/* tego_quiet is the submit flags of an open, file-operation or connect record: no wakeup of the reader, or a
 * wakeup when the ring is an eighth full or wake is set. A wakeup is paid by the process that submits:
 * bpf_ringbuf_submit queues an irq_work on its CPU to wake the reader, and a reader that keeps up with a slow
 * producer has always caught up, so the kernel's default woke it for every one of these records (1.2 µs a call
 * that writes a sample, 2.9 µs one that also queues the wakeup, §9). Left quiet, they are read at the reader's
 * timed read instead. */
static __always_inline __u64 tego_quiet(void *ring, int wake)
{
    __u64 size = bpf_ringbuf_query(ring, BPF_RB_RING_SIZE);
    __u64 avail = bpf_ringbuf_query(ring, BPF_RB_AVAIL_DATA);

    if (wake || avail >= size / TEGO_WAKE_FRACTION)
        return BPF_RB_FORCE_WAKEUP;
    return BPF_RB_NO_WAKEUP;
}

/* tego_libssl_named reports an open of a file whose name begins "libssl.so": the open the uprobe source
 * attaches a library at (capture-derive R4, Uprobe.OnOpen), where a record left for the reader's timer would be
 * an attach late by up to that long, and a request the process makes meanwhile missed. Only the dentry's own
 * name is read, never the path: its first nine bytes, which the read reports as ten (the nine and the NUL it
 * ends them with) exactly when the name is nine bytes or longer. */
static __always_inline int tego_libssl_named(struct file *file)
{
    const unsigned char *name = TEGO_READ(file, f_path.dentry, d_name.name);
#if TEGO_TRACE_RDONLY
    /* Byte by byte, each read only after the one before matched, so none reads past a shorter name's NUL. */
    __u64 a = (__u64)name;

    return tego_kbyte(a) == 'l' && tego_kbyte(a + 1) == 'i' && tego_kbyte(a + 2) == 'b' &&
           tego_kbyte(a + 3) == 's' && tego_kbyte(a + 4) == 's' && tego_kbyte(a + 5) == 'l' &&
           tego_kbyte(a + 6) == '.' && tego_kbyte(a + 7) == 's' && tego_kbyte(a + 8) == 'o';
#else
    char n[10] = {};

    if (bpf_probe_read_kernel_str(n, sizeof(n), name) != (long)sizeof(n))
        return 0;
    return n[0] == 'l' && n[1] == 'i' && n[2] == 'b' && n[3] == 's' && n[4] == 's' && n[5] == 'l' &&
           n[6] == '.' && n[7] == 's' && n[8] == 'o';
#endif
}

/* The calling process's start time: its thread group leader's start_boottime, what /proc/<pid>/stat reports
 * and the exec id's third component. It travels with every open, file-operation and connect record, so the
 * recorder can tell the process a pid names now from the one it named before an exit record was lost (§6 E14).
 */
static __always_inline __u64 tego_task_start(void)
{
#if TEGO_TRACE_RDONLY
    struct task_struct *t = bpf_get_current_task_btf();
#else
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
#endif

    return TEGO_READ(t, group_leader, start_boottime);
}

/* f_mode and f_flags bits the open program reads. The f_mode values are the same on every kernel from 5.14
 * through 7.0 (include/linux/fs.h at v5.14, v6.1, v6.5, v6.6, v6.8, v6.12, v6.13, v6.14, v6.17 and v7.0, checked
 * 2026-09-29): FMODE_CREATED is 0x100000 (1 << 20) and FMODE_NOACCOUNT 0x20000000 (1 << 29) on all of them, while
 * FMODE_BACKING moved from bit 25 to bit 24 in 6.14, which is why the skip below tests FMODE_NOACCOUNT: every
 * backing file carries both (alloc_empty_backing_file, 6.5+), and below 6.5 the overlay real file
 * open_with_fake_path opens carries FMODE_NOACCOUNT alone. The other files with it are kernel_file_open's, which no
 * descriptor table ever holds. O_CREAT, O_TRUNC and the S_IF* values are asm-generic's, which x86 and arm64 share. */
#define TEGO_FMODE_CREATED 0x00100000
#define TEGO_FMODE_NOACCOUNT 0x20000000
/* Unlike access mode, __FMODE_EXEC belongs to f_flags: Landlock tests this same kernel-private bit in
 * get_required_file_open_access (5.14's get_file_access), not file->f_mode. */
#define TEGO_FMODE_EXEC 0x00000020
#define TEGO_O_CREAT 00000100
#define TEGO_O_TRUNC 00001000
#define TEGO_S_IFMT 00170000
#define TEGO_S_IFREG 0100000

/* Copies one record into another of its type, 8 bytes at a time, for the same libcall reason as TEGO_ZERO. */
#define TEGO_COPY(dst, src)                                                                    \
    do {                                                                                        \
        __u64 *_d = (__u64 *)(dst);                                                             \
        const __u64 *_s = (const __u64 *)(src);                                                 \
        int _i;                                                                                 \
        _Static_assert(sizeof(*(dst)) == sizeof(*(src)), "copy between records of one type");   \
        _Static_assert(sizeof(*(dst)) % 8 == 0, "record must be 8-byte sized");                 \
        for (_i = 0; _i < (int)(sizeof(*(dst)) / 8); _i++)                                      \
            _d[_i] = _s[_i];                                                                    \
    } while (0)

/* The calling task's held record (struct tego_held), or NULL: with flags 0 only one already there, with
 * BPF_LOCAL_STORAGE_GET_F_CREATE one made for it. NULL from a create is a task storage the kernel could not give
 * (no memory, or the helper's recursion guard), and the caller then emits at once. */
static __always_inline struct tego_held *tego_held_of(__u64 flags)
{
    return bpf_task_storage_get(&tego_task_scratch, bpf_get_current_task_btf(), 0, flags);
}

/* Emits whatever the task holds, as it is, and empties the hold: the task's next recorded event, or its exit, is
 * where a held record nothing consumed ends up (struct tego_held). A run with no ring or a full ring counts it
 * lost at the run's slot. */
static __always_inline void tego_held_flush(struct tego_held *h, const struct tego_run *run)
{
    void *ring;

    if (!h || h->tag == TEGO_HELD_NONE)
        return;
    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
    } else if (h->tag == TEGO_HELD_OPEN) {
        struct tego_ev_fs *e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);

        if (!e) {
            tego_lost_inc(&tego_lost, run->run_idx);
        } else {
            TEGO_COPY(e, &h->fs);
            bpf_ringbuf_submit(e, tego_quiet(ring, 0));
        }
    } else {
        struct tego_ev_fsop *e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);

        if (!e) {
            tego_lost_inc(&tego_lost, run->run_idx);
        } else {
            TEGO_COPY(e, &h->op);
            bpf_ringbuf_submit(e, tego_quiet(ring, 0));
        }
    }
    h->tag = TEGO_HELD_NONE;
}

/* tego_flush_task is tego_held_flush for a program that holds nothing itself: exec, exit and connect. */
static __always_inline void tego_flush_task(const struct tego_run *run)
{
    tego_held_flush(tego_held_of(0), run);
}

/* Splits a task's exit_code into the wait(2) status halves. */
static __always_inline void tego_exit_status(int exit_code, __s32 *code, __u32 *signal)
{
    *code = (__s32)((exit_code >> 8) & 0xff);
    *signal = (__u32)(exit_code & 0x7f);
}

/* ---- The decision plane's word on this call (ADR 0024 (11), ADR 0016 (3); TIER3-PLAN T9) ----
 *
 * The plane (bpf/decide.bpf.c) leaves each decision in the task's tego_plane_scratch value, {rule_idx, hook,
 * verdict, reason, obj}. The fexit on the same security_ function runs after it in both modes (an LSM program inside
 * the chain, an fmod_ret program before the function), on the same task, so the value is this call's exactly when
 * its hook and object are this call's: a plane that returned before deciding (another run, a skipped object, an LSM
 * earlier in the chain that refused first) leaves an earlier call's value there, which the object tells apart, and
 * each fexit consumes what it reads. A refusal the plane made is the line's verdict with the plane's reason and rule
 * (the header's, as an enforcing program's own refusal always is; observe.fsVerdict), and only when the chain
 * returned -EACCES, the one refusal a plane program makes. Everything else leaves the header as it was: the chain's
 * return decides, and the model explains. */
struct tego_plane_said {
    __u32 rule_idx;
    __u8 refused;
    __u8 allowed;
    __u8 reason;
    __u8 pad;
    __u32 listen_run_idx;
    __u32 listen_gen;
};

static __always_inline struct tego_plane_said tego_plane_take(__u16 hook, __u64 obj)
{
    struct tego_plane_said said = {};
    struct tego_plane_decision *sc =
        bpf_task_storage_get(&tego_plane_scratch, bpf_get_current_task_btf(), 0, 0);

    if (!sc || sc->hook != hook || sc->obj != obj)
        return said;
    sc->hook = TEGO_HOOK_NONE;
    said.rule_idx = sc->rule_idx;
    said.reason = sc->reason;
    said.refused = sc->verdict == TEGO_V_REFUSED;
    said.allowed = sc->verdict == TEGO_V_ALLOW;
    said.listen_run_idx = sc->listen_run_idx;
    said.listen_gen = sc->listen_gen;
    return said;
}

/* Puts a plane refusal on a record's header; ret is the chain's return. */
static __always_inline void tego_plane_stamp(struct tego_hdr *h, struct tego_plane_said said, int ret)
{
    if (!said.refused || ret != -EACCES)
        return;
    h->verdict = TEGO_V_REFUSED;
    h->reason = said.reason;
    h->rule_idx = (__u16)said.rule_idx;
}

/* sched_process_exec's take: the plane's last bprm_check decision, which the task keeps apart from its other
 * decisions (the ELF loader's open of PT_INTERP comes between), on the file the exec went ahead with (the last
 * stage's: bprm->file is the interpreter's after a #! stage). */
static __always_inline struct tego_plane_said tego_plane_take_exec(__u64 obj)
{
    struct tego_plane_said said = {};
    struct tego_plane_decision *sc =
        bpf_task_storage_get(&tego_plane_scratch, bpf_get_current_task_btf(), 0, 0);

    if (!sc || sc->exec_verdict == TEGO_V_OBSERVED || sc->exec_obj != obj)
        return said;
    said.rule_idx = sc->exec_rule;
    said.allowed = sc->exec_verdict == TEGO_V_ALLOW;
    sc->exec_verdict = TEGO_V_OBSERVED;
    sc->exec_obj = 0;
    return said;
}

/* sched_process_exec: the exec the plane's last bprm_check allowed names the plane's rule. */
static __always_inline void tego_plane_exec_named(struct tego_ev_exec *e, struct tego_plane_said said)
{
    if (!said.allowed)
        return;
    e->plane = (said.rule_idx & TEGO_PLANE_RULE_FS_ROW) ? TEGO_PLANE_NAMED_FS_ROW : TEGO_PLANE_NAMED_ENTRY;
    e->hdr.rule_idx = (__u16)said.rule_idx;
}

/* sched_process_exec: the seq of the pin the plane holds this exec to (ADR 0048 (8)), 0 for none. The plane's pin
 * program on the same tracepoint may run before or after this one; cur_seq is the exec's from its bprm_check either
 * way, and whether the pin held is the plane's held or kill sample's to say, which names the same cur_seq
 * (tego_exec_pin_check), so the ledger pairs the two by it. */
static __always_inline __u32 tego_exec_pin_seq(const struct tego_run *run)
{
    struct tego_exec_armed *st = bpf_task_storage_get(&tego_plane_exec_armed, bpf_get_current_task_btf(), 0, 0);

    if (!st || st->run_idx != run->run_idx || st->gen != run->gen)
        return 0;
    return st->cur_seq;
}

/* sched_process_exec: one record per successful execve (after the binfmt search), the anchor of every exec id.
 *
 * 6.1 prototype: TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm). The kernel added
 * no argument since; nothing past it is read (ARCHITECTURE §11.1).
 *
 * argv is copied from the new mm's [arg_start, arg_end) — the only place the full vector exists at this point
 * — clamped to TEGO_ARGV_MAX with a truncation marker (§6 E25). Exec matching never depends on it. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(tego_sched_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_ev_exec *e;
    struct dentry *pwd;
    const char *filename;
    __u64 arg_start, arg_end, span;
    __u32 len;
    void *ring;
    long n;

    if (!run)
        return 0;
    said = tego_plane_take_exec((__u64)TEGO_READ(bprm, file));
    tego_flush_task(run); /* what the task held ends before its exec */
    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
        return 0;
    }

    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return 0;
    }
    TEGO_ZERO(e);
    tego_hdr_fill(&e->hdr, TEGO_EV_EXEC, sizeof(*e), run, cgroup_id);
    e->hdr.ppid = TEGO_READ(p, real_parent, tgid);
    tego_plane_exec_named(e, said);
    e->exec_start_ns = TEGO_READ(p, start_boottime);
    e->parent_start_ns = TEGO_READ(p, real_parent, group_leader, start_boottime);
    e->old_tid = old_pid;
    e->pin_seq = tego_exec_pin_seq(run);
    /* The working directory a relative filename was looked up in (§2.4). bprm->filename is the name
     * the process passed, and userspace resolves a relative one against /proc/<pid>/cwd only while that is still
     * this directory: a process that changed directory since would have its exec named by another file. */
    pwd = TEGO_READ(p, fs, pwd.dentry);
    e->cwd_dev = TEGO_READ(pwd, d_sb, s_dev);
    e->cwd_ino = TEGO_READ(pwd, d_inode, i_ino);
#if TEGO_TRACE_RDONLY
    /* comm is a char array inside the task: direct loads up to its NUL (the record is zeroed past it). */
    {
        int k;

#pragma unroll
        for (k = 0; k < TEGO_COMM_LEN - 1; k++) {
            char c = p->comm[k];

            if (!c)
                break;
            e->comm[k] = c;
        }
    }
#else
    BPF_CORE_READ_STR_INTO(&e->comm, p, comm);
#endif

    filename = TEGO_READ(bprm, filename);
    /* alloc_bprm aliases interp to filename; bprm_change_interp replaces it when a binfmt interpreter
     * changes the image and its argv. ELF's ordinary PT_INTERP loader does not make that replacement. */
    e->interpreted = TEGO_READ(bprm, interp) != filename;
#if TEGO_TRACE_RDONLY
    n = tego_kstr(e->path, filename);
#else
    n = bpf_probe_read_kernel_str(&e->path, TEGO_PATH_MAX, filename);
#endif
    if (n < 0)
        e->hdr.reason = TEGO_R_PATH_UNRESOLVED;
    else if (n == TEGO_PATH_MAX) {
        /* A 255-byte name fills the buffer with its NUL too: truncated only when a 256th byte exists. */
#if TEGO_TRACE_RDONLY
        if (tego_kbyte((__u64)filename + TEGO_PATH_MAX - 1) != 0)
            e->path_truncated = 1;
#else
        char c = 0;
        if (bpf_probe_read_kernel(&c, 1, filename + TEGO_PATH_MAX - 1) != 0 || c != 0)
            e->path_truncated = 1;
#endif
    }

    arg_start = TEGO_READ(p, mm, arg_start);
    arg_end = TEGO_READ(p, mm, arg_end);
    span = arg_end > arg_start ? arg_end - arg_start : 0;
    if (span > TEGO_ARGV_MAX) {
        span = TEGO_ARGV_MAX;
        e->argv_truncated = 1;
    }
    len = (__u32)span;
    /* A failed read leaves argv empty: marked truncated, so the recorder's argv-truncated gap names the loss
     * rather than the line reading as an exec with no arguments (§6 E25). */
    if (len > 0 && len <= TEGO_ARGV_MAX) {
        if (bpf_probe_read_user(&e->argv, len, (void *)arg_start) == 0)
            e->argv_len = len;
        else
            e->argv_truncated = 1;
    }

    bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
    return 0;
}

/* Linux-private restart results (include/linux/errno.h) reach sys_exit before signal handling decides whether
 * to restart the call. In particular, prepare_bprm_creds can return ERESTARTNOINTR while waiting for the exec
 * credential lock. These are not terminal failures and must not consume the attempt's metadata or fragments. */
#define TEGO_ERESTARTSYS 512
#define TEGO_ERESTARTNOINTR 513
#define TEGO_ERESTARTNOHAND 514
#define TEGO_ERESTART_RESTARTBLOCK 516

static __always_inline bool tego_exec_restart(__s64 ret)
{
    return ret == -TEGO_ERESTARTSYS || ret == -TEGO_ERESTARTNOINTR ||
           ret == -TEGO_ERESTARTNOHAND || ret == -TEGO_ERESTART_RESTARTBLOCK;
}

/* A failed exec's terminal result follows every file-open/bprm refusal fragment. The syscall tracepoint's
 * common result layout is independent of architecture syscall numbers. Success has sched_process_exec's own
 * record, so only a negative return reaches the ring here; failed attempts are retained under record: off. */
static __always_inline int tego_exec_result_emit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_ev_exec_result *e;
    __s64 ret;
    void *ring;

    if (!run)
        return 0;
    ret = ctx->ret;
    if (ret >= 0)
        return 0;
    if (tego_exec_restart(ret))
        return 0;
    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return 0;
    }
    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return 0;
    }
    TEGO_ZERO(e);
    tego_hdr_fill(&e->hdr, TEGO_EV_EXEC_RESULT, sizeof(*e), run, cgroup_id);
    e->start_ns = tego_task_start();
    e->ret = ret;
    bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tego_exec_result(struct trace_event_raw_sys_exit *ctx)
{
    return tego_exec_result_emit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tego_execat_result(struct trace_event_raw_sys_exit *ctx)
{
    return tego_exec_result_emit(ctx);
}

/* SIGNAL_GROUP_EXIT (include/linux/sched/signal.h, 0x4 from 5.14 through 6.17): signal->flags says the thread
 * group is exiting as one, by exit_group(2) or a fatal signal, and signal->group_exit_code holds its status. */
#define TEGO_SIGNAL_GROUP_EXIT 0x00000004

/* sched_process_exit: the process's last record, and what evicts its row from the userspace process cache
 * even when the run records nothing (§6 E23).
 *
 * One record per thread group, when its last thread exits: a per-thread record would multiply traffic without
 * adding a fact the ledger names. It used to be the leader's exit, which is not the process's: a leader that
 * ends with pthread_exit leaves its threads running, and the recorder evicted the process, flushed its reads as
 * final and told the uprobe source to let it go while it went on. do_exit
 * decrements signal->live before this tracepoint, so the group's last thread finds it at 0. Two threads ending
 * at one instant can both find it so, and the recorder takes the first of their records. An exec by a thread
 * other than the leader ends the others without the count reaching 0, so it is no exit either.
 *
 * The status is wait(2)'s: the group's exit code when the group exits as one, else the leader's own
 * (wait_task_zombie). exec_start_ns is the leader's start time, the process's, so a lagging exec for a reused
 * pid is disambiguated (E14).
 *
 * 6.1 prototype: TP_PROTO(struct task_struct *p). 6.5 appended a `bool group_dead` argument; it is deliberately
 * not declared and not read (ARCHITECTURE §11.1 rule 1). */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(tego_sched_exit, struct task_struct *p)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_ev_exit *e;
    int exit_code;
    void *ring;

    if (!run)
        return 0;
    tego_flush_task(run); /* every thread's exit ends what it held, before the group's last one returns */
    if (TEGO_READ(p, signal, live.counter) != 0)
        return 0;
    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
        return 0;
    }

    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return 0;
    }
    TEGO_ZERO(e);
    tego_hdr_fill(&e->hdr, TEGO_EV_EXIT, sizeof(*e), run, cgroup_id);
    e->hdr.ppid = TEGO_READ(p, real_parent, tgid);
    e->exec_start_ns = TEGO_READ(p, group_leader, start_boottime);
    if (TEGO_READ(p, signal, flags) & TEGO_SIGNAL_GROUP_EXIT)
        exit_code = TEGO_READ(p, signal, group_exit_code);
    else
        exit_code = TEGO_READ(p, group_leader, exit_code);
    tego_exit_status(exit_code, &e->code, &e->signal);

    bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
    return 0;
}

/* Fills an open record from security_file_open's file and the chain's return, all but the path. */
static __always_inline void tego_fs_fill(struct tego_ev_fs *e, struct file *file, __u32 mode,
                                          const struct tego_run *run, __u64 cgroup_id, int ret)
{
    TEGO_ZERO(e);
    tego_hdr_fill(&e->hdr, TEGO_EV_OPEN, sizeof(*e), run, cgroup_id);
    e->flags = TEGO_READ(file, f_flags);
    e->exec_open = (e->flags & TEGO_FMODE_EXEC) ? 1 : 0;
    e->start_ns = tego_task_start();
    e->dev = TEGO_READ(file, f_inode, i_sb, s_dev);
    e->ino = (__u32)TEGO_READ(file, f_inode, i_ino);
    e->created = (mode & TEGO_FMODE_CREATED) ? 1 : 0;
    e->ret = ret;
    e->ret_ok = 1;
}

/* Reports whether the open that security_file_open just allowed goes on to truncate: do_open truncates a regular
 * file it did not create when O_TRUNC is set (do_truncate; f_flags still carries O_TRUNC here, since
 * do_dentry_open clears it only after the hook returns). */
static __always_inline int tego_will_truncate(struct file *file, __u32 mode)
{
    if (!(TEGO_READ(file, f_flags) & TEGO_O_TRUNC) || (mode & TEGO_FMODE_CREATED))
        return 0;
    return (TEGO_READ(file, f_inode, i_mode) & TEGO_S_IFMT) == TEGO_S_IFREG;
}

/* Reports whether a held create names the dentry this open opened: the one security_path_mknod was asked about,
 * or, where the filesystem's lookup spliced in another, the one with its parent and its name. */
static __always_inline int tego_held_names(const struct tego_held *h, struct file *file)
{
    struct dentry *d = TEGO_READ(file, f_path.dentry);

    if ((__u64)d == h->dentry)
        return 1;
    return (__u64)TEGO_READ(d, d_parent) == h->parent && TEGO_READ(d, d_name.hash_len) == h->hash_len;
}

/* A mount no path of the agent's reaches: a private clone the kernel made for a stacking filesystem
 * (clone_private_mount, overlayfs' layers), whose mnt_ns is fs/mount.h's MNT_NS_INTERNAL, ERR_PTR(-EINVAL); the
 * plane's tego_internal_mount, which skips the same opens (enforce-plane §2.7's condition 1). Every name the agent
 * opens resolves through the mounts of its own namespace, so no open of its own is skipped here; a detached mount
 * (mnt_ns NULL) is not. */
#define TEGO_MNT_NS_INTERNAL ((__u64)-22)

static __always_inline int tego_rec_internal_mount(struct file *file)
{
    __u64 m = (__u64)TEGO_READ(file, f_path.mnt) - bpf_core_field_offset(struct mount, mnt);

#if TEGO_TRACE_RDONLY
    return (__u64)bpf_core_cast((void *)m, struct mount)->mnt_ns == TEGO_MNT_NS_INTERNAL;
#else
    return (__u64)BPF_CORE_READ((struct mount *)m, mnt_ns) == TEGO_MNT_NS_INTERNAL;
#endif
}

/* security_file_open: every open of a matched run, on every mount, independent of the fanotify marks that
 * enforce them (§5 R8). It is the only complete signal for read aggregation and fs.watch, and the one hook the
 * kernel's btf_allowlist_d_path lets a program call bpf_d_path from (§5 R10).
 *
 * fexit, so the record carries the LSM chain's own return (ADR 0016 (3)): on kernels up to 6.12 that includes
 * fanotify's permission answers (security_file_open returned fsnotify_open_perm's there), from 6.13 it does not;
 * on no kernel does it include IMA or anything checked after the function returned. A refusal is recorded under
 * record: off too.
 *
 * One action, one line (struct tego_held): an O_CREAT open that goes ahead drops the create its mknod hook
 * held, and an O_TRUNC open the chain allowed is held for the truncate hook that follows it. Files the kernel
 * opens on the task's behalf are not recorded: the task's own open of the user path already was. They are a
 * stacking filesystem's backing file (FMODE_NOACCOUNT) and any file on a private clone of a mount
 * (tego_rec_internal_mount): overlayfs' copy-up opens the lower file and the new upper one there with a plain
 * dentry_open, in the agent's task, after the agent's own open of the merged file, and bpf_d_path names them
 * relative to the clone's root, a layer-relative path no name of the agent's is. Neither skip flushes a hold: the
 * copy-up runs inside the agent's own open, whose O_TRUNC hold waits for its truncate.
 *
 * 6.1 prototype, all of it (an fexit program's return follows the last declared argument): int
 * security_file_open(struct file *file). */
SEC("fexit/security_file_open")
int BPF_PROG(tego_file_open, struct file *file, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_held *held;
    struct tego_ev_fs *e;
    __u32 mode;
    void *ring;
    long n;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_FILE_OPEN, (__u64)file);
    mode = TEGO_READ(file, f_mode);
    if (mode & TEGO_FMODE_NOACCOUNT)
        return 0;
    if (tego_rec_internal_mount(file))
        return 0;
    held = tego_held_of(0);
    /* The O_CREAT open went ahead: this line is the action's. An open without O_CREAT is not the create's own (a
     * mknod(2) and then an open of the file), so the mknod is flushed as its own line. f_flags keeps O_CREAT here
     * even where lookup_open cleared its own copy (the file is made from the open's flags), so an O_CREAT open of
     * a file that was there, whose create was asked before the lookup knew, still drops its hold. */
    if (held && held->tag == TEGO_HELD_CREATE && (TEGO_READ(file, f_flags) & TEGO_O_CREAT) &&
        tego_held_names(held, file))
        held->tag = TEGO_HELD_NONE;
    tego_held_flush(held, run);
    if (ret == 0 && !tego_recording(run)) {
        tego_activity_stamp(&tego_activity, run); /* allowed, and no line under record: off: activity (limits R4) */
        return 0;
    }

    if (ret == 0 && tego_will_truncate(file, mode)) {
        held = tego_held_of(BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (held) {
            e = &held->fs;
            tego_fs_fill(e, file, mode, run, cgroup_id, ret);
            n = bpf_d_path(&file->f_path, e->path, TEGO_PATH_MAX);
            if (n > 0) {
                e->path_ok = 1;
            } else {
                e->path[0] = 0;
                e->hdr.reason = TEGO_R_PATH_UNRESOLVED; /* §6 E4 */
            }
            held->dentry = (__u64)TEGO_READ(file, f_path.dentry); /* its truncate names this dentry */
            held->tag = TEGO_HELD_OPEN;
            return 0;
        }
    }

    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
        return 0;
    }
    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return 0;
    }
    tego_fs_fill(e, file, mode, run, cgroup_id, ret);
    n = bpf_d_path(&file->f_path, e->path, TEGO_PATH_MAX);
    if (n > 0) {
        e->path_ok = 1;
    } else {
        e->path[0] = 0;
        e->hdr.reason = TEGO_R_PATH_UNRESOLVED; /* §6 E4: userspace records it and raises a gap */
    }
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, tego_libssl_named(file)));
    return 0;
}

/* ---- The directory walk (docs/p0/enforce-plane.md §2.15; ADR 0016's 2026-09-30 note) ----
 *
 * Where a plane mode decides a run, T16 leaves the mutations the plane decides unnotified, so the fsop record is the
 * action's one line and must name it by its path on its own: no supervisor naming is left to hand over. bpf_d_path
 * cannot: a tracing program may call it only at btf_allowlist_d_path's functions (security_path_truncate is the one
 * path hook there, on every kernel), and an LSM program only at a sleepable hook, which the path_* hooks became in
 * 6.8. So the parent directory is walked here, as d_path walks it: d_parent to the mount's root, then the mount's
 * mountpoint in its parent mount, until the task's root (current->fs->root), each level's name prepended to a buffer
 * that is the record's own, right to left.
 *
 * Never a wrong path. A rename moving a component while it is read would join the halves of two paths, and d_path's
 * rename_lock is no BTF symbol this program can read, so each level's dentry sequence (d_seq, which __d_move writes
 * around every change of d_parent and d_name) is read before its parent and name and kept, and a second pass walks
 * the chain again and compares: a sequence that is odd or moved is RACED. Equal sequences all the way up mean the
 * same chain: the first level is the same dentry, and a dentry whose sequence did not move kept its parent. A walk
 * that meets a disconnected dentry or a namespace root short of the task's root is UNREACHABLE, and one past
 * TEGO_DIR_WALK_MAX levels or TEGO_PATH_MAX bytes is LONG; each leaves userspace the dirIndex answer or an
 * unresolved mark.
 *
 * Mounts. d_path also reads mount_lock, which a mount move writes around its change of mnt_parent and
 * mnt_mountpoint; mount_lock is no BTF symbol either. Each crossing's pair (the parent mount, the mountpoint) is kept
 * on the first pass and read again at the same crossing on the second: a pair that differs, or was read torn (half
 * before a move, half after, which the second read then differs from), is RACED. A move completed before the first
 * read and not reverted before the second leaves a path that was true between the two, as d_path's would be. More
 * than TEGO_DIR_WALK_MOUNTS crossings is LONG.
 *
 * Ordering. A seqcount reader needs a read barrier between the sequence and the data (read_seqcount_begin's smp_rmb)
 * and between the data and the re-read (read_seqcount_retry's); on arm64 plain loads are reordered freely. BPF has
 * no barrier instruction, but an atomic with BPF_FETCH is fully ordered: the arm64 JIT emits it as ldaddal (LSE) or
 * an exclusive pair followed by dmb ish, x86 as lock xadd, as the BPF memory model and the kernel's own
 * atomic_fetch_add require. So tego_dir_fence, a fetch-add on the walk's stack whose result is kept (a result left
 * unused makes clang emit the plain, relaxed add), stands after each level's sequence on the first pass and before
 * the second pass (internal/bpf TestDirWalkFencesItsSequenceReads checks both builds' objects carry it).
 *
 * The walk is a global subprogram over bpf_loop, like the plane's (ADR 0024 (1), form d): verified once per program,
 * however many times it is called (rename and link walk two directories, mknod has two call sites), which kept the
 * sequence and mount checks inside the verifier's million instructions on 6.12 and 6.17; a static one, verified
 * per call, did not. Its kernel pointers are passed as scalars and read through the build's reader. A global
 * function cannot take the record (6.17 refuses ring-buffer memory as its argument), so it builds the path in the
 * task's storage (struct tego_dir_scratch) and the caller copies it. Every counter starts from the argument zero,
 * which the verifier does not know in a global function: a verifier before 6.8 verifies a callback once, from its
 * first call's state, and would hard-wire away a bound checked against a known 0 (the plane's walk found that on
 * AL2023's 6.1). */
struct tego_dir_buf {
    char b[TEGO_PATH_MAX];
};

#if TEGO_TRACE_RDONLY
#define TEGO_W_DENTRY(d) bpf_core_cast((void *)(d), struct dentry)
#define TEGO_W_PARENT(d) ((__u64)TEGO_W_DENTRY(d)->d_parent)
#define TEGO_W_SEQ(d) ((__u32)TEGO_W_DENTRY(d)->d_seq.seqcount.sequence)
#define TEGO_W_NAME(d) ((__u64)TEGO_W_DENTRY(d)->d_name.name)
#define TEGO_W_NAMELEN(d) ((__u32)TEGO_W_DENTRY(d)->d_name.len)
#define TEGO_W_MPARENT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt_parent)
#define TEGO_W_MPOINT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt_mountpoint)
#define TEGO_W_VMROOT(vm) ((__u64)bpf_core_cast((void *)(vm), struct vfsmount)->mnt_root)
#define TEGO_W_BYTE(a) tego_kbyte(a)
#else
static __always_inline __u64 tego_w_rd64(__u64 addr)
{
    __u64 v = 0;

    bpf_probe_read_kernel(&v, sizeof(v), (void *)addr);
    return v;
}

static __always_inline __u32 tego_w_rd32(__u64 addr)
{
    __u32 v = 0;

    bpf_probe_read_kernel(&v, sizeof(v), (void *)addr);
    return v;
}

static __always_inline char tego_w_byte(__u64 addr)
{
    char c = 0;

    bpf_probe_read_kernel(&c, 1, (void *)addr);
    return c;
}
#define TEGO_W_PARENT(d) tego_w_rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_parent))
#define TEGO_W_SEQ(d) tego_w_rd32((__u64)(d) + bpf_core_field_offset(struct dentry, d_seq.seqcount.sequence))
#define TEGO_W_NAME(d) tego_w_rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_name.name))
#define TEGO_W_NAMELEN(d) tego_w_rd32((__u64)(d) + bpf_core_field_offset(struct dentry, d_name.len))
#define TEGO_W_MPARENT(m) tego_w_rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt_parent))
#define TEGO_W_MPOINT(m) tego_w_rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt_mountpoint))
#define TEGO_W_VMROOT(vm) tego_w_rd64((__u64)(vm) + bpf_core_field_offset(struct vfsmount, mnt_root))
#define TEGO_W_BYTE(a) tego_w_byte(a)
#endif

/* tego_dir_fence is a full memory barrier (see Ordering above): a fetch-add of 0 on cell, its result kept. */
static __always_inline void tego_dir_fence(__u64 *cell)
{
    __u64 v = __sync_fetch_and_add(cell, 0);

    barrier_var(v);
}

/* The walk's state, on tego_dir_walk's stack; its arrays are the task's (struct tego_dir_scratch). */
struct tego_dir_walk_state {
    struct tego_dir_scratch *scr;
    struct tego_dir_buf *buf;
    __u64 d;        /* the dentry at this level */
    __u64 vm;       /* its struct vfsmount */
    __u64 mroot;    /* that mount's root dentry */
    __u64 root_d;   /* the task's root */
    __u64 root_vm;
    __u32 pos;      /* the path so far is buf[pos, TEGO_PATH_MAX) */
    __u32 level;
    __u32 pass;     /* 0 names each level and keeps its sequence, 1 compares */
    __u32 state;    /* enum tego_dir_state; TEGO_DIR_NONE while walking */
    __u32 cross;    /* mount crossings so far */
    __u64 fence;    /* tego_dir_fence's cell */
};

/* One name's bytes into the buffer, at base. */
struct tego_dir_copy {
    struct tego_dir_buf *buf;
    __u64 src;
    __u32 base;
    __u32 bad;
};

static long tego_dir_copy_step(__u32 j, struct tego_dir_copy *c)
{
    char ch = TEGO_W_BYTE(c->src + j);

    if (!ch) { /* a name holds no NUL: a fault */
        c->bad = 1;
        return 1;
    }
    c->buf->b[(c->base + j) & (TEGO_PATH_MAX - 1)] = ch;
    return 0;
}

/* One iteration: the task's root ends the walk whole; a mount's root crosses to its mountpoint; any other level is
 * checked, named (pass 0) or compared (pass 1), and climbed. Returns 1 to stop, 0 to go on. */
static long tego_dir_step(__u32 i, struct tego_dir_walk_state *s)
{
    __u64 d = s->d;

    if (d == s->root_d && s->vm == s->root_vm) {
        s->state = TEGO_DIR_OK;
        return 1;
    }
    if (d == s->mroot) {
        __u64 m = s->vm - bpf_core_field_offset(struct mount, mnt);
        __u64 pm = TEGO_W_MPARENT(m);
        __u64 mp = TEGO_W_MPOINT(m);
        /* Each pass keeps its own pairs, compared after both (tego_dir_walk): a branch on the pass here multiplied
         * the states the verifier walks through the callback past its million instructions on rename's two walks. */
        __u32 k = (s->pass & 1) * 2 * TEGO_DIR_WALK_MOUNTS + ((2 * s->cross) & (2 * TEGO_DIR_WALK_MOUNTS - 1));

        if (!pm || pm == m) { /* the namespace's root, and not the task's */
            s->state = TEGO_DIR_UNREACHABLE;
            return 1;
        }
        if (s->cross >= TEGO_DIR_WALK_MOUNTS) { /* bounded, as level is, so the verifier's states converge */
            s->state = TEGO_DIR_LONG;
            return 1;
        }
        barrier_var(k); /* the mask below is the last thing done to the index (the 6.1 verifier) */
        k &= 4 * TEGO_DIR_WALK_MOUNTS - 2;
        s->scr->mnt[k] = pm;
        s->scr->mnt[k + 1] = mp;
        s->cross++;
        s->d = mp;
        s->vm = pm + bpf_core_field_offset(struct mount, mnt);
        s->mroot = TEGO_W_VMROOT(s->vm);
        return 0;
    }
    __u32 lvl = s->level;
    if (lvl >= TEGO_DIR_WALK_MAX) {
        s->state = TEGO_DIR_LONG;
        return 1;
    }
    __u32 seq = TEGO_W_SEQ(d);
    if (seq & 1) { /* __d_move is writing it */
        s->state = TEGO_DIR_RACED;
        return 1;
    }
    tego_dir_fence(&s->fence); /* read_seqcount_begin's smp_rmb: the parent and name are read after seq */
    __u64 p = TEGO_W_PARENT(d);
    if (!p || p == d) {
        s->state = TEGO_DIR_UNREACHABLE;
        return 1;
    }
    if (s->pass == 0) {
        __u32 len = TEGO_W_NAMELEN(d);
        struct tego_dir_copy c = {};

        s->scr->seq[lvl & (TEGO_DIR_WALK_MAX - 1)] = seq;
        if (len == 0 || len + 1 > s->pos) {
            s->state = TEGO_DIR_LONG;
            return 1;
        }
        c.buf = s->buf;
        c.src = TEGO_W_NAME(d);
        c.base = s->pos - len;
        bpf_loop(len, tego_dir_copy_step, &c, 0);
        if (c.bad) {
            s->state = TEGO_DIR_RACED;
            return 1;
        }
        s->pos -= len + 1;
        s->buf->b[s->pos & (TEGO_PATH_MAX - 1)] = '/';
    } else if (s->scr->seq[lvl & (TEGO_DIR_WALK_MAX - 1)] != seq) {
        s->state = TEGO_DIR_RACED;
        return 1;
    }
    s->level = lvl + 1;
    s->d = p;
    return 0;
}

/* tego_dir_walk names the directory dentry on vfsmount (a struct vfsmount *) by its path below the current task's
 * root (current->fs->root, where d_path stops) into buf, right to left. Returns the enum tego_dir_state in its low
 * byte and, on TEGO_DIR_OK, the path's first byte's offset above it. zero is 0, which the verifier does not know;
 * any other value walks nothing. */
__attribute__((noinline)) int tego_dir_walk(__u64 dentry, __u64 vfsmount, __u32 zero)
{
    struct task_struct *t = bpf_get_current_task_btf();
    struct tego_dir_walk_state s = {};
    __u32 level, cross;

    if (zero)
        return TEGO_DIR_NONE;
    if (!dentry || !vfsmount)
        return TEGO_DIR_UNREACHABLE;
    /* No storage for the task: nothing is walked, and userspace names the side as it did before (never a guess). */
    {
        struct tego_held *h = tego_held_of(BPF_LOCAL_STORAGE_GET_F_CREATE);

        if (!h)
            return TEGO_DIR_NONE;
        s.scr = &h->walk;
    }
#if !TEGO_TRACE_RDONLY
    /* The probe-read build loads on kernels without bpf_loop too; no plane runs there, and nothing is walked. */
    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_loop))
        return TEGO_DIR_NONE;
#endif
    s.buf = (struct tego_dir_buf *)s.scr->buf;
    s.root_d = (__u64)TEGO_READ(t, fs, root.dentry);
    s.root_vm = (__u64)TEGO_READ(t, fs, root.mnt);
    s.d = dentry;
    s.vm = vfsmount;
    s.mroot = TEGO_W_VMROOT(vfsmount);
    s.pos = TEGO_PATH_MAX + zero;
    s.level = zero;
    s.pass = zero;
    s.state = zero;
    s.cross = zero;
    bpf_loop(TEGO_DIR_WALK_ITERS, tego_dir_step, &s, 0);
    if (s.state != TEGO_DIR_OK)
        return s.state == TEGO_DIR_NONE ? TEGO_DIR_LONG : s.state;
    level = s.level;
    cross = s.cross;
    /* read_seqcount_retry's smp_rmb: every sequence and mount pair of the second pass is read after the first
     * pass's data. */
    tego_dir_fence(&s.fence);
    s.d = dentry;
    s.vm = vfsmount;
    s.mroot = TEGO_W_VMROOT(vfsmount);
    s.level = zero;
    s.pass = zero + 1;
    s.state = zero;
    s.cross = zero;
    bpf_loop(TEGO_DIR_WALK_ITERS, tego_dir_step, &s, 0);
    if (s.state == TEGO_DIR_NONE)
        return TEGO_DIR_LONG;
    if (s.state != TEGO_DIR_OK)
        return s.state;
    if (s.level != level || s.cross != cross)
        return TEGO_DIR_RACED;
    if (cross > TEGO_DIR_WALK_MOUNTS)
        return TEGO_DIR_LONG;
#pragma unroll
    for (int j = 0; j < 2 * TEGO_DIR_WALK_MOUNTS; j++) {
        if (j < 2 * (int)cross && s.scr->mnt[j] != s.scr->mnt[2 * TEGO_DIR_WALK_MOUNTS + j])
            return TEGO_DIR_RACED; /* the mount moved between the passes, or was read mid-move */
    }
    return TEGO_DIR_OK | ((s.pos & 0x1ff) << 8);
}

/* Names one side's parent directory (dentry on vfsmount) into dir, for a run a plane mode decides; any other run's
 * record keeps TEGO_DIR_NONE, and userspace names it from dirIndex as it always has. */
static __always_inline void tego_fsop_dir(const struct tego_run *run, char *dir, __u8 *state, __u16 *off,
                                           __u64 dentry, __u64 vfsmount)
{
    struct tego_held *h;
    int r;

    *off = TEGO_PATH_MAX;
    if (run->plane == TEGO_RUN_PLANE_NONE)
        return;
    h = tego_held_of(BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!h)
        return; /* no storage, no walk: TEGO_DIR_NONE, and userspace names the side as before */
    h->walk.launder_dentry = dentry;
    h->walk.launder_mnt = vfsmount;
    r = tego_dir_walk(*(volatile __u64 *)&h->walk.launder_dentry, *(volatile __u64 *)&h->walk.launder_mnt, 0);
    *state = (__u8)(r & 0xff);
    if (*state != TEGO_DIR_OK)
        return; /* dir stays as the record was zeroed */
    __builtin_memcpy(dir, h->walk.buf, TEGO_PATH_MAX);
    *off = (__u16)((r >> 8) & 0x1ff);
}

/* Fills one side of an fsop record from a (parent path, child dentry) pair: the parent's device and inode,
 * and the child's final component. Never a resolved path (§5 R9). Returns 1 when the name was read whole. */
static __always_inline __u8 tego_fsop_side(struct path *dir, struct dentry *dentry, __u64 *dev, __u64 *ino,
                                            char *name, __u32 name_sz)
{
    const unsigned char *raw;
    __u32 len;
    long n;

    *dev = TEGO_READ(dir, dentry, d_sb, s_dev);
    *ino = TEGO_READ(dir, dentry, d_inode, i_ino);

    raw = TEGO_READ(dentry, d_name.name);
    len = TEGO_READ(dentry, d_name.len);
#if TEGO_TRACE_RDONLY
    n = tego_kstr(name, raw);
#else
    n = bpf_probe_read_kernel_str(name, name_sz, raw);
#endif
    if (n <= 0) {
        name[0] = 0;
        return 0;
    }
    /* n counts the NUL: the name is whole when it read len bytes and the NUL, which a 255-byte name (NAME_MAX)
     * does in the 256-byte buffer. */
    return (__u64)n == (__u64)len + 1 ? 1 : 0;
}

/* tego_fsop_side for a dentry with no path beside it — a link's source and a truncated file — whose parent is
 * its d_parent, on its own super block. */
static __always_inline __u8 tego_fsop_dside(struct dentry *dentry, __u64 *dev, __u64 *ino, char *name,
                                             __u32 name_sz)
{
    const unsigned char *raw;
    __u32 len;
    long n;

    *dev = TEGO_READ(dentry, d_sb, s_dev);
    *ino = TEGO_READ(dentry, d_parent, d_inode, i_ino);

    raw = TEGO_READ(dentry, d_name.name);
    len = TEGO_READ(dentry, d_name.len);
#if TEGO_TRACE_RDONLY
    n = tego_kstr(name, raw);
#else
    n = bpf_probe_read_kernel_str(name, name_sz, raw);
#endif
    if (n <= 0) {
        name[0] = 0;
        return 0;
    }
    return (__u64)n == (__u64)len + 1 ? 1 : 0;
}

/* Fills an fsop record's common fields and the chain's return. */
static __always_inline void tego_fsop_init(struct tego_ev_fsop *e, __u16 kind, __u8 op, const struct tego_run *run,
                                            __u64 cgroup_id, int ret)
{
    TEGO_ZERO(e);
    tego_hdr_fill(&e->hdr, kind, sizeof(*e), run, cgroup_id);
    e->op = op;
    e->start_ns = tego_task_start();
    e->ret = ret;
    e->ret_ok = 1;
}

/* Reserves and pre-fills an fsop record on the run's ring, or returns NULL when nothing is to be recorded: an
 * allowed operation of a run that records nothing (a refusal is recorded under record: off too, ADR 0016 (3)), a
 * run with no ring or a full ring (both counted). *ringp is the ring the record is to be submitted to. */
static __always_inline struct tego_ev_fsop *tego_fsop_begin(void **ringp, __u16 kind, __u8 op,
                                                              const struct tego_run *run, __u64 cgroup_id, int ret)
{
    struct tego_ev_fsop *e;
    void *ring;

    if (ret == 0 && !tego_recording(run)) {
        tego_activity_stamp(&tego_activity, run); /* allowed, and no line under record: off: activity (limits R4) */
        return 0;
    }
    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
        return 0;
    }
    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return 0;
    }
    tego_fsop_init(e, kind, op, run, cgroup_id, ret);
    *ringp = ring;
    return e;
}

/* The security_path_* programs below are fexit programs on the functions where the run's inherited Landlock
 * domain can refuse (ADR 0016 (3)): each records the chain's own return, and none decides anything (§5 R9). Each
 * declares its function's whole prototype, identical from 5.14 through 7.0 (security/security.c), because an
 * fexit program's return is read from the slot after the last argument (internal/bpf attach_test.go). Each first
 * emits whatever the task still held. */

/* 6.1 prototype: int security_path_unlink(const struct path *dir, struct dentry *dentry). */
SEC("fexit/security_path_unlink")
int BPF_PROG(tego_path_unlink, struct path *dir, struct dentry *dentry, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_ev_fsop *e;
    void *ring = 0;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_UNLINK, (__u64)dentry);
    tego_flush_task(run);
    e = tego_fsop_begin(&ring, TEGO_EV_UNLINK, TEGO_FSOP_UNLINK, run, cgroup_id, ret);
    if (!e)
        return 0;
    e->name_ok = tego_fsop_side(dir, dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(dir, dentry),
                   (__u64)TEGO_READ(dir, mnt));
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}

/* 6.1 prototype: int security_path_rmdir(const struct path *dir, struct dentry *dentry). */
SEC("fexit/security_path_rmdir")
int BPF_PROG(tego_path_rmdir, struct path *dir, struct dentry *dentry, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_ev_fsop *e;
    void *ring = 0;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_RMDIR, (__u64)dentry);
    tego_flush_task(run);
    e = tego_fsop_begin(&ring, TEGO_EV_RMDIR, TEGO_FSOP_RMDIR, run, cgroup_id, ret);
    if (!e)
        return 0;
    e->name_ok = tego_fsop_side(dir, dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(dir, dentry),
                   (__u64)TEGO_READ(dir, mnt));
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}

/* Both sides recorded (§5 R9).
 *
 * 6.1 prototype: int security_path_rename(const struct path *old_dir, struct dentry *old_dentry,
 * const struct path *new_dir, struct dentry *new_dentry, unsigned int flags). flags is not read. */
SEC("fexit/security_path_rename")
int BPF_PROG(tego_path_rename, struct path *old_dir, struct dentry *old_dentry, struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_ev_fsop *e;
    void *ring = 0;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_RENAME, (__u64)old_dentry);
    tego_flush_task(run);
    e = tego_fsop_begin(&ring, TEGO_EV_RENAME, TEGO_FSOP_RENAME, run, cgroup_id, ret);
    if (!e)
        return 0;
    e->name_ok = tego_fsop_side(old_dir, old_dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    e->name2_ok = tego_fsop_side(new_dir, new_dentry, &e->dev2, &e->dir_ino2, e->name2, TEGO_NAME_MAX);
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(old_dir, dentry),
                   (__u64)TEGO_READ(old_dir, mnt));
    tego_fsop_dir(run, e->dir2, &e->dir2_state, &e->dir2_off, (__u64)TEGO_READ(new_dir, dentry),
                   (__u64)TEGO_READ(new_dir, mnt));
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}

/* 6.1 prototype: int security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode).
 * mode is not read. */
SEC("fexit/security_path_mkdir")
int BPF_PROG(tego_path_mkdir, struct path *dir, struct dentry *dentry, umode_t mode, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_ev_fsop *e;
    void *ring = 0;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_MKDIR, (__u64)dentry);
    tego_flush_task(run);
    e = tego_fsop_begin(&ring, TEGO_EV_MKDIR, TEGO_FSOP_MKDIR, run, cgroup_id, ret);
    if (!e)
        return 0;
    e->name_ok = tego_fsop_side(dir, dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(dir, dentry),
                   (__u64)TEGO_READ(dir, mnt));
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}

/* A create: mknod(2), or the O_CREAT open's may_o_create, which asks before the lookup knows whether the file
 * exists and clears O_CREAT on a refusal, so its refusal refuses nothing when the file is there. A regular file
 * with no device is that shape, and is held (struct tego_held) for the open that follows to drop; anything else
 * — a FIFO, a socket, a device node — is a mknod(2), recorded at once.
 *
 * 6.1 prototype: int security_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
 * unsigned int dev). */
SEC("fexit/security_path_mknod")
int BPF_PROG(tego_path_mknod, struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_held *held;
    struct tego_ev_fsop *e;
    __u32 type = (__u32)mode & TEGO_S_IFMT;
    void *ring = 0;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_MKNOD, (__u64)dentry);
    if (type == 0140000 && ret < 0) {
        struct tego_plane_decision *bind = bpf_task_storage_get(&tego_plane_scratch, bpf_get_current_task_btf(), 0, 0);
        if (bind && bind->listen_sock && bind->bind.op == TEGO_EV_BIND_RESULT && bind->listen_gen == run->gen && bind->listen_run_idx == run->run_idx &&
            bind->bind.start_ns == tego_task_start()) {
            // This task is still inside the bind that published the marker.
            // Keep the actual parent/name even if another LSM refused before
            // the plane ran, and leave its one terminal line to sys_exit_bind.
            bind->bind.flags |= TEGO_BIND_RESOLVED;
            bind->bind.flags &= ~(TEGO_BIND_ABSTRACT | TEGO_BIND_NAME_OK);
            bind->bind.dev = TEGO_READ(dir,dentry,d_sb,s_dev);
            bind->bind.dir_ino = TEGO_READ(dir,dentry,d_inode,i_ino);
            bind->bind.name_len = TEGO_READ(dentry,d_name.len);
            if (bind->bind.name_len > 0 && bind->bind.name_len < 108) {
                const unsigned char *raw = TEGO_READ(dentry,d_name.name);
#pragma clang loop unroll(full)
                for (int i=0;i<108;i++) {
                    char c = 0;
                    if (i < bind->bind.name_len) {
#if TEGO_TRACE_RDONLY
                        c = tego_kbyte((__u64)raw+i);
#else
                        bpf_probe_read_kernel(&c,1,raw+i);
#endif
                    }
                    bind->bind.name[i] = c;
                }
                bind->bind.flags |= TEGO_BIND_NAME_OK;
            } else
                bind->bind.name_len = 0;
            if (!bind->bind.reason)
                bind->bind.flags |= TEGO_BIND_CHAIN_REFUSED;
            return 0;
        }
    }
    tego_flush_task(run);
    if ((type == TEGO_S_IFREG || type == 0) && dev == 0) {
        if (ret == 0 && !tego_recording(run)) {
            tego_activity_stamp(&tego_activity, run); /* an allowed create under record: off (limits R4) */
            return 0;
        }
        held = tego_held_of(BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (held) {
            e = &held->op;
            tego_fsop_init(e, TEGO_EV_MKNOD, TEGO_FSOP_MKNOD, run, cgroup_id, ret);
            e->name_ok = tego_fsop_side(dir, dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
            tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(dir, dentry),
                           (__u64)TEGO_READ(dir, mnt));
            tego_plane_stamp(&e->hdr, said, ret);
            held->dentry = (__u64)dentry;
            held->parent = (__u64)TEGO_READ(dentry, d_parent);
            held->hash_len = TEGO_READ(dentry, d_name.hash_len);
            held->tag = TEGO_HELD_CREATE;
            return 0;
        }
        if (ret == 0)
            return 0; /* no hold: an allowed create would be a second line beside its open's */
    }
    e = tego_fsop_begin(&ring, TEGO_EV_MKNOD, TEGO_FSOP_MKNOD, run, cgroup_id, ret);
    if (!e)
        return 0;
    e->name_ok = tego_fsop_side(dir, dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(dir, dentry),
                   (__u64)TEGO_READ(dir, mnt));
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}

/* A bind permission hook precedes pathname creation. Its task marker remains
 * live until the actual syscall exits, including kernel errors and record:off. */
static __always_inline int tego_listener_results_on(const struct tego_run *run)
{
    // Membership carries the prepared policy and generation, including for
    // descendants. The plane's slot maps are separate for its two modes and
    // cannot be an eligibility map for this globally shared trace object.
    return run && run->gen && run->plane != TEGO_RUN_PLANE_NONE &&
           (run->flags & TEGO_RUN_LISTENER_RESULTS);
}

/* ret is the operation's actual result. uring is an io_uring op's producer: the op went through no supervisor
 * notification and its socket may be any family, so only a plane-marked (Unix) operation writes its line there,
 * flagged TEGO_BIND_URING; an inet io_uring bind or listen keeps the cgroup programs' and the plane's own records.
 * Either producer clears the marker. */
static __always_inline int tego_listener_result_emit(__s64 ret, __u16 kind, int uring)
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    struct tego_plane_decision *sc;
    sc = bpf_task_storage_get(&tego_plane_scratch, bpf_get_current_task_btf(), 0, 0);
    struct tego_ev_bind_result *e = 0;
    void *ring = 0;
    __u64 start = tego_task_start();
    int marked = sc && sc->listen_sock && run && sc->listen_run_idx == run->run_idx &&
                 sc->listen_gen == run->gen && sc->bind.start_ns == start && sc->bind.op == kind;
    // These globally attached hooks share rings with legacy runs. Only an
    // explicit listener policy owns terminal bind/listen records; cleanup
    // below remains unconditional, even after a slot was cleared or reused.
    if (tego_listener_results_on(run) && (marked || !uring)) {
        ring = tego_ring_of(&tego_events,run);
        if (ring) {
            e = bpf_ringbuf_reserve(ring,sizeof(*e),0);
            if (!e)
                tego_lost_inc(&tego_lost,run->run_idx);
        } else
            tego_lost_inc(&tego_lost,run->run_idx);
    }
    if (e) {
        TEGO_ZERO(e);
        tego_hdr_fill(&e->hdr,kind,sizeof(*e),run,bpf_get_current_cgroup_id());
        e->start_ns = start;
        e->ret = ret;
        e->rule_idx = TEGO_PLANE_RULE_NONE;
        if (uring)
            e->flags = TEGO_BIND_URING;
        if (marked) {
            e->dev = sc->bind.dev;
            e->dir_ino = sc->bind.dir_ino;
            e->rule_idx = sc->bind.rule_idx;
            e->flags |= sc->bind.flags;
            e->name_len = sc->bind.name_len;
            __builtin_memcpy(e->name,sc->bind.name,sizeof(e->name));
            if (sc->bind.flags & TEGO_BIND_DECIDED) {
                e->hdr.verdict = sc->bind.reason ? TEGO_V_REFUSED : TEGO_V_ALLOW;
                e->hdr.reason = sc->bind.reason;
            }
            e->hdr.rule_idx = sc->bind.rule_idx;
        }
        bpf_ringbuf_submit(e,BPF_RB_FORCE_WAKEUP);
    }
    if (!sc)
        return 0;
    sc->listen_sock = 0;
    sc->listen_run_idx = 0;
    sc->listen_gen = 0;
    __builtin_memset(&sc->bind,0,sizeof(sc->bind));
    if (sc->rule_idx & TEGO_PLANE_RULE_LISTEN) {
        sc->hook = TEGO_HOOK_NONE;
        sc->obj = 0;
        sc->rule_idx = TEGO_PLANE_RULE_NONE;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int tego_bind_result(struct trace_event_raw_sys_exit *ctx)
{
    return tego_listener_result_emit(ctx->ret,TEGO_EV_BIND_RESULT,0);
}

SEC("tracepoint/syscalls/sys_exit_listen")
int tego_listen_result(struct trace_event_raw_sys_exit *ctx)
{
    return tego_listener_result_emit(ctx->ret,TEGO_EV_LISTEN_RESULT,0);
}

/* IORING_OP_BIND and IORING_OP_LISTEN (6.11+) reach security_socket_bind and security_socket_listen through
 * __sys_bind_socket and __sys_listen_socket, inside io_uring_enter or in an io-wq worker of the run, with no bind or
 * listen syscall exit. The op's own fexit is then the terminal producer: it writes the marked operation's line with
 * the op's result (the completion's res; a negative return is a failure before the socket call) and clears the
 * marker, which would otherwise outlive the op and make the task's next mknod(S_IFSOCK) a listener bind
 * (enforce-plane §2.20). Both programs are optional: a kernel without the functions has no such opcodes. */
SEC("fexit/io_bind")
int BPF_PROG(tego_uring_bind_result, struct io_kiocb *req, unsigned int issue_flags, int ret)
{
    tego_listener_result_emit(ret < 0 ? ret : TEGO_READ(req, cqe.res), TEGO_EV_BIND_RESULT, 1);
    return 0;
}

SEC("fexit/io_listen")
int BPF_PROG(tego_uring_listen_result, struct io_kiocb *req, unsigned int issue_flags, int ret)
{
    tego_listener_result_emit(ret < 0 ? ret : TEGO_READ(req, cqe.res), TEGO_EV_LISTEN_RESULT, 1);
    return 0;
}

/* The source is named by its own dentry's parent, the new name like any other side.
 *
 * 6.1 prototype: int security_path_link(struct dentry *old_dentry, const struct path *new_dir,
 * struct dentry *new_dentry). */
SEC("fexit/security_path_link")
int BPF_PROG(tego_path_link, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_ev_fsop *e;
    void *ring = 0;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_LINK, (__u64)new_dentry);
    tego_flush_task(run);
    e = tego_fsop_begin(&ring, TEGO_EV_LINK, TEGO_FSOP_LINK, run, cgroup_id, ret);
    if (!e)
        return 0;
    e->name_ok = tego_fsop_dside(old_dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    e->name2_ok = tego_fsop_side(new_dir, new_dentry, &e->dev2, &e->dir_ino2, e->name2, TEGO_NAME_MAX);
    /* A hard link stays on one mount (vfs_link's EXDEV), so the source's parent is walked on new_dir's. */
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(old_dentry, d_parent),
                   (__u64)TEGO_READ(new_dir, mnt));
    tego_fsop_dir(run, e->dir2, &e->dir2_state, &e->dir2_off, (__u64)TEGO_READ(new_dir, dentry),
                   (__u64)TEGO_READ(new_dir, mnt));
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}

/* The target is the string the caller passed (getname's kernel copy), recorded as it was written; a target of
 * TEGO_NAME_MAX bytes or more is marked cut; one of TEGO_NAME_MAX - 1 bytes, which fills the buffer with its NUL,
 * is whole.
 *
 * 6.1 prototype: int security_path_symlink(const struct path *dir, struct dentry *dentry,
 * const char *old_name). */
SEC("fexit/security_path_symlink")
int BPF_PROG(tego_path_symlink, struct path *dir, struct dentry *dentry, const char *old_name, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_plane_said said;
    struct tego_ev_fsop *e;
    void *ring = 0;
    long n;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_SYMLINK, (__u64)dentry);
    tego_flush_task(run);
    e = tego_fsop_begin(&ring, TEGO_EV_SYMLINK, TEGO_FSOP_SYMLINK, run, cgroup_id, ret);
    if (!e)
        return 0;
    e->name_ok = tego_fsop_side(dir, dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(dir, dentry),
                   (__u64)TEGO_READ(dir, mnt));
#if TEGO_TRACE_RDONLY
    n = tego_kstr(e->name2, old_name);
#else
    n = bpf_probe_read_kernel_str(e->name2, TEGO_NAME_MAX, old_name);
#endif
    if (n > 0 && n < TEGO_NAME_MAX)
        e->name2_ok = 1;
    else if (n == TEGO_NAME_MAX) {
        /* A 255-byte target fills the buffer with its NUL too: whole only when the 256th source byte is the NUL. */
#if TEGO_TRACE_RDONLY
        if (tego_kbyte((__u64)old_name + TEGO_NAME_MAX - 1) == 0)
            e->name2_ok = 1;
#else
        char c = 1;
        if (bpf_probe_read_kernel(&c, 1, old_name + TEGO_NAME_MAX - 1) == 0 && c == 0)
            e->name2_ok = 1;
#endif
    } else if (n <= 0)
        e->name2[0] = 0;
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}

/* Ends a truncate: the O_TRUNC open the task holds takes this return and is emitted as the action's one line;
 * with none held, the truncate(2) or ftruncate(2) is recorded on its own, its file named by its dentry's parent.
 * The held open is this truncate's only when the dentries match: an open that failed after security_file_open
 * (the filesystem's ->open, fanotify from 6.13, security_file_post_open) never reaches its truncate, and the
 * task's next truncate, of another file, must not lend it its return; that open is flushed as the allow the
 * chain answered and the truncate recorded on its own. */
static __always_inline void tego_truncate(struct dentry *dentry, struct vfsmount *mnt, const struct tego_run *run,
                                           __u64 cgroup_id, int ret, struct tego_plane_said said)
{
    struct tego_held *held = tego_held_of(0);
    struct tego_ev_fsop *e;
    void *ring = 0;

    if (held && held->tag == TEGO_HELD_OPEN && held->dentry == (__u64)dentry) {
        held->fs.ret = ret;
        tego_plane_stamp(&held->fs.hdr, said, ret);
        tego_held_flush(held, run);
        return;
    }
    tego_held_flush(held, run);
    e = tego_fsop_begin(&ring, TEGO_EV_TRUNCATE, TEGO_FSOP_TRUNCATE, run, cgroup_id, ret);
    if (!e)
        return;
    e->name_ok = tego_fsop_dside(dentry, &e->dev, &e->dir_ino, e->name, TEGO_NAME_MAX);
    tego_fsop_dir(run, e->dir, &e->dir_state, &e->dir_off, (__u64)TEGO_READ(dentry, d_parent), (__u64)mnt);
    tego_plane_stamp(&e->hdr, said, ret);
    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
}

/* truncate(2) on every kernel, and ftruncate(2) and an O_TRUNC open below 6.2.
 *
 * 6.1 prototype: int security_path_truncate(const struct path *path). */
SEC("fexit/security_path_truncate")
int BPF_PROG(tego_path_truncate, struct path *path, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);

    struct tego_plane_said said;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_PATH_TRUNCATE, (__u64)TEGO_READ(path, dentry));
    tego_truncate(TEGO_READ(path, dentry), TEGO_READ(path, mnt), run, cgroup_id, ret, said);
    return 0;
}

/* ftruncate(2) and an O_TRUNC open from 6.2, the kernel that added the hook. The backend leaves this program out
 * of the load where the function is not in the kernel's BTF (internal/bpf OptionalTracePrograms).
 *
 * Prototype since 6.2: int security_file_truncate(struct file *file). */
SEC("fexit/security_file_truncate")
int BPF_PROG(tego_file_truncate, struct file *file, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);

    struct tego_plane_said said;

    if (!run)
        return 0;
    said = tego_plane_take(TEGO_HOOK_FILE_TRUNCATE, (__u64)file);
    tego_truncate(TEGO_READ(file, f_path.dentry), TEGO_READ(file, f_path.mnt), run, cgroup_id, ret, said);
    return 0;
}

/* security_socket_connect: the record of every connect a run attempts, including the socket types
 * cgroup/connect4 and /connect6 do not see — ICMP and raw sockets are recorded here and refused nowhere, a
 * stated P0 gap (§5 R4). The address is the kernel's own copy, already validated by the syscall.
 *
 * 6.1 prototype: int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen).
 * addrlen bounds every read: move_addr_to_kernel copied only the caller's addrlen bytes into an uninitialized
 * sockaddr_storage, so the family is read only with 2 bytes, an IPv4 address with sizeof(struct sockaddr_in) and an
 * IPv6 one with SIN6_LEN_RFC2133 (24); past them is stack garbage, not the caller's address. */
SEC("fentry/security_socket_connect")
int BPF_PROG(tego_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    struct tego_ev_net *e;
    __u16 family;
    void *ring;

    if (!run)
        return 0;
    tego_flush_task(run);
    if (!tego_recording(run)) {
        /* A connect is a line under summary whatever its verdict, so under off it is activity whatever its verdict:
         * this fentry runs before connect4/6 decide (limits R4). */
        tego_activity_stamp(&tego_activity, run);
        return 0;
    }

    /* sa_family is the first two bytes of what the caller passed: with fewer, move_addr_to_kernel copied fewer
     * into an uninitialized sockaddr_storage, and the family read here would be stack garbage, not the caller's.
     * Such a connect fails in the protocol's own length check. */
    if (addrlen < 2)
        return 0;

    /* AF_UNIX is not recorded here: its name is unresolved at this hook (ARCHITECTURE §11), and the record of a
     * unix connect is the inherited tier-1 seccomp notification's, which names the socket. Recorded here it was
     * a second line, `proto=raw dst=family1:0`. */
    family = TEGO_READ(address, sa_family);
    if (family != TEGO_AF_INET && family != TEGO_AF_INET6)
        return 0;
    /* An address shorter than its family's names no destination: move_addr_to_kernel copied addrlen bytes into
     * an uninitialized sockaddr_storage, nothing past them was the caller's, and the call fails EINVAL in the
     * protocol's own length check (tcp_v4_connect, ip4_datagram_connect: sizeof(struct sockaddr_in);
     * tcp_v6_connect, ip6_datagram_connect: SIN6_LEN_RFC2133). Recorded, it was a line naming 0.0.0.0:0. The
     * supervisor keeps its own line for it (supervisor R7, kernelRecords), so the connect is not left with none. */
    if (family == TEGO_AF_INET && addrlen < (int)sizeof(struct sockaddr_in))
        return 0;
    if (family == TEGO_AF_INET6 && addrlen < 24 /* SIN6_LEN_RFC2133 */)
        return 0;
    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
        return 0;
    }

    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return 0;
    }
    TEGO_ZERO(e);
    tego_hdr_fill(&e->hdr, TEGO_EV_CONNECT, sizeof(*e), run, cgroup_id);
    e->start_ns = tego_task_start();
    e->family = (__u8)family;
    e->proto = (__u8)TEGO_READ(sock, sk, sk_protocol);

    /* addrlen covers the family's address: the early returns above left no shorter one. */
    if (family == TEGO_AF_INET) {
#if TEGO_TRACE_RDONLY
        /* The argument is typed struct sockaddr, 16 bytes; the family's own type is cast to (bpf_rdonly_cast). */
        struct sockaddr_in *sin = bpf_core_cast(address, struct sockaddr_in);
#else
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
#endif
        __be32 v4 = TEGO_READ(sin, sin_addr.s_addr);

        e->port = bpf_ntohs(TEGO_READ(sin, sin_port));
        tego_addr_v4(e->addr, v4);
    } else {
#if TEGO_TRACE_RDONLY
        struct sockaddr_in6 *sin6 = bpf_core_cast(address, struct sockaddr_in6);
        int k;

        e->port = bpf_ntohs(sin6->sin6_port);
#pragma unroll
        for (k = 0; k < 4; k++) {
            __u32 w = sin6->sin6_addr.in6_u.u6_addr32[k];

            __builtin_memcpy(&e->addr[k * 4], &w, 4);
        }
#else
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;

        e->port = bpf_ntohs(BPF_CORE_READ(sin6, sin6_port));
        BPF_CORE_READ_INTO(&e->addr, sin6, sin6_addr.in6_u.u6_addr8);
#endif
    }

    bpf_ringbuf_submit(e, tego_quiet(ring, 0));
    return 0;
}
