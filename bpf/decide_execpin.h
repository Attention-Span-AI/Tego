// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* ADR 0048 (3) P2: the kernel holds every exec of a pinned run to the facts the supervisor decided (exec pins).
 * Included by bpf/decide.bpf.c before bprm_check. The supervisor stays the one decider: nothing here allows what the
 * plane's other steps refuse, and no path returns 0 because of a pin (bpf/tests TestExecPinOnlyNarrows).
 *
 * - bprm_check's first stage (tego_pin_first): look the exec's pin up by its thread's key, compare the gen, the
 *   image's identity, its final name and the spelling the kernel looked it up by, refuse a guarded exec of a traced
 *   task, and move the pin into the task's own storage, deleting the hash entry.
 * - each later stage (tego_pin_later): a script pin's chain names the stage's file; an unknown-form pin admits it only
 *   with TEGO_PIN_INTERP_OK, and a first binfmt_misc stage with the P flag only when the decided argv[0] is the
 *   filename; a direct pin admits none.
 * - sched_process_exec (tego_exec_pin_check): MAC the area the new image maps against the pin and send SIGKILL, before
 *   the image's first instruction, when it differs, cannot be read, or the task holds no pin.
 * - the ptrace hooks (decide_control.h) refuse a peer of a task whose last exec passed with TEGO_PIN_GUARD.
 *
 * Every MAC is exec_pin.h's SipHash-2-4 under the slot's key; the area is read in TEGO_PIN_STEP-byte chunks under a
 * bpf_loop callback into the task's own storage, never a per-CPU buffer and never the stack. */

#define TEGO_PT_PTRACED 0x1  /* include/linux/ptrace.h, unchanged since 2.6 */
/* include/linux/binfmts.h BINPRM_FLAGS_PRESERVE_ARGV0 (since 5.12): binfmt_misc's P flag kept argv[0] */
#define TEGO_BINPRM_PRESERVE_ARGV0 (1u << 3)
#define TEGO_SIGKILL 9
#define TEGO_PIN_ENOMEM 12
#define TEGO_PIN_PATH_MAX 4095 /* bprm->filename's bytes before its NUL: getname's PATH_MAX - 1 */
#define TEGO_PIN_KWORDS ((TEGO_PIN_PATH_MAX + 1) / 8)

/* The task's pin state of this run and gen, or NULL. */
static __always_inline struct tego_exec_armed *tego_pin_state(const struct tego_run *run, struct task_struct *t)
{
    struct tego_exec_armed *st = bpf_task_storage_get(&tego_plane_exec_armed, t, 0, 0);

    if (!st || st->run_idx != run->run_idx || st->gen != run->gen)
        return 0;
    return st;
}

/* Whether task t of the run is argv-guarded: its last exec passed a pin with TEGO_PIN_GUARD (ADR 0048 (3), "After
 * the check"), or its thread group leader's did. The mark is stored on the task that exec'd, which de_thread makes
 * the leader; a thread the new program creates later has no mark of its own and shares the leader's mm, argv area
 * included (REXEC-PINSc1-3). Read by the plane's ptrace hooks, whose callers already found the run. */
static __always_inline int tego_pin_guarded(const struct tego_run *run, const struct tego_plane_slot *hdr,
                                             struct task_struct *t)
{
    struct tego_exec_armed *st;
    struct task_struct *leader;

    if (!hdr || !(hdr->flags & TEGO_SLOT_EXEC_PIN) || !t)
        return 0;
    st = tego_pin_state(run, t);
    if (st && st->guarded)
        return 1;
    leader = t->group_leader;
    if (!leader || leader == t)
        return 0;
    st = tego_pin_state(run, leader);
    return st && st->guarded;
}

/* ---- A MAC over kernel bytes (a final name, bprm->filename), read a word at a time through the build's reader ---- */
struct tego_kmac {
    struct tego_sip s;
    __u64 addr;
    __u64 tail;     /* the last partial word, as read */
    __u32 len;      /* bytes absorbed */
    __u32 pad;
};

static long tego_kmac_step(__u32 i, struct tego_kmac *c)
{
    __u32 off = i * 8;
    __u64 w;

    if (i >= TEGO_PIN_KWORDS || off >= c->len)
        return 1;
    w = TEGO_RD_WORD(c->addr + off);
    if (off + 8 > c->len) {
        c->tail = w;
        return 1;
    }
    tego_sip_word(&c->s, tego_sip_fix(w));
    return 0;
}

static __always_inline __u64 tego_kmac(const struct tego_pin_keyval *key, __u8 dom, __u64 addr, __u32 len)
{
    struct tego_kmac c = {};

    c.addr = addr;
    c.len = len;
    tego_sip_begin(&c.s, key->k0, key->k1, dom, len);
    bpf_loop(TEGO_PIN_KWORDS, tego_kmac_step, &c, 0);
    return tego_sip_end(&c.s, tego_sip_fix(c.tail), len & 7);
}

/* ---- bprm_check ---- */

/* The first stage (bprm->interp == bprm->filename): steps 1-5 of ADR 0048 (3). Returns 0 or the refusal's reason. */
static __always_inline __u8 tego_pin_first(const struct tego_run *run, const struct tego_plane_slot *hdr,
                                            struct linux_binprm *bprm, struct task_struct *t)
{
    struct tego_exec_armed *st = bpf_task_storage_get(&tego_plane_exec_armed, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    struct bpf_pidns_info ns = {};
    struct tego_pin_key key = {};
    struct tego_pin_keyval *mk;
    struct tego_exec_pin *pin;
    struct dentry *dentry;
    struct inode *inode;
    __u32 idx = run->run_idx;
    __u64 w;
    void *pins;

    /* A NULL is the helper's busy lock below 6.2, or no memory: the exec cannot be held, so it does not run. */
    if (!st)
        return TEGO_R_PIN_UNVERIFIABLE;
    /* 1. No earlier exec's pin survives into this one. The argv-guarded mark stays for the image that runs now, unless
     *    the state is another run's. */
    if (st->run_idx != run->run_idx || st->gen != run->gen) {
        st->run_idx = run->run_idx;
        st->gen = run->gen;
        st->guarded = 0;
    }
    st->armed = 0;
    st->stage = 0;
    st->cur_seq = 0;
    st->argc0 = 0;
    st->outcome = TEGO_PIN_OUT_NONE;
    /* 2. The pin, by the thread's key in the launcher's pid namespace. A slot with no pin map or no key of this gen,
     *    or a task outside that namespace (the helper answers -EINVAL), cannot be checked. */
    pins = bpf_map_lookup_elem(&tego_plane_exec_pins, &idx);
    mk = bpf_map_lookup_elem(&tego_plane_pin_keys, &idx);
    if (!pins || !mk || mk->gen != run->gen)
        return TEGO_R_PIN_UNVERIFIABLE;
    if (bpf_get_ns_current_pid_tgid(hdr->pidns_dev, hdr->pidns_ino, &ns, sizeof(ns)))
        return TEGO_R_PIN_UNVERIFIABLE;
    key.tid = ns.pid;
    key.start = t->start_boottime / TEGO_PIN_TICK_NS;
    pin = bpf_map_lookup_elem(pins, &key);
    if (!pin || pin->gen != run->gen)
        return TEGO_R_PIN_MISSING;
    /* 3. The image the kernel opened, its final name and the spelling it was looked up by. A swapped symlink or
     *    descriptor ends here, with a clean errno. */
    inode = bprm->file->f_inode;
    if (pin->image.dev != inode->i_sb->s_dev || pin->image.ino != inode->i_ino)
        return TEGO_R_PIN_MISMATCH;
    dentry = bprm->file->f_path.dentry;
    if (tego_kmac(mk, TEGO_PIN_DOM_NAME, (__u64)dentry->d_name.name, dentry->d_name.len & 0xff) != pin->mac_name)
        return TEGO_R_PIN_MISMATCH;
    if (pin->len_path > TEGO_PIN_PATH_MAX)
        return TEGO_R_PIN_MISMATCH;
    if (tego_kmac(mk, TEGO_PIN_DOM_PATH, (__u64)bprm->filename, pin->len_path) != pin->mac_path)
        return TEGO_R_PIN_MISMATCH;
    /* The MAC says the first len_path bytes are the pinned ones, which hold no NUL; the next must end the string. */
    w = TEGO_RD_WORD((__u64)bprm->filename + pin->len_path);
    if (tego_word_mask(w, 1))
        return TEGO_R_PIN_MISMATCH;
    /* 4. A tracer attached before the exec gets its exec stop and could rewrite the new image's argv before main. */
    if ((pin->flags & TEGO_PIN_GUARD) && (t->ptrace & TEGO_PT_PTRACED))
        return TEGO_R_EXEC_TRACED;
    /* 5. Into the task's own storage: de_thread gives a non-leader the leader's tid and start time before
     *    sched_process_exec, while its task_struct, and so this storage, stays. The key cannot be used again. */
    __builtin_memcpy(&st->pin, pin, sizeof(st->pin));
    st->cur_seq = pin->seq;
    /* The vector's length as the kernel copied it, before any binfmt stage changes it: an interpreted unknown-form
     * exec's area is held to it (tego_pin_area). */
    st->argc0 = bprm->argc;
    st->armed = 1;
    bpf_map_delete_elem(pins, &key);
    return 0;
}

/* A later stage: an interpreter's, after a #! or binfmt_misc stage. Returns 0 or the refusal's reason. */
static __always_inline __u8 tego_pin_later(const struct tego_run *run, struct linux_binprm *bprm,
                                            struct task_struct *t)
{
    struct tego_exec_armed *st = tego_pin_state(run, t);
    struct inode *inode = bprm->file->f_inode;
    __u32 s;

    if (!st || !st->armed)
        return TEGO_R_PIN_MISSING;
    s = st->stage;
    if (s >= TEGO_PIN_CHAIN_MAX)
        return TEGO_R_PIN_MISMATCH;
    st->stage = s + 1;
    if (st->pin.form == TEGO_PIN_FORM_UNKNOWN) {
        if (!(st->pin.flags & TEGO_PIN_INTERP_OK))
            return TEGO_R_PIN_MISMATCH;
        /* The first stage's handler ran just now. binfmt_misc's P flag kept argv[0] in front of the tail the area check
         * holds, which starts with the filename: only a decided argv[0] that is the filename is then held. */
        if (s == 0 && (bprm->interp_flags & TEGO_BINPRM_PRESERVE_ARGV0) && !(st->pin.flags & TEGO_PIN_ARGV0_FILENAME))
            return TEGO_R_PIN_MISMATCH;
        return 0;
    }
    /* A direct pin admits no later stage: binfmt_misc took an image the supervisor read as direct (R6c). */
    if (st->pin.form != TEGO_PIN_FORM_SCRIPT || s >= st->pin.nchain)
        return TEGO_R_PIN_MISMATCH;
    barrier_var(s);
    if (s >= TEGO_PIN_CHAIN_MAX)
        return TEGO_R_PIN_MISMATCH;
    if (st->pin.chain[s].dev != inode->i_sb->s_dev || st->pin.chain[s].ino != inode->i_ino)
        return TEGO_R_PIN_MISMATCH;
    return 0;
}

/* bprm_check's pin step, in a slot with TEGO_SLOT_EXEC_PIN, before the EXEC_DECIDES return and the #! pass. A refusal
 * disarms the task's state; the exec then never reaches sched_process_exec. */
static __always_inline __u8 tego_pin_bprm(const struct tego_run *run, const struct tego_plane_slot *hdr,
                                           struct linux_binprm *bprm)
{
    struct task_struct *t = bpf_get_current_task_btf();
    struct tego_exec_armed *st;
    __u8 reason;

    if (bprm->interp == bprm->filename)
        reason = tego_pin_first(run, hdr, bprm, t);
    else
        reason = tego_pin_later(run, bprm, t);
    if (reason) {
        st = tego_pin_state(run, t);
        if (st)
            st->armed = 0;
    }
    return reason;
}

/* ---- sched_process_exec: the argument area ---- */

/* The area MAC's state. Only s changes across iterations, and the callback branches on neither it nor i but for the
 * bound. */
struct tego_umac {
    struct tego_sip s;
    __u64 base;
    __s32 err;
    __u32 pad;
};

/* Absorbs full chunk i: one bpf_probe_read_user of TEGO_PIN_STEP bytes into the task's own storage, then its words. */
static long tego_umac_step(__u32 i, struct tego_umac *c)
{
    struct tego_exec_armed *st;
    long r;
    int j;

    if (i >= TEGO_PIN_MAX_LEN / TEGO_PIN_STEP)
        return 1;
    st = bpf_task_storage_get(&tego_plane_exec_armed, bpf_get_current_task_btf(), 0, 0);
    if (!st) {
        c->err = -TEGO_PIN_ENOMEM;
        return 1;
    }
    r = bpf_probe_read_user(st->buf, TEGO_PIN_STEP, (void *)(c->base + (__u64)i * TEGO_PIN_STEP));
    if (r) {
        c->err = (__s32)r;
        return 1;
    }
#pragma unroll
    for (j = 0; j < TEGO_PIN_STEP / 8; j++)
        tego_sip_word(&c->s, tego_sip_le64(&st->buf[j * 8]));
    return 0;
}

/* Absorbs whole word i of the last, partial chunk, which the caller read into the task's storage. A loop rather than
 * an unrolled chain: each unrolled word was a path the verifier walked the rest of the program along. */
static long tego_uword_step(__u32 i, struct tego_umac *c)
{
    struct tego_exec_armed *st;
    __u32 at = i * 8;

    if (i >= TEGO_PIN_STEP / 8)
        return 1;
    st = bpf_task_storage_get(&tego_plane_exec_armed, bpf_get_current_task_btf(), 0, 0);
    if (!st) {
        c->err = -TEGO_PIN_ENOMEM;
        return 1;
    }
    barrier_var(at);
    at &= TEGO_PIN_STEP - 8;
    tego_sip_word(&c->s, tego_sip_le64(&st->buf[at]));
    return 0;
}

/* The MAC in domain dom of len user bytes at base (len at most TEGO_PIN_MAX_LEN); *err is the read's error. */
static __always_inline __u64 tego_umac(struct tego_exec_armed *st, const struct tego_pin_keyval *key, __u8 dom,
                                        __u64 base, __u32 len, __s32 *err)
{
    struct tego_umac c = {};
    __u32 full = len / TEGO_PIN_STEP, rem = len % TEGO_PIN_STEP, at;
    long r;

    c.base = base;
    tego_sip_begin(&c.s, key->k0, key->k1, dom, len);
    if (full)
        bpf_loop(full, tego_umac_step, &c, 0);
    if (c.err) {
        *err = c.err;
        return 0;
    }
    rem &= TEGO_PIN_STEP - 1;
    if (rem) {
        r = bpf_probe_read_user(st->buf, rem, (void *)(base + (__u64)full * TEGO_PIN_STEP));
        if (r) {
            *err = (__s32)r;
            return 0;
        }
    }
    if (rem >= 8)
        bpf_loop(rem / 8, tego_uword_step, &c, 0);
    if (c.err) {
        *err = c.err;
        return 0;
    }
    at = (rem / 8) * 8;
    barrier_var(at);
    at &= TEGO_PIN_STEP - 8;
    return tego_sip_end(&c.s, tego_sip_le64(&st->buf[at]), rem & 7);
}

/* One byte of user memory, or -1. */
static __always_inline int tego_user_byte(__u64 addr)
{
    __u8 b = 0;

    if (bpf_probe_read_user(&b, 1, (void *)addr))
        return -1;
    return b;
}

/* Checks the mapped area of current (the exec's task, whose mm is the new image's) against the armed pin (ADR 0048
 * (3), "tp_btf/sched_process_exec"): 0 when it holds, else the kill's reason. argc_interp is bprm->argc << 1 | whether
 * binfmt replaced bprm->interp. Global: verified once, not once per path of the program that reaches it (each MAC's
 * loops and its many refusals made the static form 22,600 instructions on Fedora's 7.0). */
__attribute__((noinline)) int tego_pin_area(struct tego_exec_armed *st, const struct tego_pin_keyval *key,
                                             __u64 argc_interp)
{
    struct task_struct *t = bpf_get_current_task_btf();
    __u64 arg_start, arg_end, span, mac, base, want;
    __u32 len, argc = (__u32)(argc_interp >> 1);
    __u8 interpreted = argc_interp & 1, dom = TEGO_PIN_DOM_COVERED;
    __s32 err = 0;

    if (!st || !key)
        return TEGO_R_PIN_UNVERIFIABLE;
    arg_start = t->mm->arg_start;
    arg_end = t->mm->arg_end;
    len = st->pin.len_cov;
    span = arg_end > arg_start ? arg_end - arg_start : 0;
    base = arg_start;
    want = st->pin.mac_cov;
    if (st->pin.form == TEGO_PIN_FORM_UNKNOWN && interpreted) {
        /* Admitted by TEGO_PIN_INTERP_OK at its stage: the filename, then argv[1:], is the last len_tail bytes,
         * after a NUL. Only with the vector's length the first stage counted does that tail say argv[1:]: the decided
         * tail's NULs are argc of them, so no suffix of more strings, and none of fewer after a NUL, can MAC to it. */
        if (st->argc0 != st->pin.argc)
            return TEGO_R_ARGV_CHANGED;
        len = st->pin.len_tail;
        if (len > TEGO_PIN_MAX_LEN)
            return TEGO_R_ARGV_UNREADABLE;
        if (len >= span)
            return TEGO_R_ARGV_CHANGED;
        if (tego_user_byte(arg_end - len - 1) != 0)
            return TEGO_R_ARGV_CHANGED;
        base = arg_end - len;
        dom = TEGO_PIN_DOM_TAIL;
        want = st->pin.mac_tail;
    } else if (st->pin.form == TEGO_PIN_FORM_SCRIPT) {
        /* Each stage's interpreter was held at its bprm_check; the MAC covers binfmt_script's whole vector. */
        if (!interpreted || span != len)
            return TEGO_R_ARGV_CHANGED;
        dom = TEGO_PIN_DOM_SCRIPT;
    } else {
        /* Direct, or unknown and not interpreted: the covered prefix, the first k strings. An ELF the supervisor read
         * that the kernel then interpreted means the file changed under the decision, or binfmt_misc took it. */
        if (interpreted || (st->pin.form != TEGO_PIN_FORM_DIRECT && st->pin.form != TEGO_PIN_FORM_UNKNOWN))
            return TEGO_R_ARGV_CHANGED;
        if (len == 0 || len > span)
            return TEGO_R_ARGV_CHANGED;
        if (st->pin.k == st->pin.argc && (span != len || argc != st->pin.argc))
            return TEGO_R_ARGV_CHANGED;
        if (tego_user_byte(arg_start + len - 1) != 0)
            return TEGO_R_ARGV_CHANGED;
    }
    if (len > TEGO_PIN_MAX_LEN)
        return TEGO_R_ARGV_UNREADABLE;
    /* One MAC site: the loops are verified once, whichever area the form names. */
    mac = tego_umac(st, key, dom, base, len, &err);
    if (err)
        return TEGO_R_ARGV_UNREADABLE;
    return mac == want ? 0 : TEGO_R_ARGV_CHANGED;
}

/* The kill and its sample: SIGKILL is pending before the return to user mode, so the new image runs no instruction.
 * A failed send is the sample's kill_err, on which the supervisor kills through the task's pidfd (R6d). The task is
 * current; what names the kill is seq | reason << 32 | form << 40 | interpreted << 48. Global, as tego_pin_area. */
__attribute__((noinline)) int tego_pin_kill(const struct tego_run *run, __u64 old_tid, __u64 what)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct tego_ev_exec_kill *e;
    __u64 arg_start, arg_end, span;
    long sent = bpf_send_signal(TEGO_SIGKILL);
    void *ring;
    __u32 len;

    if (!run)
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
    __builtin_memset(e, 0, sizeof(*e));
    tego_hdr_fill(&e->hdr, TEGO_EV_PLANE_EXEC_KILL, sizeof(*e), run, bpf_get_current_cgroup_id());
    e->hdr.ppid = p->real_parent->tgid;
    e->hdr.verdict = TEGO_V_REFUSED;
    e->hdr.reason = (__u8)(what >> 32);
    e->hdr.rule_idx = (__u16)TEGO_PLANE_RULE_NONE;
    e->exec_start_ns = p->start_boottime;
    e->old_tid = (__u32)old_tid;
    e->seq = (__u32)what;
    e->kill_err = (__s32)sent;
    e->form = (__u8)(what >> 40);
    e->interpreted = (__u8)(what >> 48);
    arg_start = p->mm->arg_start;
    arg_end = p->mm->arg_end;
    span = arg_end > arg_start ? arg_end - arg_start : 0;
    if (span > TEGO_ARGV_MAX) {
        span = TEGO_ARGV_MAX;
        e->argv_truncated = 1;
    }
    len = (__u32)span;
    if (len > 0 && len <= TEGO_ARGV_MAX) {
        if (bpf_probe_read_user(&e->argv, len, (void *)arg_start) == 0)
            e->argv_len = len;
        else
            e->argv_truncated = 1;
    }
    bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
    return 0;
}

/* The held sample: the proof the ledger's fold reads before it says kernel_pinned (ADR 0048 (8)). A ring with no room
 * counts a lost sample, so the exec's line says unproven, never kernel_pinned. Global, as tego_pin_kill. */
__attribute__((noinline)) int tego_pin_held(const struct tego_run *run, __u64 old_tid, __u64 seq)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct tego_ev_exec_held *e;
    void *ring;

    if (!run)
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
    __builtin_memset(e, 0, sizeof(*e));
    tego_hdr_fill(&e->hdr, TEGO_EV_PLANE_EXEC_HELD, sizeof(*e), run, bpf_get_current_cgroup_id());
    e->hdr.ppid = p->real_parent->tgid;
    e->hdr.verdict = TEGO_V_ALLOW;
    e->hdr.rule_idx = (__u16)TEGO_PLANE_RULE_NONE;
    e->exec_start_ns = p->start_boottime;
    e->old_tid = (__u32)old_tid;
    e->seq = (__u32)seq;
    bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP); /* the exec's line waits for it, as for the exec record */
    return 0;
}

/* The pin program's body, once per mode: a run another mode decides is that mode's program's. */
static __always_inline void tego_exec_pin_check(int mode, struct task_struct *p, pid_t old_pid,
                                                 struct linux_binprm *bprm)
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_pin_keyval *mk;
    struct tego_exec_armed *st;
    __u32 idx, seq = 0;
    __u8 reason = 0, interpreted, form = 0;

    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return;
    interpreted = bprm->interp != bprm->filename;
    hdr = tego_plane_slot_of(run);
    if (hdr && !(hdr->flags & TEGO_SLOT_EXEC_PIN))
        return;
    /* Every sample names the seq the recorder's exec record of this exec reads as its pin_seq (tego_exec_pin_seq):
     * the task's cur_seq, which only this exec's first bprm_check stage writes, 0 when the task holds no state of the
     * run. The ledger's fold pairs the two by it alone, so a kill that named 0 for a cleared slot or an unarmed pin
     * would take whatever earlier exec of the process still waits (REXEC-PINSc2-1). */
    st = tego_pin_state(run, bpf_get_current_task_btf());
    if (st)
        seq = st->cur_seq;
    if (!hdr) {
        /* bprm_check refused every exec of a slot with no header of the run's gen; one cleared since is not held. */
        reason = TEGO_R_PIN_UNVERIFIABLE;
    } else if (!st || !st->armed) {
        reason = TEGO_R_PIN_MISSING;
    } else {
        st->armed = 0;
        form = st->pin.form;
        idx = run->run_idx;
        mk = bpf_map_lookup_elem(&tego_plane_pin_keys, &idx);
        if (!mk || mk->gen != run->gen)
            reason = TEGO_R_PIN_UNVERIFIABLE;
        else
            reason = (__u8)tego_pin_area(st, mk, (__u64)bprm->argc << 1 | interpreted);
    }
    if (reason) {
        /* A dying task stays guarded: nothing of the run writes into it while the kill lands. */
        if (st) {
            st->armed = 0; /* a cleared slot's armed pin does not outlive the check either */
            st->guarded = 1;
            st->outcome = TEGO_PIN_OUT_KILLED;
        }
        tego_pin_kill(run, (__u32)old_pid,
                       (__u64)seq | (__u64)reason << 32 | (__u64)form << 40 | (__u64)interpreted << 48);
        return;
    }
    /* Every exec rewrites the mark. */
    st->guarded = (st->pin.flags & TEGO_PIN_GUARD) != 0;
    st->outcome = TEGO_PIN_OUT_HELD;
    tego_pin_held(run, (__u32)old_pid, st->pin.seq);
}
