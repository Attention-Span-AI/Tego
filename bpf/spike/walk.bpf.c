// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* SPIKE (docs/p0/TIER3-PLAN.md ticket T0). NOT BUILT INTO TEGO: no go:generate line names this file, no
 * tego binary embeds it, and nothing under internal/ or cmd/ imports tools/spike/walk (its loader). It exists to measure the
 * form of the plane's bounded (mount, dentry) walk on real kernels; the results are ADR 0024's and ADR 0025's
 * 2026-09-28 notes. tools/spike/walk/build.sh builds it and main.go runs it.
 *
 * One source, compiled eight times (build.sh):
 *   -DWALK_GLOBAL=1 -DREAD_RDONLY=1   form a-rd: a global subprogram taking u64 addresses, reading through
 *                                     bpf_rdonly_cast (6.2+)
 *   -DWALK_GLOBAL=1 -DREAD_RDONLY=0   form a-pr: the same, reading through CO-RE bpf_probe_read_kernel
 *   -DWALK_GLOBAL=0 -DREAD_RDONLY=1   form b-rd: __always_inline in each hook, bpf_rdonly_cast reads
 *   -DWALK_GLOBAL=0 -DREAD_RDONLY=0   form b-pr: __always_inline in each hook, CO-RE probe reads
 *   -DWALK_LOOP=1 -DWALK_GLOBAL=0     forms c-rd, c-pr: the step is a bpf_loop callback (5.17+), the walk
 *                                     around it __always_inline
 *   -DWALK_LOOP=1 -DWALK_GLOBAL=1     forms d-rd, d-pr: the same bpf_loop step, the walk around it global
 * Each object carries four programs: lsm/file_open, fmod_ret/security_file_open, lsm/path_rename and
 * fmod_ret/security_path_rename (the rename ones walk both ends, so call the walk twice), plus the test-only
 * fill (fentry) and clear (syscall) programs.
 *
 * The walk: from the resolved dentry through d_parent, crossing to mnt_mountpoint/mnt_parent at a mount root,
 * bounded to 64 steps (a crossing is one), one lookup per step in the run's inner rows map (HASH_OF_MAPS by
 * run_idx, inner keyed by struct inode *). A row whose gen is not the run's is stale and counts as absent (the
 * ADR 0025 amendment under test). A hit checks i_ino, i_generation and s_dev. Disconnected or exhausted refuses. */
#include "vmlinux.h"
#include "libbpf/bpf_helpers.h"
#include "libbpf/bpf_core_read.h"
#include "libbpf/bpf_tracing.h"

#ifndef WALK_GLOBAL
#error "build.sh sets WALK_GLOBAL"
#endif
#ifndef READ_RDONLY
#error "build.sh sets READ_RDONLY"
#endif

#define EACCES 13
#define WALK_MAX 64
#define ROWS_MAX 4096
#define SLOTS 4096

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct run {
    __u32 run_idx;
    __u32 gen;
};

struct row {
    __u32 kind; /* 1 deny, 2 allow */
    __u32 rule_idx;
    __u64 i_ino;
    __u32 i_generation;
    __u32 s_dev;
    __u32 gen;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct run);
} run_set SEC(".maps");

struct rows_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, ROWS_MAX);
    __type(key, __u64);
    __type(value, struct row);
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, SLOTS);
    __type(key, __u32);
    __array(values, struct rows_inner);
} rows SEC(".maps");

/* Outcome counters, summed over CPUs by the loader: which way each walk ended, and the steps it took. */
enum { ST_CALLS, ST_ROOT, ST_BOUND, ST_DISCONNECTED, ST_HIT, ST_MISMATCH, ST_STEPS, ST_NOROWS, ST_STALE, ST_N };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ST_N);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* The global forms take scalars, so each hook launders its trusted pointers through this per-CPU slot (root
 * may store a pointer into a map value, and a load from one is a scalar); no probe read in the caller. */
struct laundry {
    __u64 d;
    __u64 m;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct laundry);
} launder SEC(".maps");

/* Test-only: who fill keys a deny row for, and at which slot. */
struct fill_cfg {
    __u32 tgid;
    __u32 run_idx;
    __u32 gen;
    __u32 kind;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fill_cfg);
} fill SEC(".maps");

static __always_inline void st(__u32 i, __u64 n)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &i);
    if (v)
        *v += n;
}

#if READ_RDONLY
/* bpf_rdonly_cast: an untrusted BTF pointer whose loads the verifier turns into exception-handled loads. */
#define D_INODE(d) ((__u64)bpf_core_cast((void *)(d), struct dentry)->d_inode)
#define D_PARENT(d) ((__u64)bpf_core_cast((void *)(d), struct dentry)->d_parent)
#define M_PARENT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt_parent)
#define M_MOUNTPOINT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt_mountpoint)
#define M_ROOT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt.mnt_root)
#define VM_ROOT(vm) ((__u64)bpf_core_cast((void *)(vm), struct vfsmount)->mnt_root)
#define I_INO(i) ((__u64)bpf_core_cast((void *)(i), struct inode)->i_ino)
#define I_GEN(i) ((__u32)bpf_core_cast((void *)(i), struct inode)->i_generation)
#define I_SDEV(i) ((__u32)bpf_core_cast((void *)(i), struct inode)->i_sb->s_dev)
#else
/* CO-RE probe reads: bpf_probe_read_kernel at a relocated offset. */
static __always_inline __u64 rd64(__u64 a)
{
    __u64 v = 0;
    bpf_probe_read_kernel(&v, sizeof(v), (void *)a);
    return v;
}
static __always_inline __u32 rd32(__u64 a)
{
    __u32 v = 0;
    bpf_probe_read_kernel(&v, sizeof(v), (void *)a);
    return v;
}
#define D_INODE(d) rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_inode))
#define D_PARENT(d) rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_parent))
#define M_PARENT(m) rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt_parent))
#define M_MOUNTPOINT(m) rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt_mountpoint))
#define M_ROOT(m) rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt) + bpf_core_field_offset(struct vfsmount, mnt_root))
#define VM_ROOT(vm) rd64((__u64)(vm) + bpf_core_field_offset(struct vfsmount, mnt_root))
#define I_INO(i) rd64((__u64)(i) + bpf_core_field_offset(struct inode, i_ino))
#define I_GEN(i) rd32((__u64)(i) + bpf_core_field_offset(struct inode, i_generation))
#define I_SDEV(i) rd32(rd64((__u64)(i) + bpf_core_field_offset(struct inode, i_sb)) + bpf_core_field_offset(struct super_block, s_dev))
#endif

#ifndef WALK_LOOP
#define WALK_LOOP 0
#endif
#if WALK_GLOBAL
#define WALK_ATTR __attribute__((noinline))
#else
#define WALK_ATTR static __always_inline
#endif

#if WALK_LOOP
/* Form c: the step is a bpf_loop callback (5.17+), so the verifier checks one step, not 64 of them. */
struct wstate {
    void *inner;
    __u64 d;
    __u64 m;
    __u64 mroot;
    __u32 gen;
    __s32 ret; /* 1 while walking, then 0 or -EACCES */
};

static long walk_step(__u32 i, struct wstate *s)
{
    __u64 d = s->d;
    __u64 inode = D_INODE(d);
    if (inode) {
        __u64 key = inode;
        struct row *r = bpf_map_lookup_elem(s->inner, &key);
        if (r) {
            if (r->gen == s->gen) {
                st(ST_STEPS, i + 1);
                if (r->i_ino != I_INO(inode) || r->i_generation != I_GEN(inode) || r->s_dev != I_SDEV(inode)) {
                    st(ST_MISMATCH, 1);
                    s->ret = -EACCES;
                    return 1;
                }
                st(ST_HIT, 1);
                s->ret = r->kind == 1 ? -EACCES : 0;
                return 1;
            }
            st(ST_STALE, 1);
        }
    }
    if (d == s->mroot) {
        __u64 m = s->m;
        __u64 pm = M_PARENT(m);
        if (pm == m || !pm) {
            st(ST_STEPS, i + 1);
            st(ST_ROOT, 1);
            s->ret = 0;
            return 1;
        }
        s->d = M_MOUNTPOINT(m);
        s->m = pm;
        s->mroot = M_ROOT(pm);
        return 0;
    }
    __u64 p = D_PARENT(d);
    if (!p || p == d) {
        st(ST_DISCONNECTED, 1);
        s->ret = -EACCES;
        return 1;
    }
    s->d = p;
    return 0;
}

WALK_ATTR int walk(__u64 d, __u64 vm, __u32 run_idx, __u32 gen)
{
    __u32 idx = run_idx;
    struct wstate s = {};
    s.inner = bpf_map_lookup_elem(&rows, &idx);
    if (!s.inner) {
        st(ST_NOROWS, 1);
        return -EACCES;
    }
    st(ST_CALLS, 1);
    s.d = d;
    s.m = vm - bpf_core_field_offset(struct mount, mnt);
    s.mroot = VM_ROOT(vm);
    s.gen = gen;
    s.ret = 1;
    bpf_loop(WALK_MAX, walk_step, &s, 0);
    if (s.ret == 1) {
        st(ST_BOUND, 1);
        return -EACCES;
    }
    return s.ret ? -EACCES : 0;
}
#else

/* walk returns 0 (no row, or an allow row) or -EACCES (a deny row, an identity mismatch, a disconnected dentry,
 * the bound exhausted, a live run without a rows map). d and vm are a struct dentry * and its struct vfsmount *. */
WALK_ATTR int walk(__u64 d, __u64 vm, __u32 run_idx, __u32 gen)
{
    __u32 idx = run_idx;
    void *inner = bpf_map_lookup_elem(&rows, &idx);
    if (!inner) {
        st(ST_NOROWS, 1);
        return -EACCES;
    }
    __u64 m = vm - bpf_core_field_offset(struct mount, mnt);
    __u64 mroot = VM_ROOT(vm);
    int i;

    st(ST_CALLS, 1);
#pragma clang loop unroll(disable)
    for (i = 0; i < WALK_MAX; i++) {
        __u64 inode = D_INODE(d);
        if (inode) {
            __u64 key = inode;
            struct row *r = bpf_map_lookup_elem(inner, &key);
            if (r) {
                if (r->gen == gen) {
                    st(ST_STEPS, i + 1);
                    if (r->i_ino != I_INO(inode) || r->i_generation != I_GEN(inode) || r->s_dev != I_SDEV(inode)) {
                        st(ST_MISMATCH, 1);
                        return -EACCES;
                    }
                    st(ST_HIT, 1);
                    return r->kind == 1 ? -EACCES : 0;
                }
                st(ST_STALE, 1);
            }
        }
        if (d == mroot) {
            __u64 pm = M_PARENT(m);
            if (pm == m || !pm) {
                st(ST_STEPS, i + 1);
                st(ST_ROOT, 1);
                return 0;
            }
            d = M_MOUNTPOINT(m);
            m = pm;
            mroot = M_ROOT(pm);
            continue;
        }
        __u64 p = D_PARENT(d);
        if (!p || p == d) {
            st(ST_DISCONNECTED, 1);
            return -EACCES;
        }
        d = p;
    }
    st(ST_BOUND, 1);
    return -EACCES;
}
#endif

#if WALK_GLOBAL
/* Hands a trusted pointer to the global walk as a scalar. */
#define LAUNDER(lv, dp, mp)                                                                                            \
    struct laundry *lv = bpf_map_lookup_elem(&launder, &zero);                                                        \
    if (!lv)                                                                                                           \
        return 0;                                                                                                      \
    lv->d = (__u64)(dp);                                                                                               \
    lv->m = (__u64)(mp);
#define ARG_D(lv) (*(volatile __u64 *)&(lv)->d)
#define ARG_M(lv) (*(volatile __u64 *)&(lv)->m)
#else
#define LAUNDER(lv, dp, mp)                                                                                            \
    __u64 lv##_d = (__u64)(dp), lv##_m = (__u64)(mp);
#define ARG_D(lv) lv##_d
#define ARG_M(lv) lv##_m
#endif

static __always_inline int decide_file_open(struct file *file)
{
    __u64 cg = bpf_get_current_cgroup_id();
    struct run *run = bpf_map_lookup_elem(&run_set, &cg);
    __u32 zero __attribute__((unused)) = 0;
    if (!run)
        return 0;
    LAUNDER(a, file->f_path.dentry, file->f_path.mnt);
    /* 0 or -EACCES only: an LSM program's return is range-checked, and a global walk's int is unknown. */
    return walk(ARG_D(a), ARG_M(a), run->run_idx, run->gen) ? -EACCES : 0;
}

static __always_inline int decide_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                                              const struct path *new_dir, struct dentry *new_dentry)
{
    __u64 cg = bpf_get_current_cgroup_id();
    struct run *run = bpf_map_lookup_elem(&run_set, &cg);
    __u32 zero __attribute__((unused)) = 0;
    int ret;
    if (!run)
        return 0;
    LAUNDER(a, old_dentry, old_dir->mnt);
    ret = walk(ARG_D(a), ARG_M(a), run->run_idx, run->gen);
    if (ret)
        return -EACCES;
    LAUNDER(b, new_dentry, new_dir->mnt);
    return walk(ARG_D(b), ARG_M(b), run->run_idx, run->gen) ? -EACCES : 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    return decide_file_open(file);
}

SEC("fmod_ret/security_file_open")
int BPF_PROG(fmr_file_open, struct file *file)
{
    return decide_file_open(file);
}

SEC("lsm/path_rename")
int BPF_PROG(lsm_path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    return decide_path_rename(old_dir, old_dentry, new_dir, new_dentry);
}

SEC("fmod_ret/security_path_rename")
int BPF_PROG(fmr_path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    return decide_path_rename(old_dir, old_dentry, new_dir, new_dentry);
}

/* Test-only fill: the next file the configured tgid opens gets a row at its inode (ADR 0025 fills in the kernel
 * from held O_PATH descriptors instead; this stands in for it so the walk can be seen to hit). */
SEC("fentry/security_file_open")
int BPF_PROG(fill_row, struct file *file)
{
    __u32 zero __attribute__((unused)) = 0;
    struct fill_cfg *c = bpf_map_lookup_elem(&fill, &zero);
    if (!c || c->tgid == 0 || c->tgid != (__u32)(bpf_get_current_pid_tgid() >> 32))
        return 0;
    __u32 idx = c->run_idx;
    void *inner = bpf_map_lookup_elem(&rows, &idx);
    if (!inner)
        return 0;
    struct inode *in = file->f_inode;
    __u64 key = (__u64)in;
    struct row r = {};
    r.kind = c->kind;
    r.rule_idx = 7;
    r.i_ino = in->i_ino;
    r.i_generation = in->i_generation;
    r.s_dev = in->i_sb->s_dev;
    r.gen = c->gen;
    bpf_map_update_elem(inner, &key, &r, BPF_ANY);
    c->tgid = 0;
    return 0;
}

/* Test-only clear: deletes every row of one slot's inner map in the kernel, so userspace never reads a key.
 * Run by BPF_PROG_TEST_RUN with the slot in ctx. */
struct clear_ctx {
    __u32 run_idx;
    __u32 deleted;
};

static long clear_one(void *map, __u64 *key, struct row *val, void *ctx)
{
    struct clear_ctx *c = ctx;
    if (bpf_map_delete_elem(map, key) == 0)
        c->deleted++;
    return 0;
}

SEC("syscall")
int clear_rows(struct clear_ctx *ctx)
{
    __u32 idx = ctx->run_idx;
    struct clear_ctx c = {.run_idx = idx};
    void *inner = bpf_map_lookup_elem(&rows, &idx);
    if (!inner)
        return 1;
    bpf_for_each_map_elem(inner, clear_one, &c, 0);
    ctx->deleted = c.deleted;
    return 0;
}
