// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* The kernel decision plane (ADRs 0024, 0025; docs/p0/TIER3-PLAN.md §2, §3). Tier bpflsm decides a governed run's
 * opens, execs and fs mutations here, on the object the kernel resolved, and tier cgroup does the same through the
 * same bodies where bpf is not an active LSM.
 *
 * One object, each hook body written once. TEGO_PLANE_HOOK emits it twice: SEC("lsm/<hook>") (BPF_LSM_MAC, LSM
 * mode) and SEC("fmod_ret/security_<hook>") (BPF_MODIFY_RETURN, fmod_ret mode). The loader loads one mode's
 * programs and never both (ADR 0024 (2)). Every program returns 0 or -EACCES and nothing else (ADR 0024 (7)): the
 * wrapper maps whatever its body returns onto those two, which an LSM program's return range needs anyway (a
 * global function's int returned unchanged is refused, T0).
 *
 * Two builds of this file (internal/bpf/gen.go), chosen at load by the plane probe from the kernel's BTF, differ
 * only in how the walk reads a dentry, a mount and an inode: TEGO_PLANE_RDONLY=1 through bpf_rdonly_cast (in BTF
 * on 6.2+ and RHEL 9.8; the only reader under lockdown=confidentiality) and TEGO_PLANE_RDONLY=0 through CO-RE
 * bpf_probe_read_kernel (AL2023 6.1). A kernel without the kfunc refuses the rd build outright, so the choice is
 * the probe's, never a fallback inside one object (ADR 0024's T0 note).
 *
 * T2 put the maps, the macro and the walk here; T3 wrote Step A's bodies (file_open, bprm_check, path_rename,
 * path_link, path_unlink, path_rmdir: docs/p0/enforce-plane.md R7-R11). The rows they read are filled by T4 and
 * compiled by T5. T15 wrote step D's (socket_connect,
 * socket_sendmsg: unix names below 6.7, R14), which a backend loads only where cgroup/connect_unix is absent.
 * T13 wrote Step B's bodies in decide_stepb.h (R12-R14):
 * path_mknod, path_mkdir, path_symlink, path_truncate, file_truncate, path_chmod, path_chown, the xattr and ACL
 * hooks and socket_create.
 * T14 wrote step C's (mmap_file, file_mprotect: ADR 0027's PROT_EXEC mappings, R26) in decide_stepc.h, included
 * last.
 */
#define TEGO_PLANE_MAPS
#include "maps.h"

#ifndef TEGO_PLANE_RDONLY
#error "internal/bpf/gen.go builds this file with -DTEGO_PLANE_RDONLY=1 (rd) and =0 (pr)"
#endif

char _license[] SEC("license") = "Dual BSD/GPL";

/* BTF anchors for bpf2go's -type mirrors (cgroup_track.bpf.c says why a struct needs one). */
const struct tego_plane_row *tego_btf_plane_row;
const struct tego_plane_exec_row *tego_btf_plane_exec_row;
const struct tego_plane_decision *tego_btf_plane_decision;
const struct tego_plane_counts *tego_btf_plane_counts;
const struct tego_ev_plane *tego_btf_ev_plane;
const struct tego_plane_unix *tego_btf_plane_unix;
const struct tego_plane_slot *tego_btf_plane_slot;
const struct tego_plane_listen_key *tego_btf_plane_listen_key;
const struct tego_plane_listen_row *tego_btf_plane_listen_row;
const struct tego_plane_bind *tego_btf_plane_bind;
const struct tego_plane_name_row *tego_btf_plane_name_row;
const struct tego_plane_name_cfg *tego_btf_plane_name_cfg;
const struct tego_pin_keyval *tego_btf_pin_keyval;
const struct tego_exec_armed *tego_btf_exec_armed;
const struct tego_ev_exec_kill *tego_btf_ev_exec_kill;
const struct tego_ev_exec_held *tego_btf_ev_exec_held;

/* The mode a program body runs in: a constant per program once the body is inlined, so a mode-only branch (the
 * security_ wrapper's own early exits, which fmod_ret mode must reproduce, ADR 0024 (8)) costs the other mode
 * nothing. */
#define TEGO_PLANE_LSM 0
#define TEGO_PLANE_FMOD_RET 1

/* The tego_run.plane value of the run a program of mode decides (enum tego_run_plane): a run prepared in the other
 * mode, or for the fanotify fallback, is not this program's to decide. */
#define TEGO_PLANE_RUN_MODE(mode) ((mode) == TEGO_PLANE_LSM ? TEGO_RUN_PLANE_LSM : TEGO_RUN_PLANE_FMOD_RET)

/* The only two values a plane program returns. */
static __always_inline int tego_plane_verdict(int decision)
{
    return decision == 0 ? 0 : -EACCES;
}

#define TEGO_UNPAREN(...) __VA_ARGS__

/* TEGO_PLANE_HOOK(name, lsm_hook, security_fn, (params), (args)) { body } defines the body once, as
 * tego_decide_<name>(mode, params), and the two programs tego_lsm_<name> (SEC lsm/<lsm_hook>) and
 * tego_fmr_<name> (SEC fmod_ret/<security_fn>) that call it with the hook's arguments. The hook name and the
 * security_ function differ for some hooks (bprm_check_security is called by security_bprm_check), so both are
 * given. params is the hook's 6.1 prototype, or a prefix of it: a program reads no argument past it (bpf/README.md).
 * Neither program reads the chain's return so far (the trailing ret argument). */
#define TEGO_PLANE_HOOK(name, lsm_hook, security_fn, params, args)                                                 \
    static __always_inline int tego_decide_##name(int mode, TEGO_UNPAREN params);                                   \
    SEC("lsm/" #lsm_hook)                                                                                          \
    int BPF_PROG(tego_lsm_##name, TEGO_UNPAREN params)                                                           \
    {                                                                                                              \
        return tego_plane_verdict(tego_decide_##name(TEGO_PLANE_LSM, TEGO_UNPAREN args));                      \
    }                                                                                                              \
    SEC("fmod_ret/" #security_fn)                                                                                  \
    int BPF_PROG(tego_fmr_##name, TEGO_UNPAREN params)                                                           \
    {                                                                                                              \
        return tego_plane_verdict(tego_decide_##name(TEGO_PLANE_FMOD_RET, TEGO_UNPAREN args));                 \
    }                                                                                                              \
    static __always_inline int tego_decide_##name(int mode, TEGO_UNPAREN params)

/* Bumps one of the slot's fail-closed counters (struct tego_plane_counts), atomically: every CPU shares a slot. */
#define TEGO_PLANE_COUNT(run_idx, field)                                                                          \
    do {                                                                                                           \
        __u32 tego_cidx_ = (run_idx);                                                                             \
        struct tego_plane_counts *tego_c_ = bpf_map_lookup_elem(&tego_plane_counters, &tego_cidx_);            \
        if (tego_c_)                                                                                              \
            __sync_fetch_and_add(&tego_c_->field, 1);                                                             \
    } while (0)

/* ---- The walk (TEGO_PLANE_WALK: bpf/tests TestPlaneWalkHasNoStringOps reads from here to its end marker) ----
 *
 * Form d of ADR 0024's T0 note: one global subprogram, verified once per program, whose body is bpf_loop(64, step)
 * over a stack state. It takes the hook's pointers as scalars (a global function cannot take a trusted BTF pointer
 * before 6.8's __arg_trusted), laundered through the task's tego_plane_scratch value, and reads through the
 * build's reader. Nearest row wins (SEMANTICS §2): from the resolved dentry through d_parent, crossing to
 * mnt_mountpoint/mnt_parent at a mount root, one lookup per step in the slot's rows map. No string is read and
 * no bpf_d_path is called (unavailable to path_* hooks below 6.8). */
#if TEGO_PLANE_RDONLY
#define TEGO_D_INODE(d) ((__u64)bpf_core_cast((void *)(d), struct dentry)->d_inode)
#define TEGO_D_PARENT(d) ((__u64)bpf_core_cast((void *)(d), struct dentry)->d_parent)
#define TEGO_M_PARENT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt_parent)
#define TEGO_M_MOUNTPOINT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt_mountpoint)
#define TEGO_M_ROOT(m) ((__u64)bpf_core_cast((void *)(m), struct mount)->mnt.mnt_root)
#define TEGO_VM_ROOT(vm) ((__u64)bpf_core_cast((void *)(vm), struct vfsmount)->mnt_root)
#define TEGO_I_INO(i) ((__u64)bpf_core_cast((void *)(i), struct inode)->i_ino)
#define TEGO_I_GEN(i) ((__u32)bpf_core_cast((void *)(i), struct inode)->i_generation)
#define TEGO_I_SDEV(i) ((__u32)bpf_core_cast((void *)(i), struct inode)->i_sb->s_dev)
#define TEGO_D_SBROOT(d) ((__u64)bpf_core_cast((void *)(d), struct dentry)->d_sb->s_root)
#else
static __always_inline __u64 tego_rd64(__u64 addr)
{
    __u64 v = 0;

    bpf_probe_read_kernel(&v, sizeof(v), (void *)addr);
    return v;
}

static __always_inline __u32 tego_rd32(__u64 addr)
{
    __u32 v = 0;

    bpf_probe_read_kernel(&v, sizeof(v), (void *)addr);
    return v;
}
#define TEGO_D_INODE(d) tego_rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_inode))
#define TEGO_D_PARENT(d) tego_rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_parent))
#define TEGO_M_PARENT(m) tego_rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt_parent))
#define TEGO_M_MOUNTPOINT(m) tego_rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt_mountpoint))
#define TEGO_M_ROOT(m)                                                                                            \
    tego_rd64((__u64)(m) + bpf_core_field_offset(struct mount, mnt) + bpf_core_field_offset(struct vfsmount, mnt_root))
#define TEGO_VM_ROOT(vm) tego_rd64((__u64)(vm) + bpf_core_field_offset(struct vfsmount, mnt_root))
#define TEGO_I_INO(i) tego_rd64((__u64)(i) + bpf_core_field_offset(struct inode, i_ino))
#define TEGO_I_GEN(i) tego_rd32((__u64)(i) + bpf_core_field_offset(struct inode, i_generation))
#define TEGO_I_SDEV(i)                                                                                            \
    tego_rd32(tego_rd64((__u64)(i) + bpf_core_field_offset(struct inode, i_sb)) +                                 \
               bpf_core_field_offset(struct super_block, s_dev))
#define TEGO_D_SBROOT(d)                                                                                          \
    tego_rd64(tego_rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_sb)) +                                \
               bpf_core_field_offset(struct super_block, s_root))
#endif

/* The walk's state, on the global function's stack and handed to each step. */
struct tego_walk_state {
    void *rows;     /* the slot's rows map */
    __u64 d;        /* the dentry at this step */
    __u64 m;        /* its struct mount; 0 for a walk inside the superblock */
    __u64 mroot;    /* that mount's root dentry; the superblock's root for a walk inside it */
    __u32 run_idx;
    __u32 gen;
    __u32 steps;    /* levels climbed: decide.PlaneRows.Find's step, which a mount crossing does not advance */
    __u32 result;   /* enum tego_plane_walk_result; TEGO_WALK_BOUND until a step ends the walk */
    __u16 rule_idx;
    __u8  kind;
    __u8  crossed;  /* d is a mountpoint just crossed to: it names the path the mount root below it did */
    __u16 exec_rule;
    __u16 pad;
};

/* One iteration: look the dentry's inode up; a current row ends the walk (after its identity check), a stale one is
 * walked past uncounted: a slot keeps its previous run's rows, so a stale row sits on the allow path of every open
 * beneath it, and a shared atomic bumped there bounced one cache line between every CPU of the run. Then climb one
 * level, or, at a mount root, cross to the parent mount's mountpoint. The mountpoint names the same path as the
 * mount root, so the next iteration neither looks it up nor counts it as a level: a crossing costs an iteration and
 * no step, so s->steps is decide.PlaneRows.Find's step, path components only. A walk that reaches a level past
 * TEGO_PLANE_WALK_MAX ends BOUND. A mounted root's row (TEGO_ROW_MOUNT_ONLY) is for the walk inside a superblock
 * only (vfsmount 0, which ends at the superblock's root); the walk that crosses mounts passes it, and meets the row
 * it was copied from above the mountpoint. A name entry's scope-only row (TEGO_ROW_SCOPE_ONLY, ADR 0043 D4) is for
 * the name check's climb only: every walk passes it, so it decides nothing and moves no walk's bound
 * (decide.PlaneRows.Find). Returns 1 to stop, 0 to go on. */
static long tego_walk_step(__u32 i, struct tego_walk_state *s)
{
    __u64 d = s->d;

    if (!s->crossed) {
        if (s->steps > TEGO_PLANE_WALK_MAX) {
            s->result = TEGO_WALK_BOUND;
            return 1;
        }
        __u64 inode = TEGO_D_INODE(d);

        if (inode) {
            __u64 key = inode;
            struct tego_plane_row *r = bpf_map_lookup_elem(s->rows, &key);

            if (r && !(s->m && (r->kind & TEGO_ROW_MOUNT_ONLY)) && !(r->kind & TEGO_ROW_SCOPE_ONLY)) {
                if (r->gen == s->gen) {
                    if (r->i_ino != TEGO_I_INO(inode) || r->i_generation != TEGO_I_GEN(inode) ||
                        r->s_dev != TEGO_I_SDEV(inode)) {
                        s->result = TEGO_WALK_MISMATCH;
                        return 1;
                    }
                    s->rule_idx = r->rule_idx;
                    s->kind = r->kind;
                    s->exec_rule = r->exec_rule;
                    s->pad = r->pad2;
                    s->result = TEGO_WALK_HIT;
                    return 1;
                }
            }
        }
    }
    s->crossed = 0;
    if (d == s->mroot) {
        __u64 m = s->m;
        if (!m) {
            s->result = TEGO_WALK_ROOT;
            return 1;
        }
        __u64 pm = TEGO_M_PARENT(m);

        if (!pm || pm == m) {
            s->result = TEGO_WALK_ROOT;
            return 1;
        }
        s->d = TEGO_M_MOUNTPOINT(m);
        s->m = pm;
        s->mroot = TEGO_M_ROOT(pm);
        s->crossed = 1;
        return 0;
    }
    __u64 p = TEGO_D_PARENT(d);
    if (!p || p == d) {
        s->result = TEGO_WALK_UNRESOLVED;
        return 1;
    }
    s->d = p;
    s->steps++;
    return 0;
}

/* tego_plane_walk walks from dentry (a struct dentry *) on vfsmount (its struct vfsmount *) for the run at run_idx
 * of generation gen, and returns an enum tego_plane_walk_result; on TEGO_WALK_HIT, *hit is the nearest row. Every
 * result but ROOT and HIT is a refusal the caller must make, and is counted at the slot. The walk stops at the first
 * current row: every row is complete (decide.PlaneRows, TIER3-PLAN T5), so the nearest row answers every question.
 * vfsmount 0 walks inside the dentry's superblock (the attribute hooks, which get no mount, R12): d_parent to the
 * superblock's root, which ends it as ROOT, meeting the mounted-root rows on the way.
 * Global: verified once per program however many times it is called (rename and link walk both ends). */
__attribute__((noinline)) int tego_plane_walk(__u64 dentry, __u64 vfsmount, __u32 run_idx, __u32 gen,
                                               struct tego_plane_hit *hit)
{
    __u32 idx = run_idx;
    struct tego_walk_state s = {};

    if (!hit)
        return TEGO_WALK_NOROWS;
    s.rows = bpf_map_lookup_elem(&tego_plane_rows, &idx);
    if (!s.rows) {
        TEGO_PLANE_COUNT(run_idx, norows);
        return TEGO_WALK_NOROWS;
    }
    s.d = dentry;
    if (vfsmount) {
        s.m = vfsmount - bpf_core_field_offset(struct mount, mnt);
        s.mroot = TEGO_VM_ROOT(vfsmount);
    } else {
        /* 0, the walk inside the superblock, read from the caller's zeroed hit as steps and crossed are below: every
         * field tego_walk_step branches on is seeded from memory (bpf/tests
         * TestBPFLoopCallbackStateIsSeededFromMemory). */
        s.m = hit->depth;
        s.mroot = TEGO_D_SBROOT(dentry);
    }
    s.run_idx = run_idx;
    s.gen = gen;
    s.result = TEGO_WALK_BOUND;
    /* The counters start at 0, read from the caller's zeroed hit rather than written as constants. A verifier before
     * 6.8's "verify callbacks as if they are called unknown number of times" (AL2023's 6.1; RHEL 9.8's 5.14 carries
     * the fix) verifies tego_walk_step once, from its first call's state: with steps a known 0 the BOUND branch was
     * dead and hard-wired away, so a row 65 levels up was met and a walk past TEGO_PLANE_WALK_MAX levels allowed
     * (TestPlaneStepAHooksDecide's bound cells, found in the guest). A global function's verifier knows nothing of
     * the memory hit points to. */
    s.steps = hit->depth;
    s.crossed = (__u8)hit->depth;
    /* The object and TEGO_PLANE_WALK_MAX levels above it (decide.PlaneRows.Find's steps 0 to agent.MaxWalk), with
     * an iteration to spare for each level's mount crossing. A walk that runs out of iterations stays BOUND. */
    bpf_loop(TEGO_PLANE_WALK_ITERS, tego_walk_step, &s, 0);
    switch (s.result) {
    case TEGO_WALK_HIT:
        hit->depth = s.steps;
        hit->rule_idx = s.rule_idx;
        hit->kind = s.kind;
        hit->exec_rule = s.exec_rule;
        hit->pad2 = s.pad;
        break;
    case TEGO_WALK_UNRESOLVED:
        TEGO_PLANE_COUNT(run_idx, unresolved);
        break;
    case TEGO_WALK_BOUND:
        TEGO_PLANE_COUNT(run_idx, bound);
        break;
    case TEGO_WALK_MISMATCH:
        TEGO_PLANE_COUNT(run_idx, mismatch);
        break;
    }
    return s.result;
}

/* Walks from a path the hook holds: launders dentry and mnt through the task's scratch value sc (ADR 0024's T2
 * note), then calls the global walk. */
static __always_inline int tego_plane_walk_path(struct tego_plane_decision *sc, struct dentry *dentry,
                                                 struct vfsmount *mnt, const struct tego_run *run,
                                                 struct tego_plane_hit *hit)
{
    sc->launder_dentry = (__u64)dentry;
    sc->launder_mnt = (__u64)mnt;
    return tego_plane_walk(*(volatile __u64 *)&sc->launder_dentry, *(volatile __u64 *)&sc->launder_mnt,
                            run->run_idx, run->gen, hit);
}
/* ---- end of the walk (TEGO_PLANE_WALK_END) ---- */

/* ---- The final name's reader (bpf/include/plane_name.h, shared with the fill) ----
 *
 * TEGO_RD_WORD(addr) is the eight bytes at a kernel address through the build's reader, the walk's: a struct qstr's
 * first member is a u64, so the rdonly build reads any eight bytes as one (bpf_rdonly_cast), and the probe-read build
 * through bpf_probe_read_kernel. bprm_check's exec name pass and the name entries' passes (decide_names.h) read
 * names through it. */
#if TEGO_PLANE_RDONLY
#define TEGO_RD_WORD(addr) (bpf_core_cast((void *)(addr), struct qstr)->hash_len)
#else
#define TEGO_RD_WORD(addr) tego_rd64(addr)
#endif
#include "plane_name.h"

/* ---- Step A hooks (TIER3-PLAN §2; enforce-plane R8-R11) ----
 *
 * Every body starts with the run-set lookup and returns 0 on a miss (R1). A decision is recorded in the task's
 * tego_plane_scratch value, {rule_idx, hook, verdict, reason}, for the recorder's fexit (ADR 0024 (11)), and every
 * body returns 0 or -EACCES only (R2). */

/* fmode_t bits and flags the plane reads. vmlinux.h carries no #define; these have held from 5.14 through 7.0. */
#define TEGO_FMODE_READ 0x1
#define TEGO_FMODE_WRITE 0x2
#define TEGO_FMODE_CREATED 0x100000
#define TEGO_O_TRUNC 01000
#define TEGO_S_PRIVATE 512
#define TEGO_SB_NOUSER (1U << 31)
#define TEGO_MNT_INTERNAL 0x4000

/* FMODE_BACKING (6.6+): a file the kernel opened for a stacking filesystem, whose user's own open was decided
 * already (ADR 0024 (6)); step C's walk starts at its user_path. file_open's skip of it is keyed on the private
 * clone alone (R8). Its bit moved when 6.11 moved per-file-type bits into file_operations.fop_flags: bit 24
 * from there on, bit 25 before, where bit 24 was FMODE_DIO_PARALLEL_WRITE, which ext4 and xfs set on every regular
 * file. So the layout is read from BTF, not from a version: fop_flags present, bit 24; else struct backing_file
 * present, bit 25; else no backing files exist. */
static __always_inline int tego_is_backing(__u32 fmode)
{
    if (bpf_core_field_exists(struct file_operations, fop_flags))
        return (fmode & (1U << 24)) != 0;
    if (bpf_core_type_exists(struct backing_file))
        return (fmode & (1U << 25)) != 0;
    return 0;
}

/* An object no path names, which no fs entry can cover: a pipe, socket or anonymous inode (a superblock the kernel
 * marks SB_NOUSER), a private inode, and a pseudo file on an internal mount (a memfd, an nsfs file), whose dentry
 * is its own parent short of its mount's root. Landlock's walk lets the same set through (is_nouser_or_private, and
 * MNT_INTERNAL at a disconnected root), so `echo > /dev/stdout` on a pipe and the reopen of a memfd are no fs
 * decision; a memfd's exec is decided at bprm_check (exec.anonymous). Any other dentry that is its own parent short
 * of a mount root is a disconnected one, which the walk refuses. */
static __always_inline int tego_no_path(struct dentry *dentry, struct vfsmount *mnt)
{
    struct inode *inode = dentry->d_inode;

    if (dentry->d_sb->s_flags & TEGO_SB_NOUSER)
        return 1;
    if (inode && (inode->i_flags & TEGO_S_PRIVATE))
        return 1;
    return (__u64)dentry->d_parent == (__u64)dentry && (__u64)dentry != (__u64)mnt->mnt_root &&
           (mnt->mnt_flags & TEGO_MNT_INTERNAL);
}

/* A mount no path of the agent's reaches: a private clone the kernel made for a stacking filesystem
 * (clone_private_mount, overlayfs' layers), whose mnt_ns is fs/mount.h's MNT_NS_INTERNAL, ERR_PTR(-EINVAL) (the
 * value the 6.17 guest's overlayfs gives its clones: TestPlaneStepAHooksDecide's overlay cells). overlayfs' copy-up
 * opens the new upper file there with a plain dentry_open (no FMODE_BACKING), in the agent's task, after the agent's
 * own open of the merged file was decided; decided again on the upper path, where no row lies, it refused the copy-up
 * of every lower file under a write entry (enforce-plane §2.7's condition 1). Every name the agent opens resolves
 * through the mounts of its own namespace, never a private clone, so the agent cannot put an open of its own there;
 * a detached mount (mnt_ns NULL) is not skipped. */
#define TEGO_MNT_NS_INTERNAL ((__u64)-22)

static __always_inline int tego_internal_mount(struct vfsmount *mnt)
{
    __u64 m = (__u64)mnt - bpf_core_field_offset(struct mount, mnt);
#if TEGO_PLANE_RDONLY
    return (__u64)bpf_core_cast((void *)m, struct mount)->mnt_ns == TEGO_MNT_NS_INTERNAL;
#else
    return tego_rd64(m + bpf_core_field_offset(struct mount, mnt_ns)) == TEGO_MNT_NS_INTERNAL;
#endif
}

/* IS_PRIVATE(inode): what security_path_* return 0 for before the LSM chain, which fmod_ret mode runs ahead of
 * (ADR 0024 (8)). */
static __always_inline int tego_is_private(struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;

    return inode && (inode->i_flags & TEGO_S_PRIVATE);
}

/* The task's scratch value, created on its first decision. */
static __always_inline struct tego_plane_decision *tego_plane_scratch_get(void)
{
    return bpf_task_storage_get(&tego_plane_scratch, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* Records one decision on obj (struct tego_plane_decision.obj says which object each hook names) and returns its
 * reason: 0 is an allow. */
static __always_inline __u8 tego_plane_record(struct tego_plane_decision *sc, __u16 hook, __u64 obj, __u32 rule,
                                               __u8 reason)
{
    sc->rule_idx = rule;
    sc->hook = hook;
    sc->obj = obj;
    sc->verdict = reason ? TEGO_V_REFUSED : TEGO_V_ALLOW;
    sc->reason = reason;
    if (hook == TEGO_HOOK_BPRM_CHECK) {
        sc->exec_obj = obj;
        sc->exec_rule = rule;
        sc->exec_verdict = sc->verdict;
    }
    return reason;
}

/* v read back through the task's scratch value: the same value, of which the verifier then knows nothing, so the
 * paths that reached it with different known values of it go on as one. */
static __always_inline __u64 tego_plane_unknown(struct tego_plane_decision *sc, __u64 v)
{
    sc->launder_mnt = v;
    return *(volatile __u64 *)&sc->launder_mnt;
}

/* Whether dentry is positive (has an inode), tested at run time: its d_inode read back through the task's scratch
 * value, a scalar the verifier knows nothing of. A verifier that takes a trusted dentry's d_inode for a pointer that
 * is never NULL (BTF_TYPE_SAFE_TRUSTED(struct dentry), "no negative dentry-s in places where bpf can see it", in RHEL
 * 9's 5.14, 6.8 and 6.12; later kernels make it trusted-or-NULL) never takes an lsm program's NULL test of one
 * loaded from a hook's argument and hard-wires the branch: path_rename then read a negative destination as positive
 * (bpf/tests TestPlaneTestsADentrysInodeAtRunTime). */
static __always_inline int tego_positive(struct tego_plane_decision *sc, struct dentry *dentry)
{
    return tego_plane_unknown(sc, (__u64)dentry->d_inode) != 0;
}

/* A hook's decision, its reason and rule, read back through the task's scratch value before the hook records it and
 * writes its fallback sample: the verifier then knows neither, so it walks the record and the sample once for every
 * path that decided, not once per reason and rule a branch wrote (the name entries' paths would multiply them past
 * ADR 0024's budget of 20,000 verified instructions a program). Returns reason << 32 | rule. */
static __always_inline __u64 tego_plane_settle(struct tego_plane_decision *sc, __u8 reason, __u32 rule)
{
    return tego_plane_unknown(sc, (__u64)reason << 32 | rule);
}

/* The nearest row's answer at dentry: the walk's result and, on a hit, *kind and *rule the row's kind and rule_idx.
 * A walk that met no row answers kind 0 (a read allowed, a modification refused) and no rule. */
static __always_inline int tego_nearest(struct tego_plane_decision *sc, struct dentry *dentry,
                                         struct vfsmount *mnt, const struct tego_run *run, __u8 *kind, __u16 *rule,
                                         __u32 *depth)
{
    struct tego_plane_hit h = {};
    int res = tego_plane_walk_path(sc, dentry, mnt, run, &h);

    *kind = 0;
    *rule = TEGO_PLANE_RULE_NONE;
    *depth = 0;
    if (res == TEGO_WALK_HIT) {
        *kind = h.kind;
        *rule = h.rule_idx;
        *depth = h.depth;
    }
    return res;
}

/* The reason a walk failed closed with, 0 when it did not fail: a row whose key inode no longer carries its
 * identity is identity-mismatch (ADR 0025 (4)), and UNRESOLVED, BOUND and NOROWS are path-unresolved. */
static __always_inline __u8 tego_walk_failed(int res)
{
    if (res < TEGO_WALK_UNRESOLVED)
        return 0;
    return res == TEGO_WALK_MISMATCH ? TEGO_R_IDENTITY_MISMATCH : TEGO_R_PATH_UNRESOLVED;
}

/* REFER's order (decide.PlaneKind.Strictness): 2 refuses reads, 1 allows reads and refuses modifications, 0 allows
 * both. */
static __always_inline __u8 tego_strictness(__u8 kind)
{
    if (kind & TEGO_ROW_READ_DENY)
        return 2;
    return (kind & TEGO_ROW_MODIFY_ALLOW) ? 0 : 1;
}

/* The reason a rename refuses one end with (decide.PlaneRows.Decide's PlaneRename): the inode itself is a
 * deny_write target or one of its ancestors (depth 0, R11), or the modification is refused there. 0 allows. */
static __always_inline __u8 tego_rename_end(__u8 kind, __u32 depth)
{
    if (depth == 0 && (kind & TEGO_ROW_RENAME_REFUSED))
        return TEGO_R_DENY_WRITE_ANCESTOR;
    return (kind & TEGO_ROW_MODIFY_ALLOW) ? 0 : TEGO_R_RENAME_OUTSIDE_CONTRACT;
}

/* ---- The plane's own samples (enforce-plane R23, §7; TIER3-PLAN T9, T13, T9b) ----
 *
 * A refusal no recorder fexit writes a line for is written by the plane itself, to the run's own ring, under
 * record: off too: an attribute change and a socket (step B's hooks, which no fexit wraps), and a refusal on a hook
 * a recorder fexit wraps where the build's fexit is not attached (tego_plane_recorded, T9b). An fs object is named
 * as an fsop record names it, by its directory's (dev, ino) and its final component, which the recorder resolves
 * through the rule table's directory index; the name is read as at most 32 eight-byte words through the build's
 * reader into the task's own buffer (tego_path_step, the exec sample's), so the rdonly build reads it under
 * lockdown=confidentiality. A socket names its family, type and protocol. bprm_check's refusal names the spelling
 * the task passed (bprm->filename) through the same writer. tego_plane_own_sample is the plane's one writer of
 * struct tego_ev_plane and sets every field of it: reserved ring memory is not zeroed, and a field left unset would
 * carry an earlier record's bytes. It is defined below tego_path_step, whose reader it uses. */
struct tego_plane_sample_args {
    __u64 name;         /* the name's address: bprm->filename, or the final component's; 0 for a socket */
    __u64 dev;
    __u64 dir_ino;
    __u32 rule;
    __s32 family;
    __s32 type;
    __s32 protocol;
    __u16 kind;         /* TEGO_EV_PLANE_ATTR, _SOCKET, _MAP or _FS */
    __u16 hook;
    __u8  reason;
    __u8  named;        /* 1: the record names its object, and path_ok says whether its name was read whole */
    __u8  pad[2];
    __u32 flags;        /* TEGO_EV_PLANE_FS: file_open's f_flags */
    __u32 name_len;     /* exact byte name for a Unix listener sample; 0 is a NUL string */
};

static __attribute__((noinline)) void tego_plane_own_sample(const struct tego_run *run,
                                                             const struct tego_plane_sample_args *a);

/* Whether the build's recorder fexit on hook is attached (tego_plane_recorded): that fexit then takes the
 * decision and writes the action's one line. A mask nobody wrote is 0, so a refusal is never left without one. */
static __always_inline int tego_recorder_wraps(__u16 hook)
{
    __u32 key = 0;
    __u32 *mask = bpf_map_lookup_elem(&tego_plane_recorded, &key);

    return mask && hook < 32 && (*mask & (1U << hook));
}

/* The record fallback (enforce-plane §7, R23; TIER3-PLAN T9b): a refusal on a hook a recorder fexit wraps, where
 * the build's fexit is not attached, writes the plane's own sample of the object at dentry (TEGO_EV_PLANE_FS), so
 * the action still has exactly one line: the sample where no fexit runs, the fexit's where one does. Called on the
 * refusal path only, before its return -EACCES. The sample's arguments are built in a function of their own
 * (tego_plane_fallback_sample), so the fs hooks' frames, which the name entries' check stacks on (decide_names.h), do
 * not carry them; it is a global function, verified once in a program however many of the program's paths fall back
 * (path_mknod's three, a missing header, a missing scratch value and a refusal, were each a verification of the
 * sample's 1,600 instructions on Fedora's 7.0 while it was a static subprogram). A global function takes no trusted
 * pointer before 6.8 and only scalars where its prototype says one, so the hook hands it scalars it read from the
 * dentry: the name's address, read as a word through the build's reader (a load of d_name.name is a pointer to read-only
 * memory on 7.0, which a scalar argument refuses), the directory's inode number, rule | reason << 32 | hook << 40, and
 * flags | s_dev << 32 (five arguments at most). */
__attribute__((noinline)) int tego_plane_fallback_sample(const struct tego_run *run, __u64 name, __u64 dir_ino,
                                                          __u64 rule_reason_hook, __u64 flags_dev)
{
    struct tego_plane_sample_args a = {};

    if (!run)
        return 0;
    a.kind = TEGO_EV_PLANE_FS;
    a.rule = (__u32)rule_reason_hook;
    a.reason = (__u8)(rule_reason_hook >> 32);
    a.hook = (__u16)(rule_reason_hook >> 40);
    a.flags = (__u32)flags_dev;
    a.named = 1;
    a.name = name;
    a.dev = flags_dev >> 32;
    a.dir_ino = dir_ino;
    tego_plane_own_sample(run, &a);
    return 0;
}

static __always_inline void tego_plane_fallback(const struct tego_run *run, __u16 hook, struct dentry *dentry,
                                                 __u32 rule, __u8 reason, __u32 flags)
{
    if (tego_recorder_wraps(hook))
        return;
    tego_plane_fallback_sample(run,
                                TEGO_RD_WORD((__u64)dentry + bpf_core_field_offset(struct dentry, d_name) +
                                              bpf_core_field_offset(struct qstr, name)),
                                dentry->d_parent->d_inode->i_ino,
                                (__u64)rule | (__u64)reason << 32 | (__u64)hook << 40,
                                (__u64)flags | (__u64)dentry->d_sb->s_dev << 32);
}

/* The slot header of run (enforce-plane R6), or NULL, counted norows, when the slot holds none of the run's gen: a
 * cleared slot (gen 0, which no epoch is), a previous run's, or one whose Prepare never finished. Every decided hook
 * reads it after its run-set hit and its no-decision skips (an object no path names, a private clone), before its
 * first decision, and refuses on NULL: a run-set row whose slot says nothing of it is decided by nothing, never
 * allowed by what is missing. doctor's probe relies on the skips coming first: its bprm_check probe execs a memfd,
 * whose open file_open passes as no path. */
static __always_inline const struct tego_plane_slot *tego_plane_slot_of(const struct tego_run *run)
{
    __u32 idx = run->run_idx;
    struct tego_plane_slot *s = bpf_map_lookup_elem(&tego_plane_slots, &idx);

    if (!s || s->gen != run->gen) {
        TEGO_PLANE_COUNT(run->run_idx, norows);
        return 0;
    }
    return s;
}

/* A decided hook's record when tego_plane_slot_of found no header of the run's gen, before it returns -EACCES:
 * refused path-unresolved, under hook on obj, for the recorder's fexit (a task with no scratch value records
 * nothing; the refusal stands). The caller writes the refusal's line where no fexit does: tego_plane_fallback for
 * an fs hook, its own sample for the others. */
static __always_inline void tego_plane_unslotted(__u16 hook, __u64 obj)
{
    struct tego_plane_decision *sc = tego_plane_scratch_get();

    if (sc)
        tego_plane_record(sc, hook, obj, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED);
}

/* tego_plane_unslotted for a hook a recorder fexit wraps, with the fallback sample of the object at dentry. */
static __always_inline void tego_plane_unslotted_fs(const struct tego_run *run, __u16 hook, __u64 obj,
                                                     struct dentry *dentry, __u32 flags)
{
    tego_plane_unslotted(hook, obj);
    tego_plane_fallback(run, hook, dentry, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, flags);
}

/* ADR 0043's name entries: the prefilter, the name check, the climb and D5, which the hooks below ask. */
#include "decide_names.h"
#include "decide_builtin.h"

TEGO_PLANE_HOOK(file_open, file_open, security_file_open, (struct file *file), (file))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    __u32 fmode, depth, rule32;
    __u64 settled;
    __u16 rule;
    __u8 kind, reason = 0;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    fmode = file->f_mode;
    if (tego_no_path(file->f_path.dentry, file->f_path.mnt))
        return 0;
    /* A file on a private clone is no decision: a stacking filesystem's backing open (FMODE_BACKING) and overlayfs'
     * copy-up alike. The skip is keyed on the mount alone, which no open of the agent's own resolves through, so no
     * FMODE_BACKING bit is read here (R8). */
    if (tego_internal_mount(file->f_path.mnt))
        return 0;
    /* A read is decided by the read cells, the open of an exec's image and PT_INTERP's loader included (they open
     * with FMODE_READ); exec rows are never applied here (R8). A write-open, an O_TRUNC and a file this open created
     * are modifications. An open that is neither (flags 3) is no decision. */
    int read = (fmode & TEGO_FMODE_READ) != 0;
    int modify = (fmode & (TEGO_FMODE_WRITE | TEGO_FMODE_CREATED)) || (file->f_flags & TEGO_O_TRUNC);
    if (!read && !modify)
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_FILE_OPEN, (__u64)file, file->f_path.dentry, file->f_flags);
        return -EACCES;
    }
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        tego_plane_fallback(run, TEGO_HOOK_FILE_OPEN, file->f_path.dentry, TEGO_PLANE_RULE_NONE,
                             TEGO_R_PATH_UNRESOLVED, file->f_flags);
        return -EACCES;
    }
    reason = tego_walk_failed(tego_nearest(sc, file->f_path.dentry, file->f_path.mnt, run, &kind, &rule, &depth));
    rule32 = rule;
    if (reason)
        ;
    else if (read && (kind & TEGO_ROW_READ_DENY))
        reason = TEGO_R_READ_DENIED;
    else if (modify && !(kind & TEGO_ROW_MODIFY_ALLOW) &&
             !((hdr->flags & TEGO_SLOT_BUILTIN_TTY) && !(kind & (TEGO_ROW_PROTECTED | TEGO_ROW_READ_DENY)) &&
               tego_builtin_terminal(file)))
        reason = TEGO_R_WRITE_OUTSIDE_CONTRACT;
    else if (!tego_is_dir(file->f_inode) && tego_names_on(hdr)) {
        /* The walk allows both questions: a covered file is refused as its own deny_read entry would refuse it, a read
         * read-denied and a modification as the walk would refuse one (ADR 0043 D1), named by its entry (D8). */
        __u32 nrule = TEGO_PLANE_RULE_NONE;
        int res = tego_name_check_path(sc, file->f_path.dentry, file->f_path.mnt, run, &nrule);

        if ((reason = tego_walk_failed(res)))
            rule32 = TEGO_PLANE_RULE_NONE;
        else if (res == TEGO_NAME_DENY) {
            reason = read ? TEGO_R_READ_DENIED : TEGO_R_WRITE_OUTSIDE_CONTRACT;
            rule32 = nrule;
        }
    }
    settled = tego_plane_settle(sc, reason, rule32);
    reason = settled >> 32;
    rule32 = (__u32)settled;
    if (tego_plane_record(sc, TEGO_HOOK_FILE_OPEN, (__u64)file, rule32, reason)) {
        tego_plane_fallback(run, TEGO_HOOK_FILE_OPEN, file->f_path.dentry, rule32, reason, file->f_flags);
        return -EACCES;
    }
    return 0;
}

/* ---- exec: the final name and the link's key (bpf/include/plane_name.h, included above with its reader) ---- */

/* An image with no name (R9's exec.anonymous): a pseudo file (memfd, whose dentry is its own parent) or one whose
 * name was dropped (unlinked since it was opened, an O_TMPFILE): its dentry is unhashed. */
static __always_inline int tego_is_anonymous(struct dentry *dentry)
{
    return (__u64)dentry->d_parent == (__u64)dentry || !dentry->d_hash.pprev;
}

/* ---- The plane's own refusal sample (enforce-plane R23, TIER3-PLAN T9) ----
 *
 * bprm_check has no recorder fexit (ADR 0016 (3) lists none: Landlock decides nothing there), so the plane writes
 * the line of an exec it refuses itself, to the run's own ring, under record: off too. The name is bprm->filename,
 * the spelling the task passed, read as at most 32 eight-byte words through the build's reader (so the rdonly
 * build reads it under lockdown=confidentiality too) into the task's own buffer (task storage, not per CPU: a
 * preempted sample would share a per-CPU one with the next refused exec on its CPU), up to and including the word
 * that holds its NUL, with the bytes past the NUL cleared: nothing of the kernel memory beside the string leaves
 * the kernel. */
#define TEGO_PATH_WORDS (TEGO_PATH_MAX / 8)

/* The index in memory order of w's first zero byte, 8 when it has none. */
static __always_inline __u32 tego_first_nul(__u64 w)
{
    __u32 j;

    for (j = 0; j < 8; j++) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        if (!((w >> (j * 8)) & 0xff))
            return j;
#else
        if (!((w >> ((7 - j) * 8)) & 0xff))
            return j;
#endif
    }
    return 8;
}

/* One path copy's state: the string's address, the words written and whether its NUL was met. */
struct tego_path_copy {
    __u64 addr;
    __u32 words;
    __u32 whole;
    __u32 len;
};

static long tego_path_step(__u32 i, struct tego_path_copy *c)
{
    __u32 n, idx;
    struct tego_plane_path *buf = bpf_task_storage_get(&tego_plane_path_buf, bpf_get_current_task_btf(), 0, 0);
    __u64 w;

    if (!buf || i >= TEGO_PATH_WORDS)
        return 1;
    if (c->len && i * 8 >= c->len)
        return 1;
    w = TEGO_RD_WORD(c->addr + i * 8);
    n = c->len ? c->len - i * 8 : tego_first_nul(w);
    /* The index is masked where the verifier sees it, as in tego_name_cmp_step: clang drops a mask it can prove
     * redundant, and the map value access then has no upper bound. */
    idx = i;
    barrier_var(idx);
    idx &= TEGO_PATH_WORDS - 1;
    buf->w[idx] = tego_word_mask(w, n);
    c->words = i + 1;
    if (c->len && (i + 1) * 8 >= c->len) {
        c->whole = 1;
        return 1;
    }
    if (!c->len && n < 8) {
        c->whole = 1;
        return 1;
    }
    return 0;
}

static __attribute__((noinline)) void tego_plane_own_sample(const struct tego_run *run,
                                                             const struct tego_plane_sample_args *a)
{
    struct task_struct *t = bpf_get_current_task_btf();
    struct tego_path_copy c = {};
    struct tego_plane_path *buf = 0;
    struct tego_ev_plane *e;
    __u32 k;
    void *ring = tego_ring_of(&tego_events, run);

    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
        return;
    }
    /* Created here, deleted below: a task holds the buffer only while its sample is built. */
    if (a->named && a->name) {
        buf = bpf_task_storage_get(&tego_plane_path_buf, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        c.addr = a->name;
        c.len = a->name_len;
        if (buf)
            bpf_loop(TEGO_PATH_WORDS, tego_path_step, &c, 0);
    }
    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        if (buf)
            bpf_task_storage_delete(&tego_plane_path_buf, t);
        return;
    }
    tego_hdr_fill(&e->hdr, a->kind, sizeof(*e), run, bpf_get_current_cgroup_id());
    e->hdr.ppid = t->real_parent->tgid;
    e->hdr.verdict = TEGO_V_REFUSED;
    e->hdr.reason = a->reason;
    e->hdr.rule_idx = (__u16)a->rule;
    e->start_ns = t->group_leader->start_boottime;
    e->rule_idx = a->rule;
    e->hook = a->hook;
    /* No name asked for (a socket, an anonymous file's mapping) is a whole, empty read; a name asked for and not read,
     * a NULL address or buf included, is path_ok 0, so the recorder never takes a refused allocation for a file no
     * path names. */
    e->path_ok = a->named ? (buf && c.whole) : 1;
    e->pad = 0;
    e->dev = a->dev;
    e->dir_ino = a->dir_ino;
    e->family = a->family;
    e->type = a->type;
    e->protocol = a->protocol;
    e->flags = a->flags | (a->name_len << 16);
    /* Reserved memory is not zeroed: every word is written, the name's or 0, each at a constant offset. */
    if (buf) {
#pragma clang loop unroll(full)
        for (k = 0; k < TEGO_PATH_WORDS; k++)
            ((__u64 *)e->path)[k] = k < c.words ? buf->w[k] : 0;
    } else {
#pragma clang loop unroll(full)
        for (k = 0; k < TEGO_PATH_WORDS; k++)
            ((__u64 *)e->path)[k] = 0;
    }
    bpf_ringbuf_submit(e, 0);
    if (buf)
        bpf_task_storage_delete(&tego_plane_path_buf, t);
}

/* bprm_check's refusal: no recorder fexit wraps it, so the refusal's one ledger line is the plane's own sample
 * (R23), naming the spelling the task passed. */
static __always_inline void tego_exec_sample(const struct tego_run *run, struct linux_binprm *bprm, __u32 rule,
                                              __u8 reason)
{
    struct tego_plane_sample_args a = {};

    a.kind = TEGO_EV_PLANE_EXEC;
    a.hook = TEGO_HOOK_BPRM_CHECK;
    a.rule = rule;
    a.reason = reason;
    a.named = 1;
    a.name = (__u64)bprm->filename;
    tego_plane_own_sample(run, &a);
}

/* Of the exec arms that matched, the lowest entry wins (decide.RootExecMatch). */
static __always_inline void tego_exec_candidate(__u32 *entry, __u32 *best, __u8 *allow, __u32 candidate,
                                                 __u32 rule, __u8 ok)
{
    if (candidate < *entry) {
        *entry = candidate;
        *best = rule;
        *allow = ok;
    }
}


/* The file arm, one function for bprm_check and step C's mappings (tego_map_exec_row), so the key they look up is
 * the one the fill writes: the row of this link, keyed by the file's inode, its directory's inode and its name's key
 * (tego_exec_link_key: one row per hard link an entry names, so every listed link of a multi-call binary has its
 * own and an unlisted one none, enforce-plane §6 E15). The key is not trusted alone: the row's inode, directory and
 * name are compared with the file's. A file whose directory has no inode cannot be identified and matches no row.
 * Returns 1 with the row's entry in *rule for a match, 0 for none, and -1 with *rule for a row whose inode no longer
 * carries its identity (counted). */
static __always_inline int tego_exec_file_row(struct tego_plane_decision *sc, void *exec_rows,
                                               const struct tego_run *run, struct dentry *dentry, struct inode *inode,
                                               struct tego_name_pass *nm, __u64 name_key, __u16 *rule)
{
    struct tego_plane_exec_row *r;
    struct inode *pinode = dentry->d_parent->d_inode;
    __u64 ikey;

    if (!pinode)
        return 0;
    /* The pointers reach the key as scalars through the task's scratch value, as the walk's do: the verifier refuses
     * arithmetic on a pointer. */
    sc->launder_dentry = (__u64)inode;
    sc->launder_mnt = (__u64)pinode;
    ikey = tego_exec_link_key(*(volatile __u64 *)&sc->launder_dentry, *(volatile __u64 *)&sc->launder_mnt, name_key);
    r = bpf_map_lookup_elem(exec_rows, &ikey);
    if (!r || r->gen != run->gen || r->inode != (__u64)inode)
        return 0;
    if (r->i_ino != inode->i_ino || r->i_generation != inode->i_generation || r->s_dev != inode->i_sb->s_dev) {
        TEGO_PLANE_COUNT(run->run_idx, mismatch);
        *rule = r->rule_idx;
        return -1;
    }
    if (r->parent == (__u64)pinode && r->parent_ino == pinode->i_ino && r->parent_generation == pinode->i_generation &&
        tego_name_eq(nm, r)) {
        *rule = r->rule_idx;
        return 1;
    }
    return 0;
}


#include "exec_pin.h"
#include "decide_execpin.h"

/* ADR 0048 P2's pin check (decide_execpin.h): tp_btf/sched_process_exec runs after the binfmt load and before the
 * return to user mode, with current->mm the new image's. One program per mode, as every plane program is; each
 * returns at once for a run of the other mode. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(tego_exec_pin_lsm, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    tego_exec_pin_check(TEGO_PLANE_LSM, p, old_pid, bprm);
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(tego_exec_pin_fmr, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    tego_exec_pin_check(TEGO_PLANE_FMOD_RET, p, old_pid, bprm);
    return 0;
}

TEGO_PLANE_HOOK(bprm_check, bprm_check_security, security_bprm_check, (struct linux_binprm *bprm), (bprm))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    struct tego_plane_exec_row *r;
    struct tego_name_pass nm = {};
    struct tego_plane_hit hit = {};
    struct dentry *dentry;
    struct inode *inode;
    struct file *file;
    void *exec_rows;
    __u32 idx, entry = TEGO_PLANE_RULE_NONE, best = TEGO_PLANE_RULE_NONE;
    int res;
    __u64 key;
    __u16 rule;
    __u8 ok = 0, reason;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted(TEGO_HOOK_BPRM_CHECK, (__u64)bprm->file);
        tego_exec_sample(run, bprm, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED);
        return -EACCES;
    }
    /* ADR 0048 P2: a pinned run's every exec is held to its pin first, deny-list runs and #! stages included. The
     * step only refuses; what it passes the steps below still decide. */
    if (hdr->flags & TEGO_SLOT_EXEC_PIN) {
        reason = tego_pin_bprm(run, hdr, bprm);
        if (reason) {
            tego_exec_sample(run, bprm, TEGO_PLANE_RULE_NONE, reason);
            return -EACCES;
        }
    }
    /* The header says the contract has no exec: section: exec is not decided. */
    if (!(hdr->flags & TEGO_SLOT_EXEC_DECIDES))
        return 0;
    __u8 anon_ok = (hdr->flags & TEGO_SLOT_EXEC_ANON) != 0;
    idx = run->run_idx;
    exec_rows = bpf_map_lookup_elem(&tego_plane_exec_rows, &idx);
    if (!exec_rows) {
        TEGO_PLANE_COUNT(run->run_idx, norows);
        tego_exec_sample(run, bprm, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED);
        return -EACCES;
    }
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        tego_exec_sample(run, bprm, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED);
        return -EACCES;
    }
    /* A #! stage passes: binfmt_script then opens the interpreter, whose own stage is decided here (R9). */
    if (bprm->buf[0] == '#' && bprm->buf[1] == '!') {
        tego_plane_record(sc, TEGO_HOOK_BPRM_CHECK, (__u64)bprm->file, TEGO_PLANE_RULE_NONE, 0);
        return 0;
    }
    file = bprm->file;
    dentry = file->f_path.dentry;
    inode = file->f_inode;
    if (tego_is_anonymous(dentry)) {
        reason = tego_plane_record(sc, TEGO_HOOK_BPRM_CHECK, (__u64)file, TEGO_PLANE_RULE_NONE,
                                    anon_ok ? 0 : TEGO_R_EXEC_NOT_ALLOWED);
        if (reason) {
            tego_exec_sample(run, bprm, TEGO_PLANE_RULE_NONE, reason);
            return -EACCES;
        }
        return 0;
    }
    key = tego_name_key(dentry, &nm);
    /* The file arm (tego_exec_file_row). */
    res = tego_exec_file_row(sc, exec_rows, run, dentry, inode, &nm, key, &rule);
    if (res < 0) {
        tego_plane_record(sc, TEGO_HOOK_BPRM_CHECK, (__u64)file, rule, TEGO_R_IDENTITY_MISMATCH);
        tego_exec_sample(run, bprm, rule, TEGO_R_IDENTITY_MISMATCH);
        return -EACCES;
    }
    if (res > 0)
        tego_exec_candidate(&entry, &best, &ok, rule, rule, 1);
    /* The name arm: an entry written as a bare name matches the final component wherever it lies. */
    r = bpf_map_lookup_elem(exec_rows, &key);
    if (r && r->gen == run->gen && tego_name_eq(&nm, r))
        tego_exec_candidate(&entry, &best, &ok, r->rule_idx, r->rule_idx, 1);
    /* Compare the directory's actual exec entry with the file/name arms, not its encoded filesystem row index.
     * The record retains the fs-row marker so its reader attributes the directory match through that row. */
    reason = tego_walk_failed(tego_plane_walk_path(sc, dentry, file->f_path.mnt, run, &hit));
    if (reason) {
        tego_plane_record(sc, TEGO_HOOK_BPRM_CHECK, (__u64)file, TEGO_PLANE_RULE_NONE, reason);
        tego_exec_sample(run, bprm, TEGO_PLANE_RULE_NONE, reason);
        return -EACCES;
    }
    if (hit.kind & TEGO_ROW_EXEC_DIR)
        tego_exec_candidate(&entry, &best, &ok, hit.exec_rule, TEGO_PLANE_RULE_FS_ROW | hit.rule_idx, 1);
    /* No arm matched: an unlisted file, a hard link under another name or in another directory, a directly invoked
     * loader. */
    if (!ok)
        best = TEGO_PLANE_RULE_NONE;
    if (tego_plane_record(sc, TEGO_HOOK_BPRM_CHECK, (__u64)file, best, ok ? 0 : TEGO_R_EXEC_NOT_ALLOWED)) {
        /* No recorder fexit wraps bprm_check, so the refusal's one ledger line is the plane's own sample (R23). */
        tego_exec_sample(run, bprm, best, TEGO_R_EXEC_NOT_ALLOWED);
        return -EACCES;
    }
    return 0;
}

TEGO_PLANE_HOOK(path_rename, path_rename, security_path_rename,
                 (const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
                  struct dentry *new_dentry),
                 (old_dir, old_dentry, new_dir, new_dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    __u32 sdepth, ddepth, rule = TEGO_PLANE_RULE_NONE, nrule = TEGO_PLANE_RULE_NONE;
    __u64 settled;
    __u16 srule, drule;
    __u8 skind, dkind, reason = 0;
    int positive, odir, ndir, files, dirs, res = TEGO_NAME_NONE;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    /* security_path_rename's IS_PRIVATE exit: a negative destination has no inode, which tego_is_private reads as
     * not private. */
    if (mode == TEGO_PLANE_FMOD_RET && (tego_is_private(old_dentry) || tego_is_private(new_dentry)))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_RENAME, (__u64)old_dentry, old_dentry, 0);
        return -EACCES;
    }
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        tego_plane_fallback(run, TEGO_HOOK_PATH_RENAME, old_dentry, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, 0);
        return -EACCES;
    }
    /* ADR 0043: a rename that moves a file (either object, under RENAME_EXCHANGE) asks the name check at both ends (D1:
     * a covered file's rename is a modification at either end); one that moves a directory asks D5 of that direction.
     * The objects' kinds are read back through the task's scratch value (tego_plane_unknown): known to the verifier,
     * each combination of them made the rest of the body a pass of its own (path_rename's verification, 6.17, 94 to
     * 104 ms with them known, 32 to 39 with them read back; 17 to 23 before the name entries). Whether the destination
     * is positive is tego_positive's run-time test (a verifier that holds d_inode never NULL would read it as 1). */
    positive = tego_positive(sc, new_dentry);
    odir = tego_is_dir(old_dentry->d_inode);
    ndir = positive && tego_is_dir(new_dentry->d_inode);
    files = !odir || (positive && !ndir);
    dirs = odir || ndir;
    {
        __u64 kinds = tego_plane_unknown(sc, (__u64)positive | (__u64)odir << 1 | (__u64)ndir << 2 |
                                                  (__u64)files << 3 | (__u64)dirs << 4);

        positive = kinds & 1;
        odir = (kinds >> 1) & 1;
        ndir = (kinds >> 2) & 1;
        files = (kinds >> 3) & 1;
        dirs = (kinds >> 4) & 1;
    }
    /* Both ends are renames of themselves (decide.PlaneRows.Decide, PlaneRename): a deny_write target or an ancestor
     * at depth 0 refuses, else the modification decides, then a covered file's name (decide.PlaneRows.DecideObject).
     * A negative destination's walk starts at its directory. Then REFER (R10): the source's nearest row may not be
     * stricter than the destination's; and, for a positive destination, which RENAME_EXCHANGE moves the other way
     * (the 5.14 hook carries no flag), not the reverse. Then D5 for a directory. The order is
     * decide.PlaneEvaluator.rename's, so a refusal names the entry the model names. */
    if ((reason = tego_walk_failed(tego_nearest(sc, old_dentry, old_dir->mnt, run, &skind, &srule, &sdepth))) ||
        (reason = tego_walk_failed(tego_nearest(sc, new_dentry, new_dir->mnt, run, &dkind, &drule, &ddepth)))) {
        rule = TEGO_PLANE_RULE_NONE;
    } else if ((reason = tego_rename_end(skind, sdepth))) {
        rule = srule;
    } else if (files && tego_names_on(hdr) &&
               (res = tego_name_check_path(sc, old_dentry, old_dir->mnt, run, &nrule)) != TEGO_NAME_NONE) {
        reason = res == TEGO_NAME_DENY ? TEGO_R_RENAME_OUTSIDE_CONTRACT : tego_walk_failed(res);
        rule = res == TEGO_NAME_DENY ? nrule : TEGO_PLANE_RULE_NONE;
    } else if ((reason = tego_rename_end(dkind, ddepth))) {
        rule = drule;
    } else if (files && tego_names_on(hdr) &&
               (res = tego_name_check_path(sc, new_dentry, new_dir->mnt, run, &nrule)) != TEGO_NAME_NONE) {
        reason = res == TEGO_NAME_DENY ? TEGO_R_RENAME_OUTSIDE_CONTRACT : tego_walk_failed(res);
        rule = res == TEGO_NAME_DENY ? nrule : TEGO_PLANE_RULE_NONE;
    } else if (tego_strictness(skind) > tego_strictness(dkind)) {
        reason = TEGO_R_REFER;
        rule = srule;
    } else if (positive && tego_strictness(dkind) > tego_strictness(skind)) {
        reason = TEGO_R_REFER;
        rule = drule;
    } else if (dirs && tego_names_on(hdr) &&
               (res = tego_name_move_path(sc, old_dentry, old_dir, odir, new_dentry, new_dir, ndir, run, &nrule)) !=
                   TEGO_NAME_NONE) {
        /* D5: the directory would take covered files out of coverage (rename-outside-contract, plane_reason refer). */
        reason = res == TEGO_NAME_DENY ? TEGO_R_REFER : tego_walk_failed(res);
        rule = res == TEGO_NAME_DENY ? nrule : TEGO_PLANE_RULE_NONE;
    } else {
        rule = srule;
    }
    if (tego_builtin_name(run,old_dentry,&rule) || tego_builtin_name(run,new_dentry,&rule))
        reason = TEGO_R_RENAME_OUTSIDE_CONTRACT;
    settled = tego_plane_settle(sc, reason, rule);
    reason = settled >> 32;
    rule = (__u32)settled;
    if (tego_plane_record(sc, TEGO_HOOK_PATH_RENAME, (__u64)old_dentry, rule, reason)) {
        tego_plane_fallback(run, TEGO_HOOK_PATH_RENAME, old_dentry, rule, reason, 0);
        return -EACCES;
    }
    return 0;
}

TEGO_PLANE_HOOK(path_link, path_link, security_path_link,
                 (struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry),
                 (old_dentry, new_dir, new_dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    __u32 sdepth, ddepth, rule = TEGO_PLANE_RULE_NONE, nrule = TEGO_PLANE_RULE_NONE;
    __u64 settled;
    __u16 srule, drule;
    __u8 skind, dkind, reason = 0;
    int file, res = TEGO_NAME_NONE;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(old_dentry))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_LINK, (__u64)new_dentry, old_dentry, 0);
        return -EACCES;
    }
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        tego_plane_fallback(run, TEGO_HOOK_PATH_LINK, old_dentry, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, 0);
        return -EACCES;
    }
    /* The new name is a creation in its directory (new_dentry is negative, so its walk starts there), and a creation
     * at a covered name is refused as one (ADR 0043 D1); REFER then holds the source's nearest row to be no stricter
     * than the destination's: a second name for a file under a deny_read or a deny_write target outside it (R10,
     * supervisor.md R15c) is refused, and a covered source is as strict as a deny_read (D1, strictness 2). A
     * directory is never linked, and a name entry decides none. */
    file = tego_plane_unknown(sc, !tego_is_dir(old_dentry->d_inode)) & 1; /* read back, as path_rename's kinds are */
    if ((reason = tego_walk_failed(tego_nearest(sc, old_dentry, new_dir->mnt, run, &skind, &srule, &sdepth))) ||
        (reason = tego_walk_failed(tego_nearest(sc, new_dentry, new_dir->mnt, run, &dkind, &drule, &ddepth)))) {
        rule = TEGO_PLANE_RULE_NONE;
    } else if (!(dkind & TEGO_ROW_MODIFY_ALLOW)) {
        reason = TEGO_R_WRITE_OUTSIDE_CONTRACT;
        rule = drule;
    } else if (file && tego_names_on(hdr) &&
               (res = tego_name_check_path(sc, new_dentry, new_dir->mnt, run, &nrule)) != TEGO_NAME_NONE) {
        reason = res == TEGO_NAME_DENY ? TEGO_R_WRITE_OUTSIDE_CONTRACT : tego_walk_failed(res);
        rule = res == TEGO_NAME_DENY ? nrule : TEGO_PLANE_RULE_NONE;
    } else if (tego_strictness(skind) > tego_strictness(dkind)) {
        reason = TEGO_R_REFER;
        rule = srule;
    } else if (file && tego_strictness(dkind) < 2 && tego_names_on(hdr) &&
               (res = tego_name_check_path(sc, old_dentry, new_dir->mnt, run, &nrule)) != TEGO_NAME_NONE) {
        reason = res == TEGO_NAME_DENY ? TEGO_R_REFER : tego_walk_failed(res);
        rule = res == TEGO_NAME_DENY ? nrule : TEGO_PLANE_RULE_NONE;
    } else {
        rule = drule;
    }
    if (tego_builtin_name(run,old_dentry,&rule) || tego_builtin_name(run,new_dentry,&rule))
        reason = TEGO_R_WRITE_OUTSIDE_CONTRACT;
    settled = tego_plane_settle(sc, reason, rule);
    reason = settled >> 32;
    rule = (__u32)settled;
    if (tego_plane_record(sc, TEGO_HOOK_PATH_LINK, (__u64)new_dentry, rule, reason)) {
        /* Named by its source, as the recorder's link line names it first. */
        tego_plane_fallback(run, TEGO_HOOK_PATH_LINK, old_dentry, rule, reason, 0);
        return -EACCES;
    }
    return 0;
}

/* A modification at dentry on mnt (decide.PlaneRows.Decide, PlaneModify): unlink and rmdir, step B's creates and
 * truncates. The crossing walk's nearest row must carry TEGO_ROW_MODIFY_ALLOW, a deny_write target's row included
 * refusing; anything else refuses with refuse_as, a walk that failed closed with its own reason and a missing scratch
 * value with PATH_UNRESOLVED. Where the walk allows and names is set, a file the hook modifies (not a directory) is
 * then asked of the name entries (ADR 0043 D1): a covered file is refused with refuse_as and its entry's rule (D8).
 * names is set by the hooks that modify a file's content or name: unlink, mknod, symlink and the truncates; never by
 * mkdir and rmdir, whose object is a directory. Recorded under hook on obj; every refusal takes the record fallback
 * (T9b). Returns the reason, 0 for an allow. */
static __always_inline __u8 tego_modify_hook(struct dentry *dentry, struct vfsmount *mnt, struct tego_run *run,
                                              const struct tego_plane_slot *hdr, int names, __u16 hook, __u64 obj,
                                              __u8 refuse_as)
{
    struct tego_plane_decision *sc = tego_plane_scratch_get();
    __u32 depth, rule32, nrule = TEGO_PLANE_RULE_NONE;
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u64 settled;
    __u8 kind, reason;
    int res;

    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        tego_plane_fallback(run, hook, dentry, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, 0);
        return TEGO_R_PATH_UNRESOLVED;
    }
    reason = tego_walk_failed(tego_nearest(sc, dentry, mnt, run, &kind, &rule, &depth));
    rule32 = rule;
    if (!reason && !(kind & TEGO_ROW_MODIFY_ALLOW))
        reason = refuse_as;
    else if (!reason && names && !tego_is_dir(dentry->d_inode) && tego_names_on(hdr) &&
             (res = tego_name_check_path(sc, dentry, mnt, run, &nrule)) != TEGO_NAME_NONE) {
        reason = res == TEGO_NAME_DENY ? refuse_as : tego_walk_failed(res);
        rule32 = res == TEGO_NAME_DENY ? nrule : TEGO_PLANE_RULE_NONE;
    }
    if (tego_builtin_name(run,dentry,&rule32))
        reason = refuse_as;
    settled = tego_plane_settle(sc, reason, rule32);
    reason = settled >> 32;
    rule32 = (__u32)settled;
    reason = tego_plane_record(sc, hook, obj, rule32, reason);
    if (reason && !(hook == TEGO_HOOK_PATH_MKNOD && sc->listen_sock && sc->bind.op == TEGO_EV_BIND_RESULT &&
                    sc->listen_run_idx == run->run_idx && sc->listen_gen == run->gen))
        tego_plane_fallback(run, hook, dentry, rule32, reason, 0);
    return reason;
}

TEGO_PLANE_HOOK(path_unlink, path_unlink, security_path_unlink, (const struct path *dir, struct dentry *dentry),
                 (dir, dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(dir->dentry))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_UNLINK, (__u64)dentry, dentry, 0);
        return -EACCES;
    }
    if (tego_modify_hook(dentry, dir->mnt, run, hdr, 1, TEGO_HOOK_PATH_UNLINK, (__u64)dentry,
                          TEGO_R_DELETE_OUTSIDE_CONTRACT))
        return -EACCES;
    return 0;
}

TEGO_PLANE_HOOK(path_rmdir, path_rmdir, security_path_rmdir, (const struct path *dir, struct dentry *dentry),
                 (dir, dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(dir->dentry))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_RMDIR, (__u64)dentry, dentry, 0);
        return -EACCES;
    }
    /* A directory's removal: no name entry decides it (ADR 0043 D1). */
    if (tego_modify_hook(dentry, dir->mnt, run, hdr, 0, TEGO_HOOK_PATH_RMDIR, (__u64)dentry,
                          TEGO_R_DELETE_OUTSIDE_CONTRACT))
        return -EACCES;
    return 0;
}

/* ---- Step D hooks: unix names below 6.7 (TIER3-PLAN §2; enforce-plane R14) ----
 *
 * Below 6.7 there is no cgroup/connect_unix or sendmsg_unix, so tier 2 decides no unix name in the kernel. These two
 * hooks decide them where a plane mode runs, by the rule and from the rows connect_unix and sendmsg_unix use on 6.7+
 * (cgroup_net.bpf.c tego_unix_decide, enforce-cgroup-observe §5 R7): the name the caller passed, in the kernel's own
 * copy of its sockaddr_un (move_addr_to_kernel's, or ____sys_sendmsg's copy of msg_name), which no thread of the
 * caller can rewrite after the hook reads it, looked up in tego_unix_names, which Prepare fills on every kernel. The
 * loader loads them only where cgroup/connect_unix is absent (bpf.PlaneHook.Unix), so no name is decided twice.
 *
 * socket_connect and socket_sendmsg rather than unix_stream_connect and unix_may_send (ADR 0024's step D list): those
 * two run after the path lookup and see the peer socket, not the name the contract's rows are keyed by, and
 * unix_may_send runs for every datagram of a connected socket as well. security_socket_connect runs before the
 * protocol's connect and security_socket_sendmsg before unix_dgram_sendmsg, so each sees what the cgroup hook sees.
 *
 * The run is the socket's, not the caller's: the supervisor relays every unix connect of the agent from the
 * launcher's cgroup on a pidfd_getfd duplicate of the agent's socket (supervisor.md R11), which cgroup/connect_unix
 * reaches through the attachment on the socket's cgroup; here the socket's cgroup is looked up in the run set. The
 * caller's cgroup is read only to recognise the relay's /proc/self/fd/<n> name, as tego_unix_relayed does.
 *
 * Each decision is recorded in the task's scratch value like every plane decision (ADR 0024 (11)); no sample is
 * written, as cgroup_net's unix programs write none: a connect's or datagram's one ledger line is the supervisor's
 * (enforce-cgroup-observe §5 R7, supervisor R13b). */

/* The run of the unix socket sock, by the cgroup the socket was created in (sk_cgrp_data, fixed at creation), or
 * NULL for a socket of another family or of no run. */
static __always_inline struct tego_run *tego_unix_sock_run(void *run_set, struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct cgroup *cg;

    if (!sk || sk->__sk_common.skc_family != TEGO_AF_UNIX)
        return 0;
    cg = sk->sk_cgrp_data.cgroup;
    if (!cg)
        return 0;
    return tego_run_lookup(run_set, cg->kn->id);
}

/* The slot's unix policy of the run's gen, or NULL: a previous run's, or none, which the hooks refuse. */
static __always_inline struct tego_plane_unix *tego_plane_unix_of(const struct tego_run *run)
{
    __u32 idx = run->run_idx;
    struct tego_plane_unix *pol = bpf_map_lookup_elem(&tego_plane_unix_policy, &idx);

    if (!pol || pol->gen != run->gen)
        return 0;
    return pol;
}

/* Builds the tego_unix_names key of the sockaddr_un at addr (a kernel copy, alen bytes long) as cgroup_net.bpf.c's
 * tego_unix_key_of does, and returns its kind, or 0 for a length no valid address has (refused; the kernel would
 * answer EINVAL after this hook). The name is read through the build's reader: bpf_rdonly_cast's untrusted pointer,
 * byte by byte at constant offsets, or one bpf_probe_read_kernel of the whole sun_path (the kernel's copy lives in a
 * sockaddr_storage, 128 bytes, so the read stays inside it). The header goes in before the name, for the verifier's
 * reason tego_unix_key_of gives. */
static __always_inline int tego_plane_unix_key(struct tego_unix_key *k, __u64 addr, __u32 alen, __u32 run_idx)
{
    __u32 n;
    __u8 first = 0;
    int abstract;

    __builtin_memset(k, 0, sizeof(*k));
    k->prefixlen = TEGO_UNIX_MAX_BITS;
    k->run_idx = run_idx;
    if (alen <= TEGO_SUN_PATH_OFF || alen > TEGO_SUN_PATH_OFF + TEGO_UNIX_NAME_MAX)
        return 0;
    n = alen - TEGO_SUN_PATH_OFF;
#if TEGO_PLANE_RDONLY
    struct sockaddr_un *un = bpf_core_cast((void *)addr, struct sockaddr_un);
    __u32 i;

    first = un->sun_path[0];
    abstract = first == 0;
    k->kind = abstract ? TEGO_UNIX_ABSTRACT : TEGO_UNIX_PATH;
    k->len = abstract ? (__u8)n : 0;
#pragma unroll
    for (i = 0; i < TEGO_UNIX_NAME_MAX; i++)
        k->name[i] = un->sun_path[i];
#else
    if (bpf_probe_read_kernel(&first, 1, (void *)(addr + TEGO_SUN_PATH_OFF)))
        return 0;
    abstract = first == 0;
    k->kind = abstract ? TEGO_UNIX_ABSTRACT : TEGO_UNIX_PATH;
    k->len = abstract ? (__u8)n : 0;
    if (bpf_probe_read_kernel(k->name, TEGO_UNIX_NAME_MAX, (void *)(addr + TEGO_SUN_PATH_OFF)))
        return 0;
#endif
    if (abstract)
        return TEGO_UNIX_ABSTRACT;
    if (n < TEGO_UNIX_NAME_MAX)
        k->name[n] = 0;
    return TEGO_UNIX_PATH;
}

/* The canonical check (common.h tego_unix_canon_byte) over a pathname's bytes, read in place: the kernel's copy of
 * sun_path at addr + TEGO_SUN_PATH_OFF, n bytes long. One bpf_loop callback, verified once, reads each byte through
 * the build's reader.
 *
 * The state starts from the slot policy's zero byte, not from a constant. A verifier before 6.8's "verify callbacks
 * as if they are called unknown number of times" (AL2023's 6.1; RHEL 9.8's 5.14 carries the fix) verifies the
 * callback once, from the state it is first called with: st a known 0 there, the branches of tego_unix_canon_byte
 * that need another st were taken for dead and hard-wired, every "/tmp/..." was refused at its second '/', and the
 * helper's cells caught it (T15, in the guest). A map byte is a value no verifier assumes. */
struct tego_unix_canon {
    __u64 addr;
    __u32 n;
    __u32 st;
    __u32 ok;
    __u32 pad;
};

static long tego_unix_canon_step(__u32 i, struct tego_unix_canon *c)
{
    __u32 j = i + 1;
    __u8 ch = 0;
    int r;

    if (j < c->n) {
        __u64 w = TEGO_RD_WORD(c->addr + TEGO_SUN_PATH_OFF + j);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        ch = (__u8)w;
#else
        ch = (__u8)(w >> 56);
#endif
    }
    r = tego_unix_canon_byte(&c->st, ch, j);
    if (r) {
        c->ok = r > 0;
        return 1;
    }
    return 0;
}

/* Whether the pathname of alen bytes' sockaddr_un at addr is spelled canonically (common.h tego_unix_canonical). */
static __always_inline int tego_plane_unix_canonical(__u64 addr, __u32 alen, const struct tego_plane_unix *pol)
{
    struct tego_unix_canon c = {};

    c.addr = addr;
    c.n = alen - TEGO_SUN_PATH_OFF;
    c.st = pol->zero;
    c.ok = pol->zero;
    bpf_loop(TEGO_UNIX_NAME_MAX, tego_unix_canon_step, &c, 0);
    return c.ok == 1;
}

/* tego_unix_decide's decision on the address at addr: 0 to allow or TEGO_R_NET_NOT_ALLOWED, and in *rule the
 * matching row's rule_idx (TEGO_PLANE_RULE_NONE for none):
 *   - an abstract name is admitted when a unix: entry names exactly its bytes;
 *   - a relative name resolves against a cwd no program can read: a datagram's is left to tier 1, which records it
 *     (supervisor R13b), and a connect's is refused, since the supervisor relays every connect by the inode it
 *     resolved and never passes a relative name on;
 *   - /proc/self/fd/<n> is admitted on a connect from the launcher's cgroup (pol->relay_cgroup_id), the relay's;
 *   - any other absolute name is admitted when spelled canonically and a unix: entry or a write entry admits it;
 *   - an abstract name no entry admits is admitted on a connect that consumes the one-connect grant of a person's
 *     approval for the socket whose cookie is cookie (supervisor R11c, tego_unix_approved; 0 for a datagram). */
static __always_inline __u8 tego_plane_unix_reason(const struct tego_run *run, const struct tego_plane_unix *pol,
                                                    __u64 addr, __u32 alen, __u8 op, __u64 cookie, __u16 *rule)
{
    struct tego_unix_key key;
    struct tego_unix_key *k = &key;
    struct tego_net_verdict *v = 0;
    __u32 idx = run->run_idx;
    int kind = tego_plane_unix_key(k, addr, alen, idx);

    *rule = TEGO_PLANE_RULE_NONE;
    if (kind == TEGO_UNIX_PATH && k->name[0] != '/')
        return op == TEGO_EV_SENDMSG ? 0 : TEGO_R_NET_NOT_ALLOWED;
    if (kind == TEGO_UNIX_PATH && op == TEGO_EV_CONNECT && pol->relay_cgroup_id != 0 &&
        bpf_get_current_cgroup_id() == pol->relay_cgroup_id && tego_unix_relay_name(k->name))
        return 0;
    if (kind == TEGO_UNIX_ABSTRACT ||
        (kind == TEGO_UNIX_PATH && tego_plane_unix_canonical(addr, alen, pol)))
        v = bpf_map_lookup_elem(&tego_unix_names, k);
    if (v && v->verdict == TEGO_V_ALLOW) {
        *rule = v->rule_idx;
        return 0;
    }
    if (kind == TEGO_UNIX_ABSTRACT && op == TEGO_EV_CONNECT && tego_unix_approved(run->run_idx, run->gen, cookie, k))
        return 0;
    if (v)
        *rule = v->rule_idx;
    return TEGO_R_NET_NOT_ALLOWED;
}

/* The cookie of the unix socket sock (sock_gen_cookie's, which the supervisor's SO_COOKIE made before it granted the
 * socket an approval), or 0 for none yet: read from the socket, as the run is (tego_unix_sock_run). */
static __always_inline __u64 tego_unix_sock_cookie(struct socket *sock)
{
    struct sock *sk = sock->sk;

    if (!sk)
        return 0;
    return (__u64)sk->__sk_common.skc_cookie.counter;
}

TEGO_PLANE_HOOK(socket_connect, socket_connect, security_socket_connect,
                 (struct socket *sock, struct sockaddr *address, int addrlen), (sock, address, addrlen))
{
    struct tego_run *run = tego_unix_sock_run(&tego_run_set, sock);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    struct tego_plane_unix *pol;
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u8 reason;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    /* A datagram socket's AF_UNSPEC connect dissolves its association, and unix_dgram_connect decides no name for
     * it; a stream socket's is refused EINVAL by unix_validate_addr. */
    if (addrlen < 2 || address->sa_family != TEGO_AF_UNIX)
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted(TEGO_HOOK_SOCKET_CONNECT, (__u64)sock);
        return -EACCES;
    }
    /* The header says whether the plane decides this run's unix names (a net: section, below 6.7). */
    if (!(hdr->flags & TEGO_SLOT_UNIX_DECIDES))
        return 0;
    pol = tego_plane_unix_of(run);
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        return -EACCES;
    }
    if (!pol) {
        TEGO_PLANE_COUNT(run->run_idx, norows);
        reason = TEGO_R_PATH_UNRESOLVED;
    } else {
        reason = tego_plane_unix_reason(run, pol, (__u64)address, addrlen, TEGO_EV_CONNECT,
                                         tego_unix_sock_cookie(sock), &rule);
    }
    if (tego_plane_record(sc, TEGO_HOOK_SOCKET_CONNECT, (__u64)sock, rule, reason))
        return -EACCES;
    return 0;
}

TEGO_PLANE_HOOK(socket_sendmsg, socket_sendmsg, security_socket_sendmsg, (struct socket *sock, struct msghdr *msg),
                 (sock, msg))
{
    struct tego_run *run = tego_unix_sock_run(&tego_run_set, sock);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    struct tego_plane_unix *pol;
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u32 alen;
    __u64 name;
    __u8 reason;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    /* Only an addressed datagram names a destination: unix_dgram_sendmsg runs sendmsg_unix for one whose
     * msg_namelen is not 0; a seqpacket send ignores its address and a stream send with one fails. */
    if (sock->type != TEGO_SOCK_DGRAM)
        return 0;
    alen = (__u32)msg->msg_namelen;
    name = (__u64)msg->msg_name;
    if (!alen || !name)
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted(TEGO_HOOK_SOCKET_SENDMSG, (__u64)sock);
        return -EACCES;
    }
    /* The header says whether the plane decides this run's unix names (a net: section, below 6.7). */
    if (!(hdr->flags & TEGO_SLOT_UNIX_DECIDES))
        return 0;
    pol = tego_plane_unix_of(run);
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        return -EACCES;
    }
    if (!pol) {
        TEGO_PLANE_COUNT(run->run_idx, norows);
        reason = TEGO_R_PATH_UNRESOLVED;
    } else {
        reason = tego_plane_unix_reason(run, pol, name, alen, TEGO_EV_SENDMSG, 0, &rule);
    }
    if (tego_plane_record(sc, TEGO_HOOK_SOCKET_SENDMSG, (__u64)sock, rule, reason))
        return -EACCES;
    return 0;
}

/* Step B (TIER3-PLAN T13): the create, truncate, attribute and socket hooks, in their own file. */
#include "decide_socket.h"
#include "decide_stepb.h"

/* Step C (TIER3-PLAN T14): the PROT_EXEC mapping hooks, in their own file. */
#include "decide_stepc.h"

#include "decide_control.h"

#include "decide_listen.h"

/* No recorder fexit wraps unix_may_send. Its named sample has one owner,
 * regardless of the filesystem recorder mask. */
static __always_inline void tego_builtin_peer_sample(const struct tego_run *run, struct dentry *dentry, __u32 rule)
{
    tego_plane_fallback_sample(run,
        TEGO_RD_WORD((__u64)dentry + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, name)),
        dentry->d_parent->d_inode->i_ino,
        (__u64)rule | (__u64)TEGO_R_NET_NOT_ALLOWED << 32 | (__u64)TEGO_HOOK_UNIX_MAY_SEND << 40,
        (__u64)dentry->d_sb->s_dev << 32);
}

/* ADR 0113: raw sockaddr checks cannot recognize a pre-existing alias after a
 * sibling changes an admitted datagram's address/descriptor. This hook sees
 * the actual bound peer, including connected sends with no msg_name. */
TEGO_PLANE_HOOK(unix_may_send, unix_may_send, security_unix_may_send,
                 (struct socket *sock, struct socket *other), (sock, other))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    struct path path = {};
    struct sock *sk;
    __u32 rule = TEGO_PLANE_RULE_BUILTIN_HOST;
    struct tego_plane_hit hit = {};
    int match;

    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted(TEGO_HOOK_UNIX_MAY_SEND, (__u64)other);
        return -EACCES;
    }
    if (!(hdr->flags & TEGO_SLOT_BUILTIN_TTY))
        return 0;
    sc = tego_plane_scratch_get();
    if (!sc)
        return -EACCES;
    /* A single decision pass; every failure reaches one sampled refusal. */
    do {
        sk = other->sk;
        if (!sk)
            break;
    #if TEGO_PLANE_RDONLY
        struct unix_sock *peer = bpf_core_cast(sk, struct unix_sock);
        path.dentry = peer->path.dentry;
        path.mnt = peer->path.mnt;
    #else
        if (bpf_core_read(&path, sizeof(path), &((struct unix_sock *)sk)->path))
            break;
    #endif
        /* Abstract/unnamed peers have no filesystem path. The inherited abstract
         * scope is the authority for them. A partial path is uncertainty. */
        if (!path.dentry && !path.mnt)
            return 0;
        if (!path.dentry || !path.mnt)
            break;
        match = tego_builtin_name_decision(run, path.dentry, &rule, 1);
        if (match == 2)
            return 0; /* own runtime, even a linked run-created socket */
        if (path.dentry->d_inode->i_nlink > 1) {
            rule = TEGO_PLANE_RULE_BUILTIN_HOST;
            break;
        }
        if (match == 3)
            return 0;
        if (match == 1)
            break;
        rule = TEGO_PLANE_RULE_BUILTIN_HOST;
        if (tego_walk_failed(tego_plane_walk_path(sc, path.dentry, path.mnt, run, &hit)))
            break;
        if ((hit.pad2 & 1) && tego_builtin_control_name(path.dentry)) {
            rule = TEGO_PLANE_RULE_BUILTIN_SURFACE;
            break;
        }
        if (!(hit.kind & TEGO_ROW_BUILTIN_IPC))
            return 0;
        rule = hit.rule_idx;
    } while (0);
    tego_plane_record(sc, TEGO_HOOK_UNIX_MAY_SEND, (__u64)other, rule, TEGO_R_NET_NOT_ALLOWED);
    if (path.dentry)
        tego_builtin_peer_sample(run, path.dentry, rule);
    return -EACCES;
}
