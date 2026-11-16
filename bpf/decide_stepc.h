// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* ---- Step C hooks: PROT_EXEC mappings (ADR 0027; TIER3-PLAN T14; docs/p0/enforce-plane.md R26) ----
 *
 * Included at the end of decide.bpf.c, after the walk, the exec arms and the recorder's scratch, which these bodies
 * reuse. With an exec: section (the slot header's TEGO_SLOT_EXEC_DECIDES), a mapping that is or becomes executable is
 * refused (reason exec-not-allowed) when:
 *   (a) its file is anonymous (a memfd, an unlinked file, an SB_NOUSER superblock) and exec.anonymous is not set;
 *   (b) its file's nearest fs row allows a modification (a write entry: code the agent could have written there)
 *       and no exec.allow entry covers it: not an exec.allow directory above it (PlaneExecDir), not its own exec row
 *       under its name in its directory, not a name row (bprm_check's three arms, so whatever the plane lets run the
 *       ELF loader may map, and a library under a write entry needs an exec.allow directory as a binary does);
 *   (c) SELinux's execmem and execmod for files: a private file mapping that is writable and executable, and an
 *       mprotect that makes a private file mapping with copy-on-write pages (anon_vma, text relocations)
 *       executable.
 * A readable file under no write entry maps as before: the loader's own maps of a system binary and its libraries
 * meet no row, or a row that refuses modifications, and pass. An inode the kernel marks private (S_PRIVATE: the
 * shmem file behind a MAP_SHARED|MAP_ANONYMOUS region, a SysV shm segment) is anonymous memory, not a file, and stays
 * GAPS A2 as MAP_ANONYMOUS does.
 *
 * Both bodies return 0 before the run-set lookup when there is no file or no PROT_EXEC, so a host process pays one
 * branch on an anonymous or non-executable map. Both decide on the effective prot: mmap_file's LSM hook is handed
 * mmap_prot(file, reqprot) (READ_IMPLIES_EXEC adds PROT_EXEC to a PROT_READ map on a mount that is not noexec), which
 * the fmod_ret program, attached to security_mmap_file ahead of that computation, reproduces (enforce-plane R4);
 * file_mprotect's hook is handed that prot in both modes (ADR 0027's 2026-09-29 amendment).
 *
 * mmap_file's hook and its security_ function take different arguments: bpf_lsm_mmap_file(file, reqprot, prot,
 * flags) and security_mmap_file(file, prot, flags). One body reads both from four u64 parameters by mode; in fmod_ret
 * mode the fourth is the trailing return slot, which the body never reads (enforce-plane §2.14). */

#define TEGO_PROT_READ 0x1
#define TEGO_PROT_WRITE 0x2
#define TEGO_PROT_EXEC 0x4
#define TEGO_MAP_TYPE 0x0f
#define TEGO_MAP_PRIVATE 0x02
#define TEGO_READ_IMPLIES_EXEC 0x0400000
#define TEGO_MNT_NOEXEC 0x04
#define TEGO_SB_I_NOEXEC 0x02
#define TEGO_VM_EXEC 0x04
#define TEGO_VM_SHARED 0x08

/* mmap_prot(): the prot security_mmap_file hands its LSM hooks (include/linux/security.h, 5.14 through 7.0). */
static __always_inline __u64 tego_mmap_prot(struct file *file, __u64 prot)
{
    struct task_struct *t;

    if ((prot & (TEGO_PROT_READ | TEGO_PROT_EXEC)) != TEGO_PROT_READ)
        return prot;
    t = bpf_get_current_task_btf();
    if (!(t->personality & TEGO_READ_IMPLIES_EXEC))
        return prot;
    if (!file)
        return prot | TEGO_PROT_EXEC;
    if ((file->f_path.mnt->mnt_flags & TEGO_MNT_NOEXEC) || (file->f_path.mnt->mnt_sb->s_iflags & TEGO_SB_I_NOEXEC))
        return prot;
    return prot | TEGO_PROT_EXEC;
}

/* A backing file's user path (6.8+, where f_path is the real layer's path and struct backing_file carries the path
 * the user mapped, backing_file_user_path()), read through the build's reader: bpf_rdonly_cast, or CO-RE probe reads.
 * Before 6.8 a backing file's f_path is the user path already (6.6, 6.7), or no backing file exists. */
#if TEGO_PLANE_RDONLY
#define TEGO_BF_USER_DENTRY(f) ((__u64)bpf_core_cast((void *)(f), struct backing_file)->user_path.dentry)
#define TEGO_BF_USER_MNT(f) ((__u64)bpf_core_cast((void *)(f), struct backing_file)->user_path.mnt)
#else
#define TEGO_BF_USER_DENTRY(f)                                                                                    \
    tego_rd64((__u64)(f) + bpf_core_field_offset(struct backing_file, user_path) +                               \
               bpf_core_field_offset(struct path, dentry))
#define TEGO_BF_USER_MNT(f)                                                                                       \
    tego_rd64((__u64)(f) + bpf_core_field_offset(struct backing_file, user_path) +                               \
               bpf_core_field_offset(struct path, mnt))
#endif

/* Whether an exec row of this run covers the file at dentry, whose inode is inode: bprm_check's file arm
 * (tego_exec_file_row, the row of this link) or its name arm (a bare name, wherever it lies). Returns 1 for a match,
 * 0 for none, and -1 for a row whose inode no longer carries its identity (counted). */
static __always_inline int tego_map_exec_row(struct tego_plane_decision *sc, void *exec_rows,
                                              const struct tego_run *run, struct dentry *dentry, struct inode *inode,
                                              __u16 *rule)
{
    struct tego_name_pass nm = {};
    struct tego_plane_exec_row *r;
    __u64 key = tego_name_key(dentry, &nm);
    int res;

    res = tego_exec_file_row(sc, exec_rows, run, dentry, inode, &nm, key, rule);
    if (res)
        return res;
    r = bpf_map_lookup_elem(exec_rows, &key);
    if (r && r->gen == run->gen && tego_name_eq(&nm, r)) {
        *rule = r->rule_idx;
        return 1;
    }
    return 0;
}

/* A refusal's one ledger line (R23): no recorder fexit wraps mmap_file or file_mprotect, so the plane writes its own
 * sample, TEGO_EV_PLANE_MAP, naming the file as an attribute change's sample does (its directory's dev and ino and
 * its final component) when named is set, and with no name for a file no path names. Returns -EACCES. */
static __always_inline int tego_map_refuse(const struct tego_run *run, struct file *file, __u16 hook, __u16 rule,
                                            __u8 reason, int named)
{
    struct tego_plane_sample_args a = {};
    struct dentry *dentry = file->f_path.dentry;

    a.kind = TEGO_EV_PLANE_MAP;
    a.hook = hook;
    a.rule = rule;
    a.reason = reason;
    if (named) {
        a.named = 1;
        a.name = (__u64)dentry->d_name.name;
        a.dev = dentry->d_sb->s_dev;
        a.dir_ino = dentry->d_parent->d_inode->i_ino;
    }
    tego_plane_own_sample(run, &a);
    return -EACCES;
}

/* The decision on an executable mapping of file by run, whose slot header the body read (hdr, NULL for none of the
 * run's gen), recorded under hook on obj; wx is (c): a writable and executable private mapping, or copy-on-write
 * pages made executable. Returns 0 or -EACCES; every refusal writes the plane's own sample (tego_map_refuse). */
static __always_inline int tego_map_decide(const struct tego_run *run, const struct tego_plane_slot *hdr,
                                            struct file *file, int wx, __u16 hook, __u64 obj)
{
    struct tego_plane_decision *sc;
    struct tego_plane_hit h = {};
    struct dentry *dentry;
    struct inode *inode = file->f_inode;
    void *exec_rows;
    __u32 idx = run->run_idx, depth;
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u8 kind, reason;
    int res;

    if (!hdr) {
        tego_plane_unslotted(hook, obj);
        return tego_map_refuse(run, file, hook, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, 0);
    }
    /* The header says the contract has no exec: section: no mapping is decided. */
    if (!(hdr->flags & TEGO_SLOT_EXEC_DECIDES))
        return 0;
    /* The shmem file behind shared anonymous memory or a SysV segment: anonymous memory, not a file (GAPS A2). */
    if (inode && (inode->i_flags & TEGO_S_PRIVATE))
        return 0;
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        return tego_map_refuse(run, file, hook, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, 0);
    }
    exec_rows = bpf_map_lookup_elem(&tego_plane_exec_rows, &idx);
    if (!exec_rows) {
        TEGO_PLANE_COUNT(run->run_idx, norows);
        tego_plane_record(sc, hook, obj, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED);
        return tego_map_refuse(run, file, hook, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, 0);
    }
    /* A backing file on 6.8+ (an overlay mapping mprotected): walk from the path the user mapped. No exec row names
     * the real layer's inode, so only the fs rows decide: a write row with no exec.allow directory refuses. Its
     * f_path is the real layer's, so the sample names no file. */
    if (tego_is_backing(file->f_mode) && bpf_core_field_exists(struct backing_file, user_path)) {
        reason = 0;
        if (wx) {
            reason = TEGO_R_EXEC_NOT_ALLOWED;
        } else {
            /* Laundered through the task's scratch value as tego_plane_walk_path does: the rdonly build's read is
             * a pointer, which the global walk takes only as a scalar. */
            sc->launder_dentry = TEGO_BF_USER_DENTRY(file);
            sc->launder_mnt = TEGO_BF_USER_MNT(file);
            res = tego_plane_walk(*(volatile __u64 *)&sc->launder_dentry, *(volatile __u64 *)&sc->launder_mnt,
                                   run->run_idx, run->gen, &h);
            reason = tego_walk_failed(res);
            if (!reason && res == TEGO_WALK_HIT) {
                rule = h.rule_idx;
                if ((h.kind & TEGO_ROW_MODIFY_ALLOW) && !(h.kind & TEGO_ROW_EXEC_DIR))
                    reason = TEGO_R_EXEC_NOT_ALLOWED;
            }
        }
        if (tego_plane_record(sc, hook, obj, rule, reason))
            return tego_map_refuse(run, file, hook, rule, reason, 0);
        return 0;
    }
    dentry = file->f_path.dentry;
    /* (a): an image with no name, as bprm_check's exec.anonymous decides it, or a pseudo filesystem's file. */
    if (tego_is_anonymous(dentry) || (dentry->d_sb->s_flags & TEGO_SB_NOUSER)) {
        reason = (wx || !(hdr->flags & TEGO_SLOT_EXEC_ANON)) ? TEGO_R_EXEC_NOT_ALLOWED : 0;
        rule = TEGO_PLANE_RULE_NONE;
        if (tego_plane_record(sc, hook, obj, rule, reason))
            return tego_map_refuse(run, file, hook, rule, reason, 0);
        return 0;
    }
    /* (c) whatever the file. */
    if (wx) {
        tego_plane_record(sc, hook, obj, TEGO_PLANE_RULE_NONE, TEGO_R_EXEC_NOT_ALLOWED);
        return tego_map_refuse(run, file, hook, TEGO_PLANE_RULE_NONE, TEGO_R_EXEC_NOT_ALLOWED, 1);
    }
    /* (b): the nearest fs row. Anything but a write row, or an exec.allow directory above the file, allows. */
    reason = tego_walk_failed(tego_nearest(sc, dentry, file->f_path.mnt, run, &kind, &rule, &depth));
    if (!reason && (kind & TEGO_ROW_MODIFY_ALLOW) && !(kind & TEGO_ROW_EXEC_DIR)) {
        res = tego_map_exec_row(sc, exec_rows, run, dentry, inode, &rule);
        if (res < 0)
            reason = TEGO_R_IDENTITY_MISMATCH;
        else if (res == 0)
            reason = TEGO_R_EXEC_NOT_ALLOWED;
    }
    if (tego_plane_record(sc, hook, obj, rule, reason))
        return tego_map_refuse(run, file, hook, rule, reason, 1);
    return 0;
}

TEGO_PLANE_HOOK(mmap_file, mmap_file, security_mmap_file, (struct file *file, __u64 a1, __u64 a2, __u64 a3),
                 (file, a1, a2, a3))
{
    struct tego_run *run;
    __u64 prot, flags;

    if (!file)
        return 0;
    /* LSM: (file, reqprot, prot, flags), prot already effective. fmod_ret: (file, prot, flags) as the task asked. */
    if (mode == TEGO_PLANE_LSM) {
        prot = a2;
        flags = a3;
    } else {
        prot = tego_mmap_prot(file, a1);
        flags = a2;
    }
    if (!(prot & TEGO_PROT_EXEC))
        return 0;
    run = tego_current_run(&tego_run_set);
    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (tego_map_decide(run, tego_plane_slot_of(run), file,
                         (prot & TEGO_PROT_WRITE) && (flags & TEGO_MAP_TYPE) == TEGO_MAP_PRIVATE,
                         TEGO_HOOK_MMAP_FILE, (__u64)file))
        return -EACCES;
    return 0;
}

TEGO_PLANE_HOOK(file_mprotect, file_mprotect, security_file_mprotect,
                 (struct vm_area_struct *vma, __u64 reqprot, __u64 prot), (vma, reqprot, prot))
{
    struct tego_run *run;
    const struct tego_plane_slot *hdr;
    struct file *file;
    __u64 vm_flags;
    int wx;

    if (!(prot & TEGO_PROT_EXEC))
        return 0;
    file = vma->vm_file;
    if (!file)
        return 0;
    run = tego_current_run(&tego_run_set);
    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    vm_flags = vma->vm_flags;
    /* execmem: writable and executable, private. execmod: private pages written (anon_vma) made executable. */
    wx = (prot & TEGO_PROT_WRITE) && !(vm_flags & TEGO_VM_SHARED);
    if (vm_flags & TEGO_VM_EXEC) {
        /* Already executable: its file was decided when it became so; only execmem is new. */
        if (!wx)
            return 0;
    } else if (vma->anon_vma && !(vm_flags & TEGO_VM_SHARED)) {
        wx = 1;
    }
    hdr = tego_plane_slot_of(run);
    if (tego_map_decide(run, hdr, file, wx, TEGO_HOOK_FILE_MPROTECT, (__u64)vma))
        return -EACCES;
    return 0;
}
