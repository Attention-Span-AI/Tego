// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Step B of the decision plane (TIER3-PLAN T13; docs/p0/enforce-plane.md R12, R13, R14), included by decide.bpf.c
 * after Step A's bodies, whose macro, walk, readers and records it uses. Three groups:
 *
 * - The create and truncate hooks (R13): path_mknod (called from may_o_create, before an O_CREAT open makes the
 *   inode, so a refused create leaves no file), path_mkdir, path_symlink, path_truncate and, where the kernel has it
 *   (6.2+, RHEL 9's 5.14), file_truncate. Each is a modification at its object, decided by the walk that crosses
 *   mounts exactly as unlink is (decide.PlaneRows.Decide, PlaneModify), and a recorder fexit wraps each, so the
 *   decision goes to the task's scratch value, and to the plane's own sample only where the build's fexit is not
 *   attached (tego_plane_fallback, T9b).
 * - The attribute hooks (R12): path_chmod, path_chown, inode_setxattr, inode_removexattr and, on 6.2+,
 *   inode_set_acl and inode_remove_acl (setfacl rewrites the mode through set_acl, never path_chmod). Landlock
 *   governs none of them, and they protect deny_write targets only: refused when the nearest row carries
 *   TEGO_ROW_PROTECTED, else passed. The inode hooks get a dentry and no mount, so every one walks inside the
 *   dentry's superblock (tego_plane_walk with no vfsmount), and Prepare keys a row on each mounted root at or below
 *   a deny_write target (TEGO_ROW_MOUNT_ONLY) so that walk meets one. No recorder fexit wraps them: each refusal
 *   writes the plane's own sample.
 * - socket_create (R14): ADR 0018's family allowlist under a net: section (the slot header's
 *   TEGO_SLOT_NET_DECIDES), for every creation path, io_uring's IORING_OP_SOCKET included; a kernel socket
 *   (kern != 0) passes. Its own sample too.
 */

/* path_mknod's socket node (enforce-plane §2.20), after the filesystem floor decided it: a standalone mknod socket is
 * an ordinary filesystem operation, and only a live bind attempt in this task transfers terminal ownership, with the
 * bind's evidence and the listener's own rule. A subprogram of its own, so that path_mknod's frame, on which the name
 * entries' check stacks (decide_names.h), does not carry the bind's name copy. The floor is read from the task's
 * record of this very decision (tego_modify_hook's: hook path_mknod, object dentry), not handed in as an argument:
 * known to the verifier as 0 on one path, as a constant on the no-scratch path and unknown on the rest, an argument
 * made the subprogram a verification of its own for each (three on Fedora's 7.0, 3,300 verified instructions). No
 * record of this decision (no scratch value) refuses, as the floor did. Returns -EACCES or 0. */
static __attribute__((noinline)) int tego_mknod_bind(struct tego_run *run, struct dentry *dentry)
{
    struct tego_plane_decision *sc = tego_plane_scratch_get();
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u8 reason, floor;

    if (!sc || sc->hook != TEGO_HOOK_PATH_MKNOD || sc->obj != (__u64)dentry)
        return -EACCES;
    floor = sc->reason;
    if (sc->listen_sock && sc->bind.op == TEGO_EV_BIND_RESULT && sc->listen_run_idx == run->run_idx && sc->listen_gen == run->gen) {
        tego_bind_path(sc, dentry);
        sc->bind.flags |= TEGO_BIND_DECIDED;
        if (floor) {
            sc->bind.reason = floor;
            sc->bind.rule_idx = TEGO_PLANE_RULE_FS_ROW | sc->rule_idx;
            sc->rule_idx |= TEGO_PLANE_RULE_LISTEN; // exact tracer ownership tag, not the terminal rule
            return -EACCES;
        }
        reason = tego_listen_path_reason(run, dentry, &rule);
        sc->bind.reason = reason;
        sc->bind.rule_idx = TEGO_PLANE_RULE_LISTEN | rule;
        if (reason) {
            tego_plane_record(sc, TEGO_HOOK_PATH_MKNOD, (__u64)dentry,
                               TEGO_PLANE_RULE_LISTEN | rule, reason);
            return -EACCES;
        }
    }
    return floor ? -EACCES : 0;
}

TEGO_PLANE_HOOK(path_mknod, path_mknod, security_path_mknod, (const struct path *dir, struct dentry *dentry, umode_t node_mode),
                 (dir, dentry, node_mode))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(dir->dentry))
        return 0;
    /* may_o_create asks here before an O_CREAT open makes its file, and mknod(2) before it makes a node: refused,
     * nothing is created (R13), a file at a covered name included (ADR 0043 D1). */
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_MKNOD, (__u64)dentry, dentry, 0);
        return -EACCES;
    }
    __u8 floor = tego_modify_hook(dentry, dir->mnt, run, hdr, 1, TEGO_HOOK_PATH_MKNOD, (__u64)dentry,
                                   TEGO_R_WRITE_OUTSIDE_CONTRACT);
    if ((node_mode & 0170000) == 0140000)
        return tego_mknod_bind(run, dentry);
    return floor ? -EACCES : 0;
}

TEGO_PLANE_HOOK(path_mkdir, path_mkdir, security_path_mkdir, (const struct path *dir, struct dentry *dentry),
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
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_MKDIR, (__u64)dentry, dentry, 0);
        return -EACCES;
    }
    /* A directory's creation: no name entry decides it (ADR 0043 D1; `python -m venv .env` stays allowed). */
    if (tego_modify_hook(dentry, dir->mnt, run, hdr, 0, TEGO_HOOK_PATH_MKDIR, (__u64)dentry,
                          TEGO_R_MKDIR_OUTSIDE_CONTRACT))
        return -EACCES;
    return 0;
}

TEGO_PLANE_HOOK(path_symlink, path_symlink, security_path_symlink, (const struct path *dir, struct dentry *dentry),
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
    /* The new name is the modification; the target string decides nothing (Landlock's MAKE_SYM is the same). */
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_SYMLINK, (__u64)dentry, dentry, 0);
        return -EACCES;
    }
    if (tego_modify_hook(dentry, dir->mnt, run, hdr, 1, TEGO_HOOK_PATH_SYMLINK, (__u64)dentry,
                          TEGO_R_WRITE_OUTSIDE_CONTRACT))
        return -EACCES;
    return 0;
}

/* truncate(2) on every kernel; ftruncate(2) and an O_TRUNC open below 6.2, where file_truncate does not exist. */
TEGO_PLANE_HOOK(path_truncate, path_truncate, security_path_truncate, (const struct path *path), (path))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(path->dentry))
        return 0;
    if (tego_no_path(path->dentry, path->mnt))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_PATH_TRUNCATE, (__u64)path->dentry, path->dentry, 0);
        return -EACCES;
    }
    if (tego_modify_hook(path->dentry, path->mnt, run, hdr, 1, TEGO_HOOK_PATH_TRUNCATE, (__u64)path->dentry,
                          TEGO_R_WRITE_OUTSIDE_CONTRACT))
        return -EACCES;
    return 0;
}

/* ftruncate(2) and an O_TRUNC open from 6.2 (RHEL 9's 5.14 carries it too); security_file_truncate has no early exit
 * of its own. An object no path names and a private clone's file (a backing file included) are no decision, as
 * for file_open. */
TEGO_PLANE_HOOK(file_truncate, file_truncate, security_file_truncate, (struct file *file), (file))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (tego_no_path(file->f_path.dentry, file->f_path.mnt))
        return 0;
    if (tego_internal_mount(file->f_path.mnt))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr) {
        tego_plane_unslotted_fs(run, TEGO_HOOK_FILE_TRUNCATE, (__u64)file, file->f_path.dentry, 0);
        return -EACCES;
    }
    if (tego_modify_hook(file->f_path.dentry, file->f_path.mnt, run, hdr, 1, TEGO_HOOK_FILE_TRUNCATE, (__u64)file,
                          TEGO_R_WRITE_OUTSIDE_CONTRACT))
        return -EACCES;
    return 0;
}

/* An object no path names, for a hook that has its dentry only: a pipe, socket or anonymous inode (SB_NOUSER), a
 * private inode, and a pseudo file of a kernel-internal superblock (a memfd: its dentry is its own parent short of
 * the superblock's root, on a kern_mount's superblock). tego_no_path's answer without the mount. */
#define TEGO_SB_KERNMOUNT (1U << 22)

static __always_inline int tego_no_path_sb(struct dentry *dentry)
{
    struct super_block *sb = dentry->d_sb;
    struct inode *inode = dentry->d_inode;

    if (sb->s_flags & TEGO_SB_NOUSER)
        return 1;
    if (inode && (inode->i_flags & TEGO_S_PRIVATE))
        return 1;
    return (__u64)dentry->d_parent == (__u64)dentry && (__u64)dentry != (__u64)sb->s_root &&
           (sb->s_flags & TEGO_SB_KERNMOUNT);
}

/* An attribute hook's refusal sample (R23) on dentry: its directory's dev and ino and its final component. */
static __always_inline void tego_attr_sample(struct dentry *dentry, struct tego_run *run, __u16 hook, __u16 rule,
                                              __u8 reason)
{
    struct tego_plane_sample_args a = {};

    a.kind = TEGO_EV_PLANE_ATTR;
    a.hook = hook;
    a.rule = rule;
    a.reason = reason;
    a.named = 1;
    a.name = (__u64)dentry->d_name.name;
    a.dev = dentry->d_sb->s_dev;
    a.dir_ino = dentry->d_parent->d_inode->i_ino;
    tego_plane_own_sample(run, &a);
}

/* One attribute hook's decision on dentry (R12): the walk inside its superblock, refused when the nearest row
 * carries TEGO_ROW_PROTECTED (a deny_write target at or above it) or the walk failed closed; any other row, and no
 * row at all, passes: Landlock governs no chmod, chown, xattr or ACL, so these hooks exist only to protect deny
 * targets. A refusal writes the plane's own sample. Returns the reason, 0 for a pass. */
static __always_inline __u8 tego_protect_hook(struct dentry *dentry, struct tego_run *run, __u16 hook)
{
    struct tego_plane_decision *sc = tego_plane_scratch_get();
    struct tego_plane_hit h = {};
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u8 reason;

    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        reason = TEGO_R_PATH_UNRESOLVED;
    } else {
        sc->launder_dentry = (__u64)dentry;
        reason = tego_walk_failed(tego_plane_walk(*(volatile __u64 *)&sc->launder_dentry, 0, run->run_idx, run->gen,
                                                    &h));
        if (!reason && (h.kind & TEGO_ROW_PROTECTED)) {
            rule = h.rule_idx;
            reason = TEGO_R_WRITE_OUTSIDE_CONTRACT;
        }
        tego_plane_record(sc, hook, (__u64)dentry, rule, reason);
    }
    if (!reason)
        return 0;
    tego_attr_sample(dentry, run, hook, rule, reason);
    return reason;
}

/* An attribute hook's record and sample when its slot holds no header of the run's gen, before it returns -EACCES:
 * refused path-unresolved, recorded, and its own sample written (no recorder fexit wraps these hooks). */
static __always_inline void tego_protect_unslotted(struct dentry *dentry, struct tego_run *run, __u16 hook)
{
    tego_plane_unslotted(hook, (__u64)dentry);
    tego_attr_sample(dentry, run, hook, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED);
}

TEGO_PLANE_HOOK(path_chmod, path_chmod, security_path_chmod, (const struct path *path), (path))
{
    struct tego_run *run = tego_current_run(&tego_run_set);

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(path->dentry))
        return 0;
    if (tego_no_path(path->dentry, path->mnt))
        return 0;
    if (!tego_plane_slot_of(run)) {
        tego_protect_unslotted(path->dentry, run, TEGO_HOOK_PATH_CHMOD);
        return -EACCES;
    }
    if (tego_protect_hook(path->dentry, run, TEGO_HOOK_PATH_CHMOD))
        return -EACCES;
    return 0;
}

/* The uid and gid arguments are kuid_t and kgid_t structs the body never reads. */
TEGO_PLANE_HOOK(path_chown, path_chown, security_path_chown, (const struct path *path), (path))
{
    struct tego_run *run = tego_current_run(&tego_run_set);

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(path->dentry))
        return 0;
    if (tego_no_path(path->dentry, path->mnt))
        return 0;
    if (!tego_plane_slot_of(run)) {
        tego_protect_unslotted(path->dentry, run, TEGO_HOOK_PATH_CHOWN);
        return -EACCES;
    }
    if (tego_protect_hook(path->dentry, run, TEGO_HOOK_PATH_CHOWN))
        return -EACCES;
    return 0;
}

/* The inode hooks' first argument is a struct user_namespace * below 6.3 and a struct mnt_idmap * from 6.3; the
 * bodies never read it, so it is declared void *. Each security_ function returns 0 for an IS_PRIVATE inode before
 * the chain, which fmod_ret mode reproduces (R4); in LSM mode a program's 0 lets the bpf_lsm_ stub's own default
 * stand, so security_inode_setxattr's capability check below 6.11 still runs. */
TEGO_PLANE_HOOK(inode_setxattr, inode_setxattr, security_inode_setxattr, (void *idmap, struct dentry *dentry),
                 (idmap, dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(dentry))
        return 0;
    if (tego_no_path_sb(dentry))
        return 0;
    if (!tego_plane_slot_of(run)) {
        tego_protect_unslotted(dentry, run, TEGO_HOOK_INODE_SETXATTR);
        return -EACCES;
    }
    if (tego_protect_hook(dentry, run, TEGO_HOOK_INODE_SETXATTR))
        return -EACCES;
    return 0;
}

TEGO_PLANE_HOOK(inode_removexattr, inode_removexattr, security_inode_removexattr,
                 (void *idmap, struct dentry *dentry), (idmap, dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(dentry))
        return 0;
    if (tego_no_path_sb(dentry))
        return 0;
    if (!tego_plane_slot_of(run)) {
        tego_protect_unslotted(dentry, run, TEGO_HOOK_INODE_REMOVEXATTR);
        return -EACCES;
    }
    if (tego_protect_hook(dentry, run, TEGO_HOOK_INODE_REMOVEXATTR))
        return -EACCES;
    return 0;
}

/* 6.2+: setfacl's set_acl rewrites the mode of an equivalent ACL without path_chmod (ADR 0024's documented note).
 * Below 6.2 an ACL is an xattr write, which inode_setxattr decides. */
TEGO_PLANE_HOOK(inode_set_acl, inode_set_acl, security_inode_set_acl, (void *idmap, struct dentry *dentry),
                 (idmap, dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(dentry))
        return 0;
    if (tego_no_path_sb(dentry))
        return 0;
    if (!tego_plane_slot_of(run)) {
        tego_protect_unslotted(dentry, run, TEGO_HOOK_INODE_SET_ACL);
        return -EACCES;
    }
    if (tego_protect_hook(dentry, run, TEGO_HOOK_INODE_SET_ACL))
        return -EACCES;
    return 0;
}

TEGO_PLANE_HOOK(inode_remove_acl, inode_remove_acl, security_inode_remove_acl, (void *idmap, struct dentry *dentry),
                 (idmap, dentry))
{
    struct tego_run *run = tego_current_run(&tego_run_set);

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (mode == TEGO_PLANE_FMOD_RET && tego_is_private(dentry))
        return 0;
    if (tego_no_path_sb(dentry))
        return 0;
    if (!tego_plane_slot_of(run)) {
        tego_protect_unslotted(dentry, run, TEGO_HOOK_INODE_REMOVE_ACL);
        return -EACCES;
    }
    if (tego_protect_hook(dentry, run, TEGO_HOOK_INODE_REMOVE_ACL))
        return -EACCES;
    return 0;
}

/* ---- socket_create (R14; ADR 0018 (5)) ---- */

/* ADR 0018 (1)'s allowlist, the seccomp filter's socketAllowTest (enforce/landlock filter.go) for socket(2), is
 * tego_socket_allowed in bpf/include/socket_allow.h, which cgroup_net.bpf.c's cgroup/sock_create calls too. */
#include "socket_allow.h"

TEGO_PLANE_HOOK(socket_create, socket_create, security_socket_create,
                 (int family, int type, int protocol, int kern), (family, type, protocol, kern))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    struct tego_plane_sample_args a = {};
    __u8 reason = 0;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    /* A socket the kernel makes for itself decides nothing of the agent's (ADR 0024 (5)). */
    if (kern)
        return 0;
    hdr = tego_plane_slot_of(run);
    a.kind = TEGO_EV_PLANE_SOCKET;
    a.hook = TEGO_HOOK_SOCKET_CREATE;
    a.rule = TEGO_PLANE_RULE_NONE;
    a.family = family;
    a.type = type;
    a.protocol = protocol;
    if (!hdr) {
        /* A live run-set row whose slot says nothing of its run: fail closed. */
        tego_plane_unslotted(TEGO_HOOK_SOCKET_CREATE, 0);
        a.reason = TEGO_R_PATH_UNRESOLVED;
        tego_plane_own_sample(run, &a);
        return -EACCES;
    }
    /* The header says the contract has no net: section: no family is refused (SEMANTICS §1, ADR 0018 (4)). */
    if (!(hdr->flags & TEGO_SLOT_NET_DECIDES))
        return 0;
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        a.reason = TEGO_R_PATH_UNRESOLVED;
        tego_plane_own_sample(run, &a);
        return -EACCES;
    }
    if (!tego_socket_allowed(family, type, protocol, (hdr->flags & TEGO_SLOT_NET_ICMP) != 0))
        reason = TEGO_R_NET_NOT_ALLOWED;
    if (tego_plane_record(sc, TEGO_HOOK_SOCKET_CREATE, 0, TEGO_PLANE_RULE_NONE, reason)) {
        a.reason = reason;
        tego_plane_own_sample(run, &a);
        return -EACCES;
    }
    return 0;
}
