// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef TEGO_DECIDE_SOCKET_H
#define TEGO_DECIDE_SOCKET_H

/* A Unix socket's stored path/address is read from memory, rather than supplied
 * as a trusted hook argument. Keep following it through the plane's reader:
 * probe reads produce scalar addresses; readonly casts support lockdown. */
#if TEGO_PLANE_RDONLY
#define TEGO_LISTEN_D_LEN(d) (bpf_core_cast((void *)(d), struct dentry)->d_name.len)
#define TEGO_LISTEN_D_NAME(d) ((__u64)bpf_core_cast((void *)(d), struct dentry)->d_name.name)
#define TEGO_LISTEN_D_DEV(d) (bpf_core_cast((void *)(d), struct dentry)->d_sb->s_dev)
#define TEGO_LISTEN_U_LEN(a) (bpf_core_cast((void *)(a), struct unix_address)->len)
#else
#define TEGO_LISTEN_D_LEN(d)                                                                                     \
    tego_rd32((__u64)(d) + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, len))
#define TEGO_LISTEN_D_NAME(d)                                                                                    \
    tego_rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, name))
#define TEGO_LISTEN_D_DEV(d)                                                                                     \
    tego_rd32(tego_rd64((__u64)(d) + bpf_core_field_offset(struct dentry, d_sb)) +                                 \
               bpf_core_field_offset(struct super_block, s_dev))
#define TEGO_LISTEN_U_LEN(a) tego_rd32((__u64)(a) + bpf_core_field_offset(struct unix_address, len))
#endif

static __always_inline void tego_listen_name(struct tego_plane_listen_key *key, __u64 addr, __u32 len)
{
    __u32 i;
    key->name_len = len;
#pragma clang loop unroll(full)
    for (i = 0; i < 14; i++) {
        __u64 word = 0;
        if (i * 8 < len)
            word = tego_word_mask(TEGO_RD_WORD(addr + i * 8), len - i * 8);
        ((__u64 *)key->name)[i] = word; // last word includes the zero padding
    }
}

static __always_inline __u8 tego_listen_key_reason(struct tego_run *run,
                                                   struct tego_plane_listen_key *key,
                                                   __u64 parent, __u16 *rule)
{
    void *rows = bpf_map_lookup_elem(&tego_plane_listen_rows, &run->run_idx);
    struct tego_plane_listen_row *row;
    if (!rows) {
        TEGO_PLANE_COUNT(run->run_idx, norows);
        return TEGO_R_PATH_UNRESOLVED;
    }
    row = bpf_map_lookup_elem(rows, key);
    if (!row || row->gen != run->gen || (row->rule_idx & 0xe000))
        return TEGO_R_NET_NOT_ALLOWED;
    if (!key->abstract && (!parent || row->parent_ino != TEGO_I_INO(parent) ||
                          row->parent_generation != TEGO_I_GEN(parent) || row->s_dev != TEGO_I_SDEV(parent))) {
        TEGO_PLANE_COUNT(run->run_idx, mismatch);
        return TEGO_R_IDENTITY_MISMATCH;
    }
    *rule = row->rule_idx;
    return 0;
}

static __always_inline __u8 tego_listen_path_reason(struct tego_run *run, struct dentry *dentry, __u16 *rule)
{
    struct tego_plane_listen_key key = {};
    __u64 parent = TEGO_D_INODE(TEGO_D_PARENT(dentry));
    __u32 len = TEGO_LISTEN_D_LEN(dentry);
    if (!parent || !len || len > 107)
        return TEGO_R_NET_NOT_ALLOWED;
    key.parent = parent;
    tego_listen_name(&key, TEGO_LISTEN_D_NAME(dentry), len);
    return tego_listen_key_reason(run, &key, parent, rule);
}

static __always_inline __u8 tego_listen_abstract_reason(struct tego_run *run, __u64 addr, __u32 len, __u16 *rule)
{
    struct tego_plane_listen_key key = {.abstract = 1};
    if (!len || len > 107)
        return TEGO_R_NET_NOT_ALLOWED;
    tego_listen_name(&key, addr, len);
    return tego_listen_key_reason(run, &key, 0, rule);
}

static __always_inline void tego_bind_name(struct tego_plane_decision *sc, __u64 name, __u32 len)
{
    struct tego_plane_listen_key key = {};
    if (!len || len > 107)
        return;
    tego_listen_name(&key, name, len);
    __builtin_memcpy(sc->bind.name, key.name, sizeof(sc->bind.name));
    sc->bind.name_len = len;
    sc->bind.flags |= TEGO_BIND_NAME_OK;
}

static __always_inline void tego_bind_path(struct tego_plane_decision *sc, struct dentry *dentry)
{
    __u64 parent = TEGO_D_INODE(TEGO_D_PARENT(dentry));
    if (!parent)
        return; // no resolved-parent evidence can be reported from a failed read
    sc->bind.dev = TEGO_LISTEN_D_DEV(dentry);
    sc->bind.dir_ino = TEGO_I_INO(parent);
    sc->bind.flags &= ~(TEGO_BIND_ABSTRACT | TEGO_BIND_NAME_OK);
    sc->bind.flags |= TEGO_BIND_RESOLVED;
    sc->bind.name_len = 0;
    tego_bind_name(sc, TEGO_LISTEN_D_NAME(dentry), TEGO_LISTEN_D_LEN(dentry));
}

TEGO_PLANE_HOOK(socket_bind, socket_bind, security_socket_bind,
                 (struct socket *sock, struct sockaddr *address, int addrlen), (sock, address, addrlen))
{
    // Imported sockets keep their outside creator cgroup. An original Unix
    // bind applies its current task's policy; only an outside relay falls back
    // to socket ownership, as the connect hooks do.
    struct sock *sk = sock->sk;
    struct tego_run *run = sk && sk->__sk_common.skc_family == TEGO_AF_UNIX
                            ? tego_current_run(&tego_run_set) : 0;
    if (!run)
        run = tego_unix_sock_run(&tego_run_set, sock);
    const struct tego_plane_slot *slot;
    struct tego_plane_decision *sc;
    __u16 rule = TEGO_PLANE_RULE_NONE;
    __u8 reason;
    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode) || addrlen < 2 || address->sa_family != TEGO_AF_UNIX)
        return 0;
    slot = tego_plane_slot_of(run);
    if (!slot)
        return -EACCES;
    if (!(slot->flags & TEGO_SLOT_LISTEN_DECIDES))
        return 0;
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        return -EACCES;
    }
    // Cleared by the mandatory sys_exit_bind producer, including failures.
    sc->listen_sock = (__u64)sock;
    sc->listen_run_idx = run->run_idx;
    sc->listen_gen = run->gen;
    __builtin_memset(&sc->bind, 0, sizeof(sc->bind));
    sc->bind.start_ns = bpf_get_current_task_btf()->group_leader->start_boottime;
    sc->bind.flags = TEGO_BIND_MARKED;
    sc->bind.op = TEGO_EV_BIND_RESULT;
    sc->bind.rule_idx = TEGO_PLANE_RULE_LISTEN | TEGO_PLANE_RULE_NONE;
    // Kernel rejects oversized/empty addresses; explicit policy denies autobind.
    if (addrlen <= 2 || addrlen > 110) {
        sc->bind.flags |= TEGO_BIND_DECIDED;
        sc->bind.reason = TEGO_R_NET_NOT_ALLOWED;
        return -EACCES;
    }
    // A pathname's resolved parent and basename are checked at path_mknod.
    if (((struct sockaddr_un *)address)->sun_path[0]) {
        tego_bind_name(sc, (__u64)address + 2, addrlen - 2);
        return 0;
    }
    sc->bind.flags |= TEGO_BIND_ABSTRACT;
    sc->bind.flags |= TEGO_BIND_DECIDED;
    tego_bind_name(sc, (__u64)address + 3, addrlen - 3);
    reason = tego_listen_abstract_reason(run, (__u64)address + 3, addrlen - 3, &rule);
    sc->bind.rule_idx = TEGO_PLANE_RULE_LISTEN | rule;
    sc->bind.reason = reason;
    if (reason) {
        return -EACCES;
    }
    return 0;
}

// An already-bound Unix listener still has to be a declared listener. Unix
// listen has no implicit bind; an unbound socket is refused by the normal chain.
static __always_inline __u8 tego_unix_listen_reason(struct socket *sock, struct tego_run *run, __u16 *rule)
{
    struct sock *sk = sock->sk;
    if (!sk)
        return TEGO_R_NET_NOT_ALLOWED;
#if TEGO_PLANE_RDONLY
    struct unix_sock *us = bpf_core_cast(sk, struct unix_sock);
    struct unix_address *addr = us->addr;
    struct dentry *dentry = us->path.dentry;
#else
    struct unix_sock *us = (struct unix_sock *)sk;
    struct unix_address *addr = BPF_CORE_READ(us, addr);
    struct dentry *dentry = BPF_CORE_READ(us, path.dentry);
#endif
    if (dentry)
        return tego_listen_path_reason(run, dentry, rule);
    __u32 len = addr ? TEGO_LISTEN_U_LEN(addr) : 0;
    if (len > 3 && len <= 110)
        return tego_listen_abstract_reason(run, (__u64)addr + bpf_core_field_offset(struct unix_address, name) + 3,
                                            len - 3, rule);
    return TEGO_R_NET_NOT_ALLOWED;
}

/* The original task's Unix listen is owned by its actual syscall result. A
 * supervisor relay remains its supervisor's completion, with no marker here. */
static __always_inline int tego_unix_listen_marker(struct socket *sock, struct tego_run *run, __u8 reason, __u16 rule)
{
    struct sock *sk = sock->sk;
    struct tego_run *current = tego_current_run(&tego_run_set);
    if (!sk || !current || current->run_idx != run->run_idx || current->gen != run->gen ||
        sk->__sk_common.skc_family != TEGO_AF_UNIX)
        return 0;
    struct tego_plane_decision *sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx,unresolved);
        return 1; // the no-marker terminal result reports the unknown attribution
    }
    sc->listen_sock = (__u64)sock;
    sc->listen_run_idx = run->run_idx;
    sc->listen_gen = run->gen;
    __builtin_memset(&sc->bind,0,sizeof(sc->bind));
    sc->bind.start_ns = bpf_get_current_task_btf()->group_leader->start_boottime;
    sc->bind.op = TEGO_EV_LISTEN_RESULT;
    sc->bind.flags = TEGO_BIND_MARKED | TEGO_BIND_DECIDED;
    sc->bind.rule_idx = TEGO_PLANE_RULE_LISTEN | rule;
    sc->bind.reason = reason;
#if TEGO_PLANE_RDONLY
    struct unix_sock *us = bpf_core_cast(sk,struct unix_sock);
    struct unix_address *addr = us->addr;
    struct dentry *dentry = us->path.dentry;
#else
    struct unix_sock *us = (struct unix_sock *)sk;
    struct unix_address *addr = BPF_CORE_READ(us,addr);
    struct dentry *dentry = BPF_CORE_READ(us,path.dentry);
#endif
    if (dentry)
        tego_bind_path(sc,dentry);
    else if (addr) {
        __u32 len = TEGO_LISTEN_U_LEN(addr);
        if (len > 3 && len <= 110) {
            sc->bind.flags |= TEGO_BIND_ABSTRACT;
            tego_bind_name(sc,(__u64)addr + bpf_core_field_offset(struct unix_address,name) + 3,len-3);
        }
    }
    return 1;
}

#endif
