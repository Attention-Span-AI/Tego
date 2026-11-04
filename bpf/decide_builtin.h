// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef TEGO_DECIDE_BUILTIN_H
#define TEGO_DECIDE_BUILTIN_H

/* ADR 0113: the protected basename is keyed by the pinned parent inode. The
 * 0x8000 tag is private to the listener-name map; its low bits name an FS row.
 * Missing targets are covered without granting or denying their parent's other
 * entries. The normal fs row additionally follows an existing target's inode. */
// Copy one word per bounded callback so the verifier checks each copy once,
// instead of exploring every length through fourteen unrolled branches.
struct tego_builtin_name_copy {
    __u64 addr;
    __u32 len;
    struct tego_plane_listen_key key;
};

static long tego_builtin_name_word(__u32 i, struct tego_builtin_name_copy *s)
{
    __u32 off = i * 8;
    /* Keep the bound in the generated code: callback indices are not bounded
     * by the verifier's model of bpf_loop's count. */
    barrier_var(off);
    off &= 0x78;
    if (off > 104 || off >= s->len)
        return 1;
    __u64 word = tego_word_mask(TEGO_RD_WORD(s->addr + off), s->len - off);
    __builtin_memcpy(&s->key.name[off], &word, sizeof(word));
    return 0;
}

static __always_inline int tego_builtin_component(__u32 gen, void *rows, struct dentry *dentry, __u32 *rule, int peer)
{
    struct tego_builtin_name_copy s = {};
    struct tego_plane_listen_row *row;
    __u64 parent = TEGO_D_INODE(TEGO_D_PARENT(dentry));
    if (!parent)
        return 0;
#if TEGO_PLANE_RDONLY
    __u32 len = bpf_core_cast(dentry, struct dentry)->d_name.len;
    __u64 name = (__u64)bpf_core_cast(dentry, struct dentry)->d_name.name;
#else
    __u32 len = tego_rd32((__u64)dentry + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, len));
    __u64 name = tego_rd64((__u64)dentry + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, name));
#endif
    if (!len || len > 107)
        return 0;
    s.addr = name;
    s.len = len;
    s.key.parent = parent;
    s.key.name_len = len;
    bpf_loop(14, tego_builtin_name_word, &s, 0);
    row = bpf_map_lookup_elem(rows, &s.key);
    if (!row || row->gen != gen || !(row->rule_idx & 0xe000))
        return 0;
    *rule = row->rule_idx & 0x1fff;
    if (row->parent_ino != TEGO_I_INO(parent) || row->parent_generation != TEGO_I_GEN(parent) || row->s_dev != TEGO_I_SDEV(parent))
        return 1; /* uncertainty must never turn the own-runtime exception into an allow */
    if (row->rule_idx & 0x4000)
        return 2; /* validated own-runtime subtree: stop before outer refusals */
    if (peer && (row->rule_idx & 0x2000))
        return 3; /* exact peer exception; never a filesystem mutation exception */
    return !!(row->rule_idx & 0x8000);
}

/* Also check ancestor names. A fixed directory absent at Prepare may have an
 * absent parent too: protecting its nearest existing ancestor's entry must
 * continue to protect the subtree if an outside server creates it later. */
struct tego_builtin_walk {
    void *rows;
    __u64 dentry;
    __u32 gen, rule, peer, match;
};

static long tego_builtin_step(__u32 level, struct tego_builtin_walk *s)
{
    struct dentry *dentry = (struct dentry *)s->dentry;
    __u64 parent;
    if (!dentry)
        return 1;
    int match = tego_builtin_component(s->gen, s->rows, dentry, &s->rule, s->peer);
    if (match) {
        s->match = match;
        return 1;
    }
    parent = TEGO_D_PARENT(dentry);
    if (!parent || parent == s->dentry)
        return 1;
    s->dentry = parent;
    return 0;
}

/* Like the FS walk, verify one global subprogram and one bounded callback,
 * instead of exploring the ancestor loop afresh at each mutation hook. */
__attribute__((noinline)) __u64 tego_builtin_name_walk(__u64 dentry, __u32 run_idx, __u32 gen, __u32 rule, int peer)
{
    struct tego_builtin_walk s = {.dentry = dentry, .gen = gen, .rule = rule, .peer = peer};
    s.rows = bpf_map_lookup_elem(&tego_plane_listen_rows, &run_idx);
    if (!s.rows)
        return (__u64)rule << 32;
    bpf_loop(TEGO_PLANE_WALK_MAX, tego_builtin_step, &s, 0);
    return (__u64)s.rule << 32 | s.match;
}

static __always_inline int tego_builtin_name_decision(struct tego_plane_decision *sc, struct tego_run *run, struct dentry *dentry, __u32 *rule, int peer)
{
    __u64 result = tego_builtin_name_walk(tego_name_launder(sc, dentry), run->run_idx, run->gen, *rule, peer);
    *rule = result >> 32;
    return (__u32)result;
}

static __always_inline int tego_builtin_name(struct tego_plane_decision *sc, struct tego_run *run, struct dentry *dentry, __u32 *rule)
{
    return tego_builtin_name_decision(sc, run, dentry, rule, 0) == 1;
}

/* A shared ledger root may contain unrelated sockets. Reserve just the two
 * endpoint basenames after the inode walk establishes ledger ancestry. */
static __always_inline int tego_builtin_control_name(struct dentry *dentry)
{
#if TEGO_PLANE_RDONLY
    __u32 len = bpf_core_cast(dentry, struct dentry)->d_name.len;
    __u64 name = (__u64)bpf_core_cast(dentry, struct dentry)->d_name.name;
#else
    __u32 len = tego_rd32((__u64)dentry + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, len));
    __u64 name = tego_rd64((__u64)dentry + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, name));
#endif
    if (len != 8 && len != 13)
        return 0;
    __u64 words[2] = {TEGO_RD_WORD(name), TEGO_RD_WORD(name + 8)};
    return (len == 8 && !__builtin_memcmp(words, "ask.sock", 8)) ||
           (len == 13 && !__builtin_memcmp(words, "operator.sock", 13));
}

/* No per-pty plane row: the independent domain withholds foreign terminals
 * and the supervisor imports run-created slaves. Only the default write floor
 * delegates; explicit deny-read/protected rows still decide before this. */
static __always_inline int tego_builtin_terminal(struct file *file)
{
    struct inode *inode = file->f_inode;
    __u32 dev, major, minor;
    if ((inode->i_mode & 0170000) != 0020000)
        return 0;
    dev = inode->i_rdev;
    major = dev >> 20;
    minor = dev & 0xfffff;
    if ((major == 5 && (minor == 0 || minor == 2)) || (major == 4 && minor < 64))
        return 1;
    return inode->i_sb->s_magic == 0x1cd1; /* devpts */
}
#endif
