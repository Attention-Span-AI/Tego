// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* The exec rows' keys and the final name's compare, shared by bpf/decide.bpf.c (bprm_check) and
 * bpf/decide_fill.bpf.c (the fill), so the key a row is written under and the key an exec looks up are one function
 * (ADR 0025's 2026-09-30 note; docs/p0/enforce-plane.md R9, R16, §6 E15).
 *
 * tego_exec_link_key needs nothing. The name pass needs the includer's reader: TEGO_RD_WORD(addr), the eight bytes
 * at a kernel address through bpf_rdonly_cast or bpf_probe_read_kernel, defined before this header is included. */
#ifndef TEGO_PLANE_NAME_H
#define TEGO_PLANE_NAME_H

/* ---- The exec row of one hard link ----
 *
 * An exec row is keyed by the link an entry names, not by the inode alone: the executable's struct inode *, its
 * directory's struct inode * and its final name's key (tego_name_key), mixed (murmur3's 64-bit finalizer, a
 * bijection, at each step) and with the top bit set, so the key is never a name key (top bit clear) nor the reserved
 * key 0. Hard links of one inode (a multi-call binary: uutils' 115 commands are hard links of one file, busybox's
 * applets the same) are other keys under other names or in other directories, so every link an entry names has its
 * own row with its own entry's rule_idx, and a link no entry names has none. A key is never trusted alone: a hit is
 * a match only when the row's inode, directory and name bytes are the exec'd file's (bprm_check), so two links whose
 * keys collide cannot stand in for each other; the fill refuses a second row at a key of this gen, which fails
 * Prepare. The key is a kernel value built from kernel addresses and never leaves the kernel (ADR 0025 (1)). */
static __always_inline __u64 tego_mix64(__u64 h)
{
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

static __always_inline __u64 tego_exec_link_key(__u64 inode, __u64 parent, __u64 name_key)
{
    return tego_mix64(tego_mix64(tego_mix64(inode) ^ parent) ^ name_key) | (1ULL << 63);
}

#ifdef TEGO_RD_WORD
/* ---- The final name, read and compared without a string helper ----
 *
 * bprm_check matches an exec row by the file's inode, its directory's inode and the bytes of its final name (R9).
 * The name is read as at most 32 eight-byte words from d_name.name through the build's reader (bpf_rdonly_cast of
 * the address as a struct qstr, whose first member is a u64, or bpf_probe_read_kernel), with the bytes past d_name.len
 * zeroed, and compared word for word with the row's zero-padded name, after the lengths; each pass is a bpf_loop
 * callback, verified once. d_name.hash is not used: the kernel salts it with the parent dentry's address, which the
 * run's domain does not pin (it pins the inode), so a directory whose dentry was reclaimed and looked up again
 * would carry every name under another hash. The fill reads the dentry it keys through the same pass, so the name
 * key a row is written under is the one bprm_check computes for that link. */
#define TEGO_NAME_WORDS (TEGO_NAME_MAX / 8)

/* Keeps the first n bytes of a word in memory order (all of it for n >= 8). */
static __always_inline __u64 tego_word_mask(__u64 w, __u32 n)
{
    if (n >= 8)
        return w;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return w & ((1ULL << (n * 8)) - 1);
#else
    return w & ~((1ULL << ((8 - n) * 8)) - 1);
#endif
}

/* One name pass's state: the name's address, length and words; the running hash; the row compared against. */
struct tego_name_pass {
    __u64 addr;
    __u64 h;
    const struct tego_plane_exec_row *r;
    __u32 len;
    __u32 words;
    __u32 eq;
    __u32 pad;
};

static __always_inline __u64 tego_name_word(const struct tego_name_pass *p, __u32 i)
{
    return tego_word_mask(TEGO_RD_WORD(p->addr + i * 8), p->len - i * 8);
}

static long tego_name_hash_step(__u32 i, struct tego_name_pass *p)
{
    if (i >= p->words)
        return 1;
    p->h = (p->h ^ tego_name_word(p, i)) * 0x100000001b3ULL;
    return 0;
}

static long tego_name_cmp_step(__u32 i, struct tego_name_pass *p)
{
    const struct tego_plane_exec_row *r = p->r;
    __u64 row_word;
    __u32 off;

    if (i >= p->words || !r)
        return 1;
    /* The offset is masked where the verifier sees it: clang drops a mask it can prove redundant, and the map value
     * access then has no upper bound. */
    off = i * 8;
    barrier_var(off);
    off &= TEGO_NAME_MAX - 8;
    __builtin_memcpy(&row_word, &r->name[off], sizeof(row_word));
    if (tego_name_word(p, i) != row_word) {
        p->eq = 0;
        return 1;
    }
    return 0;
}

/* Starts a pass over the dentry's final name and returns its name key: FNV-1a over the length and the words, top
 * bit cleared and bit 0 set, so it is never 0 (reserved) and never a link key (top bit set).
 * internal/bpf.PlaneNameKey is the same function. */
static __always_inline __u64 tego_name_key(struct dentry *dentry, struct tego_name_pass *p)
{
    __u32 len = dentry->d_name.len;

    if (len > TEGO_NAME_MAX - 1)
        len = TEGO_NAME_MAX - 1;
    p->addr = (__u64)dentry->d_name.name;
    p->len = len;
    p->words = (len + 7) / 8;
    p->h = 0xcbf29ce484222325ULL ^ len;
    bpf_loop(TEGO_NAME_WORDS, tego_name_hash_step, p, 0);
    return (p->h >> 1) | 1;
}

/* Whether an exec row's name is the pass's name, byte for byte. */
static __always_inline int tego_name_eq(struct tego_name_pass *p, const struct tego_plane_exec_row *r)
{
    if (r->name_len != p->len)
        return 0;
    p->r = r;
    p->eq = 1;
    bpf_loop(TEGO_NAME_WORDS, tego_name_cmp_step, p, 0);
    return p->eq;
}
#endif /* TEGO_RD_WORD */

/* ---- The folded word (ADR 0043 D2), for the name entries; the exec passes above stay byte-exact (F10) ----
 *
 * A name entry compares a final name after ASCII case folding: bytes 'A' to 'Z' become 'a' to 'z' and every other
 * byte is kept, as agent.FoldByte does. Eight bytes at a time (SWAR), with no carry between bytes and no dependence
 * on the byte order: each byte's low seven bits plus 0x3f reach bit 7 exactly when they are at least 'A' (0x41),
 * plus 0x25 exactly when they are above 'Z' (0x5a), neither sum leaves its byte, and a byte with its own bit 7 set
 * is no capital. */
static __always_inline __u64 tego_upper_bits(__u64 w)
{
    __u64 hept = w & 0x7f7f7f7f7f7f7f7fULL;
    __u64 ge_a = hept + 0x3f3f3f3f3f3f3f3fULL;
    __u64 gt_z = hept + 0x2525252525252525ULL;

    return (ge_a ^ gt_z) & ~w & 0x8080808080808080ULL;
}

/* w with its capitals lowered: each capital's 0x80 marker shifted to its 0x20 bit, which a capital has clear. */
static __always_inline __u64 tego_fold_word(__u64 w)
{
    return w | (tego_upper_bits(w) >> 2);
}

/* Byte k (0 to 7) of w in memory order. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define TEGO_WORD_BYTE(w, k) (((w) >> ((k) * 8)) & 0xff)
#else
#define TEGO_WORD_BYTE(w, k) (((w) >> ((7 - (k)) * 8)) & 0xff)
#endif

#endif /* TEGO_PLANE_NAME_H */
