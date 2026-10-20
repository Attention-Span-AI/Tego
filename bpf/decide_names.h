// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* ADR 0043's name entries in the decision plane (NAME-BPF; ADR 0039 as ADR 0043 amends it; docs/p0/enforce-plane.md
 * R5 to R8, R10). Included by decide.bpf.c after the walk, its readers and plane_name.h, before the hooks that ask it:
 * file_open (a read or a modification of a file), path_mknod, path_symlink, path_unlink, path_truncate and
 * file_truncate (through tego_modify_hook), path_link (the new name, and REFER's source) and path_rename (both ends
 * of a file's rename; D5 for a directory's). Never bprm_check, step C, path_mkdir, path_rmdir, the attribute hooks or
 * the socket hooks (D1: a name entry decides no directory, no metadata and no exec match; an exec of a covered file
 * fails at file_open's read of it).
 *
 * Each question is asked only where the walk allowed it (D1: "a name entry decides only what the walk allows"), and
 * only under the slot header's TEGO_SLOT_NAME_DECIDES, so a run without name entries pays one flag test.
 *
 * - The prefilter (tego_name_candidate, inline in a hook): the final name's first word, masked to its length and
 *   folded, against the header's leads (D2). A name passing none is decided by the walk alone, with no lookup.
 * - The name check (tego_plane_name_check, global): the name's keys (exact, and one per prefix length), the rows
 *   they find confirmed by the folded bytes (a key collision matches nothing), and their arms (deny, a built-in
 *   exception, D3's exemption): the candidate entries.
 * - The climb (tego_plane_climb, global): from a directory towards the root (D4), the scope bits of the rows it meets
 *   until a dependency directory's name, the namespace root, the bound, or what it was asked is decided.
 * - tego_plane_name (global), a hook's one call: the name check, then the climb from the name's directory, and the
 *   answer: TEGO_NAME_NONE, a refusal named by the entry's tagged rule (D8), or the walk's fail-closed codes: no
 *   name map or config row of the run's gen (NOROWS, D9), a climb that could not decide (UNRESOLVED, BOUND), a row
 *   whose identity is gone (MISMATCH). tego_plane_move (global), path_rename's for a directory: D5.
 *
 * Built for the verifier of every MATRIX row (enforce-plane R21) and for ADR 0024's budget of 20,000 verified
 * instructions a program: each global function is verified once per program however many hooks of it call it; the
 * hook's pointers reach them as scalars laundered through the task's scratch value (a global function cannot take a
 * trusted pointer before 6.8), and every kernel address is read through TEGO_RD_WORD. The callbacks are the walk's
 * shape (form d): straight-line arithmetic where a branch would only choose a value (masks, folds, the keys' and arms'
 * updates, the dependency compare), so the verifier walks one path through them; no map value pointer is NULL past
 * its lookup (a missing row is the config row, looked up afresh, which no compare accepts), and none is another's
 * (a verifier that keeps a map value's id tells rows that alias one pointer from rows that do not), so the paths do
 * not multiply by the rows found; a value one iteration hands the next is never a known constant the next branches
 * on, so a verifier that runs a callback until its states converge (6.8+) converges in a few rounds; and every field
 * a callback branches on is seeded from an argument (TestBPFLoopCallbackStateIsSeededFromMemory): a verifier before
 * 6.8 (AL2023's 6.1) verifies a callback once, from its first call's state, and would hard-wire a branch on a
 * constant seed. The climb is outside the walk's markers, so the walk still reads no name
 * (TestPlaneWalkHasNoStringOps, TestPlaneClimbIsOutsideTheWalk). decide.PlaneRows.nameCheck and ScopeMoveRefused are
 * the model, and TestPlaneRowsMatchEvaluate holds the model to the root model.
 */

#define TEGO_FNV_BASIS 0xcbf29ce484222325ULL
#define TEGO_FNV_PRIME 0x100000001b3ULL

/* The answers, in the low byte of a return (the rule of a DENY in the bits above); every other answer is an enum
 * tego_plane_walk_result failure (UNRESOLVED and up), which tego_walk_failed turns into its refusal reason as it does
 * the walk's. NONE and DENY sit where ROOT and HIT do. */
#define TEGO_NAME_NONE 0      /* no entry covers the object */
#define TEGO_NAME_DENY 1      /* an entry covers it: refused as its own deny_read entry would refuse it */
#define TEGO_NAME_CANDIDATE 1 /* the name check's answer to tego_plane_name: entries match; the climb decides */

/* How a climb ended: STOP and DONE are answers, every other value a failure code. */
#define TEGO_CLIMB_STOP 0 /* a dependency directory or the namespace root: a scope not met by now never will be */
#define TEGO_CLIMB_DONE 1 /* the stop test held: what was asked is decided */

/* The climb's parameters, packed into tego_plane_climb's params: the start's level, the mode (0: the name check's
 * lowest candidate decided; 1: a place's coverage, D5) and, in bit 16, TEGO_CLIMB_NEW_NAME: the start is a rename's
 * new name, whose row is not looked up (D5: the inode there after the move is the source's) but whose name takes the
 * dependency test, as a mountpoint just crossed to is climbed. */
#define TEGO_CLIMB_NAME 0
#define TEGO_CLIMB_PLACE 1
#define TEGO_CLIMB_NEW_NAME (1ULL << 16)
#define TEGO_CLIMB_PARAMS(level, mode) ((__u64)(level) | (__u64)(mode) << 8)

/* The addresses the name entries read, as scalars through the build's reader (TEGO_RD_WORD reads any eight bytes),
 * so a global function can be handed them and every path holds one type. */
#define TEGO_N_PTR(base, type, field) TEGO_RD_WORD((__u64)(base) + bpf_core_field_offset(type, field))
#define TEGO_N_PARENT(d) TEGO_N_PTR(d, struct dentry, d_parent)
#define TEGO_N_INODE(d) TEGO_N_PTR(d, struct dentry, d_inode)
#define TEGO_N_MPARENT(m) TEGO_N_PTR(m, struct mount, mnt_parent)
#define TEGO_N_MPOINT(m) TEGO_N_PTR(m, struct mount, mnt_mountpoint)
#define TEGO_N_MROOT(m)                                                                                           \
    TEGO_RD_WORD((__u64)(m) + bpf_core_field_offset(struct mount, mnt) + bpf_core_field_offset(struct vfsmount, mnt_root))
#define TEGO_N_VMROOT(vm) TEGO_N_PTR(vm, struct vfsmount, mnt_root)
/* ADR 0043 D2's failure paths, for the reads of a name: its d_name's hash_len word (the length in its high half on
 * either byte order), its bytes' address, and its bytes. The rdonly build's loads have no fault signal (an
 * exception-table load reads 0). The probe-read build ORs bpf_probe_read_kernel's error into flt, and a fault refuses
 * path-unresolved, counted: in the prefilter and the name check, where a word read as 0 would match nothing and let
 * the walk's allow stand, and in the climb's dependency test, where it would read a dependency directory as none and
 * so D5's new place as covered. TEGO_N_FAULTS says whether the build has the signal. */
#if TEGO_PLANE_RDONLY
#define TEGO_N_FAULTS 0
#define TEGO_N_RDF(addr, flt) TEGO_RD_WORD(addr)
#else
#define TEGO_N_FAULTS 1
static __always_inline __u64 tego_n_rdf(__u64 addr, __u64 *flt)
{
    __u64 v = 0;

    *flt |= (__u64)bpf_probe_read_kernel(&v, sizeof(v), (void *)addr);
    return v;
}
#define TEGO_N_RDF(addr, flt) tego_n_rdf((addr), &(flt))
#endif
#define TEGO_N_HASHLEN(d, flt) TEGO_N_RDF((__u64)(d) + bpf_core_field_offset(struct dentry, d_name), flt)
#define TEGO_N_NAME(d, flt)                                                                                       \
    TEGO_N_RDF((__u64)(d) + bpf_core_field_offset(struct dentry, d_name) + bpf_core_field_offset(struct qstr, name), \
                flt)

/* ---- Straight-line arithmetic: a value chosen without a branch ----
 *
 * BPF has no conditional move or set, so clang turns a comparison used as a value into a branch, and the verifier
 * then walks both sides. These compute the same 0 or 1 with ALU operations; the barriers keep clang from recognizing
 * the patterns and turning them back into comparisons. */

/* 1 when x is not 0. */
static __always_inline __u64 tego_nz(__u64 x)
{
    __u64 n = -x;

    barrier_var(n);
    return (x | n) >> 63;
}

/* 1 when a < b, for a and b below 2^63. */
static __always_inline __u64 tego_lt(__u64 a, __u64 b)
{
    __u64 d = a - b;

    barrier_var(d);
    return d >> 63;
}

/* -1 (every bit) when c is 1, 0 when c is 0. */
#define TEGO_ALL(c) (-(__u64)(c))

/* The first n bytes of w in memory order, all of it for n >= 8; n is at least 1 (below 2^63). A shift count of 64
 * would be undefined, so the mask is built from c * 8 - 1 and one more shift. */
static __always_inline __u64 tego_name_mask(__u64 w, __u64 n)
{
    __u64 c = n - ((n - 8) & TEGO_ALL(tego_lt(8, n))), sh = c * 8 - 1;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return w & ~((~0ULL << sh) << 1);
#else
    return w & ~((~0ULL >> sh) >> 1);
#endif
}

/* One past the memory index of the last byte up marks (tego_upper_bits' 0x80 markers), 0 for none: the marks
 * smeared towards memory index 0 and counted. */
static __always_inline __u64 tego_marks_end(__u64 up)
{
    __u64 x = up >> 7;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
#else
    x |= x << 8;
    x |= x << 16;
    x |= x << 32;
#endif
    return (x * 0x0101010101010101ULL) >> 56;
}

/* Index of x's lowest set bit, masked to an entry's position (0 to 63; x is not 0): the bits below it, counted
 * (SWAR). The barriers keep clang from turning the count into a table lookup (a cttz through .rodata, whose u8 result
 * the verifier sees as 0 to 255) and from dropping the final mask, which the verifier needs for the index's bound. */
static __always_inline __u32 tego_ctz64(__u64 x)
{
    __u64 v = (x & -x) - 1;
    __u32 n;

    barrier_var(v);
    v = v - ((v >> 1) & 0x5555555555555555ULL);
    v = (v & 0x3333333333333333ULL) + ((v >> 2) & 0x3333333333333333ULL);
    v = (v + (v >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
    n = (__u32)((v * 0x0101010101010101ULL) >> 56);
    barrier_var(n);
    return n & (TEGO_PLANE_NAME_ENTRIES - 1);
}

/* The index (0 to 7) of the one bit of a scope byte. */
static __always_inline __u32 tego_bit_index(__u64 b)
{
    return (__u32)(tego_nz(b & 0xaa) | tego_nz(b & 0xcc) << 1 | tego_nz(b & 0xf0) << 2);
}

/* The entries whose deny arm carries one of the scope bits in bits (tego_plane_name_cfg.bit_entries). */
static __always_inline __u64 tego_entries_of(const struct tego_plane_name_cfg *cfg, __u64 bits)
{
    __u64 out = 0;
    __u32 b;

#pragma unroll
    for (b = 0; b < TEGO_PLANE_SCOPES_MAX; b++)
        out |= cfg->bit_entries[b] & TEGO_ALL((bits >> b) & 1);
    return out;
}

/* A name decision's rule_idx (decide.PlaneNameTag). */
static __always_inline __u32 tego_name_tag(__u32 bit, __u32 entry)
{
    return TEGO_PLANE_RULE_NAME | ((bit & 7) << 6) | (entry & 63);
}

/* Counts a failure that refuses at the slot, as the walk counts its own, and returns it. */
static __always_inline int tego_name_failed(__u32 run_idx, int res)
{
    switch (res) {
    case TEGO_WALK_UNRESOLVED:
        TEGO_PLANE_COUNT(run_idx, unresolved);
        break;
    case TEGO_WALK_BOUND:
        TEGO_PLANE_COUNT(run_idx, bound);
        break;
    case TEGO_WALK_MISMATCH:
        TEGO_PLANE_COUNT(run_idx, mismatch);
        break;
    case TEGO_WALK_NOROWS:
        TEGO_PLANE_COUNT(run_idx, norows);
        break;
    }
    return res;
}

/* The slot's config row of the run's gen in its name map names, or NULL (D9: a candidate is then refused NOROWS). */
static __always_inline const struct tego_plane_name_cfg *tego_name_cfg(void *names, __u32 gen)
{
    const struct tego_plane_name_cfg *cfg;
    __u64 key0 = 0;

    if (!names)
        return 0;
    cfg = bpf_map_lookup_elem(names, &key0);
    if (!cfg || cfg->gen != gen || !(cfg->flags & TEGO_NAME_ROW_CONFIG))
        return 0;
    return cfg;
}

/* What the global functions hand each other, on the caller's stack. */
struct tego_name_out {
    __u64 live;     /* the name check's out: the candidate entries; the climb's out: those its scopes cover */
    __u64 seq;      /* the climb's out: the scope bits in the order it met them (tego_climb_state.seq) */
    __u8  exempt;   /* the name check's out: D3's scope bits, which a level-1 scope cancels */
    __u8  met;      /* the climb's out: the scope bits it met */
    __u8  own;      /* the scope bits it met at level 1 */
    __u8  nearest;  /* the lowest covered candidate's nearest scope bit (D8) */
    __u8  pad[4];
};

/* ---- The climb (D4, D5) ----
 *
 * From a directory towards the root, through d_parent and, at a mount root, across to the mountpoint, as the walk
 * climbs (tego_walk_step: a crossing is no level, and the mountpoint is not looked up), but never stopping at a row:
 * at each level it looks the inode up in the slot's fs rows, checks a current row's identity as the walk does (a
 * mismatch refuses, ADR 0025 (4)) and ORs the row's scope bit (one a row) into what it met; a scope-only row counts
 * here, a mount-only row does not. At each level it then reads the directory's name, the mountpoint's at a mount root
 * (D4), and stops at a dependency directory's (agent.EnvSkipDirs, byte for byte): no scope above one covers a file
 * below it. The namespace root stops it too; a level past TEGO_PLANE_WALK_MAX ends it BOUND and a dentry with no
 * parent short of a mount root UNRESOLVED. It stops early once its test holds: in name mode a bit of term (the
 * lowest candidate's scopes), in place mode every bit of term (every scope an entry's deny arm carries: what it met
 * then covers every entry). The bits met at level 1 are own (D3's exemption parent, D5's moved directory). */

/* The climb's state, on its caller's stack and handed to tego_climb_step. Every field the step changes is a full
 * word written whole, and every value written there is XORed with the config row's zero (TEGO_CLIMB_ZERO), a word
 * that is 0 at run time and that the verifier, reading it from map memory afresh each time, knows nothing of, so it
 * knows nothing of the value either: no bound, no known bit, no tie to another register. The
 * 6.8+ verifier verifies a callback again until the state at its call is contained, range for range and stack slot
 * type for slot type, in one it verified before, and Ubuntu 24.04's 6.8 keeps a value written to the stack through
 * another register than the frame pointer as a spilled register when it knows anything of it (and marks it precise)
 * but as plain bytes when it knows nothing. A field that one iteration left a known 0 and the next a known 1, a byte
 * stored as a constant beside a register's, or a word now known in part and now not, made each combination a pass of
 * its own: twenty-odd passes on 6.17 in NAME-BPF's first form, and the climb alone 9,400 to 39,500 verified
 * instructions on 6.8 with seeds the verifier could bound. With every write unknown whole, each later iteration is
 * contained in the first on every kernel. */
struct tego_climb_state {
    void *rows;                                 /* the slot's fs rows map */
    const struct tego_plane_name_cfg *cfg;     /* the slot's config row */
    __u64 d;                                    /* the climb's dentry, mount and mount root */
    __u64 m;
    __u64 mroot;
    __u64 level;                                /* the climb's level: 1 the start */
    __u64 crossed;                              /* not 0: the climb's dentry is a mountpoint just crossed to, or a
                                                 * rename's new name (TEGO_CLIMB_NEW_NAME): no row looked up */
    __u64 met;                                  /* the scope bits the climb met */
    __u64 own;                                  /* the scope bits it met at level 1 */
    __u64 seq;                                  /* the scope bits in the order it met them: a byte each, newest
                                                 * lowest (tego_scope_first) */
    __u64 result;                               /* the climb's end: TEGO_WALK_BOUND until a step ends it */
    __u64 fault;                                /* the probe-read build's failed reads of a name (TEGO_N_RDF) */
    __u32 gen;
    __u8  term;                                 /* the stop test's bits */
    __u8  place;                                /* 1: place mode (every bit of term), 0: name mode (any bit) */
    __u8  pad[2];
};

/* The config row's zero, read afresh (the state's note above), and the climb's end, stored as a word the verifier does
 * not know. */
#define TEGO_CLIMB_ZERO(s) ((s)->cfg->zero)
#define TEGO_CLIMB_END(s, code) ((s)->result = TEGO_CLIMB_ZERO(s) ^ (code))

/* Whether the directory at d is a dependency directory: its name, at most TEGO_PLANE_NAME_DEP_LEN bytes, is one of
 * the config row's, byte for byte (the scan compares exactly, ADR 0043 Terms). A name longer than
 * TEGO_PLANE_NAME_DEP_LEN, or whose length is no dependency name's (dep_lens), is not read: its length alone says it
 * is none (a length taken modulo 32 here once let a 48-byte name that starts with a 16-byte dependency name pass for
 * it, and the climb stop short of the scope). Otherwise its two words, masked to its length, are compared with each
 * name's zero-padded words, without a branch: a slot the row does not use is zero, and a name holds no NUL, so it
 * matches nothing. */
static __always_inline int tego_dep_dir(__u64 d, const struct tego_plane_name_cfg *cfg, __u64 *flt)
{
    __u64 len = TEGO_N_HASHLEN(d, *flt) >> 32, addr, w0, w1, acc = 0;
    __u32 k;

    if (len > TEGO_PLANE_NAME_DEP_LEN || !((cfg->dep_lens >> len) & 1))
        return 0;
    addr = TEGO_N_NAME(d, *flt);
    w0 = tego_name_mask(TEGO_N_RDF(addr, *flt), len);
    w1 = tego_name_mask(TEGO_N_RDF(addr + 8, *flt), len - 8) & TEGO_ALL(tego_lt(8, len));
#pragma unroll
    for (k = 0; k < TEGO_PLANE_NAME_DEPS; k++)
        acc |= tego_nz((cfg->dep[k][0] ^ w0) | (cfg->dep[k][1] ^ w1)) ^ 1;
    return (int)acc;
}

static long tego_climb_step(__u32 i, struct tego_climb_state *s)
{
    const struct tego_plane_name_cfg *cfg = s->cfg;
    __u64 d = s->d;

    if (!cfg || !s->rows) {
        TEGO_CLIMB_END(s, TEGO_WALK_NOROWS);
        return 1;
    }
    if (!s->crossed) {
        if (s->level > TEGO_PLANE_WALK_MAX) {
            TEGO_CLIMB_END(s, TEGO_WALK_BOUND);
            return 1;
        }
        __u64 inode = TEGO_N_INODE(d);

        if (inode) {
            __u64 key = inode;
            struct tego_plane_row *r = bpf_map_lookup_elem(s->rows, &key);

            if (r && r->gen == s->gen && !(r->kind & TEGO_ROW_MOUNT_ONLY)) {
                __u64 bits = r->scope, x, fresh;

                if (r->i_ino != TEGO_I_INO(inode) || r->i_generation != TEGO_I_GEN(inode) ||
                    r->s_dev != TEGO_I_SDEV(inode)) {
                    TEGO_CLIMB_END(s, TEGO_WALK_MISMATCH);
                    return 1;
                }
                fresh = bits & ~s->met;
                s->seq = ((s->seq << (8 * tego_nz(fresh))) | fresh) ^ TEGO_CLIMB_ZERO(s);
                s->own = (s->own | (bits & TEGO_ALL(tego_nz(s->level ^ 1) ^ 1))) ^ TEGO_CLIMB_ZERO(s);
                s->met = (s->met | bits) ^ TEGO_CLIMB_ZERO(s);
                x = s->met & s->term;
                if (((tego_nz(x ^ s->term) ^ 1) & s->place) | (tego_nz(x) & (s->place ^ 1))) {
                    TEGO_CLIMB_END(s, TEGO_CLIMB_DONE);
                    return 1;
                }
            }
        }
    }
    s->crossed = TEGO_CLIMB_ZERO(s);
    if (d == s->mroot) {
        __u64 m = s->m, pm;

        if (!m) {
            TEGO_CLIMB_END(s, TEGO_CLIMB_STOP);
            return 1;
        }
        pm = TEGO_N_MPARENT(m);
        if (!pm || pm == m) {
            TEGO_CLIMB_END(s, TEGO_CLIMB_STOP);
            return 1;
        }
        s->d = TEGO_N_MPOINT(m);
        s->m = pm;
        s->mroot = TEGO_N_MROOT(pm);
        s->crossed = TEGO_CLIMB_ZERO(s) ^ 1;
        return 0;
    }
    if (tego_dep_dir(d, cfg, &s->fault)) {
        TEGO_CLIMB_END(s, TEGO_CLIMB_STOP);
        return 1;
    }
    __u64 p = TEGO_N_PARENT(d);

    if (!p || p == d) {
        TEGO_CLIMB_END(s, TEGO_WALK_UNRESOLVED);
        return 1;
    }
    s->d = p;
    s->level = (s->level + 1) ^ TEGO_CLIMB_ZERO(s);
    return 0;
}

/* Sets the climb's state s up for a climb from the directory dentry on its struct mount m for the run in run
 * (run_idx << 32 | gen), as params asks (TEGO_CLIMB_PARAMS), over the slot's rows map and config row cfg: in name
 * mode its stop test is the scope bits of the lowest entry in live, in place mode every scope bit an entry's deny arm
 * carries. Every field the climb changes starts as the config row's zero, XORed with what it starts at (the state's
 * note): a seed made of the arguments, which the verifier can follow through the stack and back, became a known value
 * again on 6.17 (x ^ x is 0). */
static __always_inline void tego_climb_setup(struct tego_climb_state *s, __u64 dentry, __u64 m, __u64 run,
                                              __u64 params, void *rows, const struct tego_plane_name_cfg *cfg,
                                              __u64 live)
{
    s->rows = rows;
    s->cfg = cfg;
    s->d = dentry;
    s->m = m;
    s->gen = (__u32)run;
    s->level = cfg->zero ^ (params & 0xff);
    s->place = (params >> 8) & 1;
    s->crossed = cfg->zero ^ ((params >> 16) & 1);
    s->met = cfg->zero;
    s->own = cfg->zero;
    s->seq = cfg->zero;
    s->result = cfg->zero ^ TEGO_WALK_BOUND;
#if TEGO_N_FAULTS
    s->fault = cfg->zero;
#endif
    s->term = s->place ? cfg->scopes : cfg->entry_mask[tego_ctz64(live)];
    s->mroot = TEGO_N_MROOT(m);
}

/* The scope bit among mask a climb met first, by its sequence seq (tego_climb_state.seq): the oldest byte holding
 * one, its lowest bit of them (a row carries one bit); 0 when it met none. The entry's nearest scope (D8). */
static __always_inline __u64 tego_scope_first(__u64 seq, __u64 mask)
{
    __u64 pick = 0, b;
    __u32 j;

#pragma unroll
    for (j = 0; j < 8; j++) {
        b = (seq >> (8 * j)) & mask;
        pick ^= (pick ^ b) & TEGO_ALL(tego_nz(b));
    }
    return pick & -pick;
}

/* What a finished climb met, into *out: the scope bits (all, those at level 1, and in the order met), and for the
 * name check, of the candidates in out->live (none in place mode), those its scopes cover and the lowest one's
 * nearest scope bit, which names the refusal. A name-mode climb that ended DONE met the lowest candidate's scope, so
 * that candidate is the lowest covered; one that ended STOP met every scope it will, so a higher candidate covered
 * there is decided by the same climb. */
static __always_inline void tego_climb_out(const struct tego_climb_state *s, struct tego_name_out *out)
{
    __u64 hit = out->live & tego_entries_of(s->cfg, s->met);

    out->live = hit;
    out->seq = s->seq;
    out->met = (__u8)s->met;
    out->own = (__u8)s->own;
    out->nearest = (__u8)tego_scope_first(s->seq, s->cfg->entry_mask[tego_ctz64(hit)]);
}

/* tego_plane_climb climbs from the directory dentry on its struct mount m for the run in run (run_idx << 32 | gen),
 * as params asks (tego_climb_setup), for the name check (tego_plane_name) and for D5 (tego_plane_move). It writes
 * what it met into *out (tego_climb_out) and returns how it ended: STOP, DONE or an uncounted failure code; the
 * caller counts a failure, since it alone knows whether one decides. A global function verified once per program
 * however many times it is called, over arguments its verifier knows nothing of. */
__attribute__((noinline)) int tego_plane_climb(__u64 dentry, __u64 m, __u64 run, __u64 params,
                                                struct tego_name_out *out)
{
    struct tego_climb_state st = {}, *s = &st;
    __u32 run_idx = run >> 32;
    const struct tego_plane_name_cfg *cfg;
    void *rows, *names;

    barrier_var(s);
    s->d = dentry; /* stored before the lookups (tego_climb_setup stores the rest) */
    s->m = m;
    if (!out)
        return TEGO_WALK_NOROWS;
    rows = bpf_map_lookup_elem(&tego_plane_rows, &run_idx);
    names = bpf_map_lookup_elem(&tego_plane_name_rows, &run_idx);
    cfg = tego_name_cfg(names, (__u32)run);
    if (!rows || !cfg)
        return TEGO_WALK_NOROWS;
    tego_climb_setup(s, s->d, s->m, run, params, rows, cfg, out->live);
    bpf_loop(TEGO_PLANE_WALK_ITERS, tego_climb_step, s, 0);
    tego_climb_out(s, out);
#if TEGO_N_FAULTS
    /* A dependency name the climb could not read was taken for none: what it met is not to be trusted (D2). */
    if (s->fault)
        return TEGO_WALK_UNRESOLVED;
#endif
    return (int)s->result;
}

/* ---- The name check (D1 to D3, D9) ---- */

/* The name check's state, on its stack and handed to its callbacks: the name; its keys (k0 the exact key, k1 to k4
 * one per prefix length, each an FNV state until the keys' pass ends); the rows they find (r0 to r4, each the config
 * row when its key finds none, which no compare accepts), and which of them still compare equal (ok, bit j for rj). */
struct tego_name_state {
    const struct tego_plane_name_row *r0, *r1, *r2, *r3, *r4;
    __u64 addr;                                 /* the name's bytes */
    __u64 k0, k1, k2, k3, k4;
    __u64 plens;                                /* the prefix lengths in bytes 0 to 3, each 0 or at most len */
    __u64 len;                                  /* the name's length (1 to 255) */
    __u64 words;
    __u64 upper_end;                            /* one past the name's last capital, 0 for none */
    __u64 ok;
    __u64 fault;                                /* the probe-read build's failed reads of the name (TEGO_N_RDF) */
};

/* Prefix key j's length (1 to 4), 0 for none. */
#define TEGO_PLEN(s, j) (((s)->plens >> (8 * ((j) - 1))) & 0xff)

/* One word of the name at the byte offset at: masked to its length and folded; *up its capitals' markers. */
static __always_inline __u64 tego_name_folded(struct tego_name_state *s, __u64 at, __u64 *up)
{
    __u64 w = tego_name_mask(TEGO_N_RDF(s->addr + at, s->fault), s->len - at);

    *up = tego_upper_bits(w);
    return w | (*up >> 2);
}

/* One FNV step of prefix key j: the word's first n - at bytes, where its prefix reaches this word. */
#define TEGO_PREFIX_STEP(s, h, j, f, at)                                                                           \
    do {                                                                                                           \
        __u64 n_ = TEGO_PLEN(s, j), h_ = ((h) ^ tego_name_mask((f), n_ - (at))) * TEGO_FNV_PRIME;                 \
        (h) ^= ((h) ^ h_) & TEGO_ALL(tego_lt((at), n_));                                                          \
    } while (0)

/* The keys' pass: each word folded into the exact key's FNV state and each prefix key's that reaches it (agent.NameKey
 * over the folded literal: the length, then the zero-padded words in the host's order), and the last capital's
 * position kept for the built-in exceptions, which compare the name's tail as spelled. */
static long tego_name_keys_step(__u32 i, struct tego_name_state *s)
{
    __u64 at = (__u64)i * 8, f, up, end;

    if (i >= s->words)
        return 1;
    f = tego_name_folded(s, at, &up);
    end = tego_marks_end(up);
    s->upper_end ^= (s->upper_end ^ (at + end)) & TEGO_ALL(tego_nz(end));
    s->k0 = (s->k0 ^ f) * TEGO_FNV_PRIME;
    TEGO_PREFIX_STEP(s, s->k1, 1, f, at);
    TEGO_PREFIX_STEP(s, s->k2, 2, f, at);
    TEGO_PREFIX_STEP(s, s->k3, 3, f, at);
    TEGO_PREFIX_STEP(s, s->k4, 4, f, at);
    return 0;
}

/* A row's word at the byte offset at, read where the verifier sees its bound (plane_name.h's tego_name_cmp_step). */
static __always_inline __u64 tego_name_row_word(const struct tego_plane_name_row *r, __u64 at)
{
    __u64 w;
    __u32 off = (__u32)at;

    barrier_var(off);
    off &= TEGO_NAME_MAX - 8;
    __builtin_memcpy(&w, &r->name[off], sizeof(w));
    return w;
}

/* Row j's compare at one word: its first n bytes against the folded word f at offset at, where n reaches it. */
#define TEGO_ROW_CMP(s, r, j, n, f, at)                                                                            \
    ((s)->ok &= ~((tego_lt((at), (n)) & tego_nz(tego_name_mask((f), (n) - (at)) ^ tego_name_row_word((r), (at))))   \
                  << (j)))

/* The compare pass: each row a key found counts only when its folded bytes are the name's (a key collision matches
 * nothing, D9); the exact row over the whole name, a prefix row over its literal's length. */
static long tego_name_rows_cmp_step(__u32 i, struct tego_name_state *s)
{
    __u64 at = (__u64)i * 8, f, up;

    if (i >= s->words)
        return 1;
    f = tego_name_folded(s, at, &up);
    TEGO_ROW_CMP(s, s->r0, 0, s->len, f, at);
    TEGO_ROW_CMP(s, s->r1, 1, TEGO_PLEN(s, 1), f, at);
    TEGO_ROW_CMP(s, s->r2, 2, TEGO_PLEN(s, 2), f, at);
    TEGO_ROW_CMP(s, s->r3, 3, TEGO_PLEN(s, 3), f, at);
    TEGO_ROW_CMP(s, s->r4, 4, TEGO_PLEN(s, 4), f, at);
    return 0;
}

/* What row j (r, its literal n bytes long) says, where it compared equal: its deny entries are candidates; its D3
 * scope bits are kept for the level-1 test; its exception entries are cancelled where the name is the row's whole
 * literal and its bytes from except_from on are the row's as spelled (no capital there), as the scan compares them
 * (ADR 0043 implementation note, C2). decide.PlaneRows.nameCheck applies the same arms. */
#define TEGO_ROW_SAYS(s, r, j, n, live, cancel, exempt)                                                             \
    do {                                                                                                           \
        __u64 ok_ = ((s)->ok >> (j)) & 1, whole_ = (j) == 0 ? 1 : tego_nz((n) ^ (s)->len) ^ 1;                       \
        (live) |= (r)->deny & TEGO_ALL(ok_);                                                                      \
        (exempt) |= (__u64)(r)->exempt & TEGO_ALL(ok_);                                                           \
        (cancel) |= (r)->except & TEGO_ALL(ok_ & whole_ & (tego_lt((r)->except_from, (s)->upper_end) ^ 1));       \
    } while (0)

/* agent.NameKey's last step: bit 63 clear, bit 62 the form, 0 (the config row's key) replaced by 1. */
static __always_inline __u64 tego_name_key_of(__u64 h, __u64 prefix)
{
    h = (h & ~(3ULL << 62)) | prefix << 62;
    return h | (tego_nz(h) ^ 1);
}

/* The row key finds in names, or, when it finds none, the config row at key 0 looked up afresh (no compare accepts it:
 * its flags carry TEGO_NAME_ROW_CONFIG), so a row pointer is a lookup's own value either way, never the caller's
 * config row pointer: a verifier that keeps a map value's id past its NULL test (Fedora's 7.2) told the name check's
 * paths apart by which of its five rows aliased that pointer, 2^5 states at the compare pass, each verifying it anew
 * (65,000 verified instructions in every program that asks names, against 8,700 on 6.17), where values of lookups of
 * their own are equal up to their ids. A key of 0 (an unused prefix length) looks the config row up at once. NULL
 * when the config row is gone as well, which the caller refuses NOROWS (D9). *valid is whether the row is a name row
 * of the run's gen, of the form looked for and of the length its compare reads. */
static __always_inline const struct tego_plane_name_row *tego_name_row(void *names, __u64 key, __u32 gen,
                                                                         __u64 prefix, __u64 n, __u64 *valid)
{
    const struct tego_plane_name_row *r;
    __u64 k = key;

    r = bpf_map_lookup_elem(names, &k);
    if (!r) {
        k = 0;
        r = bpf_map_lookup_elem(names, &k);
        if (!r)
            return 0;
    }
    *valid = (tego_nz(r->gen ^ gen) | tego_nz(r->name_len ^ n) |
              tego_nz((r->flags & (TEGO_NAME_ROW_PREFIX | TEGO_NAME_ROW_CONFIG)) ^ prefix)) ^ 1;
    return r;
}

/* Row j of the name check's state, from tego_name_row: refused NOROWS when the config row is gone (D9), and its
 * validity bit put at bit j of s->ok. */
#define TEGO_NAME_ROW_AT(rj, key, prefix, n, j)                                                                    \
    do {                                                                                                           \
        const struct tego_plane_name_row *r_ = tego_name_row(names, (key), gen, (prefix), (n), &v);              \
        if (!r_)                                                                                                   \
            return tego_name_failed(run_idx, TEGO_WALK_NOROWS);                                                  \
        (rj) = r_;                                                                                                 \
        s->ok |= v << (j);                                                                                         \
    } while (0)

/* tego_plane_name_check asks the slot's name rows of the name at d, the object's final name's dentry
 * (tego_plane_name resolved a mount root to its mountpoint), for the run in run (run_idx << 32 | gen), with the slot
 * header's prefix lengths in plens' low four bytes (its high four are 0). It returns TEGO_NAME_NONE,
 * TEGO_NAME_CANDIDATE with the candidate entries and D3's scope bits in *out (for the climb to decide), or a counted
 * failure code. */
__attribute__((noinline)) int tego_plane_name_check(__u64 d, __u64 run, __u64 plens, struct tego_name_out *out)
{
    struct tego_name_state st = {}, *s = &st;
    __u32 run_idx = run >> 32, gen = (__u32)run, k;
    const struct tego_plane_name_cfg *cfg;
    __u64 len, v, live = 0, cancel = 0, exempt = 0;
    void *names;

    barrier_var(s); /* the state is stored as written, not held in registers spilled across the lookups */
    s->upper_end = plens >> 32;
    if (!out)
        return tego_name_failed(run_idx, TEGO_WALK_NOROWS);
    names = bpf_map_lookup_elem(&tego_plane_name_rows, &run_idx);
    cfg = tego_name_cfg(names, gen);
    if (!names || !cfg)
        return tego_name_failed(run_idx, TEGO_WALK_NOROWS);

    /* The keys (D2, D9). */
#if TEGO_N_FAULTS
    /* Unknown to the verifier from the start, as each callback's OR of an error leaves it. */
    s->fault = cfg->zero;
#endif
    len = TEGO_N_HASHLEN(d, s->fault) >> 32;
    s->addr = TEGO_N_NAME(d, s->fault);
#if TEGO_N_FAULTS
    if (s->fault)
        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);
#endif
    if (!len || len > TEGO_NAME_MAX - 1)
        return TEGO_NAME_NONE;
    s->len = len;
    s->words = (len + 7) / 8;
    /* A prefix length longer than the name keys nothing: it is 0 here, and its row compares unequal. */
#pragma unroll
    for (k = 0; k < TEGO_PLANE_NAME_PREFIXES; k++) {
        __u64 n = (plens >> (8 * k)) & 0xff;

        s->plens |= (n & TEGO_ALL(tego_lt(len, n) ^ 1)) << (8 * k);
    }
    s->k0 = TEGO_FNV_BASIS ^ len;
    s->k1 = TEGO_FNV_BASIS ^ TEGO_PLEN(s, 1);
    s->k2 = TEGO_FNV_BASIS ^ TEGO_PLEN(s, 2);
    s->k3 = TEGO_FNV_BASIS ^ TEGO_PLEN(s, 3);
    s->k4 = TEGO_FNV_BASIS ^ TEGO_PLEN(s, 4);
    bpf_loop(TEGO_NAME_WORDS, tego_name_keys_step, s, 0);
#if TEGO_N_FAULTS
    /* A word of the name not read: no key of it is the name's (D2). */
    if (s->fault)
        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);
#endif

    /* The rows they find, each confirmed below by its folded bytes; an unused prefix length's key is 0, the config
     * row's, which no compare accepts. */
    s->ok = 0;
    TEGO_NAME_ROW_AT(s->r0, tego_name_key_of(s->k0, 0), 0, s->len, 0);
    TEGO_NAME_ROW_AT(s->r1, tego_name_key_of(s->k1, 1) & TEGO_ALL(tego_nz(TEGO_PLEN(s, 1))), TEGO_NAME_ROW_PREFIX,
                      TEGO_PLEN(s, 1), 1);
    TEGO_NAME_ROW_AT(s->r2, tego_name_key_of(s->k2, 1) & TEGO_ALL(tego_nz(TEGO_PLEN(s, 2))), TEGO_NAME_ROW_PREFIX,
                      TEGO_PLEN(s, 2), 2);
    TEGO_NAME_ROW_AT(s->r3, tego_name_key_of(s->k3, 1) & TEGO_ALL(tego_nz(TEGO_PLEN(s, 3))), TEGO_NAME_ROW_PREFIX,
                      TEGO_PLEN(s, 3), 3);
    TEGO_NAME_ROW_AT(s->r4, tego_name_key_of(s->k4, 1) & TEGO_ALL(tego_nz(TEGO_PLEN(s, 4))), TEGO_NAME_ROW_PREFIX,
                      TEGO_PLEN(s, 4), 4);
    if (!s->ok)
        return TEGO_NAME_NONE;
    bpf_loop(TEGO_NAME_WORDS, tego_name_rows_cmp_step, s, 0);
#if TEGO_N_FAULTS
    if (s->fault)
        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);
#endif

    /* What they say. */
    TEGO_ROW_SAYS(s, s->r0, 0, s->len, live, cancel, exempt);
    TEGO_ROW_SAYS(s, s->r1, 1, TEGO_PLEN(s, 1), live, cancel, exempt);
    TEGO_ROW_SAYS(s, s->r2, 2, TEGO_PLEN(s, 2), live, cancel, exempt);
    TEGO_ROW_SAYS(s, s->r3, 3, TEGO_PLEN(s, 3), live, cancel, exempt);
    TEGO_ROW_SAYS(s, s->r4, 4, TEGO_PLEN(s, 4), live, cancel, exempt);
    out->live = live & ~cancel;
    out->exempt = (__u8)exempt;
    return out->live ? TEGO_NAME_CANDIDATE : TEGO_NAME_NONE;
}

/* D2's prefilter: whether the final name at d is a candidate for the name rows by the slot header hdr. Its first
 * word, masked to the name's length (an inline d_iname keeps stale bytes past its NUL) and folded, must start with
 * one of the header's leads; a lead's bytes are a literal's, none of them 0, so a name shorter than a lead fails its
 * compare without a length test, and an unused lead (length 0) matches nothing. Unrolled: a loop's index, which
 * addresses the header, is a value the verifier must know exactly, and it walked back through the loop for it at
 * every iteration (a thousand lines of precision tracking a program). */
static __always_inline int tego_name_candidate(const struct tego_plane_slot *hdr, __u64 d, __u64 *flt)
{
    __u64 len = TEGO_N_HASHLEN(d, *flt) >> 32, f, hit = 0;
    __u32 i;

    if (len < hdr->min_len || len > TEGO_NAME_MAX - 1)
        return 0;
    f = tego_fold_word(tego_name_mask(TEGO_N_RDF(TEGO_N_NAME(d, *flt), *flt), len));
#pragma unroll
    for (i = 0; i < TEGO_PLANE_NAME_LEADS; i++) {
        __u64 n = hdr->lead_len[i];

        hit |= (tego_nz(tego_name_mask(f, n) ^ hdr->lead[i]) ^ 1) & tego_nz(n);
        /* One lead at a time: clang would hoist the eight side by side and spill them into the frame the name check
         * stacks on. */
        asm volatile("" : "+r"(hit), "+r"(f)::"memory");
    }
    return (int)hit;
}

/* tego_plane_name is a hook's one question of the name entries, of the object at dentry on vfsmount (a file the hook
 * holds, where the walk allowed the question), for the run in run (run_idx << 32 | gen); the caller has seen
 * TEGO_SLOT_NAME_DECIDES in the slot header. The object's final name is its dentry's, or, at the root of a mount that
 * is not the namespace root (a file bind-mounted over the name), its mountpoint's (D2): the path's own component,
 * which Evaluate reads. A name no lead admits (D2's prefilter, by the slot header read again here) is TEGO_NAME_NONE
 * with no lookup. Otherwise the name check, then the climb from the name's directory (level 1). The lowest candidate
 * entry decides (decide.PlaneRows.nameCheck's order): covered at the scope the climb stopped at (DONE), a refusal
 * named by that entry and scope; its scopes behind a dependency directory or the root (STOP), the lowest covered
 * candidate refuses, named by its nearest scope, the first of its bits the same climb met (tego_climb_out);
 * undecided at the bound, refused path-unresolved. A D3 exemption met at level 1 answers TEGO_NAME_NONE. A name the
 * probe-read build could not read refuses path-unresolved (D2). It returns TEGO_NAME_NONE, TEGO_NAME_DENY | rule << 8,
 * or a counted failure code. */
__attribute__((noinline)) int tego_plane_name(__u64 dentry, __u64 vfsmount, __u64 run)
{
    struct tego_name_out o = {};
    __u32 run_idx = run >> 32, k;
    const struct tego_plane_slot *hdr;
    __u64 d, m, mroot, p, plens, flt = 0;
    int res, cand;

    if (!vfsmount)
        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);
    hdr = bpf_map_lookup_elem(&tego_plane_slots, &run_idx);
    if (!hdr || hdr->gen != (__u32)run || !(hdr->flags & TEGO_SLOT_NAME_DECIDES))
        return tego_name_failed(run_idx, TEGO_WALK_NOROWS);
    /* The name's dentry: a mount root's name is its mountpoint's, crossing at most four stacked mounts. */
    d = dentry;
    m = vfsmount - bpf_core_field_offset(struct mount, mnt);
    mroot = TEGO_N_VMROOT(vfsmount);
#pragma unroll
    for (k = 0; k < 4; k++) {
        __u64 pm = d == mroot ? TEGO_N_MPARENT(m) : 0;

        if (pm && pm != m) {
            d = TEGO_N_MPOINT(m);
            m = pm;
            mroot = TEGO_N_MROOT(pm);
        }
    }
    if (d == mroot && TEGO_N_MPARENT(m) != m)
        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);
    cand = tego_name_candidate(hdr, d, &flt);
#if TEGO_N_FAULTS
    /* The name not read: refused, never read as one no lead admits (D2). */
    if (flt)
        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);
#endif
    if (!cand)
        return TEGO_NAME_NONE;
    plens = (__u64)hdr->prefix_len[0] | (__u64)hdr->prefix_len[1] << 8 | (__u64)hdr->prefix_len[2] << 16 |
            (__u64)hdr->prefix_len[3] << 24;
    res = tego_plane_name_check(d, run, plens, &o);
    if (res != TEGO_NAME_CANDIDATE)
        return res;
    p = TEGO_N_PARENT(d);
    if (!p || p == d)
        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);
    res = tego_plane_climb(p, m, run, TEGO_CLIMB_PARAMS(1, TEGO_CLIMB_NAME), &o);
    if (res == TEGO_WALK_MISMATCH || res == TEGO_WALK_NOROWS)
        return tego_name_failed(run_idx, res);
    /* D3: a write entry the top-level contract declares at this name in this directory exempts it from every entry. */
    if (o.own & o.exempt)
        return TEGO_NAME_NONE;
    if (res != TEGO_CLIMB_DONE && res != TEGO_CLIMB_STOP)
        return tego_name_failed(run_idx, res);
    if (!o.live)
        return TEGO_NAME_NONE;
    return TEGO_NAME_DENY | tego_name_tag(tego_bit_index(o.nearest), tego_ctz64(o.live)) << 8;
}

/* ---- D5: a directory's rename ---- */

/* Whether a climb ended undecided: at the bound or at a dentry with no parent (1), or not (0), without a branch. */
static __always_inline __u64 tego_undecided(int res)
{
    return tego_lt((__u64)(res - TEGO_WALK_UNRESOLVED) & 0xff, 2);
}

/* tego_plane_move is D5 for one direction of a rename path_rename holds, for the run in run (run_idx << 32 | gen):
 * the directory src on its struct mount sm moved to the name dst on dm, refused when some entry's scopes cover the old
 * place and not the new one, unless the directory carries one of that entry's scope bits itself (its scope row moves
 * with it). The old place is climbed from the directory itself (level 1: its own row and name); the new place from the
 * new name, whose row is not looked up (the inode there after the move is src's, whose bits the skip answers) but
 * whose name takes the dependency test (TEGO_CLIMB_NEW_NAME), then its directory at level 2; each climb stops once
 * every scope is met. A
 * climb that cannot decide on a side the refusal depends on refuses path-unresolved. The deciding entry's rule names
 * its nearest scope above the old place, the first of its bits that place's climb met (D8).
 * decide.PlaneRows.ScopeMoveRefused is the model. It returns TEGO_NAME_NONE, TEGO_NAME_DENY | rule << 8 (refused
 * rename-outside-contract, plane_reason refer), or a counted failure code. Global, one direction a call:
 * tego_name_move_path asks the other direction of an exchange with a second call. Both climbs are
 * tego_plane_climb's, the global function tego_plane_name calls, so the program verifies the climb once; this frame
 * holds one tego_name_out, both climbs' in turn, and no climb state, so path_rename's chain (the hook, this
 * function, tego_plane_climb and its callback) stays inside the 512 bytes a chain may use as 5.14 to 6.9 round
 * frames. */
/* tego_entries_of for tego_plane_move, a static subprogram: its frame, not D5's, holds the config row's words while
 * it ORs them (inline, clang kept both sets of them live, spilled into the frame path_rename's chain stacks the climb
 * on). */
static __attribute__((noinline)) __u64 tego_move_entries(const struct tego_plane_name_cfg *cfg, __u64 bits)
{
    return tego_entries_of(cfg, bits);
}

__attribute__((noinline)) int tego_plane_move(__u64 src, __u64 sm, __u64 dst, __u64 dm, __u64 run)
{
    struct tego_name_out o = {};
    const struct tego_plane_name_cfg *cfg;
    __u32 run_idx = run >> 32, e;
    __u64 met, rel, undec, seq;
    void *names;
    int resA, resB;

    names = bpf_map_lookup_elem(&tego_plane_name_rows, &run_idx);
    cfg = tego_name_cfg(names, (__u32)run);
    if (!cfg)
        return tego_name_failed(run_idx, TEGO_WALK_NOROWS);

    /* The old place. The entries D5 may refuse for: covered there, or undecided there (the bound), and not carried
     * by the directory itself. */
    resA = tego_plane_climb(src, sm, run, TEGO_CLIMB_PARAMS(1, TEGO_CLIMB_PLACE), &o);
    if (resA >= TEGO_WALK_MISMATCH)
        return tego_name_failed(run_idx, resA);
    met = tego_move_entries(cfg, o.met);
    rel = cfg->entries & ~tego_move_entries(cfg, o.own) & (met | TEGO_ALL(tego_undecided(resA)));
    undec = rel & ~met;
    seq = o.seq;
    if (!rel)
        return TEGO_NAME_NONE;

    /* The new place, from the new name (no row; under a dependency directory's name the climb stops there, covering
     * nothing) and its directory, level 2. */
    resB = tego_plane_climb(dst, dm, run, TEGO_CLIMB_PARAMS(1, TEGO_CLIMB_PLACE) | TEGO_CLIMB_NEW_NAME, &o);
    if (resB >= TEGO_WALK_MISMATCH)
        return tego_name_failed(run_idx, resB);
    rel &= ~tego_move_entries(cfg, o.met);

    /* The deciding entry, and its nearest scope above the old place, which names the refusal: the first of its scope
     * bits the old place's climb met. */
    if (!rel)
        return TEGO_NAME_NONE;
    e = tego_ctz64(rel);
    if ((undec >> e) & 1)
        return tego_name_failed(run_idx, resA);
    if (tego_undecided(resB))
        return tego_name_failed(run_idx, resB);
    return TEGO_NAME_DENY | tego_name_tag(tego_bit_index(tego_scope_first(seq, cfg->entry_mask[e])), e) << 8;
}

/* ---- The hooks' side ---- */

/* Whether an inode is a directory: a name entry never decides one (D1). A negative dentry's object is being created
 * by a hook that creates no directory (mknod, symlink, link, an O_CREAT open). */
static __always_inline int tego_is_dir(struct inode *inode)
{
    return inode && (inode->i_mode & 0170000) == 0040000;
}

/* A pointer the hook holds, laundered to a scalar through the task's scratch value (the walk's way, ADR 0024's T0
 * note): a global function cannot take a trusted BTF pointer before 6.8. */
static __always_inline __u64 tego_name_launder(struct tego_plane_decision *sc, const void *p)
{
    sc->launder_dentry = (__u64)p;
    return *(volatile __u64 *)&sc->launder_dentry;
}

/* Whether the slot header hdr says the run has name entries (ADR 0043 D9's TEGO_SLOT_NAME_DECIDES): the one test a
 * hook makes before it asks them, so a run without name entries pays a flag test and nothing more. */
static __always_inline int tego_names_on(const struct tego_plane_slot *hdr)
{
    return (hdr->flags & TEGO_SLOT_NAME_DECIDES) != 0;
}

/* The name entries' answer for the object at dentry on mnt for run: TEGO_NAME_NONE, TEGO_NAME_DENY with *rule, or a
 * failure code (counted). The caller asks only where the walk allowed the question, the object is no directory and
 * the slot's header carries the flag (tego_names_on). */
static __always_inline int tego_name_check_path(struct tego_plane_decision *sc, struct dentry *dentry,
                                                 struct vfsmount *mnt, const struct tego_run *run, __u32 *rule)
{
    __u64 d = tego_name_launder(sc, dentry), m = tego_name_launder(sc, mnt);
    int res = tego_plane_name(d, m, (__u64)run->run_idx << 32 | run->gen);

    *rule = (__u32)res >> 8;
    return res & 0xff;
}

/* D5 for a rename path_rename holds: the directory old_dentry under old_dir moved to new_dentry under new_dir, and,
 * when the destination is a directory as well, that one moved the other way (RENAME_EXCHANGE; the 5.14 hook carries
 * no flags, so a positive destination directory is taken as an exchange, as REFER's reverse arm takes it). Each
 * direction is asked only of a directory (odir: old_dentry is one, ndir: new_dentry is one): a file that leaves
 * coverage in an exchange with a directory is D1's (both ends' name checks), never D5's, as
 * decide.PlaneEvaluator.rename asks D5 only of a directory. It returns TEGO_NAME_NONE, TEGO_NAME_DENY with *rule,
 * or a failure code (counted). */
static __always_inline int tego_name_move_path(struct tego_plane_decision *sc, struct dentry *old_dentry,
                                                const struct path *old_dir, int odir, struct dentry *new_dentry,
                                                const struct path *new_dir, int ndir, const struct tego_run *run,
                                                __u32 *rule)
{
    __u64 runw = (__u64)run->run_idx << 32 | run->gen;
    __u64 src = tego_name_launder(sc, old_dentry);
    __u64 sm = tego_name_launder(sc, old_dir->mnt) - bpf_core_field_offset(struct mount, mnt);
    __u64 dst = tego_name_launder(sc, new_dentry);
    __u64 dm = tego_name_launder(sc, new_dir->mnt) - bpf_core_field_offset(struct mount, mnt);
    int res = TEGO_NAME_NONE;

    if (odir)
        res = tego_plane_move(src, sm, dst, dm, runw);
    if (res == TEGO_NAME_NONE && ndir)
        res = tego_plane_move(dst, dm, src, sm, runw);
    *rule = (__u32)res >> 8;
    return res & 0xff;
}
