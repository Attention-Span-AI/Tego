// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* The decision plane's fill and clear (ADR 0025 (1), (2); docs/p0/TIER3-PLAN.md T4; docs/p0/enforce-plane.md R6, R16).
 *
 * The plane's rows are keyed by a struct inode *, which userspace never sees (ADR 0025): the launcher holds one
 * O_PATH descriptor per keyed path, hands this program the wanted descriptor numbers with their row templates
 * (tego_plane_fill_wants, keyed by its tgid, so launchers fill at once), and an iter/task_file pass over its own
 * descriptor table writes each row at the
 * inode the descriptor names, into the slot's inner maps (tego_plane_rows, tego_plane_exec_rows at run_idx),
 * with the run's gen. For each descriptor it reports back (mnt_id, i_ino) and a status; Prepare compares these
 * with the identity it recorded when it made the plan (one statx of the descriptor), and fails on a mismatch, so a
 * descriptor number reused on another file fails Prepare (enforce/cgroup planefill.go).
 *
 * The programs and their maps are pinned in the mode's fill directory and shared by every launcher of the build
 * (enforce/cgroup plane.go openPlaneFiller), each launcher's state keyed by its tgid (include/maps.h).
 *
 * The iteration is task-scoped where the kernel has it (bpf_iter_link_info.task, 6.1+); an older kernel ignores
 * the scope and shows every task's descriptors, so the program keeps only the launcher's tgid either way, and
 * counts what it was shown (tego_plane_fill_cfg.visited) for the unscoped cost.
 *
 * tego_plane_clear, a BPF_PROG_TYPE_SYSCALL program run by BPF_PROG_TEST_RUN, deletes a slot's rows of every gen
 * but one, in the kernel (ADR 0025 (1) as T0 amended it): stale rows count as absent to the walk without it, so it
 * runs only off the run's path, or when a fill found the slot's map full of a previous run's rows.
 *
 * Two builds, like decide.bpf.c and for the same reason (ADR 0024 (9)): the mount id is read from struct mount,
 * which only a cast reaches, through bpf_rdonly_cast (TEGO_PLANE_RDONLY=1) or a CO-RE probe read (=0).
 */
#define TEGO_PLANE_MAPS
#define TEGO_PLANE_FILL_MAPS
#include "maps.h"

#ifndef TEGO_PLANE_RDONLY
#error "internal/bpf/gen.go builds this file with -DTEGO_PLANE_RDONLY=1 (fillrd) and =0 (fillpr)"
#endif

char _license[] SEC("license") = "Dual BSD/GPL";

/* BTF anchors for bpf2go's -type mirrors. */
const struct tego_plane_fill_cfg *tego_btf_plane_fill_cfg;
const struct tego_plane_fill_row *tego_btf_plane_fill;
const struct tego_plane_clear_ctx *tego_btf_plane_clear_ctx;

#if TEGO_PLANE_RDONLY
#define TEGO_MNT_ID(vm)                                                                                           \
    ((__u64)bpf_core_cast((void *)((vm) - bpf_core_field_offset(struct mount, mnt)), struct mount)->mnt_id)
#else
static __always_inline __u64 tego_fill_mnt_id(__u64 vm)
{
    int id = 0;

    bpf_probe_read_kernel(&id, sizeof(id),
                          (void *)(vm - bpf_core_field_offset(struct mount, mnt) + bpf_core_field_offset(struct mount, mnt_id)));
    return (__u64)id;
}
#define TEGO_MNT_ID(vm) tego_fill_mnt_id(vm)
#endif

/* The exec row's name is read through the build's reader, as bprm_check reads it (plane_name.h). */
#if TEGO_PLANE_RDONLY
#define TEGO_RD_WORD(addr) (bpf_core_cast((void *)(addr), struct qstr)->hash_len)
#else
static __always_inline __u64 tego_fill_rd64(__u64 addr)
{
    __u64 v = 0;

    bpf_probe_read_kernel(&v, sizeof(v), (void *)addr);
    return v;
}
#define TEGO_RD_WORD(addr) tego_fill_rd64(addr)
#endif
#include "plane_name.h"

/* The map reads, as helpers: a program body reads maps only through helpers (bpf/tests TestRunSetLookupFirst). */
static __always_inline struct tego_plane_fill_cfg *tego_fill_config(__u32 tgid)
{
    return bpf_map_lookup_elem(&tego_plane_fill_config, &tgid);
}

static __always_inline struct tego_plane_fill_row *tego_fill_want(__u32 tgid, __u32 what, __u32 fd)
{
    __u64 key = TEGO_PLANE_FILL_KEY(tgid, what, fd);

    return bpf_map_lookup_elem(&tego_plane_fill_wants, &key);
}

static __always_inline void *tego_slot_rows(void *outer, __u32 run_idx)
{
    __u32 idx = run_idx;

    return bpf_map_lookup_elem(outer, &idx);
}

/* Writes one wanted descriptor's row. An fs row's key is the dentry's inode pointer, the one the walk looks up; an
 * exec row's is the link's (tego_exec_link_key over the inode, the dentry's directory's inode and the dentry's own
 * name, read as bprm_check reads it), so hard links of one inode that two entries name get a row each (enforce-plane §6 E15). A row
 * of this run's gen already at the key is a second entry on one fs inode, or on one exec link, which fails (a
 * duplicate must refuse Prepare, not keep one); a row of another gen is a previous run's and is replaced. */
static __always_inline void tego_fill_one(struct tego_plane_fill_cfg *cfg, struct tego_plane_fill_row *w,
                                           struct file *file)
{
    struct dentry *dentry = file->f_path.dentry;
    struct inode *inode = dentry->d_inode;
    __u64 key;
    void *rows;
    long err;

    /* The mount pointer is laundered through the map value into a scalar: container_of on a BTF pointer is
     * refused, and the cast or the probe read takes an address. */
    cfg->launder = (__u64)file->f_path.mnt;
    w->mnt_id = TEGO_MNT_ID(*(volatile __u64 *)&cfg->launder);
    if (!inode) {
        w->status = TEGO_FILL_NOINODE;
        return;
    }
    w->ino = inode->i_ino;
    key = (__u64)inode;

    if (w->what == TEGO_FILL_FS) {
        struct tego_plane_row row = {};
        struct tego_plane_row *old;

        rows = tego_slot_rows(&tego_plane_rows, cfg->run_idx);
        if (!rows) {
            w->status = TEGO_FILL_NOMAP;
            return;
        }
        old = bpf_map_lookup_elem(rows, &key);
        if (old && old->gen == cfg->gen) {
            w->status = TEGO_FILL_DUP;
            w->other_rule = old->rule_idx;
            return;
        }
        row.i_ino = inode->i_ino;
        row.i_generation = inode->i_generation;
        row.s_dev = inode->i_sb->s_dev;
        row.gen = cfg->gen;
        row.rule_idx = w->rule_idx;
        row.kind = w->kind;
        row.scope = w->scope; /* ADR 0043 D4: a scope directory's bit, which only the name check's climb reads */
        row.exec_rule = w->exec_rule;
        row.pad2 = w->pad2; /* C40: immutable ledger control-name classifier */
        err = bpf_map_update_elem(rows, &key, &row, BPF_ANY);
        if (err) {
            w->status = TEGO_FILL_UPDATE;
            w->err = err;
            return;
        }
        w->status = TEGO_FILL_OK;
        return;
    }
    if (w->what == TEGO_FILL_EXEC) {
        struct tego_plane_exec_row *old;
        struct inode *parent = dentry->d_parent->d_inode;
        struct tego_name_pass nm = {};
        struct tego_plane_exec_row *row = &cfg->row;
        __u64 name_key;

        if (!parent) {
            w->status = TEGO_FILL_NOINODE;
            return;
        }
        w->parent_ino = parent->i_ino;
        if (dentry->d_name.len != w->name_len) {
            w->status = TEGO_FILL_NAME;
            return;
        }
        rows = tego_slot_rows(&tego_plane_exec_rows, cfg->run_idx);
        if (!rows) {
            w->status = TEGO_FILL_NOMAP;
            return;
        }
        row->name_len = w->name_len;
        __builtin_memcpy(row->name, w->name, sizeof(row->name));
        /* The link this descriptor holds: its name must be the entry's, byte for byte, and keys the row as
         * bprm_check's lookup of an exec of it will. */
        name_key = tego_name_key(dentry, &nm);
        if (!tego_name_eq(&nm, row)) {
            w->status = TEGO_FILL_NAME;
            return;
        }
        /* The pointers reach the key as scalars through the config value, as the mount's does: the verifier refuses
         * arithmetic on a pointer. */
        cfg->launder = (__u64)inode;
        key = *(volatile __u64 *)&cfg->launder;
        cfg->launder = (__u64)parent;
        key = tego_exec_link_key(key, *(volatile __u64 *)&cfg->launder, name_key);
        old = bpf_map_lookup_elem(rows, &key);
        if (old && old->gen == cfg->gen) {
            w->status = TEGO_FILL_DUP;
            w->other_rule = old->rule_idx;
            return;
        }
        row->parent = (__u64)parent;
        row->inode = (__u64)inode;
        row->parent_ino = parent->i_ino;
        row->i_ino = inode->i_ino;
        row->parent_generation = parent->i_generation;
        row->i_generation = inode->i_generation;
        row->s_dev = inode->i_sb->s_dev;
        row->gen = cfg->gen;
        row->rule_idx = w->rule_idx;
        row->flags = 0;
        err = bpf_map_update_elem(rows, &key, row, BPF_ANY);
        if (err) {
            w->status = TEGO_FILL_UPDATE;
            w->err = err;
            return;
        }
        w->status = TEGO_FILL_OK;
        return;
    }
    if (w->what == TEGO_FILL_LISTEN) {
        struct tego_plane_listen_key lk = {};
        struct tego_plane_listen_row lr = {};
        struct tego_plane_listen_row *old;

        if ((inode->i_mode & 0170000) != 0040000 || !w->name_len || w->name_len > 107) {
            w->status = TEGO_FILL_NAME;
            return;
        }
        rows = tego_slot_rows(&tego_plane_listen_rows, cfg->run_idx);
        if (!rows) {
            w->status = TEGO_FILL_NOMAP;
            return;
        }
        lk.parent = (__u64)inode;
        lk.name_len = w->name_len;
        __builtin_memcpy(lk.name, w->name, sizeof(lk.name));
        old = bpf_map_lookup_elem(rows, &lk);
        if (old && old->gen == cfg->gen) {
            w->status = TEGO_FILL_DUP;
            w->other_rule = old->rule_idx;
            return;
        }
        lr.parent_ino = inode->i_ino;
        lr.parent_generation = inode->i_generation;
        lr.s_dev = inode->i_sb->s_dev;
        lr.gen = cfg->gen;
        lr.rule_idx = w->rule_idx;
        err = bpf_map_update_elem(rows, &lk, &lr, BPF_ANY);
        if (err) {
            w->status = TEGO_FILL_UPDATE;
            w->err = err;
            return;
        }
        w->parent_ino = inode->i_ino;
        w->status = TEGO_FILL_OK;
        return;
    }
    w->status = TEGO_FILL_WHAT;
}

/* The fill: shown each descriptor of each task the link's scope admits, it keeps the wanted ones of the launcher
 * reading the iterator, the task the program runs in: each launcher filling at once has its own config and
 * templates (enforce-plane §2.6), and a template of another gen (a dead launcher's, whose tgid this one has now) is
 * not applied. */
SEC("iter/task_file")
int tego_plane_fill(struct bpf_iter__task_file *ctx)
{
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    struct tego_plane_fill_cfg *cfg;
    struct tego_plane_fill_row *w;
    __u32 me = bpf_get_current_pid_tgid() >> 32;

    if (!task || !file)
        return 0;
    cfg = tego_fill_config(me);
    if (!cfg)
        return 0;
    cfg->visited++;
    if ((__u32)task->tgid != me || cfg->tgid != me)
        return 0;
    cfg->matched++;
    w = tego_fill_want(me, TEGO_FILL_FS, ctx->fd);
    if (w && w->status == TEGO_FILL_UNSEEN && w->gen == cfg->gen)
        tego_fill_one(cfg, w, file);
    w = tego_fill_want(me, TEGO_FILL_EXEC, ctx->fd);
    if (w && w->status == TEGO_FILL_UNSEEN && w->gen == cfg->gen)
        tego_fill_one(cfg, w, file);
    w = tego_fill_want(me, TEGO_FILL_LISTEN, ctx->fd);
    if (w && w->status == TEGO_FILL_UNSEEN && w->gen == cfg->gen)
        tego_fill_one(cfg, w, file);
    return 0;
}

struct tego_clear_state {
    __u32 keep_gen;
    __u32 deleted;
};

static long tego_clear_row(struct bpf_map *map, __u64 *key, struct tego_plane_row *row, struct tego_clear_state *c)
{
    if (row->gen != c->keep_gen && bpf_map_delete_elem(map, key) == 0)
        c->deleted++;
    return 0;
}

static long tego_clear_exec_row(struct bpf_map *map, __u64 *key, struct tego_plane_exec_row *row,
                                 struct tego_clear_state *c)
{
    if (row->gen != c->keep_gen && bpf_map_delete_elem(map, key) == 0)
        c->deleted++;
    return 0;
}

static long tego_clear_listen_row(struct bpf_map *map, struct tego_plane_listen_key *key,
                                   struct tego_plane_listen_row *row, struct tego_clear_state *c)
{
    if (row->gen != c->keep_gen && bpf_map_delete_elem(map, key) == 0)
        c->deleted++;
    return 0;
}

/* The clear: deletes every row of the slot whose gen is not keep_gen, fs and exec, without a key leaving the
 * kernel. A slot with no exec-rows map yet is no error: its fs map is the one every slot has from its first use. */
SEC("syscall")
int tego_plane_clear(struct tego_plane_clear_ctx *ctx)
{
    struct tego_clear_state fs = {.keep_gen = ctx->keep_gen};
    struct tego_clear_state ex = {.keep_gen = ctx->keep_gen};
    struct tego_clear_state ls = {.keep_gen = ctx->keep_gen};
    void *rows = tego_slot_rows(&tego_plane_rows, ctx->run_idx);
    void *exec;

    if (!rows) {
        ctx->status = 1;
        return 0;
    }
    bpf_for_each_map_elem(rows, tego_clear_row, &fs, 0);
    exec = tego_slot_rows(&tego_plane_exec_rows, ctx->run_idx);
    if (exec)
        bpf_for_each_map_elem(exec, tego_clear_exec_row, &ex, 0);
    void *listen = tego_slot_rows(&tego_plane_listen_rows, ctx->run_idx);
    if (listen)
        bpf_for_each_map_elem(listen, tego_clear_listen_row, &ls, 0);
    ctx->deleted = fs.deleted;
    ctx->exec_deleted = ex.deleted;
    ctx->listen_deleted = ls.deleted;
    ctx->status = 0;
    return 0;
}
