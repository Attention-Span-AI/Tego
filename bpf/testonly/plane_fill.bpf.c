// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* A test-only fill of the decision plane's rows (internal/bpf plane_decide_integration_test.go), compiled into a
 * binding that builds with -tags integration,tegobpf only and that no tego binary embeds.
 *
 * The plane's rows are keyed by struct inode *, which userspace never learns (ADR 0025 (2)); TIER3-PLAN T4's
 * bpf/decide_fill.bpf.c fills them for a run from the launcher's held O_PATH descriptors and checks the result
 * against fdinfo. T3's root tests need rows before T4 exists, so this iter/task_file program does the smallest part
 * of that job: for each descriptor of the test process named in tego_test_fill_tmpl, it writes the template's row
 * into the slot's rows map (or exec-rows map) under the descriptor's inode, with the identity fields read from the
 * same inode, and optionally corrupted so that a test can make a row whose identity no longer matches. */
#define TEGO_PLANE_MAPS
#include "maps.h"
#include "plane_name.h"

char _license[] SEC("license") = "Dual BSD/GPL";

/* One template: exec selects the exec-rows map and xrow, else row goes to the rows map. corrupt flips the row's
 * i_generation so that its identity check fails (ADR 0025 (4)). name_key is an exec row's name key
 * (internal/bpf.PlaneNameKey of xrow's name), which keys the row at its link with the descriptor's inode and
 * directory (tego_exec_link_key), as the fill does. */
struct tego_test_fill_tmpl {
    __u8 exec;
    __u8 corrupt;
    __u8 pad[6];
    __u64 name_key;
    struct tego_plane_row row;
    struct tego_plane_exec_row xrow;
};

/* The test process's tgid and the slot it fills; written[0] counts the rows written. */
struct tego_test_fill_cfg {
    __u32 tgid;
    __u32 run_idx;
    __u32 written;
    __u32 failed;
};

const struct tego_test_fill_tmpl *tego_btf_test_fill_tmpl;
const struct tego_test_fill_cfg *tego_btf_test_fill_cfg;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* descriptor number */
    __type(value, struct tego_test_fill_tmpl);
} tego_test_fill_tmpls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tego_test_fill_cfg);
} tego_test_fill_cfgs SEC(".maps");

SEC("iter/task_file")
int tego_test_fill(struct bpf_iter__task_file *ctx)
{
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    struct tego_test_fill_tmpl *t;
    struct tego_test_fill_cfg *cfg;
    struct inode *inode;
    __u32 zero = 0, fd, idx;
    __u64 key;
    void *inner;
    long err;

    if (!task || !file)
        return 0;
    cfg = bpf_map_lookup_elem(&tego_test_fill_cfgs, &zero);
    if (!cfg || task->tgid != cfg->tgid)
        return 0;
    fd = ctx->fd;
    t = bpf_map_lookup_elem(&tego_test_fill_tmpls, &fd);
    if (!t)
        return 0;
    inode = file->f_inode;
    if (!inode)
        return 0;
    key = (__u64)inode;
    idx = cfg->run_idx;
    if (t->exec) {
        struct dentry *parent = file->f_path.dentry->d_parent;
        struct inode *pinode = parent ? parent->d_inode : 0;

        if (!pinode)
            return 0;
        t->xrow.parent = (__u64)pinode;
        t->xrow.inode = (__u64)inode;
        /* Read back from the map value, the pointers are scalars the key may be built from. */
        key = tego_exec_link_key(*(volatile __u64 *)&t->xrow.inode, *(volatile __u64 *)&t->xrow.parent, t->name_key);
        t->xrow.parent_ino = pinode->i_ino;
        t->xrow.parent_generation = pinode->i_generation;
        t->xrow.i_ino = inode->i_ino;
        t->xrow.i_generation = inode->i_generation ^ (t->corrupt ? 0x5a5a : 0);
        t->xrow.s_dev = inode->i_sb->s_dev;
        inner = bpf_map_lookup_elem(&tego_plane_exec_rows, &idx);
        if (!inner)
            return 0;
        err = bpf_map_update_elem(inner, &key, &t->xrow, BPF_ANY);
    } else {
        t->row.i_ino = inode->i_ino;
        t->row.i_generation = inode->i_generation ^ (t->corrupt ? 0x5a5a : 0);
        t->row.s_dev = inode->i_sb->s_dev;
        inner = bpf_map_lookup_elem(&tego_plane_rows, &idx);
        if (!inner)
            return 0;
        err = bpf_map_update_elem(inner, &key, &t->row, BPF_ANY);
    }
    if (err)
        __sync_fetch_and_add(&cfg->failed, 1);
    else
        __sync_fetch_and_add(&cfg->written, 1);
    return 0;
}
