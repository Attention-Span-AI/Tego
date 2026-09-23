// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Descendant materialization: the run set is a flat map of cgroup ids, so a cgroup created inside a run must
 * be inserted before any task can join it (docs/p0/enforce-cgroup-observe.md §5 R2, R11, §8 I6).
 *
 * cgroup_mkdir fires before kernfs_activate(), so the row always exists by the time the new directory is
 * reachable — the ordering that makes R2's "no ancestor walk at hook time" safe. The program reads the new
 * cgroup's kernfs id and its parent's, looks the parent up in the run set and, when the parent's entry says
 * descendants=1, inserts the child with the parent's value under BPF_NOEXIST; an existing row is left alone
 * (ADR 0010's "re-read on EEXIST"). cgroup_rmdir deletes the row and the cgroup's reason breadcrumb.
 *
 * Scope is the run's own subtree only: cross-daemon lineage adoption and the Docker-proxy pre-created parent
 * are P2 (§5 R11, §11). Userspace closes the same race for children that already existed at Prepare by
 * scanning cgroupfs under the run's cgroup.
 *
 * The parent id is read through cgrp->self.parent->cgroup->kn->id rather than through the kernfs node's own
 * parent pointer: kernfs_node's parent member was renamed (parent -> __parent) in 6.14, and this component
 * must load unchanged from 6.1 onward (ARCHITECTURE §11).
 *
 * Every read is a direct load off the tracepoint's BTF-typed argument, CO-RE relocated like BPF_CORE_READ but with
 * no bpf_probe_read_kernel call: lockdown=confidentiality refuses that helper at load on every kernel (ADR 0024's
 * T0 note), and tp_btf programs have had direct loads since 5.5, so this one build loads with and without it.
 */
#include "maps.h"

char _license[] SEC("license") = "Dual BSD/GPL";

/* BTF anchors. A struct only reaches the object's BTF — and therefore bpf2go's Go mirror — when something
 * global names it; a record reserved from the ring buffer is a local pointer and does not count. These
 * pointers are never read or written and cost one .bss word each. */
const struct tego_hdr *tego_btf_hdr;
const struct tego_ev_cgroup *tego_btf_ev_cgroup;

/* Reports whether a cgroup belongs to the unified hierarchy, the one bpf_get_current_cgroup_id() names
 * (hierarchy_id 0, the "0::" line of /proc/<pid>/cgroup). The tracepoints fire for every hierarchy, and a
 * cgroup v1 hierarchy numbers its kernfs nodes from its own idr, so its ids collide with the unified ones. */
static __always_inline int tego_on_dfl(struct cgroup *cgrp)
{
    return cgrp->root->hierarchy_id == 0;
}

/* Reads a cgroup's 64-bit id — the same value bpf_get_current_cgroup_id() reports for a task inside it. */
static __always_inline __u64 tego_cgroup_id(struct cgroup *cgrp)
{
    return cgrp->kn->id;
}

/* Reads the id of a cgroup's parent, or 0 at the root (the root css has no parent). */
static __always_inline __u64 tego_parent_cgroup_id(struct cgroup *cgrp)
{
    struct cgroup_subsys_state *parent = cgrp->self.parent;

    if (!parent)
        return 0;
    return parent->cgroup->kn->id;
}

/* Pushes the materialization record when the run records, and every failed insertion even under record: off.
 * A missing membership row loses enforcement too: userspace reports the gap and stops the run. */
static __always_inline void tego_cgroup_event(__u16 kind, const struct tego_run *run, __u64 parent_id,
                                               __u64 child_id, __s32 err)
{
    struct tego_ev_cgroup *e;
    void *ring;

    if (!err && !tego_recording(run))
        return;
    ring = tego_ring_of(&tego_events, run);
    if (!ring) {
        tego_lost_inc(&tego_lost, run->run_idx); /* a row and no ring: counted, never silent */
        return;
    }

    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_lost, run->run_idx);
        return;
    }
    tego_hdr_fill(&e->hdr, kind, sizeof(*e), run, parent_id);
    e->parent_cgroup_id = parent_id;
    e->child_cgroup_id = child_id;
    e->err = err;
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
}

/* cgroup_mkdir: materialize a descendant of a run cgroup before it can be joined (§5 R11).
 *
 * 6.1 prototype: TP_PROTO(struct cgroup *cgrp, const char *path); path is not read. */
SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(tego_cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
    struct tego_run *parent_run;
    struct tego_run val;
    __u64 parent_id, child_id;
    long err;

    if (!tego_on_dfl(cgrp))
        return 0;
    parent_id = tego_parent_cgroup_id(cgrp);
    if (!parent_id)
        return 0;

    parent_run = tego_run_lookup(&tego_run_set, parent_id);
    if (!parent_run || !parent_run->descendants)
        return 0;

    child_id = tego_cgroup_id(cgrp);
    if (!child_id)
        return 0;

    val = *parent_run;
    err = bpf_map_update_elem(&tego_run_set, &child_id, &val, BPF_NOEXIST);
    if (err == -EEXIST)
        err = 0; /* another build or an earlier scan already placed it; the row is correct either way */

    if (err)
        tego_lost_inc(&tego_tracking_failed, val.run_idx);

    tego_cgroup_event(TEGO_EV_CGROUP_MKDIR, parent_run, parent_id, child_id, (__s32)err);
    return 0;
}

/* cgroup_rmdir: drop the row and the cgroup's breadcrumb. A create-then-immediate-rmdir is net zero (§6 E6);
 * an operator removing a live run's cgroup by hand leaves its tasks failing open, a self-inflicted case the
 * design states rather than defends (§6 E26).
 *
 * 6.1 prototype: TP_PROTO(struct cgroup *cgrp, const char *path); path is not read. */
SEC("tp_btf/cgroup_rmdir")
int BPF_PROG(tego_cgroup_rmdir, struct cgroup *cgrp, const char *path)
{
    struct tego_run *run;
    struct tego_run snapshot;
    __u64 parent_id, child_id;

    if (!tego_on_dfl(cgrp))
        return 0;
    child_id = tego_cgroup_id(cgrp);
    if (!child_id)
        return 0;

    run = tego_run_lookup(&tego_run_set, child_id);
    if (!run)
        return 0;

    snapshot = *run;
    parent_id = tego_parent_cgroup_id(cgrp);

    bpf_map_delete_elem(&tego_run_set, &child_id);
    bpf_map_delete_elem(&tego_reason_map, &child_id);

    tego_cgroup_event(TEGO_EV_CGROUP_RMDIR, &snapshot, parent_id, child_id, 0);
    return 0;
}
