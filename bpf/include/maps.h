// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Map definitions shared by the Tego BPF programs (docs/p0/enforce-cgroup-observe.md §3).
 *
 * Every map here is LIBBPF_PIN_BY_NAME: the loader supplies /sys/fs/bpf/tego/<bpf_hash>/maps as the pin
 * directory, so the three objects of one build (cgroup_net, cgroup_track, trace_proc) share one instance of
 * each map and many launchers of one build share one attachment (§3 table, §5 R14). Two builds with different
 * bpf_hash values get two directories and therefore two disjoint map sets and run_idx spaces (§6 E22).
 *
 * max_entries here are the §3 defaults; the loader may raise the others, so these values are a floor, not a limit
 * built into the object. The rings are not sized here: each run gets its own, created by the loader at the size
 * the machine config sets and inserted into tego_events (and tego_capture_events) at its slot (ADR 0026).
 */
#ifndef TEGO_MAPS_H
#define TEGO_MAPS_H

#include "common.h"
#include "plane_listener.h"

/* Host-wide membership: cgroup id -> run. Written at Prepare, by cgroup_track for descendants, and cleared at
 * Detach; read by every hook exactly once (§8 I1). 4096 rows bound concurrent runs and their subtrees (§6 E11). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TEGO_RUN_SET_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u64);               /* cgroup id */
    __type(value, struct tego_run);
} tego_run_set SEC(".maps");

/* Exact host:port verdicts, keyed by run_idx. An exact hit always wins over the LPM trie (§5 R3, §6 E8). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TEGO_NET_ROWS_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_net_key);
    __type(value, struct tego_net_verdict);
} tego_net_exact SEC(".maps");

/* CIDR verdicts. BPF_F_NO_PREALLOC is mandatory for LPM tries; the longest matching prefix wins (§5 R3). */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_NET_ROWS_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_net_lpm_key);
    __type(value, struct tego_net_verdict);
} tego_net_cidr SEC(".maps");

/* Last network decision per run, keyed by the run's own cgroup id: the breadcrumb for the `net` event's reader
 * (§5 R5). One row per live run, removed after the run's links at Detach so no straggler can resurrect it
 * (§5 R15). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TEGO_CGROUP_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u64);               /* cgroup id */
    __type(value, struct tego_reason);
} tego_reason_map SEC(".maps");

/* The prototype of a run's ring: the inner map type the two ring outers below are created with. A run's own ring
 * is a ring buffer of any legal size (the kernel compares an inner ring's type, key, value and flags with the
 * prototype, not its max_entries), made by the loader at Prepare from the machine config (ADR 0026 (1), (2)). */
struct tego_ring {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
};

/* The record's rings, one per run, at the run's slot (run_idx): every record-only program looks its run's ring up
 * here after its run-set hit and emits nothing when the slot has none (ADR 0026 (1)). So each run's recorder reads
 * a ring no other run writes, and two runs of one build never share a consumer position (§2 "Run scope").
 * HASH_OF_MAPS, the outer type measured loading and reserving on an inner ring of another size on every kernel of
 * the matrix; ARRAY_OF_MAPS is not measured (ADR 0026). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __array(values, struct tego_ring);
} tego_events SEC(".maps");

/* Count of each run's record reserves that failed, by run_idx, zeroed at Prepare so a run counts its own drops
 * from its own start (ADR 0026 (4)). Diffed per drain into a gap event (§7). Incremented atomically: one slot is
 * shared by every CPU. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, __u64);
} tego_lost SEC(".maps");

/* Enforcement membership failures cannot depend on delivery of a ring sample. This preallocated per-slot
 * counter is incremented before emitting a failed descendant insertion, even under record: off. The run's
 * enforcement watchdog reads it independently of the recorder and stops the run on any nonzero value.
 * Prepare clears the slot before publishing its membership rows. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u64);
} tego_tracking_failed SEC(".maps");

/* Capture's rings, one per run whose capture is uprobe, at the run's slot (ADR 0026 (1), (3)). Declared with the
 * record's maps rather than with capture's own below, so the loader can create a run's capture ring at Prepare,
 * before any capture object is loaded. A run with no capture ring gets nothing from the shared probes: the probe
 * finds no ring and counts a miss (tego_capture_miss), so no plaintext of a capture: off run is written anywhere. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __array(values, struct tego_ring);
} tego_capture_events SEC(".maps");

/* Count of each run's capture chunks whose reserve failed, by run_idx: tego_lost's shape, capture's own (ADR 0026
 * (4)), zeroed at Prepare. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, __u64);
} tego_capture_lost SEC(".maps");

/* Count of probe hits, by run_idx, in a run that has no capture ring: a capture: off run's TLS calls, which the
 * probes shared by the build's runs see and must not capture (ADR 0026 (3), (7)). Zeroed at Prepare. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, __u64);
} tego_capture_miss SEC(".maps");

/* Each run's activity stamp, by run_idx (struct tego_activity_slot): the bpf_ktime_get_ns() (CLOCK_MONOTONIC) of the
 * newest action of the run that the record keeps no line or sample for, to a jiffy, written by tego_activity_stamp
 * only for a run whose row carries TEGO_RUN_ACTIVITY (a stall_after bounds it): trace_proc's allowed opens, file
 * operations and connects under record: off, and the TLS probes' calls that moved bytes in every record mode (limits
 * R4, A-REC-1, A-REC-6). The run's watcher pulls it once a tick (observe.Recorder.LastActivity); no ring, no wakeup, no
 * plaintext. Not per CPU: one load is the whole read, and an aligned u64 store does not tear. Zeroed at Prepare like
 * the counters beside it, and a reading below the run's start is ignored by the watcher, so a stamp a previous run's
 * in-flight program lands after the zeroing changes nothing. Declared in every object, like the counters, so whichever
 * object a launcher loads first creates the one pinned instance. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, struct tego_activity_slot);
} tego_activity SEC(".maps");

/* The network programs' own map. It is compiled only into bpf/cgroup_net.bpf.c, which defines TEGO_NET_MAPS
 * before including this header, for the same reason the capture maps below are guarded: no other object has
 * a program that could read it. */
#ifdef TEGO_NET_MAPS

/* Which run each cgroup attachment enforces: BPF_MAP_TYPE_CGROUP_STORAGE, one value per cgroup the network
 * programs are attached to, which the kernel hands a running program through bpf_get_local_storage (§5 R1,
 * R2). The key is the attach point's cgroup id alone (a __u64 rather than struct bpf_cgroup_storage_key), so
 * the deciding programs of one attachment (four, six on 6.7+ with the two unix ones, and cgroup/sock_create) share
 * one value (Linux 5.9+). The kernel creates the value,
 * zeroed, when the first program that uses the map is attached to a cgroup, and frees it with the cgroup or
 * the map; userspace can only overwrite it, which is how Attach configures it (internal/runtime/enforce/
 * cgroup kernel.go). max_entries is left 0 because the kernel refuses anything else for this map type.
 *
 * Why storage and not a lookup keyed by the caller. The kernel chooses the program array by the socket's
 * cgroup (sock_cgroup_ptr(&sk->sk_cgrp_data), fixed when the socket is created), and a program attached to a
 * cgroup runs for every socket of that cgroup and its descendants. The storage it is handed belongs to the
 * cgroup the program was attached to, which is the run's own cgroup. bpf_get_current_cgroup_id() instead
 * names whoever made the call: the seccomp supervisor relays every allowed connect from its own process on a
 * pidfd_getfd duplicate of the agent's socket (docs/p0/supervisor.md R9, I2), so a lookup keyed by the caller
 * missed, took the neutral branch, and no connect of the agent was ever decided in the kernel. */
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u64);               /* the attach point's cgroup id */
    __type(value, struct tego_net_owner);
} tego_net_owners SEC(".maps");

#endif /* TEGO_NET_MAPS */

/* Unix socket names, keyed by run_idx like the verdict maps: a run's declared unix: entries and the
 * filesystem entries that admit or refuse a pathname socket beneath them (§5 R7, struct tego_unix_key). Read
 * by connect_unix and sendmsg_unix (6.7+), and below 6.7 by the plane's socket_connect and socket_sendmsg
 * (bpf/decide.bpf.c, enforce-plane R14), which the loader hands the build's own instance; written by Prepare,
 * removed at Detach, and purged by slot when a slot is reclaimed from a dead launcher, exactly as tego_net_exact
 * is (§5 R12). The plane's fill has no use for it. */
#if defined(TEGO_NET_MAPS) || (defined(TEGO_PLANE_MAPS) && !defined(TEGO_PLANE_FILL_MAPS))
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_UNIX_ROWS_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_unix_key);
    __type(value, struct tego_net_verdict);
} tego_unix_names SEC(".maps");

/* One-connect grants for an approved abstract name (supervisor R11c): the relay connects the agent's own socket with
 * the agent's bytes, which no unix: row admits, so the supervisor grants that socket (by cookie) that one name for
 * that run's gen, for a second at most, and revokes the grant when the relay returns. Read by connect_unix (6.7+)
 * and the plane's socket_connect (below 6.7) beside tego_unix_names; purged by slot at Detach and by the reaper, and
 * a row a missed purge left names a gen no later run of the slot has. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TEGO_UNIX_APPROVALS_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_unix_approval_key);
    __type(value, struct tego_unix_credit);
} tego_unix_approvals SEC(".maps");

/* Whether the abstract-name connect k, on the socket cookie of the run's slot run_idx at gen, consumes a grant
 * (tego_unix_approvals): the grant must be live and name exactly k's bytes; it is taken once and removed. */
static __always_inline int tego_unix_approved(__u32 run_idx, __u32 gen, __u64 cookie, const struct tego_unix_key *k)
{
    struct tego_unix_approval_key key = {};
    struct tego_unix_credit *v;
    __u32 i, len = k->len;

    if (k->kind != TEGO_UNIX_ABSTRACT || cookie == 0 || gen == 0)
        return 0;
    key.run_idx = run_idx;
    key.gen = gen;
    key.cookie = cookie;
    v = bpf_map_lookup_elem(&tego_unix_approvals, &key);
    if (!v || v->name.kind != TEGO_UNIX_ABSTRACT || v->name.len != len || len == 0 || len > TEGO_UNIX_NAME_MAX ||
        v->deadline_ns <= bpf_ktime_get_ns())
        return 0;
#pragma unroll
    for (i = 0; i < TEGO_UNIX_NAME_MAX; i++) {
        if (i < len && v->name.name[i] != k->name[i])
            return 0;
    }
    if (__sync_val_compare_and_swap(&v->credit, 1, 0) != 1)
        return 0;
    bpf_map_delete_elem(&tego_unix_approvals, &key);
    return 1;
}
#endif

/* The record's own map. It is compiled only into bpf/trace_proc.bpf.c, which defines TEGO_TRACE_MAPS before
 * including this header: no other object has a program that could read it. */
#ifdef TEGO_TRACE_MAPS

/* What a task's fexit program holds back for a later hook of the same task to finish (ADR 0016 (3), one action,
 * one line):
 *   - TEGO_HELD_OPEN: an O_TRUNC open of an existing regular file the chain allowed at security_file_open. The
 *     truncate hook that follows in the same open (security_file_truncate from 6.2, security_path_truncate
 *     before), on the same dentry, writes its own return into it and emits it, so a truncate the chain refuses
 *     is the open's line and not a second one. A truncate of another dentry is not the open's: the open failed
 *     before its truncate, and is emitted as it is.
 *   - TEGO_HELD_CREATE: a security_path_mknod of a regular file with no device, the shape an O_CREAT open
 *     asks in may_o_create before it knows whether the file exists. A security_file_open with O_CREAT of the
 *     same dentry that follows drops it: the open went ahead, so its line is the action's (created or not,
 *     refused or not). An open without O_CREAT is not the create's own, and the mknod(2) is emitted.
 *     Anything else — a mknod(2), or an O_CREAT open that failed — leaves it to be emitted with the mknod's own
 *     return.
 * A held record not consumed is emitted by the task's next recorded event, or at its exit. */
enum tego_held_tag {
    TEGO_HELD_NONE = 0,
    TEGO_HELD_OPEN = 1,
    TEGO_HELD_CREATE = 2,
};

struct tego_held {
    __u8  tag;          /* enum tego_held_tag */
    __u8  pad[7];
    __u64 dentry;       /* TEGO_HELD_CREATE: the dentry security_path_mknod was asked about; TEGO_HELD_OPEN:
                         * the opened file's, which its truncate names */
    __u64 parent;       /* ... its parent dentry */
    __u64 hash_len;     /* ... and its d_name.hash_len, for a lookup that spliced another dentry in */
    struct tego_ev_fs fs;      /* TEGO_HELD_OPEN's record */
    struct tego_ev_fsop op;    /* TEGO_HELD_CREATE's record */
    struct tego_dir_scratch walk; /* the directory walk's two passes (tego_dir_walk); no part of any hold */
};

/* The task storage the fexit programs hold a record in (ADR 0016 (3), tego_task_scratch; ADR 0024 adds the
 * plane's rule_idx to it). A value is created only for a task of a matched run that holds something, and the
 * kernel frees it with the task. Pinned by name like every other map, so a launcher that adopts the object
 * finds it (adoptObject). */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, int);
    __type(value, struct tego_held);
} tego_task_scratch SEC(".maps");

#endif /* TEGO_TRACE_MAPS */

/* Capture's own maps (docs/p0/capture-derive.md §3). They are compiled only into bpf/uprobe_ssl.bpf.c, which
 * defines TEGO_CAPTURE_MAPS before including this header: the three tier-2 objects have no use for them. The
 * definitions still live here, because include/maps.h is the single place a map may be declared (§9). Capture's
 * rings and counters are above, with the record's. */
#ifdef TEGO_CAPTURE_MAPS

/* One row per in-flight SSL_read, keyed by (pid_tgid, ssl_ptr) (§5 R5). LRU because a process killed
 * between an entry and its return leaves its row behind: eviction under a burst loses a read, which is a
 * gap, where a full non-LRU map would lose every read after the first 8192 forever.
 *
 * The map is not called tego_ssl_scratch although its value is struct tego_ssl_scratch: bpf2go resolves
 * each -type name against every named BTF type in the object, and a map is a named BTF variable, so the
 * shared name stopped `make gen` with "found multiple types" (bpf/tests TestNoMapNamedLikeAStruct). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TEGO_SSL_SCRATCH_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_ssl_key);
    __type(value, struct tego_ssl_scratch);
} tego_ssl_reads SEC(".maps");

/* The chunk counter of each connection, keyed like the scratch map by (pid_tgid, ssl_ptr) — the connection as
 * httpstream keys it — and shared by both directions. Every chunk takes the next number before its reserve, so
 * a reserve that fails still uses one up, and the reader finds the hole at the connection's next chunk, in
 * either direction, and gaps the connection instead of pairing every later response with the request before
 * its own (I2). The count was userspace's, assigned on arrival, which structurally could not contain a
 * hole. LRU for the scratch map's reason: a row a dead process left behind goes first. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TEGO_SSL_SEQ_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tego_ssl_key);
    __type(value, __u32);
} tego_ssl_seq SEC(".maps");

/* The SSL* a thread's innermost in-flight SSL_read named, so the uretprobe — which sees no arguments — can
 * rebuild the scratch key R5 specifies rather than keying the scratch map by pid_tgid alone. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TEGO_SSL_SCRATCH_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u64);               /* pid_tgid */
    __type(value, __u64);             /* ssl_ptr */
} tego_ssl_current SEC(".maps");

#endif /* TEGO_CAPTURE_MAPS */

/* Each task's last plane decision and its walk arguments (struct tego_plane_decision). TASK_STORAGE needs
 * NO_PREALLOC and max_entries 0; the kernel frees a task's value with the task. The plane writes it and the
 * recorder's fexit programs read it (ADR 0024 (11), TIER3-PLAN T9), so both objects declare it, pinned by name
 * beside each other's maps: whichever loads first creates it and the other reuses the pin. */
#if defined(TEGO_TRACE_MAPS) || defined(TEGO_PLANE_MAPS)
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, int);
    __type(value, struct tego_plane_decision);
} tego_plane_scratch SEC(".maps");
#endif

/* Each task's exec-pin state (struct tego_exec_armed; ADR 0048 (3) P2): the plane's bprm_check moves a pin here, its
 * sched_process_exec program checks it, its ptrace hooks read the argv-guarded mark, and the recorder's
 * sched_process_exec reads the pin seq into its exec record. Declared by both objects and pinned by name, as
 * tego_plane_scratch is; the fill has no use for it. */
#if defined(TEGO_TRACE_MAPS) || (defined(TEGO_PLANE_MAPS) && !defined(TEGO_PLANE_FILL_MAPS))
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, int);
    __type(value, struct tego_exec_armed);
} tego_plane_exec_armed SEC(".maps");
#endif

/* The decision plane's own maps (ADRs 0024, 0025; docs/p0/TIER3-PLAN.md §3). Compiled only into bpf/decide.bpf.c,
 * which defines TEGO_PLANE_MAPS; the plane shares tego_run_set and the rings above with tier 2. These are the
 * only maps keyed by a kernel object's address, which ADR 0025 supersedes ADR 0010 to allow, and only here: the key
 * never reaches userspace (bpf/tests TestNoInodeKeyedKernelMap). */
#ifdef TEGO_PLANE_MAPS

/* The prototype of a slot's rows map: struct inode * -> struct tego_plane_row. NO_PREALLOC, so an idle slot
 * charges nothing for its 4096 rows. */
struct tego_plane_rows_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_PLANE_ROWS_MAX);
    __type(key, __u64);               /* struct inode *, as a scalar */
    __type(value, struct tego_plane_row);
};

/* The prototype of a slot's exec-rows map: a link key (plane_name.h's tego_exec_link_key over the executable's inode,
 * its directory's and its name) or a name key -> struct tego_plane_exec_row; key 0 is reserved, never written. */
struct tego_plane_exec_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_PLANE_EXEC_ROWS_MAX);
    __type(key, __u64);               /* a link or name key; 0 is reserved */
    __type(value, struct tego_plane_exec_row);
};

struct tego_plane_listen_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_PLANE_LISTEN_ROWS_MAX);
    __type(key, struct tego_plane_listen_key);
    __type(value, struct tego_plane_listen_row);
};
/* Map-only uses can become unsized BTF forward types with the pinned LLVM.
 * Retain their full layouts even in a test filler that never accesses a row. */
const struct tego_plane_listen_key *tego_btf_listen_map_key;
const struct tego_plane_listen_row *tego_btf_listen_map_row;
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __array(values, struct tego_plane_listen_inner);
} tego_plane_listen_rows SEC(".maps");

/* Each slot's rows map, at its run_idx, like its rings (ADR 0025 (1) as T0 amended it): a slot keeps its map across
 * runs, because an outer insert or delete waits an RCU grace period (12-80 ms a run); every row carries the gen of
 * the run it was filled for, and a row of another gen counts as absent. A run-set hit whose slot has no map
 * refuses (TEGO_WALK_NOROWS). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __array(values, struct tego_plane_rows_inner);
} tego_plane_rows SEC(".maps");

#ifndef TEGO_PLANE_FILL_MAPS
/* The prototype of a slot's exec pins (ADR 0048 (3) P2): the exec's thread -> its pin, written by the supervisor
 * immediately before it continues the exec and deleted by bprm_check's move into the task's storage. NO_PREALLOC: a
 * slot charges only for the pins in flight. */
struct tego_plane_pin_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_PIN_ROWS);
    __type(key, struct tego_pin_key);
    __type(value, struct tego_exec_pin);
};

/* As the listen rows' types: retained whole in an object that only names the map (the test filler). */
const struct tego_pin_key *tego_btf_pin_map_key;
const struct tego_exec_pin *tego_btf_pin_map_row;

/* Each slot's pins, at its run_idx, kept across runs with gen like tego_plane_rows: a pin of another gen is absent. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __array(values, struct tego_plane_pin_inner);
} tego_plane_exec_pins SEC(".maps");

/* Each slot's pin key (struct tego_pin_keyval), by run_idx, written by Prepare with the run's gen. Root-only like
 * every pinned map, and no process of a run can call bpf(2) (the plane refuses it): the key never leaves the
 * launcher, the supervisor and the kernel. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, struct tego_pin_keyval);
} tego_plane_pin_keys SEC(".maps");
#endif

/* Each slot's exec-rows map, at its run_idx, kept across runs with gen like tego_plane_rows. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __array(values, struct tego_plane_exec_inner);
} tego_plane_exec_rows SEC(".maps");

/* Each slot's name rows (ADR 0043 D9), at its run_idx, kept across runs with gen like tego_plane_rows: a name key
 * (agent.NameKey: a hash of a folded literal's bytes, never an address, so userspace writes and clears these rows) or
 * 0 for the config row -> struct tego_plane_name_row (struct tego_plane_name_cfg at key 0). Prepare clears the
 * slot's rows, then writes the config row, then the name rows with BPF_NOEXIST, then the header with
 * TEGO_SLOT_NAME_DECIDES; a hook reads the map only under that flag, and refuses a candidate whose slot has no inner
 * map or no config row of the run's gen. The fill never writes it, so the fill's object does not declare it. */
#ifndef TEGO_PLANE_FILL_MAPS
/* The row's full layout, kept in every object that declares the map, as the listener rows' is above: a map-only use
 * (the test filler's) otherwise leaves an unsized BTF forward type the loader refuses. */
const struct tego_plane_name_row *tego_btf_name_map_row;
struct tego_plane_name_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_PLANE_NAME_KEYS);
    __type(key, __u64);               /* a name key, or 0 for the config row */
    __type(value, struct tego_plane_name_row);
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __array(values, struct tego_plane_name_inner);
} tego_plane_name_rows SEC(".maps");
#endif

/* The name a plane refusal's sample carries (an exec's, an fs object's, a mapping's), in the refused task's own
 * storage while its sample is built (decide.bpf.c tego_plane_own_sample): too big for the stack beside bprm_check's
 * own. Not per CPU: the plane's programs run
 * with migration disabled but can be preempted (ADR 0024's T2 note), and a per-CPU buffer filled before the ring
 * reserve could be overwritten by another task's refused exec on the same CPU, putting that task's (maybe another
 * run's) path on this run's line. Created for the sample and deleted after it. Never read by userspace, and pinned
 * by name all the same: a later launcher adopts the plane's pinned programs only when every map they use is pinned
 * (cgroup adoptObjectIn), and an unpinned map here made every run load and verify the mode's programs again,
 * 0.6 s of each run's start in the 6.17 guest (enforce-plane §2.18). */
#ifndef TEGO_PLANE_FILL_MAPS
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, int);
    __type(value, struct tego_plane_path);
} tego_plane_path_buf SEC(".maps");
#endif

/* The plane's fail-closed counters by run_idx (struct tego_plane_counts), zeroed at Prepare and added to
 * atomically: every CPU shares a slot. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, struct tego_plane_counts);
} tego_plane_counters SEC(".maps");

/* Each slot's header (struct tego_plane_slot), by run_idx: the gen of the run whose rows the slot holds and what its
 * contract decides, written last by Prepare and zeroed first by every clear. Every decided hook reads it after its
 * run-set hit and refuses on a header of another gen (enforce-plane R6). The fill has no use for it. */
#ifndef TEGO_PLANE_FILL_MAPS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, struct tego_plane_slot);
} tego_plane_slots SEC(".maps");
#endif

/* Each slot's unix policy for step D's hooks (struct tego_plane_unix), by run_idx, written with the run's gen by
 * Prepare's fill and never cleared: a policy of another gen is absent, and its run refuses. The fill has no use for
 * it. */
#ifndef TEGO_PLANE_FILL_MAPS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEGO_MAX_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);               /* run_idx */
    __type(value, struct tego_plane_unix);
} tego_plane_unix_policy SEC(".maps");
#endif

/* The build's recorder fexit programs that are attached, as a mask of 1 << enum tego_plane_hook, at key 0
 * (enforce-plane §7, R23; TIER3-PLAN T9b). A hook whose bit is set has the recorder's fexit on the same security_
 * function, which takes the plane's decision and writes the action's one line; on a hook whose bit is clear the
 * plane writes its own sample of every refusal (TEGO_EV_PLANE_FS) instead. The backend writes it from the tracing
 * links it holds before it attaches the plane's programs, and every launcher of the build writes the same value.
 * Fail closed for the ledger: a mask nobody wrote is 0, and every refusal still has its line. Read on the refusal
 * path only. */
#ifndef TEGO_PLANE_FILL_MAPS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u32);
} tego_plane_recorded SEC(".maps");
#endif

/* The fill's own maps (bpf/decide_fill.bpf.c, which alone defines TEGO_PLANE_FILL_MAPS): pinned with the fill's
 * programs in the mode's fill directory and adopted by every later launcher of the build (enforce/cgroup plane.go
 * openPlaneFiller), so they are shared host-wide, not per Prepare. Each launcher's config and templates are keyed by
 * its tgid, so fills and clears run at once and take no lock; the build's fill lock (bpfPlane.lockFill) covers only
 * the pinning. The fill writes the plane's pinned row maps above, which the loader hands it. */
#ifdef TEGO_PLANE_FILL_MAPS

/* tgid -> that launcher's fill (struct tego_plane_fill_cfg): one entry per launcher filling now. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_PLANE_FILL_CFGS);
    __type(key, __u32);
    __type(value, struct tego_plane_fill_cfg);
} tego_plane_fill_config SEC(".maps");

/* TEGO_PLANE_FILL_KEY(tgid, what, descriptor number) -> the wanted row: one descriptor can carry an fs row and an exec
 * row (an executable that is also an fs entry), and each launcher's templates are its own. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, TEGO_PLANE_FILL_MAX * TEGO_PLANE_FILL_LAUNCHERS);
    __type(key, __u64);
    __type(value, struct tego_plane_fill_row);
} tego_plane_fill_wants SEC(".maps");

#endif /* TEGO_PLANE_FILL_MAPS */

#endif /* TEGO_PLANE_MAPS */

#endif /* TEGO_MAPS_H */
