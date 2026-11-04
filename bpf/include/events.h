// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Shared event and map key structs between the BPF programs and Go (bpf2go copies these types). Keep every
 * struct explicitly padded and fixed-size; the Go side mirrors them in internal/bpf.
 *
 * Normative source: docs/p0/enforce-cgroup-observe.md §2.2 (map keys), §2.3 (ring-buffer events), §3 (map
 * sizing). Layout rules: no implicit padding anywhere (every hole is a named pad field), every struct is a
 * multiple of its own alignment, and no field is wider than the 6.1 kernel exposes for it (ARCHITECTURE §11.1).
 */
#ifndef TEGO_EVENTS_H
#define TEGO_EVENTS_H

#include "plane_listener.h"

#define TEGO_EVENTS_VERSION 4
#define TEGO_PATH_MAX 256
#define TEGO_ARGV_MAX 512
#define TEGO_COMM_LEN 16
#define TEGO_NAME_MAX 256

/* Capacity constants shared with userspace (§3 sizing table, §6 E11/E12). run_idx is a dense per-host slot
 * and rule_idx indexes the compiled RuleTable entry an event names; both are bounded so a corrupt value can
 * never index out of range in userspace. */
#define TEGO_MAX_SLOTS 4096      /* run_idx space: [0, TEGO_MAX_SLOTS) */
#define TEGO_RUN_SET_MAX 4096    /* run_set rows: live runs plus their materialized descendants */
#define TEGO_NET_ROWS_MAX 4096   /* rows in each of the exact and CIDR verdict maps */
#define TEGO_CGROUP_MAX 4096     /* reason-breadcrumb rows: one per live run, keyed by its cgroup id */
#define TEGO_MAX_RULES 65535     /* rule_idx space */

/* Capture sizing (docs/p0/capture-derive.md §5 R5, R6). One chunk carries at most TEGO_SSL_CHUNK_MAX bytes
 * — headroom over the 16 KiB TLSPlaintext fragment RFC 8446 §5.1 fixes, plus verifier-friendly fixed sizing
 * — and one SSL_write/SSL_read moving more is split into at most TEGO_SSL_CHUNKS_MAX of them; past that the
 * remainder is dropped and the last chunk says so. The scratch map holds one row per in-flight SSL_read,
 * sized for the default pids: 4096 ceiling at about two in-flight calls per pid. */
#define TEGO_SSL_CHUNK_MAX 32768
#define TEGO_SSL_CHUNKS_MAX 4
#define TEGO_SSL_SCRATCH_MAX 8192
/* Record size classes (R6). A chunk record is reserved at the smallest class that holds its bytes, so a 40-byte
 * SSE read costs a 512-byte record and not a 32 KiB one: at one fixed size about 255 chunks filled the default
 * 8 MiB ring whatever they carried, and a streamed response's many tiny reads dropped the rest. Each class is a
 * compile-time constant at its reserve (§8 I7); the header's size says which one a record is. A
 * bpf_ringbuf_reserve_dynptr would size each record exactly, but it needs 5.19, and RHEL 9's 5.14 is a
 * supported target (ARCHITECTURE §14). */
#define TEGO_SSL_CLASS_SMALL 512
#define TEGO_SSL_CLASS_MEDIUM 4096
/* Rows of tego_ssl_seq, the per-connection chunk counter: one per (thread, SSL*) that moved plaintext, LRU, so
 * a row evicted under a burst restarts its count and the reader gaps that connection (I2). Twice the
 * scratch map, since every connection has a row whether or not a read of it is in flight. */
#define TEGO_SSL_SEQ_MAX 16384

/* A read whose entry and return probes are further apart than this is not paired: its scratch row is older than
 * the bound allows any read to be, so it is a row whose own return was missed, and a pid reused inside the
 * scratch map's lifetime could pair it with a new process's SSL* at the same address (§6 edge case #3). The
 * bound has to catch only that, never a slow answer: a non-streaming completion routinely takes minutes to its
 * first byte (the Anthropic and OpenAI SDKs time a request out at 10 minutes by default), and a bound of 60 s
 * dropped such a response with no trace, so the next response on the connection paired with its request.
 * 30 minutes is three times the longest of those defaults. A read past it still uses its number up and is
 * emitted as a hole (TEGO_SSL_HOLE_STALE), never dropped silently. */
#define TEGO_SSL_MAX_CALL_NS (30ULL * 60ULL * 1000000000ULL)

enum tego_kind {
    TEGO_EV_EXEC = 1,
    TEGO_EV_EXIT = 2,
    TEGO_EV_OPEN = 3,
    TEGO_EV_UNLINK = 4,
    TEGO_EV_RENAME = 5,
    TEGO_EV_MKDIR = 6,
    TEGO_EV_CONNECT = 7,
    TEGO_EV_SENDMSG = 8,
    TEGO_EV_BIND = 9,
    TEGO_EV_CGROUP_MKDIR = 10,
    TEGO_EV_CGROUP_RMDIR = 11,
    TEGO_EV_SSL_CHUNK = 12,
    TEGO_EV_SSL_CLOSE = 13,
    /* ADR 0016 step 2: the remaining security_path_* functions where the run's Landlock domain can refuse, each
     * a tego_ev_fsop read at fexit with the chain's return. */
    TEGO_EV_MKNOD = 14,
    TEGO_EV_RMDIR = 15,
    TEGO_EV_LINK = 16,
    TEGO_EV_SYMLINK = 17,
    TEGO_EV_TRUNCATE = 18,
    /* The decision plane's own refusal sample (bpf/decide.bpf.c, struct tego_ev_plane), on a hook no recorder
     * fexit wraps: bprm_check (docs/p0/enforce-plane.md R23, TIER3-PLAN T9). */
    TEGO_EV_PLANE_EXEC = 19,
    /* The plane's own refusal samples on step B's hooks no recorder fexit wraps (TIER3-PLAN T13, R23), the same
     * struct tego_ev_plane: an attribute change (path_chmod, path_chown, the xattr and ACL hooks), named by its
     * directory's (dev, ino) and final component as an fsop record is, and a socket (socket_create), named by its
     * family, type and protocol. */
    TEGO_EV_PLANE_ATTR = 20,
    TEGO_EV_PLANE_SOCKET = 21,
    /* The plane's own refusal of an executable mapping (TIER3-PLAN T14, R23, R26; bpf/decide_stepc.h), named as
     * TEGO_EV_PLANE_ATTR names a file, or with no name for a file no path names. */
    TEGO_EV_PLANE_MAP = 22,
    /* The plane's own refusal sample on a hook a recorder fexit wraps whose fexit is not attached (the build's
     * tego_plane_recorded mask says which; enforce-plane §7, R23, TIER3-PLAN T9b): file_open and the file
     * operations, named as an fsop record is, by the object's directory (dev, ino) and final component, with
     * file_open's f_flags. The hook says which action it was. */
    TEGO_EV_PLANE_FS = 23,
    /* A failed execve/execveat's syscall return, after every image-open or bprm refusal fragment. Successful
     * execs are recorded by sched_process_exec alone, so there is no second success record. */
    TEGO_EV_EXEC_RESULT = 24,
    TEGO_EV_PLANE_CONTROL = 25,
    TEGO_EV_BIND_RESULT = 26,
    TEGO_EV_LISTEN_RESULT = 27,
    /* cgroup/sock_create's own refusal of an inet socket outside ADR 0018's allowlist (bpf/cgroup_net.bpf.c, struct
     * tego_ev_sock; enforce-cgroup-observe §5 R4, R5): the one line of a socket no other Tego mechanism saw. */
    TEGO_EV_SOCK_CREATE = 28,
    /* cgroup/setsockopt's own refusal of setsockopt(SOL_TCP, TCP_ULP) (bpf/cgroup_net.bpf.c, struct tego_ev_sockopt;
     * ADR 0018 (7)): the one line of an upper-layer protocol a submission the seccomp filter never sees asked for. */
    TEGO_EV_SOCKOPT = 29,
    /* The plane's kill of an exec whose mapped argument area is not the one its pin covers, or that had no pin to
     * check (ADR 0048 (3) P2; bpf/decide_execpin.h, struct tego_ev_exec_kill): sched_process_exec sent SIGKILL
     * before the new image's first instruction. */
    TEGO_EV_PLANE_EXEC_KILL = 30,
    /* The plane's proof that an exec held to its pin (ADR 0048 (8); bpf/decide_execpin.h, struct tego_ev_exec_held):
     * sched_process_exec checked the mapped argument area against the pin and it matched. Every exec of a pinned
     * slot that sched_process_exec checks has exactly one of this and TEGO_EV_PLANE_EXEC_KILL, so the ledger's fold
     * says kernel_pinned only on this sample, never on the absence of a kill. */
    TEGO_EV_PLANE_EXEC_HELD = 31,
};

enum tego_verdict {
    TEGO_V_ALLOW = 0,
    TEGO_V_REFUSED = 1,
    TEGO_V_OBSERVED = 2,
};

/* Record mode of a run, mirrored from agent.RecordMode. A program that finds TEGO_RECORD_OFF does every
 * enforcement step and no ring-buffer reserve (§6 E23). */
enum tego_record {
    TEGO_RECORD_OFF = 0,
    TEGO_RECORD_SUMMARY = 1,
    TEGO_RECORD_FULL = 2,
};

/* Reason index carried by a verdict, a breadcrumb or an event header. Userspace maps it to a record.Reason
 * (spec/reason/REASON-CHANNEL.md); the kernel never carries strings. 0 means "no reason" (an allow). */
enum tego_reason_code {
    TEGO_R_NONE = 0,
    TEGO_R_WRITE_OUTSIDE_CONTRACT = 1,
    TEGO_R_DELETE_OUTSIDE_CONTRACT = 2,
    TEGO_R_RENAME_OUTSIDE_CONTRACT = 3,
    TEGO_R_MKDIR_OUTSIDE_CONTRACT = 4,
    TEGO_R_READ_DENIED = 5,
    TEGO_R_PATH_UNRESOLVED = 6,
    TEGO_R_EXEC_NOT_ALLOWED = 7,
    TEGO_R_NET_NOT_ALLOWED = 8,
    TEGO_R_NET_HTTP = 9,
    /* The decision plane's own three (TIER3-PLAN §5): a REFER refusal, a rename of a deny_write target or one of
     * its ancestors, and a row whose key inode no longer carries the row's identity (ADR 0025 (4)). The ledger
     * keeps its reason in the closed set and names these in plane_reason (T9, spec/record/v1). */
    TEGO_R_REFER = 10,
    TEGO_R_DENY_WRITE_ANCESTOR = 11,
    TEGO_R_IDENTITY_MISMATCH = 12,
    TEGO_R_PROCESS_SCOPE = 13,
    /* ADR 0048 P2's exec pins (bpf/decide_execpin.h): no pin for the exec at bprm_check, or none armed at
     * sched_process_exec; a pinned fact (gen, image identity, final name, spelling, an interpreter's identity, the
     * stage count) differs; the key, the slot's pin map or the task's storage could not be had; the mapped argument
     * area differs from the covered one; the area could not be read; a guarded exec of a traced task. */
    TEGO_R_PIN_MISSING = 14,
    TEGO_R_PIN_MISMATCH = 15,
    TEGO_R_PIN_UNVERIFIABLE = 16,
    TEGO_R_ARGV_CHANGED = 17,
    TEGO_R_ARGV_UNREADABLE = 18,
    TEGO_R_EXEC_TRACED = 19,
};

/* Operation code of struct tego_ev_fsop. Landlock enforces every one; trace_proc records each with the LSM
 * chain's return, read at fexit (§5 R9, ADR 0016). */
enum tego_fsop {
    TEGO_FSOP_UNLINK = 0,
    TEGO_FSOP_RENAME = 1,
    TEGO_FSOP_MKDIR = 2,
    TEGO_FSOP_MKNOD = 3,
    TEGO_FSOP_RMDIR = 4,
    TEGO_FSOP_LINK = 5,
    TEGO_FSOP_SYMLINK = 6,
    TEGO_FSOP_TRUNCATE = 7,
};

/* The decision plane's mode that decides a run (tego_run.plane; docs/p0/enforce-plane.md R18, R22). A plane
 * program of another mode, or any plane program for a run of the fanotify fallback, returns 0 at once: one build's
 * run set holds every run of the build, whichever mode it was prepared in, and a build's two modes can be attached
 * at once (bpf.plane changed while the build lingers). Without it a mode would decide a run whose rows it does not
 * hold and refuse its every open (NOROWS). cgroup_track copies the whole row to a descendant, this byte with it. */
enum tego_run_plane {
    TEGO_RUN_PLANE_NONE = 0,
    TEGO_RUN_PLANE_LSM = 1,
    TEGO_RUN_PLANE_FMOD_RET = 2,
};

enum tego_run_flag {
    TEGO_RUN_LISTENER_RESULTS = 0x01, /* explicit listener policy, prepared in a plane mode */
    TEGO_RUN_ACTIVITY = 0x02,         /* stall-bounded: tego_activity_stamp stamps the run's slot */
};

/* One slot of tego_activity (maps.h), a run's activity stamp (limits R4): the bpf_ktime_get_ns (CLOCK_MONOTONIC) of
 * the first stamped action of the newest jiffy the run acted in, and that jiffy (bpf_jiffies64). An action in the
 * jiffy the slot already names writes nothing (tego_activity_stamp), so the reading lags the run's newest action by
 * at most one jiffy, 1 to 10 ms by CONFIG_HZ, which the stall check, reading the slot once a second, cannot tell
 * apart; and a busy run's threads share the slot's cache line instead of bouncing it on every action. Userspace reads
 * mono_ns alone. */
struct tego_activity_slot {
    __u64 mono_ns;
    __u64 jiffies;
};

/* Run-set entry: cgroup id -> run. descendants=1 means cgroups created beneath inherit this run (§5 R11). */
struct tego_run {
    __u32 run_idx;      /* index into the userspace run table; dense per-host slot (§5 R12) */
    __u8  descendants;  /* materialize children on cgroup_mkdir */
    __u8  tier;         /* 1 landlock, 2 cgroup, 3 bpflsm */
    __u8  record;       /* enum tego_record */
    __u8  plane;        /* enum tego_run_plane: the one plane mode that decides this run, or none */
    __u32 gen;          /* the run's generation: every record the run's programs write carries it (tego_hdr.gen),
                         * so a ring reused by the slot's next run never hands that run a record of this one
                         * (ADR 0026 (6) as amended) */
    __u8 flags;         /* immutable prepared capabilities; propagated with the whole run row */
    __u8 pad[3];
};

/* The run a cgroup attachment of the network programs enforces: the value of tego_net_owners, the cgroup
 * storage of the cgroup the links are attached to (§5 R1, R2, R5). cgroup_id is that cgroup's own id and is
 * never 0 once userspace has configured the attachment, so 0 means "attached, not configured yet", which the
 * programs refuse. The breadcrumb is keyed by cgroup_id.
 *
 * relay_cgroup_id is the cgroup of the launcher whose seccomp supervisor relays the run's unix connects
 * (docs/p0/supervisor.md R11). The relay names the socket it resolved through /proc/self/fd/<n>, a name only
 * the supervisor's own descriptor table gives a meaning to, so connect_unix admits that one name shape only
 * when the caller is in this cgroup (§5 R7). 0 admits it from no one.
 *
 * flags and gen are cgroup/sock_create's (§5 R4, R5; ADR 0018 PR 2): flags says whether the contract admits ping
 * sockets, and gen is the run's generation, which that program stamps on its own refusal record. It cannot take
 * either from the run set: a lookup keyed by the caller is what R1 forbids here, and the row keyed by cgroup_id
 * exists only from Arm on. Attach writes both with the rest of the value. */
struct tego_net_owner {
    __u64 cgroup_id;        /* the run's own cgroup: the attach point, and the breadcrumb's key */
    __u32 run_idx;          /* the run's slot; the verdict maps are keyed by it (§5 R12) */
    __u32 flags;            /* TEGO_OWNER_NET_*: what the run's contract asks of socket creation */
    __u64 relay_cgroup_id;  /* the supervisor's cgroup, the one caller whose /proc/self/fd/<n> is a decision */
    __u32 gen;              /* the run's tego_run.gen, stamped on cgroup/sock_create's record (tego_hdr.gen) */
    __u32 pad;
};

/* tego_net_owner.flags. ICMP admits ping sockets at cgroup/sock_create: the run's net section names an ICMP
 * destination (agent.RuleTable.NetSocketPolicy, the predicate the seccomp filter's socket arm and the plane's slot
 * header read too, ADR 0018 (1), (5)). */
#define TEGO_OWNER_NET_ICMP 0x1

/* Unix socket name key (§5 R7): one trie holds a run's declared unix: entries and the filesystem entries a
 * pathname socket is implicitly admitted or refused by (SEMANTICS §5, supervisor.md R11's name check).
 * prefixlen counts bits over everything after it, so the run_idx/kind/len header is always matched whole:
 *   - a declared pathname entry is exact: its bytes plus the terminating NUL, len 0;
 *   - a filesystem entry is two rows: its bytes plus "/" (the subtree beneath it, matched only at a component
 *     boundary) and its bytes plus NUL (the entry itself); the longest match is the nearest entry;
 *   - an abstract name keeps its length in the header, so only a name of exactly that many bytes matches,
 *     NUL bytes included (supervisor.md E5).
 * A lookup always asks for TEGO_UNIX_MAX_BITS with every byte past the name zero. */
#define TEGO_UNIX_NAME_MAX 108     /* sizeof(((struct sockaddr_un *)0)->sun_path) */
#define TEGO_UNIX_HDR_BITS 48      /* run_idx(32) + kind(8) + len(8) */
#define TEGO_UNIX_MAX_BITS (TEGO_UNIX_HDR_BITS + 8 * TEGO_UNIX_NAME_MAX)
#define TEGO_UNIX_ROWS_MAX 4096    /* rows of tego_unix_names, shared by every run of a build */

enum tego_unix_kind {
    TEGO_UNIX_PATH = 1,
    TEGO_UNIX_ABSTRACT = 2,
};

struct tego_unix_key {
    __u32 prefixlen;
    __u32 run_idx;
    __u8  kind;                         /* enum tego_unix_kind */
    __u8  len;                          /* abstract: the name's byte count; pathname: 0 */
    __u8  name[TEGO_UNIX_NAME_MAX];    /* pathname bytes up to its NUL, or the abstract name after its NUL */
} __attribute__((packed));

/* One approved abstract-name connect (supervisor R11c, ADR 0008's note of 2026-10-19): the run's slot and gen and the
 * cookie of the agent's socket the relay connects. A socket holds at most one grant at a time; the value names the
 * approved name. */
#define TEGO_UNIX_APPROVALS_MAX 4096
struct tego_unix_approval_key {
    __u32 run_idx;
    __u32 gen;
    __u64 cookie;
};
struct tego_unix_credit {
    __u64 credit;                       /* 1 until a connect consumes it */
    __u64 deadline_ns;                  /* CLOCK_MONOTONIC; the grant is dead after it */
    struct tego_unix_key name;         /* the approved name as tego_unix_key_of builds it: kind, len, bytes */
    __u8  pad[2];
};

/* Network verdict map key (exact host:port). Keyed by run_idx, never by cgroup id: every cgroup of a run —
 * the run's own scope and every descendant cgroup_mkdir materializes — shares one set of rows (§2.2, §5 R2,
 * R11, R12). port is host byte order; addr is network byte order with v4 in the first four bytes. */
struct tego_net_key {
    __u32 run_idx;
    __u8  family;       /* 2 AF_INET, 10 AF_INET6 */
    __u8  proto;        /* 6 tcp, 17 udp */
    __u16 port;         /* host order */
    __u8  addr[16];     /* network order; v4 in the first 4 bytes, rest zero */
};

/* LPM trie key for CIDR rules. prefixlen counts bits over everything after it, so the fixed
 * run_idx(32)+family(8)+proto(8)+port(16) header is always fully matched and only addr[] varies:
 * prefixlen = TEGO_LPM_HDR_BITS + the declared CIDR width. Packed so the trie's byte-wise compare sees the
 * header and the address contiguously; the header bytes' own order is irrelevant because insert and lookup
 * encode them identically and the header is never partially matched. */
#define TEGO_LPM_HDR_BITS 64
#define TEGO_LPM_MAX_BITS (TEGO_LPM_HDR_BITS + 128)

struct tego_net_lpm_key {
    __u32 prefixlen;
    __u32 run_idx;
    __u8  family;
    __u8  proto;
    __u16 port;
    __u8  addr[16];
} __attribute__((packed));

struct tego_net_verdict {
    __u8  verdict;      /* enum tego_verdict */
    __u8  reason;       /* enum tego_reason_code */
    __u16 rule_idx;     /* declared entry index for the event's rule field */
    __u32 timeline;     /* zero static; otherwise per-run composed expiry chain */
    __u64 deadline_ns;  /* monotonic expiry of the first composed interval */
};

/* Last network decision of a run: the breadcrumb the supervisor reads instead of re-deriving a verdict, through
 * cgroup.Handle.KernelNet after a relayed connect fails EPERM (§5 R5). Keyed by the run's own cgroup id,
 * overwritten per decision, last-write-wins (§6 E5); a mono_ns older than the notification's staleness window
 * is to be ignored by the reader. */
struct tego_reason {
    __u8  op;           /* TEGO_EV_CONNECT or TEGO_EV_SENDMSG */
    __u8  verdict;      /* enum tego_verdict */
    __u8  reason;       /* enum tego_reason_code */
    __u8  family;
    __u8  proto;
    __u8  pad0;
    __u16 port;         /* host order */
    __u8  addr[16];
    __u64 mono_ns;      /* bpf_ktime_get_ns(), boot monotonic (§6 E20) */
    __u32 run_idx;
    __u16 rule_idx;
    __u16 pad1;
};

/* Common event header on the ring buffer. */
struct tego_hdr {
    __u16 version;
    __u16 kind;         /* enum tego_kind */
    __u32 size;         /* total bytes incl. header */
    __u64 ts_mono_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 run_idx;
    __u8  verdict;      /* enum tego_verdict; TEGO_V_OBSERVED for every record-only program */
    __u8  reason;       /* enum tego_reason_code */
    __u16 rule_idx;
    __u32 gen;          /* tego_run.gen of the row the program found: the reader drops a record of another gen */
};

/* start_ns and parent_start_ns below are thread group leaders' task->start_boottime, the process start time
 * /proc/<pid>/stat reports and an exec id's third component. They say which process a record's pid or ppid named
 * when the record was made, so a pid reused after an exit record was lost is not taken for the process that
 * had it before (§6 E14). */

struct tego_ev_exec {
    struct tego_hdr hdr;
    __u64 exec_start_ns;    /* task->start_boottime; the exec id's third component */
    __u64 parent_start_ns;  /* the parent's (hdr.ppid's) start time */
    __u64 cwd_dev;          /* the working directory's super block s_dev, at exec */
    __u64 cwd_ino;          /* the working directory's i_ino, at exec: a relative path's base (H8) */
    __u32 old_tid;          /* sched_process_exec's old_pid: the thread id before de_thread, for attempt joins */
    __u32 pad0;
    char  comm[TEGO_COMM_LEN];
    __u32 argv_len;         /* bytes used in argv */
    __u8  argv_truncated;   /* §6 E25 */
    __u8  path_truncated;   /* §6 E4 */
    __u8  plane;            /* enum tego_plane_named: whether the plane's bprm_check allowed this exec and what
                             * hdr.rule_idx then names (TIER3-PLAN T9) */
    __u8  interpreted;      /* binfmt replaced bprm->interp, and may have rewritten the mapped argv */
    char  path[TEGO_PATH_MAX];
    char  argv[TEGO_ARGV_MAX]; /* NUL-separated */
    __u32 pin_seq;          /* the seq of the pin the plane holds this exec to (ADR 0048 (8)), 0 for none: the task's
                             * tego_exec_armed cur_seq of the run and gen. Whether the pin held is the plane's held or
                             * kill sample's to say, which names the same cur_seq; the ledger folds them by seq */
    __u32 pad1;
};

struct tego_ev_exit {
    struct tego_hdr hdr;
    __u64 exec_start_ns;    /* disambiguates pid reuse against a lagging exec (§6 E14) */
    __s32 code;             /* exit status */
    __u32 signal;           /* terminating signal, 0 when none */
};

/* Terminal result of a failed exec attempt. start_ns identifies the thread group before the failed exec;
 * hdr.tid remains the calling thread's id. The notified attempt supplies its immutable pathname and argv. */
struct tego_ev_exec_result {
    struct tego_hdr hdr;
    __u64 start_ns;
    __s64 ret;             /* the syscall's negative errno */
};

/* Open record from fexit/security_file_open: the one hook in the kernel's btf_allowlist_d_path that trace_proc
 * attaches to (§5 R10), so it carries a resolved path. flags is file->f_flags.
 *
 * ret is the LSM chain's signed return, read at fexit (ADR 0016 (3)): 0 or -errno, and ret_ok says the program
 * that wrote the record read it. A record with ret_ok 0 carries no return, and userspace falls back to the
 * tier's model for it. On an O_TRUNC open that the chain allowed, ret is the truncate hook's return (ADR 0016
 * (3), the held record).
 *
 * An open has one path. The record carried a second, reserved and always empty, which cost every open 256 of its
 * 592 bytes on the ring and in each task's held record; events version 2 dropped it. */
struct tego_ev_fs {
    struct tego_hdr hdr;
    __u64 start_ns;     /* the opening process's start time */
    __u64 dev;          /* the opened inode's super block s_dev */
    __u32 flags;        /* file->f_flags */
    __u32 ino;          /* low 32 bits of the target inode number, informational */
    __u8  path_ok;      /* 0 when bpf_d_path failed or truncated (§6 E4) */
    __u8  ret_ok;       /* 1 when ret is the chain's return */
    __u8  created;      /* 1 when this open created the file (FMODE_CREATED) */
    __u8  exec_open;        /* file->f_flags carried __FMODE_EXEC: an image or interpreter open */
    __s32 ret;          /* the LSM chain's return: 0 or -errno */
    char  path[TEGO_PATH_MAX];
};

/* What an fsop record's dir (or dir2) holds: the parent directory's path, walked in the kernel for a run a plane
 * mode decides (trace_proc tego_dir_walk; docs/p0/enforce-plane.md §2.15, ADR 0016's 2026-09-30 note). Anything but
 * OK leaves dir empty, and userspace names the side from dirIndex as before, or marks it unresolved: never a path
 * the walk could not prove. */
enum tego_dir_state {
    TEGO_DIR_NONE = 0,         /* not walked: a run no plane decides, or a kernel without bpf_loop */
    TEGO_DIR_OK = 1,           /* dir[dir_off, TEGO_PATH_MAX) is the path; empty is the root */
    TEGO_DIR_LONG = 2,         /* the path does not fit in TEGO_PATH_MAX bytes, or has over TEGO_DIR_WALK_MAX
                                 * components or TEGO_DIR_WALK_MOUNTS mount crossings */
    TEGO_DIR_RACED = 3,        /* a component was renamed while it was read (its d_seq moved), or a mount it
                                 * crosses was moved */
    TEGO_DIR_UNREACHABLE = 4,  /* disconnected, or not below the task's root (another mount namespace's) */
};

/* Components a directory walk names, and its iterations: each level and a mount crossing above it. */
#define TEGO_DIR_WALK_MAX 64
#define TEGO_DIR_WALK_ITERS (2 * (TEGO_DIR_WALK_MAX + 1))
#define TEGO_DIR_WALK_MOUNTS 8   /* mount crossings a walk checks again on its second pass; a power of two */

/* What a directory walk keeps between its two passes (trace_proc tego_dir_walk): each level's full d_seq, each
 * crossing's parent mount and mountpoint (the first pass's pairs, then the second's), and the path it builds. It
 * lives in the task's storage (struct tego_held), not on the stack: the four frames of a walk share 512 bytes, and
 * a 16-bit sequence could wrap under a rename loop while a preempted walk waits. The walk being a global function,
 * verified once per program, it takes no pointer to the record: it builds here, and the caller copies. */
struct tego_dir_scratch {
    __u32 seq[TEGO_DIR_WALK_MAX];
    __u64 mnt[4 * TEGO_DIR_WALK_MOUNTS];
    char  buf[TEGO_PATH_MAX];  /* the path, right to left; the caller copies it into its record */
    __u64 launder_dentry;       /* the walk's arguments, stored and loaded back so they reach the global function
                                 * as scalars, not the hook's BTF pointers (the plane's laundry, ADR 0024's T2) */
    __u64 launder_mnt;
};

/* File-operation record: unlink, rename, mkdir, mknod, rmdir, link, symlink and truncate. security_path_* (but
 * truncate) are in the kernel's btf_allowlist_d_path BTF_SET on no version, so these programs never call
 * bpf_d_path (§5 R9/R10): they carry the parent directory's (dev, inode) and the final component's raw bytes, and
 * userspace names the rule from dirIndex. A link's source and a truncate's file are named by their dentry's
 * parent the same way; a symlink's second name is its target, the string the caller passed.
 *
 * For a run a plane mode decides, each side's parent directory is also named by its path (dir, dir2), walked in
 * the kernel as d_path walks it (trace_proc tego_dir_walk): the plane leaves such an action unnotified (T16), so
 * this record is its one line and must name it by path on its own. The path is built right to left and starts at
 * dir_off; dir_state says whether it is whole.
 *
 * ret and ret_ok are struct tego_ev_fs's: the LSM chain's return, read at fexit (ADR 0016 (3)). */
struct tego_ev_fsop {
    struct tego_hdr hdr;
    __u64 start_ns;     /* the acting process's start time */
    __u64 dev;          /* parent directory's super block s_dev */
    __u64 dir_ino;      /* parent directory's i_ino */
    __u64 dev2;         /* rename destination's or new link's parent; 0 for the other ops */
    __u64 dir_ino2;
    __u8  op;           /* enum tego_fsop */
    __u8  name_ok;      /* 0 when the final component was truncated or unreadable */
    __u8  name2_ok;
    __u8  ret_ok;       /* 1 when ret is the chain's return */
    __s32 ret;          /* the LSM chain's return: 0 or -errno */
    char  name[TEGO_NAME_MAX];
    char  name2[TEGO_NAME_MAX]; /* rename's or link's new final component, symlink's target; empty otherwise */
    __u8  dir_state;    /* enum tego_dir_state of dir */
    __u8  dir2_state;   /* ... of dir2: a rename's or a link's new name's parent */
    __u16 dir_off;      /* dir's path is dir[dir_off, TEGO_PATH_MAX), no NUL; TEGO_PATH_MAX for the root */
    __u16 dir2_off;
    __u16 pad;
    char  dir[TEGO_PATH_MAX];
    char  dir2[TEGO_PATH_MAX];
};

struct tego_ev_net {
    struct tego_hdr hdr;
    __u64 start_ns;     /* the connecting process's start time */
    __u8  family;
    __u8  proto;
    __u16 port;         /* host order */
    __u8  addr[16];
    __u32 pad;
};

/* cgroup/sock_create's own refusal record (bpf/cgroup_net.bpf.c; enforce-cgroup-observe §5 R4, R5): an inet socket
 * outside ADR 0018's allowlist, named by the family, type and protocol the program read from struct bpf_sock (type
 * is sk_type, which carries no SOCK_NONBLOCK or SOCK_CLOEXEC; protocol is the whole number, MPTCP's 262 included).
 * hdr.verdict is TEGO_V_REFUSED, hdr.reason TEGO_R_NET_NOT_ALLOWED, hdr.cgroup_id the run's own cgroup (the
 * attachment's, never the caller's) and hdr.run_idx and hdr.gen the owner's. hdr.ppid is 0: a CGROUP_SOCK program
 * has no task to read it from, and the recorder names the actor by hdr.pid. */
struct tego_ev_sock {
    struct tego_hdr hdr;
    __s32 family;
    __s32 type;
    __s32 protocol;
    __u32 pad;
};

/* The longest TCP upper-layer-protocol name the kernel reads from setsockopt(TCP_ULP)'s value: TCP_ULP_NAME_MAX (16)
 * less its NUL (net/ipv4/tcp.c do_tcp_setsockopt). */
#define TEGO_ULP_NAME_MAX 15

/* cgroup/setsockopt's own refusal record (bpf/cgroup_net.bpf.c; ADR 0018 (7), enforce-cgroup-observe §5 R4, R5): a
 * setsockopt(SOL_TCP, TCP_ULP) of the run's, on whatever path reached the protocol's setsockopt (io_uring's
 * SOCKET_URING_OP_SETSOCKOPT, which no seccomp filter sees). level and optname are the option's, optlen the caller's
 * value length, and name the first TEGO_ULP_NAME_MAX bytes of the kernel's own copy of the value, zero-padded; cut
 * at optlen and the first NUL it is what the kernel would have read as the ULP's name. hdr as struct tego_ev_sock's:
 * verdict TEGO_V_REFUSED, reason TEGO_R_NET_NOT_ALLOWED, the attachment's cgroup and the owner's run_idx and gen. */
struct tego_ev_sockopt {
    struct tego_hdr hdr;
    __s32 level;
    __s32 optname;
    __s32 optlen;
    __u32 pad;
    __u8  name[16];
};

/* Descendant materialization record from cgroup_track. err is the run_set insert's result, 0 when the row is in
 * place and -E2BIG when the hash is at capacity (§6 E11). Failed insertions are emitted under record: off too;
 * the recorder counts a cgroup-tracking-failed gap and the runtime stops the run whose descendant has no row.
 * Successful membership changes need no ledger action. */
struct tego_ev_cgroup {
    struct tego_hdr hdr;
    __u64 parent_cgroup_id;
    __u64 child_cgroup_id;
    __s32 err;
    __u32 pad;
};

/* Direction of one plaintext chunk, as the ledger's ssl_request/ssl_response split needs it. */
enum tego_ssl_dir {
    TEGO_SSL_WRITE = 0,
    TEGO_SSL_READ = 1,
};

/* Which OpenSSL entry point a scratch row came from: the return probe needs it to know where the length is
 * (R3 — SSL_read's is the return value, SSL_read_ex's is *readbytes and only when the return is 1). */
enum tego_ssl_call {
    TEGO_SSL_CALL_READ = 0,
    TEGO_SSL_CALL_READ_EX = 1,
};

/* Why a chunk carries no bytes of its own although its call moved some (struct tego_ev_ssl.hole). */
enum tego_ssl_hole {
    TEGO_SSL_HOLE_NONE = 0,       /* data holds the chunk's bytes */
    TEGO_SSL_HOLE_UNREADABLE = 1, /* bpf_probe_read_user could not read them; skipped counts them */
    TEGO_SSL_HOLE_STALE = 2,      /* a read whose scratch row was older than TEGO_SSL_MAX_CALL_NS (§6 #3): the
                                    * buffer it names is not trusted, and skipped is the length the call reported */
    TEGO_SSL_HOLE_EVICTED = 3,    /* a read whose scratch row the LRU evicted (R5): buffer and length unknown,
                                    * skipped 0 */
    TEGO_SSL_HOLE_NOLENGTH = 4,   /* an SSL_read_ex that returned 1 whose *readbytes could not be read (§6 #13):
                                    * the call moved bytes, how many is unknown, skipped 0 */
};

/* Scratch key for an in-flight SSL_read (R5): two threads sharing one SSL* and one thread's two SSL*
 * objects never collide. A uretprobe sees no arguments, so tego_ssl_current maps the thread back to the
 * SSL* its entry probe recorded and this key is rebuilt from the pair. */
struct tego_ssl_key {
    __u64 pid_tgid;
    __u64 ssl_ptr;
};

/* Scratch value: where the plaintext will land and, for SSL_read_ex, where its length will. */
struct tego_ssl_scratch {
    __u64 buf;          /* user pointer the call will fill */
    __u64 len_ptr;      /* SSL_read_ex's size_t *readbytes; 0 for SSL_read */
    __u64 enter_ns;     /* bpf_ktime_get_ns() at entry, bounded by TEGO_SSL_MAX_CALL_NS */
    __u8  call;         /* enum tego_ssl_call */
    __u8  pad[7];
};

struct tego_ev_ssl {
    struct tego_hdr hdr;
    __u64 ssl_ptr;
    __u32 len;          /* bytes in data */
    __u8  direction;    /* enum tego_ssl_dir: 0 write, 1 read */
    __u8  truncated;    /* bytes of this call before data were lost: an earlier part never reached the ring */
    __u8  hole;         /* enum tego_ssl_hole: why len is 0 although the call moved bytes */
    __u8  pad;
    __u32 seq;          /* this chunk's number on its (pid_tgid, ssl_ptr), both directions, from
                         * tego_ssl_seq: taken before the reserve, so a chunk that never reached the ring
                         * leaves a hole the reader finds at the connection's next chunk (I2) */
    __u32 pad2;
    __u64 skipped;      /* bytes of this call after data that are not on the ring: the tail past
                         * TEGO_SSL_CHUNKS_MAX chunks (R6), or a hole's own bytes. Userspace steps over the
                         * hole inside a body and records the prefix (#8), instead of waiting for bytes that
                         * never come. */
    /* followed by len bytes of plaintext */
};

/* The ring-buffer record uprobe_ssl.bpf.c writes: the header above followed by the plaintext. It is reserved at
 * sizeof(meta) plus the smallest size class that holds len (TEGO_SSL_CLASS_SMALL, TEGO_SSL_CLASS_MEDIUM,
 * TEGO_SSL_CHUNK_MAX), and a stale read's hole at sizeof(meta) alone, so data is declared at its largest and
 * hdr.size says how much of it a record has. Every reserve is still a compile-time constant and the record is
 * written exactly once — reserve, fill, submit, never a second copy (§8 I7). meta.len says how much of data is
 * filled; the rest is whatever the ring buffer last held and no reader ever looks at it. */
struct tego_ev_ssl_chunk {
    struct tego_ev_ssl meta;
    __u8 data[TEGO_SSL_CHUNK_MAX];
};

/* The ring-buffer record uprobe_ssl.bpf.c writes at SSL_free: the connection a process's SSL* named is over
 * (R3a). Userspace closes every connection of that process keyed by the pointer, so a new SSL_new that
 * glibc hands the same address starts a new connection instead of continuing the old one's framing. */
struct tego_ev_ssl_close {
    struct tego_hdr hdr;
    __u64 ssl_ptr;
};

/* Tier 3's kernel decision plane (ADRs 0024, 0025; docs/p0/TIER3-PLAN.md §3). bpf/decide.bpf.c decides opens,
 * execs and fs mutations of a governed run on the object the kernel resolved, from rows keyed by the struct
 * inode * the run's own Landlock domain pins. Userspace never reads a key (a kernel address): rows are filled and
 * cleared in the kernel, so the only structs Go mirrors here are the values and the counters. */
#define TEGO_PLANE_WALK_MAX 64          /* d_parent steps per walk; a mount crossing counts none (ADR 0024 (1)) */
/* bpf_loop iterations per walk: a lookup at each of the WALK_MAX + 1 levels and one mount crossing above each. A
 * path that crosses more mounts than that (mounts stacked on one mountpoint) runs out and is refused BOUND. */
#define TEGO_PLANE_WALK_ITERS (2 * (TEGO_PLANE_WALK_MAX + 1))
#define TEGO_PLANE_ROWS_MAX 4096        /* rows in one slot's inner rows map */
#define TEGO_PLANE_EXEC_ROWS_MAX 1024   /* rows in one slot's inner exec-rows map */
#define TEGO_PLANE_LISTEN_ROWS_MAX 256

/* ADR 0043's name entries (D9): a run's name rows, beside its fs, exec and listener rows. A slot's name map holds at
 * most TEGO_PLANE_NAME_ROWS_MAX rows (exact, prefix, exception and exemption-only rows) and one config row at key 0,
 * so TEGO_PLANE_NAME_KEYS entries; compile gives a row at most TEGO_PLANE_NAME_ARMS arms (the row holds their
 * summary); a run has at most
 * TEGO_PLANE_SCOPES_MAX scope directories (one bit each in a scope row's tego_plane_row.scope),
 * TEGO_PLANE_NAME_LEADS prefilter leads and TEGO_PLANE_NAME_PREFIXES distinct prefix lengths in its slot header,
 * TEGO_PLANE_NAME_ENTRIES entries (the six bits of a name rule's tag) and TEGO_PLANE_NAME_DEPS dependency
 * directory names of at most TEGO_PLANE_NAME_DEP_LEN bytes in its config row. internal/bpf mirrors each, and
 * TestPlaneCapsMatchRowCompiler holds them to pkg/spec/agent's caps. */
#define TEGO_PLANE_NAME_ROWS_MAX 64
#define TEGO_PLANE_NAME_KEYS (TEGO_PLANE_NAME_ROWS_MAX + 1)
#define TEGO_PLANE_NAME_ARMS 8
#define TEGO_PLANE_SCOPES_MAX 8
#define TEGO_PLANE_NAME_LEADS 8
#define TEGO_PLANE_NAME_PREFIXES 4
#define TEGO_PLANE_NAME_ENTRIES 64
#define TEGO_PLANE_NAME_DEPS 8
#define TEGO_PLANE_NAME_DEP_LEN 16

/* The hook a decision was made at: tego_plane_decision.hook, for the recorder's fexit (ADR 0024 (11)). Step A of
 * TIER3-PLAN §2; steps B-D add theirs after these. 0 means no decision recorded yet. */
enum tego_plane_hook {
    TEGO_HOOK_NONE = 0,
    TEGO_HOOK_FILE_OPEN = 1,
    TEGO_HOOK_BPRM_CHECK = 2,
    TEGO_HOOK_PATH_RENAME = 3,
    TEGO_HOOK_PATH_LINK = 4,
    TEGO_HOOK_PATH_UNLINK = 5,
    TEGO_HOOK_PATH_RMDIR = 6,
    TEGO_HOOK_SOCKET_CONNECT = 7,  /* step D: unix names below 6.7 */
    TEGO_HOOK_SOCKET_SENDMSG = 8,
    /* Step B (TIER3-PLAN T13; bpf/decide_stepb.h). file_truncate and the ACL hooks are absent from some kernels'
     * BTF (internal/bpf PlaneHook.Optional); their values stay, so every hook keeps its number on every kernel. */
    TEGO_HOOK_PATH_MKNOD = 9,
    TEGO_HOOK_PATH_MKDIR = 10,
    TEGO_HOOK_PATH_SYMLINK = 11,
    TEGO_HOOK_PATH_TRUNCATE = 12,
    TEGO_HOOK_FILE_TRUNCATE = 13,
    TEGO_HOOK_PATH_CHMOD = 14,
    TEGO_HOOK_PATH_CHOWN = 15,
    TEGO_HOOK_INODE_SETXATTR = 16,
    TEGO_HOOK_INODE_REMOVEXATTR = 17,
    TEGO_HOOK_INODE_SET_ACL = 18,
    TEGO_HOOK_INODE_REMOVE_ACL = 19,
    TEGO_HOOK_SOCKET_CREATE = 20,
    TEGO_HOOK_MMAP_FILE = 21,      /* step C (TIER3-PLAN T14; bpf/decide_stepc.h): PROT_EXEC mappings */
    TEGO_HOOK_FILE_MPROTECT = 22,
    TEGO_HOOK_SOCKET_BIND = 23,    /* no sample: its terminal line is the bind producer's (decide_socket.h) */
    TEGO_HOOK_PTRACE_ACCESS_CHECK = 24,
    TEGO_HOOK_PTRACE_TRACEME = 25,
    TEGO_HOOK_BPF = 26,
    TEGO_HOOK_KEY_PERMISSION = 27,
    TEGO_HOOK_SOCKET_LISTEN = 28,
    TEGO_HOOK_CAPABLE = 29,
    TEGO_HOOK_UNIX_MAY_SEND = 30,
};

/* A slot's unix policy for the plane's step D hooks (socket_connect, socket_sendmsg; enforce-plane R14), in
 * tego_plane_unix_policy at run_idx, written with the run's gen by Prepare's fill. The two hooks are loaded only where
 * cgroup/connect_unix is absent (below 6.7) and decide a run's unix names exactly as connect_unix and sendmsg_unix
 * do on 6.7+, from the same tego_unix_names rows. Whether they decide is the slot header's TEGO_SLOT_UNIX_DECIDES
 * (decides mirrors it for a reader of the map). A deciding run whose slot holds no policy of the run's gen refuses
 * (fail-closed, counted as norows). */
struct tego_plane_unix {
    __u64 relay_cgroup_id;  /* the launcher's cgroup: the one caller whose /proc/self/fd/<n> connect is admitted;
                             * 0 admits it from no one */
    __u32 gen;              /* the run's tego_run.gen; a policy of another gen is a previous run's, and absent */
    __u8  decides;          /* 1: the plane decides this run's unix names (the header's flag is what the hooks read) */
    __u8  zero;             /* always 0: where the canonical check's state starts (decide.bpf.c says why a map byte) */
    __u8  pad[2];
};

/* tego_plane_slot.flags: what the slot's run decides beyond its fs rows. */
enum tego_plane_slot_flag {
    TEGO_SLOT_EXEC_DECIDES = 0x01, /* the contract has an exec: section: bprm_check and step C decide */
    TEGO_SLOT_EXEC_ANON = 0x02,    /* exec.anonymous: an image with no name may run */
    TEGO_SLOT_UNIX_DECIDES = 0x04, /* step D's hooks decide the run's unix names (below 6.7, a net: section) */
    TEGO_SLOT_NET_DECIDES = 0x08,  /* the contract has a net: section: socket_create applies ADR 0018's allowlist */
    TEGO_SLOT_NET_ICMP = 0x10,     /* the net section names an ICMP destination (a port-0 entry): ping sockets */
    TEGO_SLOT_LISTEN_DECIDES = 0x20,
    TEGO_SLOT_KEYRING_ALLOWED = 0x40,
    /* ADR 0043 D9: the slot has name rows and a config row of the run's gen in tego_plane_name_rows at run_idx, and
     * the header's leads below say which final names are candidates; file_open, the create, unlink and truncate
     * hooks, path_link and path_rename then ask the name check where the walk allows, and path_rename asks D5 of a
     * directory. Clear, no hook reads the name map or the leads: a run without name entries pays one flag test. */
    TEGO_SLOT_NAME_DECIDES = 0x80,
    /* ADR 0048 (3) P2: every exec of the run carries a pin the supervisor wrote in tego_plane_exec_pins, keyed in
     * the pid namespace the header's pidns_dev and pidns_ino name, and the plane holds the exec to it (bprm_check,
     * then sched_process_exec). Clear, bprm_check and the pin program return after this flag test. */
    TEGO_SLOT_EXEC_PIN = 0x100,
    TEGO_SLOT_BUILTIN_TTY = 0x200, /* ADR 0113: the inherited Landlock tty layer decides terminal opens */
};

/* A slot's header, in tego_plane_slots at run_idx (enforce-plane R6): the gen of the run whose rows the slot holds
 * and what that run's contract decides. Prepare writes it last, after the fill and its check and before Arm inserts
 * the run-set row, and every clear of the slot zeroes it first. Every decided hook reads it after its run-set hit,
 * and a header of another gen (0 when cleared; a slot's epoch is never 0) refuses and counts norows: a missing row
 * never reads as a permission. What a section's absence used to say by a missing policy row (no exec: section, no
 * net: section) a flag says here, so a slot whose rows are gone refuses rather than allows. fs_rows and exec_rows are
 * the counts the fill wrote, for a reader of the maps. */
struct tego_plane_slot {
    __u32 gen;
    __u32 flags;        /* enum tego_plane_slot_flag */
    __u32 fs_rows;
    __u32 exec_rows;
    /* ADR 0043 D2's prefilter, read only under TEGO_SLOT_NAME_DECIDES and laid out so a name tested against at most
     * four leads stays on the header's first cache line (D9): a final name is a candidate for the name rows only
     * when its first min(8, len) bytes, masked to its length and ASCII-folded, start with one of the leads, each a
     * literal's first min(8, n) folded bytes (agent.MinimalNameLeads), zero past lead_len. min_len is the shortest
     * lead's length: a shorter name is no candidate. prefix_len are the distinct prefix literals' lengths,
     * ascending, each a prefix key the name check computes. */
    __u8  nleads;
    __u8  nprefixes;
    __u8  lead_len[TEGO_PLANE_NAME_LEADS];
    __u8  prefix_len[TEGO_PLANE_NAME_PREFIXES];
    __u8  min_len;
    __u8  pad;
    __u64 lead[TEGO_PLANE_NAME_LEADS];
    /* Under TEGO_SLOT_EXEC_PIN, the launcher's pid namespace, in which a pin's key numbers its tid: nsfs's s_dev in
     * the kernel's own encoding (major << 20 | minor, not stat's st_dev) and the namespace's inode, the two arguments
     * bpf_get_ns_current_pid_tgid compares (ADR 0048's K0 note). */
    __u64 pidns_dev;
    __u64 pidns_ino;
    __u8  pad2[16];     /* to 128 bytes, two cache lines: the slots ARRAY's elements stay line-aligned */
};

#define TEGO_BIND_ABSTRACT 1U
#define TEGO_BIND_NAME_OK 2U
#define TEGO_BIND_RESOLVED 4U
#define TEGO_BIND_MARKED 8U
#define TEGO_BIND_CHAIN_REFUSED 16U
#define TEGO_BIND_DECIDED 32U
#define TEGO_BIND_URING 64U /* written by an io_uring op's producer, not a syscall exit (enforce-plane §2.20) */

/* Immutable kernel bind evidence, separate from the task's last generic hook. */
struct tego_plane_bind {
    __u64 start_ns;
    __u64 dev;
    __u64 dir_ino;
    __u32 rule_idx;
    __u32 flags;
    __u32 name_len;
    __u8 reason;
    __u8 op;
    __u8 pad[2];
    char name[108];
    __u32 pad2;
};

/* How one walk ended (tego_plane_walk's return). ROOT and HIT are answers; every other value is a fail-closed
 * refusal with the reason path-unresolved, counted in the slot's tego_plane_counts. */
enum tego_plane_walk_result {
    TEGO_WALK_ROOT = 0,        /* reached the namespace root with no current row: the plane has no entry here */
    TEGO_WALK_HIT = 1,         /* the nearest current row; tego_plane_hit says which */
    TEGO_WALK_UNRESOLVED = 2,  /* a disconnected dentry (no parent short of a mount root) */
    TEGO_WALK_BOUND = 3,       /* the object and TEGO_PLANE_WALK_MAX levels above it without a row or the root */
    TEGO_WALK_MISMATCH = 4,    /* a row's key inode no longer carries the row's identity (ADR 0025 (4)) */
    TEGO_WALK_NOROWS = 5,      /* a live run-set row whose slot has no rows map */
};

/* tego_plane_row.kind: the row compiler's decide.PlaneKind, bit for bit (internal/bpf
 * TestPlaneCapsMatchRowCompiler). Every row is complete (TIER3-PLAN T5): it carries the root model's answer at its
 * own path for every question, so the walk stops at the first current row it meets. A row with no bit set allows a
 * read and refuses a modification, as a walk that meets no row does. */
enum tego_plane_row_kind {
    TEGO_ROW_READ_DENY = 0x01,         /* a read here or beneath is refused */
    TEGO_ROW_MODIFY_ALLOW = 0x02,      /* a modification here or beneath is allowed */
    TEGO_ROW_RENAME_REFUSED = 0x04,    /* renaming this inode itself (the walk's depth 0) is refused: a deny_write
                                         * target or a directory above one up to its write entry (R11) */
    TEGO_ROW_EXEC_DIR = 0x08,          /* an exec.allow directory covers this inode */
    TEGO_ROW_PROTECTED = 0x10,         /* a deny_write target is at or above this inode: the attribute hooks
                                         * (chmod, chown, xattr, ACL) refuse here and beneath (R12) */
    TEGO_ROW_MOUNT_ONLY = 0x20,        /* a mounted root at or below a deny_write target, keyed from mountinfo at
                                         * Prepare for the attribute hooks' walk inside a superblock (R12): the
                                         * walk that crosses mounts passes it as absent and meets the target's
                                         * own row above the mountpoint */
    TEGO_ROW_BUILTIN_IPC = 0x80,       /* native Unix peer immutable floor */
    TEGO_ROW_SCOPE_ONLY = 0x40,        /* a name entry's scope directory no entry, target or exec grant keys
                                         * (ADR 0043 D4, decide.PlaneScopeOnly): only the name check's climb reads
                                         * it, for its scope bit; every walk passes it as absent, so it changes no
                                         * answer and no walk's bound */
};

/* The rule_idx of a decision no row made: an unmatched read (allowed), modification or exec (refused), and every
 * fail-closed walk. TEGO_MAX_RULES leaves it outside the rule space. */
#define TEGO_PLANE_RULE_NONE 0xffff

/* The rule_idx bprm_check records for a match by an exec.allow directory: the fs row's position with this bit set,
 * since the fs row, not an exec entry, is what the kernel holds there; the ledger names the row's exec.allow entry
 * (decide.PlaneRows.ExecRuleAt, TIER3-PLAN T9). */
#define TEGO_PLANE_RULE_FS_ROW 0x10000
#define TEGO_PLANE_RULE_LISTEN 0x20000
#define TEGO_PLANE_RULE_BUILTIN_HOST 0x40000
#define TEGO_PLANE_RULE_BUILTIN_SURFACE 0x80000

/* The rule_idx of a refusal a name entry decided (ADR 0043 D8): TEGO_PLANE_RULE_NAME | scope bit << 6 | the entry's
 * position in RuleTable.NameDeny (decide.PlaneNameTag). fs rows stay below TEGO_PLANE_ROWS_MAX, so a reader tests
 * this bit before it reads rule_idx as a row; TEGO_PLANE_RULE_NONE has every bit set and is never read as a tag. */
#define TEGO_PLANE_RULE_NAME 0x8000

/* One row of a slot's rows map, keyed by the entry's struct inode * (ADR 0025 (1), amended by T0): kind is the
 * row's answer (enum tego_plane_row_kind) and rule_idx the row's position in the row compiler's rows, which the
 * ledger resolves by the hook's question (decide.PlaneRows.RuleAt); i_ino, i_generation and s_dev are compared with
 * the key inode on every hit (a recycled pointer refuses); gen is the run's tego_run.gen, and a row of another gen
 * is a previous run's, which the walk treats as absent. */
struct tego_plane_row {
    __u64 i_ino;
    __u32 i_generation;
    __u32 s_dev;
    __u32 gen;
    __u16 rule_idx;
    __u8  kind;
    __u8  scope;            /* ADR 0043 D4: the bit of the name entries' scope directory this row is keyed at, 0
                             * elsewhere; only the name check's climb and D5 read it */
    __u16 exec_rule;        /* the lowest exec.allow entry covering this row, or TEGO_PLANE_RULE_NONE */
    __u16 pad2;
    __u32 pad3;
};

/* One exec row; every exec entry allows (decide.ErrPlaneExecVerdict), so a row is a match, and rule_idx the exec
 * entry's position in RuleTable.Exec. Whether exec is decided at all, and exec.anonymous, are the slot header's
 * (struct tego_plane_slot), never a row's. Two key forms share the map, and neither meets the other or key 0:
 * - A link key (plane_name.h's tego_exec_link_key over the executable's struct inode *, its directory's struct
 *   inode * and its name key; top bit set): the file may be executed under this name in this directory, so a hard
 *   link under another name or elsewhere is refused (ADR 0025 (1), SEMANTICS §4), and each link of one inode an
 *   entry names has its own row (a multi-call binary, ADR 0025's 2026-09-30 note, enforce-plane §6 E15). inode and
 *   parent are the pointers the key was built from, compared on a hit, never trusted from the key; parent is checked
 *   with its own identity where the domain cannot pin it (ADR 0025 (3)).
 * - A name key (plane_name.h's tego_name_key, internal/bpf.PlaneNameKey; top bit clear, never 0): an entry the
 *   author wrote as a bare name (decide.PlaneExecName), matched by the final component wherever the file lies.
 *   inode, parent and the identity fields are 0.
 * Either way the name's bytes are compared whole, never a hash alone. */
struct tego_plane_exec_row {
    __u64 parent;               /* the directory's struct inode *, compared with the dentry's d_parent->d_inode */
    __u64 inode;                /* the executable's struct inode *, compared with bprm->file's f_inode */
    __u64 parent_ino;
    __u64 i_ino;
    __u32 parent_generation;
    __u32 i_generation;
    __u32 s_dev;
    __u32 gen;
    __u16 rule_idx;
    __u8  name_len;             /* bytes of name used, at most TEGO_NAME_MAX - 1 (255, NAME_MAX) */
    __u8  flags;                /* always 0 (exec.anonymous is the slot header's TEGO_SLOT_EXEC_ANON) */
    __u8  pad[4];
    char  name[TEGO_NAME_MAX]; /* the final component's bytes, zero past name_len */
};

/* ADR 0043 D9's name rows, in a slot's tego_plane_name_rows inner map, keyed by agent.NameKey of a folded literal and
 * its form (FNV-1a over the length and the folded words in the host's byte order, bit 63 clear, bit 62 set for a
 * prefix key, never 0) or by 0 for the run's config row. A key is a hash of name bytes, never a kernel address, so
 * userspace computes and writes it, and a hit counts only when the row's folded bytes equal the name's (a collision
 * matches nothing). Every row carries the run's gen; a row of another gen is a previous run's and absent. */
enum tego_plane_name_flag {
    TEGO_NAME_ROW_PREFIX = 0x01,   /* name is a prefix literal: a final name matches when it starts with it */
    TEGO_NAME_ROW_CONFIG = 0x02,   /* the config row at key 0 (struct tego_plane_name_cfg) */
};

/* A name row (decide.PlaneNameRow): the literal and what its arms say, summed up by userspace so the kernel reads
 * a row with no pass over its arms (ADR 0043's NAME-BPF note: the arms' pass cost every program that asks names a
 * thousand verified instructions). deny is the entries whose deny arm is on the row: the name is a candidate of each,
 * decided by the climb against the entry's scopes (tego_plane_name_cfg.entry_mask). except is the entries a
 * built-in exception at this name cancels where the name's bytes from except_from on are the row's as spelled (the
 * scan's spelling, ADR 0043's C2 note; one literal length a row: the built-in prefix entry's). exempt is D3's scope
 * bits: where the object's own directory, met at level 1 of the climb, carries one, every entry is cancelled for this
 * name. A row compile's arms cannot sum up so (an exception arm of another length, an exemption at another depth) is
 * refused at Prepare (bpf.NewPlaneNameRow), never written loosely. */
struct tego_plane_name_row {
    __u32 gen;
    __u8  flags;            /* enum tego_plane_name_flag */
    __u8  name_len;         /* bytes of name used, 1 to TEGO_NAME_MAX - 1 */
    __u8  exempt;
    __u8  except_from;
    __u64 deny;
    __u64 except;
    char  name[TEGO_NAME_MAX]; /* the literal, ASCII-folded, zero past name_len */
    __u8  pad[8];           /* to the config row's size */
};

/* The config row, at key 0 of the same map and of the same size (the map has one value type): what the name check
 * and D5 read after a candidate or for a directory rename. A candidate whose slot has no name map, no config row or
 * one of another gen is refused path-unresolved and counted norows, never read as no match (D9). scopes is every
 * scope bit an entry's deny arm carries (D5's climb stops once it met them all: what it met then covers every
 * entry); entries every entry with a scope, by its position in RuleTable.NameDeny; bit_entries[b] the entries whose
 * deny arm carries scope bit b; entry_mask each entry's deny arm's scope bits (the name check's climb stops at the
 * lowest candidate's); dep the dependency directories' names (agent.EnvSkipDirs), zero-padded words compared byte
 * for byte, and dep_lens their lengths (bit n for a name n bytes long), so a directory whose name has none of them
 * is not read. zero is 0: a word the climb reads from map memory, which the verifier knows nothing of, and XORs into
 * every value it keeps from one level to the next (decide_names.h's tego_climb_state). */
struct tego_plane_name_cfg {
    __u32 gen;
    __u8  flags;            /* TEGO_NAME_ROW_CONFIG */
    __u8  ndeps;
    __u8  nentries;
    __u8  scopes;
    __u64 entries;
    __u64 bit_entries[TEGO_PLANE_SCOPES_MAX];
    __u8  entry_mask[TEGO_PLANE_NAME_ENTRIES];
    __u64 dep[TEGO_PLANE_NAME_DEPS][TEGO_PLANE_NAME_DEP_LEN / 8];
    __u32 dep_lens;
    __u32 pad;
    __u64 zero;
};
_Static_assert(sizeof(struct tego_plane_name_cfg) == sizeof(struct tego_plane_name_row),
               "the config row shares the name map's value size");

/* The nearest row a walk found (TEGO_WALK_HIT): what the caller decides with. depth is the steps taken, 0 for the
 * object itself. A caller hands the walk a zeroed hit: the walk starts its counters from depth (decide.bpf.c says
 * why). */
struct tego_plane_hit {
    __u32 depth;
    __u16 rule_idx;
    __u8  kind;
    __u8  pad;
    __u16 exec_rule;
    __u16 pad2;
};

/* The task's last plane decision, in tego_plane_scratch (TASK_STORAGE): the recorder's fexit on the same hook
 * reads it to put the rule on the verdict line (ADR 0024 (11)). launder_* carry the hook's trusted pointers to the
 * global walk as scalars (root may store a pointer in a map value, and a load back is a scalar; ADR 0024's T0
 * note). T0 laundered through a per-CPU slot, which a preempted program shares with the next one on its CPU; a
 * task's own storage is shared with nothing. */
struct tego_plane_decision {
    __u32 rule_idx;
    __u16 hook;             /* enum tego_plane_hook */
    __u8  verdict;          /* enum tego_verdict */
    __u8  reason;           /* enum tego_reason_code */
    __u64 obj;              /* the object decided on, which the recorder's fexit compares with its own argument
                             * so that it never takes an earlier call's decision (T9): file_open's struct file *,
                             * bprm_check's bprm->file, path_rename's old_dentry, path_link's new_dentry,
                             * path_unlink's and path_rmdir's dentry, socket_connect's and socket_sendmsg's
                             * struct socket *, mmap_file's struct file *, file_mprotect's vm_area_struct * */
    __u64 launder_dentry;
    __u64 launder_mnt;
    /* bprm_check's last decision, kept apart for sched_process_exec: between the two the ELF loader opens its
     * PT_INTERP, whose file_open decision replaces the fields above (T9). */
    __u64 exec_obj;         /* bprm->file */
    __u32 exec_rule;
    __u8  exec_verdict;     /* enum tego_verdict; TEGO_V_OBSERVED when no exec decision is held */
    __u8  exec_pad[3];
    __u64 listen_sock;
    __u32 listen_run_idx;
    __u32 listen_gen;
    struct tego_plane_bind bind;
};

/* Actual syscall outcome. A result without MARKED carries no kernel name or
 * policy attribution; the userspace attempt join must not manufacture either. */
struct tego_ev_bind_result {
    struct tego_hdr hdr;
    __u64 start_ns;
    __s64 ret;
    __u64 dev;
    __u64 dir_ino;
    __u32 rule_idx;
    __u32 flags;
    __u32 name_len;
    char name[108];
};

/* tego_ev_exec.plane: what the plane's bprm_check said of an exec that went ahead (TIER3-PLAN T9). The rule an
 * exec.allow directory matched is its fs row's position (TEGO_PLANE_RULE_FS_ROW), which the u16
 * rule_idx cannot carry with its bit 16, so the bit travels here. */
enum tego_plane_named {
    TEGO_PLANE_NAMED_NONE = 0,     /* the plane did not decide this exec (no exec: section, or no plane) */
    TEGO_PLANE_NAMED_ENTRY = 1,    /* allowed by the exec entry at hdr.rule_idx, TEGO_PLANE_RULE_NONE for none */
    TEGO_PLANE_NAMED_FS_ROW = 2,   /* allowed by the exec.allow directory of the fs row at hdr.rule_idx */
};

/* tego_plane_path_buf's value: a refused exec's name while its sample is built. */
struct tego_plane_path {
    __u64 w[TEGO_PATH_MAX / 8];
};

/* The plane's own refusal sample, on a hook no recorder fexit wraps (bprm_check, and step B's attribute and socket
 * hooks; enforce-plane R23), or on one whose fexit is not attached (TEGO_EV_PLANE_FS, T9b): the ledger's one line
 * of the refused action. hdr.verdict is TEGO_V_REFUSED and
 * hdr.reason the plane's; rule_idx is the decision's whole rule, bit 16 included (an exec.allow directory's fs row),
 * where hdr.rule_idx keeps its low 16 bits. hdr.kind says which: TEGO_EV_PLANE_EXEC's path is bprm->filename, the
 * spelling the task passed; TEGO_EV_PLANE_ATTR's and TEGO_EV_PLANE_FS's path is the object's final component
 * and dev, dir_ino its directory's, as an fsop record names a file; TEGO_EV_PLANE_SOCKET's family, type and protocol are
 * socket_create's (path empty). */
struct tego_ev_plane {
    struct tego_hdr hdr;
    __u64 start_ns;         /* the acting process's start time */
    __u32 rule_idx;
    __u16 hook;             /* enum tego_plane_hook */
    __u8  path_ok;          /* 0 when path could not be read whole */
    __u8  pad;
    __u64 dev;              /* TEGO_EV_PLANE_ATTR and _MAP: the directory's super block s_dev */
    __u64 dir_ino;          /* TEGO_EV_PLANE_ATTR and _MAP: the directory's i_ino */
    __s32 family;           /* TEGO_EV_PLANE_SOCKET */
    __s32 type;
    __s32 protocol;
    __u32 flags;            /* TEGO_EV_PLANE_FS: file_open's f_flags, else 0 */
    char  path[TEGO_PATH_MAX];
};

/* Per-slot fail-closed counters of the plane, indexed by run_idx in tego_plane_counters and zeroed at Prepare like
 * tego_lost. mismatch cannot fire by construction (ADR 0025 (4)); the recorder turns any count into a gap. Every
 * count is of a refusal: a row of another gen walked past on the allow path is not counted (decide.bpf.c
 * tego_walk_step). norows counts a slot with no header of the run's gen (struct tego_plane_slot) or no row map. */
struct tego_plane_counts {
    __u64 mismatch;
    __u64 unresolved;
    __u64 bound;
    __u64 norows;
};

/* ---- ADR 0048 (3) P2: exec pins ----
 *
 * The supervisor decides every exec of a pinned run and, immediately before it answers CONTINUE, writes the facts its
 * decision read as a pin (struct tego_exec_pin) in the slot's inner hash of tego_plane_exec_pins, keyed by the
 * exec's thread (struct tego_pin_key). bprm_check's first stage compares the pin with the exec the kernel is about
 * to load and moves it into the task's own storage (struct tego_exec_armed); each later binfmt stage compares its
 * file with the pinned interpreter chain; sched_process_exec MACs the argument area the new image maps and kills the
 * task before its first instruction when it is not the covered one. Names travel as keyed MACs (exec_pin.h), never
 * as bytes: no process of the run holds the run's key, so equal MACs say equal bytes. */
#define TEGO_PIN_CHAIN_MAX 5           /* later stages: exec_binprm refuses depth > 5 (-ELOOP) */
#define TEGO_PIN_TICK_NS 10000000ULL   /* USER_HZ 100: /proc/<pid>/stat's start time is in these */
#define TEGO_PIN_STEP 64               /* bytes the argument MAC reads per bpf_loop iteration */
#define TEGO_PIN_ROWS 4096             /* pins one slot holds at once (each exec's, until its bprm_check) */

/* tego_exec_pin.form: how the supervisor read the image (ADR 0048 (3) P1's #! header). */
enum tego_pin_form {
    TEGO_PIN_FORM_DIRECT = 1,  /* not a script: no later stage may run; the covered argv is the program's */
    TEGO_PIN_FORM_SCRIPT = 2,  /* a #! script: each later stage is the pinned chain's; the MAC covers binfmt_script's
                                 * whole vector */
    TEGO_PIN_FORM_UNKNOWN = 3, /* the header could not be read (an execute-only file) */
};

/* tego_exec_pin.flags. */
enum tego_pin_flag {
    TEGO_PIN_GUARD = 0x01,      /* guarded, or the image is dispatch-sensitive: a traced task's exec is refused and
                                  * the task is argv-guarded once the exec passes */
    TEGO_PIN_INTERP_OK = 0x02,  /* unknown form: a later stage may run unpinned (no rule is reachable through one) */
    TEGO_PIN_TRACE_GATE = 0x04, /* reserved for ADR 0044 (13)'s trace gate; no program reads it yet */
    TEGO_PIN_ARGV0_FILENAME = 0x08, /* unknown form: the decided argv[0] is the filename; without it a first
                                      * binfmt_misc stage with the P flag (argv[0] kept before the tail) is refused */
};

/* tego_exec_armed.outcome: what the task's last check said. */
enum tego_pin_outcome {
    TEGO_PIN_OUT_NONE = 0,
    TEGO_PIN_OUT_HELD = 1,     /* sched_process_exec matched the pin */
    TEGO_PIN_OUT_KILLED = 2,   /* it sent SIGKILL, or tried to (the kill sample says which) */
};

/* A pin's key in a slot's inner hash: the exec's thread as the launcher's pid namespace numbers it, and that thread's
 * start time in clock ticks (task->start_boottime / TEGO_PIN_TICK_NS, /proc/<tid>/stat's field 22). */
struct tego_pin_key {
    __u32 tid;
    __u32 pad;
    __u64 start;
};

/* A file's identity as the plane's fill checks rows against: its inode's super block s_dev and i_ino. */
struct tego_pin_ident {
    __u64 dev;
    __u64 ino;
};

/* One exec's pin (ADR 0048 (3)): the facts the supervisor's decision read, and MACs under the run's key. */
struct tego_exec_pin {
    __u32 gen;          /* the run's tego_run.gen: a pin of another gen is absent */
    __u32 seq;          /* per run, from 1: the ledger folds the kill sample and the exec record by (run, seq) */
    __u8  form;         /* enum tego_pin_form */
    __u8  flags;        /* enum tego_pin_flag */
    __u8  nchain;       /* script form: the pinned interpreter stages in chain */
    __u8  pad0;
    __u32 k;            /* argv elements the decision read; the covered prefix is their bytes */
    __u32 argc;         /* the vector's length as the supervisor read it; k == argc covers the whole vector */
    __u32 len_cov;      /* bytes mac_cov covers from arg_start, NULs included */
    __u32 len_tail;     /* unknown form: bytes mac_tail covers up to arg_end (the filename, then argv[1:]) */
    __u32 len_path;     /* bytes of bprm->filename before its NUL (at most 4095) mac_path covers */
    struct tego_pin_ident image;   /* the first stage's file */
    __u64 mac_cov;      /* TEGO_PIN_DOM_COVERED (direct, unknown) or TEGO_PIN_DOM_SCRIPT (script: the whole area) */
    __u64 mac_tail;     /* TEGO_PIN_DOM_TAIL, unknown form only */
    __u64 mac_name;     /* TEGO_PIN_DOM_NAME over the image's final name (its dentry's) */
    __u64 mac_path;     /* TEGO_PIN_DOM_PATH over bprm->filename, the spelling the kernel looked the image up by:
                         * the path passed, or /dev/fd/<n>[/<name>] for an execveat relative to a descriptor */
    struct tego_pin_ident chain[TEGO_PIN_CHAIN_MAX]; /* script form: each later stage's file, in order */
};

/* A task's pin state (tego_plane_exec_armed, TASK_STORAGE): bprm_check's first stage moves the exec's pin here, the
 * later stages and sched_process_exec read it, and the plane's ptrace hooks read guarded. run_idx and gen name the
 * run whose state it is: a value of another run or gen reads as absent. buf is the argument MAC's chunk, in the task's
 * own storage because a preempted program would share a per-CPU one. The recorder reads cur_seq into its exec record. */
struct tego_exec_armed {
    struct tego_exec_pin pin;
    __u32 run_idx;
    __u32 gen;
    __u32 cur_seq;      /* the pin seq of the exec in flight or last checked; 0 from each exec's first stage */
    __u32 argc0;        /* bprm->argc at the first stage: the vector's length the kernel copied */
    __u8  armed;        /* 1 from bprm_check's move until sched_process_exec's check */
    __u8  stage;        /* later binfmt stages bprm_check saw */
    __u8  guarded;      /* the task's last exec passed with TEGO_PIN_GUARD: the plane's ptrace hooks refuse a peer */
    __u8  outcome;      /* enum tego_pin_outcome */
    __u8  buf[TEGO_PIN_STEP];
};

/* A slot's pin key, in tego_plane_pin_keys at run_idx: the run's 128-bit SipHash key as two little-endian halves,
 * written by Prepare with the run's gen. A key of another gen is absent, and every pinned exec is refused. */
struct tego_pin_keyval {
    __u32 gen;
    __u32 pad;
    __u64 k0;
    __u64 k1;
};

/* The plane's kill sample (TEGO_EV_PLANE_EXEC_KILL): hdr.verdict TEGO_V_REFUSED and hdr.reason the plane reason
 * (argv-changed, argv-unreadable, pin-missing or pin-unverifiable). argv is the area the new image maps, as the
 * recorder's exec record copies it. */
struct tego_ev_exec_kill {
    struct tego_hdr hdr;
    __u64 exec_start_ns;    /* task->start_boottime, as the recorder's exec record carries it */
    __u32 old_tid;          /* sched_process_exec's old_pid */
    __u32 seq;              /* the task's cur_seq, as the exec record's pin_seq reads it: the armed pin's seq, else
                             * what this exec's first bprm_check stage left, 0 when the task holds no state of the run */
    __s32 kill_err;         /* bpf_send_signal's return: 0 sent; anything else is kill_failed with this error */
    __u32 argv_len;
    __u8  argv_truncated;
    __u8  form;             /* the pin's form; 0 when none */
    __u8  interpreted;      /* binfmt replaced bprm->interp */
    __u8  pad[5];
    char  argv[TEGO_ARGV_MAX];
};

/* The plane's held sample (TEGO_EV_PLANE_EXEC_HELD): hdr.verdict TEGO_V_ALLOW, hdr.reason 0. The exec record of the
 * same task and start carries the same seq as its pin_seq. */
struct tego_ev_exec_held {
    struct tego_hdr hdr;
    __u64 exec_start_ns;    /* task->start_boottime, as the recorder's exec record carries it */
    __u32 old_tid;          /* sched_process_exec's old_pid */
    __u32 seq;              /* the seq of the pin the check held the exec to, which is the task's cur_seq */
};

/* The plane's fill (bpf/decide_fill.bpf.c, ADR 0025 (2); TIER3-PLAN T4): userspace names each wanted descriptor
 * with its row template, the fill writes the row at the descriptor's inode and reports what it saw there. */
/* Descriptors one fill may name: a slot's fs rows plus its exec rows. */
#define TEGO_PLANE_FILL_MAX (TEGO_PLANE_ROWS_MAX + TEGO_PLANE_EXEC_ROWS_MAX + TEGO_PLANE_LISTEN_ROWS_MAX)
/* Launchers whose fills of a slot's whole rows the wants map holds at once; a fill that finds it full waits for
 * room. The configs are one per filling launcher. */
#define TEGO_PLANE_FILL_LAUNCHERS 8
#define TEGO_PLANE_FILL_CFGS 1024
/* A wants key: the launcher's tgid in the high half, the kind in bits 30-31 and the descriptor number, below
 * fs.nr_open's ceiling of 2^30, in the rest. */
#define TEGO_PLANE_FILL_KEY(tgid, what, fd) (((__u64)(tgid) << 32) | ((__u64)(what) << 30) | (__u64)(fd))

/* Which of the slot's maps a wanted descriptor's row goes into. */
enum tego_plane_fill_what {
    TEGO_FILL_FS = 1,   /* tego_plane_rows: struct tego_plane_row */
    TEGO_FILL_EXEC = 2, /* tego_plane_exec_rows: struct tego_plane_exec_row */
    TEGO_FILL_LISTEN = 3, /* pathname listener parent descriptor */
};

/* What the fill did with one wanted descriptor. Anything but OK fails Prepare. */
enum tego_plane_fill_status {
    TEGO_FILL_UNSEEN = 0,  /* the iterator never showed this number in the launcher's table: not open */
    TEGO_FILL_OK = 1,      /* the row is written at the descriptor's inode with this run's gen */
    TEGO_FILL_NOMAP = 2,   /* the slot has no inner map for this row's kind */
    TEGO_FILL_DUP = 3,     /* a row of this run's gen already has the key (fs: two entries, one inode; exec: one link) */
    TEGO_FILL_UPDATE = 4,  /* bpf_map_update_elem failed (err): the map is full, or out of memory */
    TEGO_FILL_NAME = 5,    /* exec: the dentry's name is not the template's, byte for byte */
    TEGO_FILL_NOINODE = 6, /* a negative dentry, or an exec file with no parent inode */
    TEGO_FILL_WHAT = 7,    /* the template's what is neither FS nor EXEC */
};

/* One launcher's fill: its parameters, its counts and its scratch, keyed by its tgid in tego_plane_fill_config, so
 * launchers of one build fill at once without a lock (enforce-plane §2.6): the program looks up the config of the task
 * reading the iterator (bpf_get_current_pid_tgid), which is the launcher filling. */
struct tego_plane_fill_cfg {
    __u32 tgid;     /* the launcher's: only its descriptors are read */
    __u32 run_idx;  /* the slot */
    __u32 gen;      /* the run's tego_run.gen, written into every row, and the templates' (tego_plane_fill_row.gen) */
    __u32 pad;
    __u64 visited;  /* out: descriptors the iterator showed the program, every task's */
    __u64 matched;  /* out: of those, the launcher's */
    __u64 launder;  /* scratch: a pointer laundered to a scalar for the cast */
    struct tego_plane_exec_row row; /* scratch: the exec row under construction (too big for the stack), this
                                      * launcher's own, so no other fill can write it meanwhile */
};

/* One wanted descriptor, keyed by the launcher's tgid, its kind and its number in tego_plane_fill_wants
 * (TEGO_PLANE_FILL_KEY): the row template in, the kernel's view out.
 * For an exec row the name is the template's (the compiler's final component), which the fill compares with the
 * dentry's byte for byte; the parent is the dentry's d_parent at the fill, and the row's key the link's
 * (tego_exec_link_key), so the descriptor must be held at the link the entry names (enforce-landlock's plane link
 * descriptors), not at another name of its inode. */
struct tego_plane_fill_row {
    __u8  what;         /* enum tego_plane_fill_what */
    __u8  kind;         /* fs: the row's kind (decide.PlaneKind) */
    __u16 rule_idx;     /* the row's rule_idx */
    __u8  name_len;     /* exec: bytes of name used */
    __u8  scope;        /* fs: the row's scope bit (ADR 0043 D4), copied into tego_plane_row.scope */
    __u16 exec_rule;    /* fs: lowest exec.allow directory entry, or TEGO_PLANE_RULE_NONE */
    __u32 status;       /* out: enum tego_plane_fill_status */
    __u16 other_rule;   /* out, DUP: the rule_idx of the row already at the inode */
    __u16 pad2;
    __s32 err;          /* out, UPDATE: bpf_map_update_elem's return */
    __u32 gen;          /* the fill's gen: a template of another (a launcher that died mid-fill whose tgid this one
                         * has now) is not applied */
    __u64 mnt_id;       /* out: real_mount(f_path.mnt)->mnt_id, as fdinfo prints it */
    __u64 ino;          /* out: the inode's i_ino, as fdinfo prints it */
    __u64 parent_ino;   /* out, exec: the parent directory's i_ino */
    char  name[TEGO_NAME_MAX]; /* exec: the final component, zero past name_len */
};

/* A clear's arguments and result, the BPF_PROG_TEST_RUN context of tego_plane_clear. */
struct tego_plane_clear_ctx {
    __u32 run_idx;
    __u32 keep_gen;     /* rows of this gen stay; 0 keeps none (no run has gen 0) */
    __u32 deleted;      /* out: fs rows deleted */
    __u32 exec_deleted; /* out: exec rows deleted */
    __s32 status;       /* out: 0, or 1 when the slot has no fs rows map */
    __u32 listen_deleted;
};

#endif /* TEGO_EVENTS_H */
