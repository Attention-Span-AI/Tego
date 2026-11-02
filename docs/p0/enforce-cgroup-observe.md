# Tier 2 backend and eBPF record — `enforce/cgroup`, `observe`, `bpf` (P0 detailed spec)

Covers `internal/runtime/enforce/cgroup` (tier-2 `enforce.Backend`: cgroup network programs, fanotify listener,
descendant materialization), `internal/runtime/observe` (the eBPF record: ring buffer reader, process cache, read
aggregation, watch lists), `internal/bpf` (bpf2go bindings), and the C it binds: `bpf/cgroup_net.bpf.c`,
`bpf/cgroup_track.bpf.c`, `bpf/trace_proc.bpf.c`. Not owned here: `internal/runtime/cgroup` (cgroup v2 fs ops — a
dependency), `enforce/landlock`/`enforce/bpflsm`, `bpf/lsm_*.bpf.c` (tier 3), `capture/uprobe`, `ask` (P1).

## 1. Purpose and boundaries

**Owns.** For tier 2 (root or `cap_bpf,cap_net_admin,cap_sys_admin`, no boot change): the eight
`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs (`connect4/6`, `sendmsg4/6`, `bind4/6`, `connect_unix`, `sendmsg_unix`)
deciding host:port/CIDR and unix socket names per cgroup in-kernel, and `cgroup/sock_create`
(`BPF_PROG_TYPE_CGROUP_SOCK`) refusing an inet socket outside ADR 0018's allowlist on any path (R4), and
`cgroup/setsockopt` (`BPF_PROG_TYPE_CGROUP_SOCKOPT`) refusing an upper-layer protocol (`TCP_ULP`) on any path (R4,
ADR 0018 (7)); `cgroup_mkdir`/`cgroup_rmdir` materializing the run's own cgroup subtree; the
fanotify listener (`FAN_OPEN_PERM`/`FAN_OPEN_EXEC_PERM` deny with reason for write, deny-read, exec opens); the
eBPF record (`sched_process_exec/exit` tracepoints, ten record-only fexit programs on the `security_` fs functions and
one fentry program on `security_socket_connect`, each run's own ring buffer,
process cache, exec ids, read aggregation, watch lists, lost-event accounting); pinning, links, build lock,
attach/detach, upgrade coexistence.

**Must not.** Decide `ask` (out of P0, `docs/P0-DESIGN.md` §0 — every kernel decision here is binary). Reimplement
tier 1/3; compose tier 1's Landlock ruleset and seccomp filter through shared helpers, never by importing
`enforce/landlock` (backends never import each other, `docs/REPO-LAYOUT.md`). Enforce delete/rename/mkdir/mknod
— Landlock's, inherited; this package only *records* those, with the kernel's own verdict (§5 R9); chmod no tier-2 mechanism can refuse
(agent-contract E35). Create a
`BPF_MAP_TYPE_INODE_STORAGE` map — tier-3-only (ADR 0010, `docs/ARCHITECTURE.md` §10). Touch the ledger directly —
everything crosses `internal/runtime`'s buffered `events chan record.Event`. Import `internal/check`/`internal/serve`.

**Imports allowed.** `cilium/ebpf` (+`link`,`ringbuf`,`rlimit`), `golang.org/x/sys/unix`, `internal/bpf`,
`internal/runtime/cgroup` (cgroup id/fd, a dependency not owned here), `internal/platform/{proc,sys}`,
`pkg/spec/{agent,record,backend,identity}`. Not `golang.org/x/net/bpf` (tier 1's seccomp filter only). TCB member
(`docs/ARCHITECTURE.md` §16): every reader of kernel- or process-supplied bytes needs a fuzz target (§9).

## 2. Models

### 2.1 `internal/bpf` bindings (mechanical)
Two `go:generate` lines join the existing five in `internal/bpf/gen.go`:
```go
//go:generate ... bpf2go ... cgroupnet   ../../bpf/cgroup_net.bpf.c   -- -I../../bpf/include
//go:generate ... bpf2go ... cgrouptrack ../../bpf/cgroup_track.bpf.c -- -I../../bpf/include
```
`trace` (already generated from `bpf/trace_proc.bpf.c`) is this component's record binding. Each produces
`<name>Objects{<name>Maps; <name>Programs}` per endianness. The bpf2go output, objects and Go bindings both, is
committed: a build with `-tags tegobpf` needs no clang, `make gen` regenerates it with the toolchain `bpf/README.md`
pins, and CI's `bpf-gen` job regenerates it and fails on any difference. The three
tier-2 objects are compiled once per byte order (`bpfel`, `bpfeb`); capture's `uprobessl` is compiled per
architecture (`amd64`, `arm64`, the two a release ships), because its `PT_REGS_*` reads need `__TARGET_ARCH_<arch>`
and libbpf refuses them for a generic BPF target (`internal/bpf/gen.go`).

### 2.2 `bpf/include/common.h` — shared structs (mirrored in Go via bpf2go `-type`)
```c
struct run_key { __u64 cgroup_id; };
struct run_val { __u32 run_idx; __u8 descendants; __u8 tier; __u16 _pad; };   // tier: 2 or 3, host mixes runs

struct net_key { __u32 run_idx; __u8 family; __u8 proto; __u16 port; __u8 addr[16]; };  // port host byte order
struct net_val { __u8 verdict; __u8 reason; __u16 rule_idx; };               // verdict 0 allow / 1 refused

// LPM trie: prefixlen counts bits over the WHOLE struct after it, so the run/family/proto/port header is always
// "matched" (fixed width) and only addr[] varies in prefix length. Packed, the header is 64 bits.
struct cidr_key { __u32 prefixlen; __u32 run_idx; __u8 family; __u8 proto; __u16 port; __u8 addr[16]; };
struct cidr_val { __u8 verdict; __u8 reason; __u16 rule_idx; };              // one struct, tego_net_verdict

struct reason_key { __u64 cgroup_id; };            // last connect/sendmsg breadcrumb, per run: the run's cgroup id
struct reason_val {
    __u8 op; __u8 verdict; __u8 reason; __u8 family; __u8 proto; __u8 _pad0; __u16 port;
    __u8 addr[16]; __u64 mono_ns;                    // bpf_ktime_get_ns(); discards a stale breadcrumb
};
```
```c
// tego_net_owners (BPF_MAP_TYPE_CGROUP_STORAGE, key: the attach point's cgroup id): which run one cgroup
// attachment of the network programs enforces. The kernel creates it zeroed when the first deciding program is
// attached; Attach writes it; cgroup_id 0 means "not configured yet" and the programs refuse (§5 R1, R2).
// relay_cgroup_id is the launcher's own cgroup, the one caller connect_unix admits the supervisor's
// /proc/self/fd/<n> relay name from (§5 R7); 0 admits it from no one. flags (TEGO_OWNER_NET_ICMP 0x1: the net
// section names an ICMP destination) and gen (the run's tego_run.gen) are cgroup/sock_create's (§5 R4, R5), which
// takes neither from the run set. 32 bytes.
struct tego_net_owner { __u64 cgroup_id; __u32 run_idx; __u32 flags; __u64 relay_cgroup_id; __u32 gen; __u32 pad; };

// tego_unix_names (BPF_MAP_TYPE_LPM_TRIE, 6.7+ programs only): a run's unix: entries and the filesystem entries
// that admit (write) or refuse (any other kind) a pathname socket beneath them (§5 R7). prefixlen counts bits
// after it; the run_idx/kind/len header is always matched whole. Pathname rows: an entry's bytes + NUL (the entry
// itself) and + "/" (its subtree); abstract rows: NUL + the name, with the sun_path length in len.
struct tego_unix_key { __u32 prefixlen; __u32 run_idx; __u8 kind; __u8 len; __u8 name[108]; } __attribute__((packed));
```
Go mirrors: `CgroupnetRunKey/Val`, `NetKey/Val`, `CidrKey/Val`, `ReasonKey/Val`, `NetOwner` — bpf2go `-type` asserts
layout parity. (The code's names are `struct tego_run`, `tego_net_key`, `tego_net_lpm_key`, `tego_net_verdict`,
`tego_reason` and `tego_net_owner` in `bpf/include/events.h`, mirrored in `internal/bpf/types.go`.)
The code's `enum tego_verdict` is `TEGO_V_ALLOW = 0`, `TEGO_V_REFUSED = 1` (and `TEGO_V_OBSERVED = 2`), the
value carries the `rule_idx` the event names, and the CIDR key's header is `run_idx`, `family`, `proto`, `port`,
packed, as above. `TestFieldParity` checks these offsets against the objects' own BTF, the breadcrumb's, the CIDR
key's and the run-set row's among them.

### 2.3 `bpf/include/events.h` — ring buffer events (single source of truth)
```c
enum tego_kind { TEGO_EV_EXEC=1, EXIT=2, OPEN=3, UNLINK=4, RENAME=5, MKDIR=6, CONNECT=7, SENDMSG=8, BIND=9,
                  CGROUP_MKDIR=10, CGROUP_RMDIR=11, SSL_CHUNK=12 };
struct tego_hdr { __u16 version; __u16 kind; __u32 size; __u64 ts_mono_ns; __u64 cgroup_id; __u32 pid; __u32 tid;
                   __u32 ppid; __u32 run_idx; __u8 verdict; __u8 reason; __u16 rule_idx; __u32 pad; };   // 48 bytes
struct tego_ev_exec {                             // 872 bytes
    struct tego_hdr hdr; __u64 exec_start_ns; __u64 parent_start_ns;  // start_boottime of the process and its parent
    __u64 cwd_dev; __u64 cwd_ino;                  // the working directory at exec: a relative path's base (H8)
    char comm[16]; __u32 argv_len; __u8 argv_truncated; __u8 path_truncated; __u8 pad[2];
    char path[256];                                // bprm->filename, as passed
    char argv[512];                                // NUL-separated, argv_truncated past 512 bytes (E25)
};
struct tego_ev_exit { struct tego_hdr hdr; __u64 exec_start_ns; __s32 code; __u32 signal; };  // the thread group's
struct tego_ev_fs {                               // open, 336 bytes: bpf_d_path; path_ok=0 truncated (E4)
    struct tego_hdr hdr; __u64 start_ns; __u64 dev; __u32 flags; __u32 ino;
    __u8 path_ok; __u8 ret_ok; __u8 created; __u8 pad; __s32 ret;   // ret: the LSM chain's return (R9)
    char path[256];                                // an open has one path (events version 2)
};
struct tego_ev_fsop {                             // 0 unlink 1 rename 2 mkdir 3 mknod 4 rmdir 5 link 6 symlink
                                                   // 7 truncate, 1128 bytes — no bpf_d_path (R9/R10)
    struct tego_hdr hdr; __u64 start_ns;
    __u64 dev; __u64 dir_ino; __u64 dev2; __u64 dir_ino2;  // each side's parent (dev, ino); dev2 rename/link only
    __u8 op; __u8 name_ok; __u8 name2_ok; __u8 ret_ok; __s32 ret;  // ret: the LSM chain's return (R9)
    char name[256]; char name2[256];               // final components, from BTF args; symlink: name2 its target
    __u8 dir_state; __u8 dir2_state; __u16 dir_off; __u16 dir2_off; __u16 pad;
    char dir[256]; char dir2[256];                 // each parent's path, walked in BPF for a plane run only
};                                                 // (enforce-plane §2.15): dir[dir_off:], else empty
struct tego_ev_net { struct tego_hdr hdr; __u64 start_ns; __u8 family; __u8 proto; __u16 port; __u8 addr[16];
                      __u32 pad; };                // AF_INET/AF_INET6 connects only, 80 bytes
struct tego_ev_sock { struct tego_hdr hdr; __s32 family; __s32 type; __s32 protocol; __u32 pad; };
                                                   // TEGO_EV_SOCK_CREATE = 28: cgroup/sock_create's own refusal
                                                   // (§5 R4, R5), 64 bytes; type is sk_type, protocol whole
```
`start_ns` is the acting process's thread group leader's `start_boottime` (§6 E14). Each record is its own fixed
struct of `bpf/include/events.h`, reserved at its own size, and the decoder refuses a header whose `size` is not its
kind's (§2.4 "Decoding"); there is no common padded slot. `ev_open`
resolves a real path via `bpf_d_path` (`security_file_open` is in the kernel's fixed `btf_allowlist_d_path`
BTF_SET, R10); `ev_fsop` never calls `bpf_d_path` — the `security_path_*` functions but `truncate` are not in that set
on any kernel (R9/R10), and the truncate programs share the layout — so it carries only what `BPF_CORE_READ` takes
directly off the BTF args: the parent directory's device/inode (`dentry->d_sb->s_dev`, `dentry->d_inode->i_ino`; a
link's source and a truncated file by their `d_parent`) and the final component's raw bytes (`d_name`). Both
records carry `ret`, the signed return of the kernel's LSM chain their fexit program read, with `ret_ok` set; a
record with `ret_ok` 0 carries none (R9, ADR 0016). The five kinds 14–18 (`mknod`, `rmdir`, `link`, `symlink`,
`truncate`) are `ev_fsop`s; `created` marks an open whose file it created (`FMODE_CREATED`).

### 2.4 `internal/runtime/observe`
```go
type Recorder struct { /* rd *ringbuf.Reader; procs *procCache; rules *agent.RuleTable; dirs dirIndex; agg *aggTable; watch map[string]bool; out chan<- record.Event; lost lostCounter */ }
// dirIndex: ruleIndex.dirs map[devIno]int (a position in the sorted []fsEntry), built once in New from rt.FS (O_PATH-open + fstat each declared dir; plain Go
// map, never BPF_MAP_TYPE_INODE_STORAGE, ADR 0010). Infers R9's verdict for a raw ev_fsop; never kernel-consulted.
func New(objs *bpf.TraceObjects, rt *agent.RuleTable, out chan<- record.Event) *Recorder
func (r *Recorder) Start(ctx context.Context, run identity.Run) error   // one goroutine, batch drain
func (r *Recorder) Stop() error // flush aggregates, close reader

type procEntry struct { ExecID string; PPID int; StartBootNS uint64; FromProc bool }  // fixed size, below
type aggKey struct { ExecID, Rule string }  // add's argument and the flush output; the table is map[execID]map[rule]aggEntry
type aggEntry struct { Count, LastNS uint64 }

// record.Event.Payload shapes this package marshals (spec/record/v1 §3.2):
type ExecPayload struct { Path string `json:"path"`; Argv []string `json:"argv"`; Script string `json:"script,omitempty"`; Stage string `json:"stage,omitempty"`; ExecID string `json:"exec_id"`; ParentExecID string `json:"parent_exec_id,omitempty"` }
type FSPayload struct { Op string `json:"op"`; Path string `json:"path"`; Path2 string `json:"path2,omitempty"`; Flags int `json:"flags,omitempty"`; Count uint64 `json:"count,omitempty"`; Created bool `json:"created,omitempty"`; Errno int `json:"errno,omitempty"`; By string `json:"by,omitempty"`; VerdictFrom string `json:"verdict_from,omitempty"` }
type NetPayload struct { Proto string `json:"proto"`; Dst string `json:"dst"`; Host string `json:"host,omitempty"`; Boundary bool `json:"boundary,omitempty"`; Propagated []string `json:"propagated,omitempty"` }
```
Validation: `ExecID = <run id>/<pid>/<start_boot_ns>` (`spec/identity/RUN-IDENTITY.md`), with the kernel's exact
`start_boot_ns` rounded down to a USER_HZ tick by `proc.ExecID`, so it equals the id the seccomp supervisor builds
from `/proc`, and adopting the exact time over a `/proc` guess never changes an entry's id; `FSPayload.Op ∈
{open,unlink,rename,mkdir,link,symlink,truncate}` (an rmdir is the `unlink` the supervisor calls it, and a mknod the
`open` with `O_CREAT` its creat line is, R9); `verdict_from` is `chain` or `model` on every line this package
writes, and `by: other` with `errno` marks a refusal no Tego mechanism explains (R9); `NetPayload.Dst` is always
`ip:port`.
`FSPayload.Path`/`Path2` for `unlink`/`rename`/`mkdir` are reconstructed in userspace from `ev_fsop`'s raw
`(dev,dir_ino,name)` — a `dirIndex` hit yields `<matched rule's path>/<name>`; a miss yields bare `dev:ino/name` and
`attribution.confidence: unattributed` (never a `bpf_d_path` string, R9/R10). A rename's `Path2` is resolved the
same way from its own `(dev2,dir_ino2,name2)`. A rename's verdict is both ends': Landlock decides a rename on the
destination directory too, so a rename out of a write entry is refused there. A destination `dirIndex` cannot
name is `observed` (the outcome is unknown); one `inferFS(rename, write)` refuses is `refused
rename-outside-contract` under the destination's entry; otherwise the source's verdict stands
(`TestRenameIsDecidedAtBothEnds`, and as root `TestE2ERecorderLinesSayWhatTheAgentSaw`). Every entry is matched
under both its declared `Path` and its canonical `Resolved` (`agent.FSRule.Spellings`, which `enforce/cgroup` marks and decides by),
and `dirIndex` is keyed by, and rebuilds paths under, the canonical one: `bpf_d_path` reports the canonical path,
so under a project reached through a symlink (the cwd a shell reports, a symlinked `$HOME`) matching `Path` alone
would miss every open, recording a read the kernel refused under a `deny_read` entry as `allow`. A rename's and an
unlink's `path`/`path2` are spelled canonically, as an open's is (`TestSymlinkedProjectIsMatchedByItsCanonicalPath`).
A process cache entry is what attribution needs and has a fixed size: it keeps no path, comm or argv (an exec
line's come from its sample), and an entry rebuilt from `/proc` reads `/proc/<pid>/stat` alone, never the cmdline
(up to 1 MiB each, 8 GiB at the cache's 8192 entries) (`TestProcCacheKeepsNoCommandLine`). `dev` is the super
block's `s_dev`, the kernel's internal `dev_t` (`major<<20 | minor`), and the decoder converts it to the encoding
`stat(2)` reports before `dirIndex` is consulted, because `dirIndex` is built with `fstat`; the two agree raw only
for a small anonymous device such as a tmpfs. `dir_ino` is the whole inode number and keys `dirIndex` whole.
Converted, the device is still the super block's, and `fstat`'s is not on btrfs or on an overlayfs of one
filesystem; such an entry is left out of `dirIndex` with `gap why=dir-unindexed` (§5 R9).

Decoding (as built): every fixed-width record is copied through `internal/bpf`'s `ExecEvent`, `ExitEvent`,
`FSEvent`, `FSOpEvent`, `NetEvent` and `CgroupEvent`, whose layouts are asserted against `bpf/include/events.h` and
against bpf2go's mirror of the compiled objects; `observe` keeps no offsets of its own. It used to, and they had
drifted: an open's path was read 8 bytes early, an exit's code was half of its start time, and an unlink, rename or
mkdir was decoded as an open. A record whose header `size` is not its kind's struct width is malformed
(`gap why=malformed-record`), never read at guessed offsets.

Pinned maps (as built): the recorder opens `<bpffs>/tego/<bpf_hash>/maps/tego_events`, `.../tego_lost` and
`.../tego_run_set`, the maps' ELF names, because every map is `LIBBPF_PIN_BY_NAME` and the loader pins it at
`<PinPath>/<name>`. It used to open `maps/events` and `maps/lost`, which no loader creates, so every tier-2 run
recorded `kernel-record-unavailable`. `tego_events` is a ring outer (ADR 0026 (1)): a `BPF_MAP_TYPE_HASH_OF_MAPS` of
4096 slots keyed by `run_idx`, each holding one run's own ring buffer. The lost counter is required: a build with the
outer pinned and no counter is refused rather than drained with every kernel-side drop unaccounted for (§8 I7). So is
the run set, opened read-only, which names the run's slot and so its ring. The counter is a `u64` per `run_idx`,
zeroed at `Prepare`, so a run's `ringbuf-full` is its own drops from its own start and never another run's
(`TestIntegrationLostCounterCountsItsOwnSlot`).

Run scope (as built): each run has its own record ring at its slot, which `Prepare` creates at `record.ringbuf` (a
`record: off` run's is a fixed 256 KiB) and inserts into `tego_events` before the run's run-set row (ADR 0026 (1),
(2)). Every record-only program looks the run up in the run set and then its ring by the row's `run_idx`
(`tego_ring_of`), and emits nothing when the slot holds none (`TestRecordsGoToTheRunsOwnRing`). At `Start` the
recorder reads its run's slot from the run's own cgroup row, opens the ring at that slot (`bpf.RingOf`) and its lost
counter at the same slot, and reads nothing else, so the one-reader rule holds by construction: two userspace readers
of one ring duplicate and tear samples (cilium/ebpf stores the consumer position with no compare-and-swap, measured
as root in the KVM guest), and no ring has two readers. Another run of the build no longer stops a recorder
(`TestRecorderReadsBesideAnotherRunOfItsBuild`), and a dead launcher's leftover rows cannot reach a new run's ring:
the slot table hands out no slot a run-set row still carries (R12), and a reused slot gets a fresh ring. A run with no
row, a run that names no cgroup, or a slot with no ring reads nothing, feeds no hook and records `gap what=record
why=kernel-record-unavailable` (`TestIntegrationARunWithNoRingReadsNothing`); the run continues. A sample's
`run_idx` is still checked against the run's slot, a guard that no sample of another run is recorded or fed to a
hook. 2, 8 and 32 concurrent runs of one build each recorded every open and exec of their own processes and none of
another's, with no loss, at the default 2 MiB ring (`TestIntegrationConcurrentRunsOfOneBuild`, 6.17 guest).

Process hook (as built): the recorder feeds a `source.ProcessHook` every exec, open and exit of its own run it drains
(Run scope, above), after the sample's own event is emitted and under `record: off` too (E23); an open whose path the kernel truncated is not
passed on, and an exec is passed on with the path the process exec'd (the sample's `bprm->filename`), or with none
when the kernel truncated it: that path is what names a process that has exited, and taken `/proc/<pid>/exe` with
it, before its exec reached the hook. The run adds the uprobe capture source as a hook before the recorder starts,
which is how capture learns which processes to attach to and when to let go (docs/p0/capture-derive.md §4, R4, R8),
and it adds it behind a filter that holds back the launcher's own child stage: the child's first exec, of the
launcher's binary (`/proc/self/exe`) as `tego __child` in the run's cgroup (runtime-launch.md §4.1 steps 5-7), is
recorded like any exec but is not an agent process, and handed to capture it left a `static-tls-no-symbols` gap
naming tego in every tier-2 capture run. A hook added after `Start` is refused.

*A relative exec name is resolved before anything reads it.* `bprm->filename` is the name the process passed to
`execve`, and a relative one (`./git`, `venv/bin/pip`) matched as it stood would be read by `decide.Evaluate` as
the bare name `git`, which an entry declared as `/usr/bin/git` answers. The exec record carries the working
directory's `(s_dev, i_ino)` at the exec (`cwd_dev`, `cwd_ino`), and the recorder joins the name to
`/proc/<pid>/cwd` only while that path names the same directory; the record, the rule and the hook all get the
joined path. A process that has since changed directory or exited leaves the name as passed, recorded `unmatched`
and `observed` with `gap what=record why=exec-unresolved`, and the rule index matches no relative path at all
(`TestRecorderResolvesARelativeExec`, `TestMatchExec`, and as root `TestIntegrationRelativeExecIsResolved`). Where
`stat(2)`'s device is not the super block's (btrfs, R9), the directory cannot be confirmed and the name stays
unresolved. So does a name, relative or absolute, with a `..` component: the kernel follows a symlink before the
`..` leaves it and a lexical join does not, so `link/../tool` with `link -> /usr/local/bin` ran `/usr/local/tool`
and was named `<cwd>/tool` (`TestRecorderAnExecNameWithDotDotIsUnresolved`). The kernel's own refusal keeps its
verdict.

Start order (as built, 2026-09-23): the run starts the recorder before any capture source, and when the recorder's
`Start` leaves it reading nothing (its own `kernel-record-unavailable`) the run withdraws the build from every source
that follows it (`FollowKernel("")`), which then starts with no build and records `gap what=capture
why=mechanism-unavailable binary=uprobe`. The recorder and the uprobe source each walk the run set at their own
`Start`, and another run's row can appear between the two walks, or one walk alone can fail: a source that decided to
capture beside a recorder that decided to read nothing attached nothing, since nothing fed it an exec or an open,
while `run_start` named `uprobe` as the run's capture. `run_start` also counts no source that follows the kernel
record as capture while no recorder reads for the run, whatever order the two started in (runtime.startedCapture).
The other split, a recorder that reads beside a source that found another run's row, is already stated by the
source's own gap. The recorder's drain can call a hook before the source has started; the source ignores it, and what
it can report then is only the launcher's child stage, because the agent is released after every source has started.

### 2.5 `internal/runtime/enforce/cgroup`
```go
type Backend struct { /* netObjs *bpf.CgroupnetObjects; trackObjs *bpf.CgrouptrackObjects; links []link.Link; fan *fanotifyListener; slot uint32; hash string */ }
func New(m *config.Machine) enforce.Backend
func (b *Backend) Tier() backend.Tier
func (b *Backend) Capabilities() backend.Set
func (b *Backend) Prepare(ctx context.Context, rt *agent.RuleTable, run identity.Run) (api.Handle, error)

type handle struct{ /* unexported */ }
func (h *handle) LandlockRuleset() (fd int, ok bool) // shared helper, same rights as tier 1
func (h *handle) SeccompFilter() ([]bpf.Instruction, bool) // identical cBPF program to tier 1 (inherited, R1 §5)
func (h *handle) Attach(cgroupID uint64) error
func (h *handle) RefreshNet(rt *agent.RuleTable) error      // move host rows to a TTL refresh's addresses (§6 E7)
func (h *handle) Detach() error
func (h *handle) Close() error

func (s *slotTable) acquireGen(carriedOf func() (map[uint32]bool, error)) (idx, gen uint32, err error) // host-wide, [0,4095), gen the slot's epoch (Run.Gen); ErrSlotsExhausted (§6 E12)

type fanotifyListener struct{ /* fd int; marks map[markKey]struct{}; deadline time.Duration */ }
func newFanotifyListener(deadline time.Duration) (*fanotifyListener, error)
func (f *fanotifyListener) mark(mountRoot string) error       // FAN_MARK_ADD|FAN_MARK_MOUNT, once per ruled mount
func (f *fanotifyListener) loop(ctx context.Context, out chan<- record.Event) error
```

**Changes.**
- 2026-10-19 (ADR 0029 (4)): the slot table's one acquire is `slotTable.acquireGen`, which also returns the
  slot's epoch; `acquire`, which dropped it and which only tests called, moved into the package's test files. §4
  `Prepare` step (1) names it.
- 2026-09-29: `allocSlot` was a design name; the code's is `slotTable.acquire` (`internal/runtime/enforce/cgroup/slots.go`).
- 2026-09-22, §2.4 Run scope: one reader per ring; every run draining the one ring and recording
  `kernel-record-shared` withdrawn.
- 2026-09-24, §2.4 Run scope, Pinned maps (ADR 0026 (1), (4), (5)): a ring and a lost counter per run at its slot;
  the foreign-row refusal and `NotBefore` withdrawn.
- 2026-09-24, §2.2: verdict values and `cidr_key` layout corrected to the code's.
- 2026-09-24, §2.3: the padded 512-byte slot sketch and `argv[384]` replaced by the code's
  structs.
- 2026-09-24, §2.4: process cache entries are fixed-size; a rebuild reads `/proc/<pid>/stat`.
- 2026-09-24, §2.4: an entry whose `fstat` device is not the super block's is left out of
  `dirIndex` with `gap why=dir-unindexed`.
- 2026-09-24, §2.4: the lost counter is diffed from the run's start.
- 2026-09-24, §2.4: a relative exec name is resolved against the exec's working directory.
- 2026-09-24, §2.4: a rename's verdict is decided at both ends.
- 2026-09-24, §2.4: entries are matched under their canonical path too.
- 2026-09-24, §2.4: both spellings, and path containment, come from `agent` (`FSRule.Spellings`,
  `Covers`), which tier 2 and the runtime share.
- 2026-09-28, §2.4 (ADR 0028 S1): the recorder's inference, fs chooser, exact-before-LPM net matcher and exec
  verdict are the decision core's (`internal/policy/decide`).
- 2026-09-28, §1 Must not (agent-contract E35): chmod dropped from the Landlock-inherited list; nothing at tier 2
  refuses it.
- 2026-09-29, §2.4 (recorder): an exec name with a `..` component is left unresolved.
- 2026-09-29, §2.4 (recorder): `aggEntry.FirstNS` dropped (nothing read it); an exec's `parent_exec_id`
  is computed from the parent's start time when the parent has no cache entry.
- 2026-09-29, §2.3: `tego_ev_fs` drops the always-empty `path2` (592 to 336 bytes); events version 2.
- 2026-10-05, §2.2, §2.3 (ADR 0018 PR 2): `tego_net_owner` gains `flags` (in `pad`'s place) and `gen` (24 to 32
  bytes); `tego_ev_sock`, kind 28, is cgroup/sock_create's record. The events version stays 3: no existing record
  changed, and a new build hash keeps coexisting builds' owner maps apart (ADR 0022).

## 3. Repositories and storage

| Artifact | Path | Format | Concurrency | Durability |
|---|---|---|---|---|
| Pins | `/sys/fs/bpf/tego/<bpf_hash>/{progs,maps,links}/<name>` | bpffs, no regular files | many launchers of one `bpf_hash` share one pin | survives exit; lingers `bpf.linger` after the last launcher's `Detach`, then removed by the build's timer or `tego gc` (§5 R14, ADR 0022) |
| Build lock | `/run/tego/bpf-<bpf_hash>.lock` (only there, verified: root 0700 only since ADR 0042 (3)(b), which withdrew the root:tego 1770 form, and every file in it owned by the launcher's effective uid; no `$XDG_RUNTIME_DIR` or `/tmp` fallback, which would give two users' launchers of one build two locks and two slot tables; anything else refuses `Prepare` with `ErrHostState`, and so does a state directory other than `/run/tego` named beside pins under the host's `/sys/fs/bpf` (`Options.StateDir`, the sweeps', purge's, reaper's, timer's and `tego stop`'s re-arm pass's too: a lock no other tego process reads, under which a sweep found a held build idle), before anything is locked or read; every file there is opened relative to the verified descriptor, never through a link; ADR 0034) | empty file, `flock` | every launcher `LOCK_SH`; last one `LOCK_EX\|LOCK_NB` | cannot go stale |
| `run_set` | pinned, host-wide | `BPF_MAP_TYPE_HASH`, key 8B/val 16B (`tego_run`: slot, descendants, tier, record mode, plane, generation, flags: `TEGO_RUN_LISTENER_RESULTS` 0x01, `TEGO_RUN_ACTIVITY` 0x02, which `runRow` sets exactly when the run's limits bound `stall_after`), 4096 entries | read by every hook; written by `cgroup_track` + adopt-time scan | rows deleted at `Detach`, tracked per-run in a Go set |
| `net_key`/`cidr_key` | pinned | hash 4096 / LPM `BPF_F_NO_PREALLOC` 4096 | written at `Prepare` from `rt.Net` and the run's resolver endpoints (§5 R5), none for a contract with no `net:` section (R1); host rows moved by `RefreshNet` when the runtime hands it a TTL refresh (§6 E7) | rows removed at `Detach` |
| `reason` map | pinned | hash, one row per run, keyed by the run's own cgroup id (§5 R5) | written by `connect4/6`/`sendmsg4/6`; read by the supervisor through `Handle.KernelNet` after a relayed connect fails `EPERM` (R5) | overwritten per decision |
| `tego_net_owners` | pinned, `cgroup_net` only | `BPF_MAP_TYPE_CGROUP_STORAGE`, key 8B (the attach point's cgroup id), value `tego_net_owner` 32B (run, relay cgroup, socket flags, gen), `max_entries` 0 (the kernel refuses any other) | the kernel creates one zeroed value per cgroup the deciding programs are attached to; `Attach` writes it once; the programs read it, `cgroup/sock_create` included | freed by the kernel with the cgroup or the map; unreachable once the run's links are closed (§8 I5) |
| Ring outers `tego_events`, `tego_capture_events` | pinned, one pair per build, declared in every object | `BPF_MAP_TYPE_HASH_OF_MAPS`, key `run_idx`, 4096 slots, inner prototype a 64 KiB `BPF_MAP_TYPE_RINGBUF` (`struct tego_ring`; ARRAY_OF_MAPS not measured) | written by `Prepare` (`placeRings`) and the reclaims; read by every program after its run-set hit (`tego_ring_of`) | a slot's rings stay for its next run (R12); removed when a run needs another size or no capture ring, above the build's pool after the run (`tego __ring-trim`), and at a slot no run holds when a placement lacks room or by `tego gc --builds` (R16) |
| Run ring | one per run in `tego_events` at its slot; a second in `tego_capture_events` only when the run's capture is `uprobe` and it records (ADR 0026 (3)) | `BPF_MAP_TYPE_RINGBUF` of `record.ringbuf` bytes (default 2 MiB, `/etc/tego/config.yaml` only); a `record: off` run's record ring a fixed 256 KiB | multi-CPU writers; one reader by construction, the run's own recorder or capture source, which opens it by the run's slot (§2 "Run scope") | drops counted → `gap`, never blocking; drained by the slot's next run's `Prepare` before its row exists, and every record carries its run's generation, so no run reads another's |
| Tracking failures `tego_tracking_failed` | pinned, shared by every object | `BPF_MAP_TYPE_ARRAY`, 4096 `u64`, indexed by `run_idx` | incremented before reporting a failed descendant membership insertion; read independently of event recording (E11) | zeroed at `Prepare` and reclaimed with slot counters |
| Lost counters `tego_lost`, `tego_capture_lost`; miss counter `tego_capture_miss` | pinned, declared in every object | `BPF_MAP_TYPE_ARRAY`, 4096 `u64`, indexed by `run_idx` | bumped atomically on a reserve failure, and `tego_lost` also when a run's program finds its row and no record ring (the miss counter: on a probe hit of a run with no capture ring); the two lost counters read per drain at the run's own slot, the miss counter only by tests and diagnostics (ADR 0026, capture-derive R9) | zeroed at `Prepare` for the run's slot (ADR 0026 (4)) |
| Activity stamps `tego_activity` | pinned, declared in every object | `BPF_MAP_TYPE_ARRAY`, 4096 `tego_activity_slot` of 16 bytes (a `bpf_ktime_get_ns` reading, CLOCK_MONOTONIC, and the jiffy it was taken in), indexed by `run_idx`, 64 KiB per build | written only for a run whose row carries `TEGO_RUN_ACTIVITY` (`tego_activity_stamp`): by trace_proc on each allowed action `record: off` keeps no sample of (an open, a file operation, a regular-file create, a connect), and by the TLS probes on each call that moved bytes in every record mode (capture-derive R4); an action in the jiffy the slot already names writes nothing, and the first of a new jiffy reads the clock and stores, so the clock is read once a jiffy; read once a tick by the run's recorder (`LastActivity`) for the budget watcher (limits R4) | zeroed at `Prepare` with the slot counters; a reading below the run's start is ignored by the watcher |
| Ring budget | `bpf.ring_budget` (`/etc/tego/config.yaml` only, default 256 MiB) and the lock `/run/tego/rings.lock` | compared with the `memlock:` of every live inner ring of every build, read from each ring's fdinfo | `flock` `LOCK_EX` while a `Prepare` places a ring or anything removes one it does not hold; `LOCK_SH` while a `Prepare` reuses its slot's rings | nothing stored: the rings in the outers are the account |
| Process cache | in-memory | `map[pid]procEntry`, fixed-size entries (§2.4) | single-owner goroutine | rebuilt from `/proc/<pid>/stat`+exec events on start |
| `dirIndex` | in-memory | `ruleIndex.dirs map[devIno]int`, a position in the sorted `[]fsEntry` (§2.4) | built once, read-only, single-owner goroutine | rebuilt from `rt.FS` each `Recorder.New`; never a kernel map (R9) |
| Aggregation table | in-memory | `aggTable.m map[execID]map[rule]aggEntry`, nested by exec id so `sched_process_exit` flushes one process without scanning every bucket | the drain goroutine; after it joins, ownership passes to the `Stop` caller for the final drain and flush | flushed at exit and every 5s; a crash loses ≤5s of counts |
| Fanotify fd/marks | in-memory | one `fanotify_init` fd (`FAN_CLOEXEC`), one mount mark per distinct mount (by `statx` mount id, R8) asking for the permission events a rule there can refuse, placed by `Arm` after the child stage's `execve` (ADR 0021); the group and each mark count against root's `fs.fanotify.max_user_groups` and `max_user_marks`, which every fanotify user of root on the host shares, and a run that finds them used up is refused (R8, §7) | one reading goroutine and `fanotifyWorkers` deciding ones | marks removed as the listener stops, and on cancellation before its last read of the group, which is closed after its last answer (E15); `Detach` closes whatever is left; a killed launcher's group closes with its last descriptor |
| Cgroup fd | `/sys/fs/cgroup/.../run-<id>.scope` (from `internal/runtime/cgroup`) | dir fd `O_DIRECTORY` | held for run lifetime | released at `Detach` |

**Changes.**
- 2026-10-17, build lock: a state directory of the caller's own beside pins under the host's bpffs is refused with `ErrHostState` (`openState`, `lockRootOf`; `TestHostPinsLockOnlyInTheHostStateDir`); in-process tests pinning there take `/run/tego` (`pinState`), as production always does.
- 2026-10-05, build lock (ADR 0042 (3)(b)): `/run/tego` is root 0700 only and `hoststate.OpenFile` refuses a file another uid owns; the root:tego 1770 form and its tmpfiles line are removed.
- 2026-09-24, Build lock (ADR 0034): only under `/run/tego`, verified; the `$XDG_RUNTIME_DIR` and `/tmp` fallbacks
  removed.
- 2026-09-24, Ring buffer, Lost counter (ADR 0026 (1)-(4)): ring outers of per-run rings, per-run counters and the
  capture miss counter, the ring budget and its lock replace the build's one ring and per-CPU counter.
- 2026-09-29, Fanotify fd/marks (ADR 0021): no stage ignore mark; the marks are placed by `Arm`.
- 2026-09-29, `reason` map: read by the supervisor through `Handle.KernelNet`; "not built" removed.
- 2026-09-29, Lost counters: only the two lost counters are read per drain; the miss counter is not.
- 2026-09-30, `dirIndex`, Aggregation table: the types the code has (an index into the sorted fs entries; a
  table nested by exec id) and the goroutine handover to the `Stop` caller.
- 2026-10-05, `tego_net_owners` (ADR 0018 PR 2): the value is 32 bytes (`flags`, `gen`), and `cgroup/sock_create`
  reads it too; it was listed at 16, which it had not been since `relay_cgroup_id`.
- 2026-10-19, `run_set`, Activity stamps (limits R4, record-off plan C2): `tego_activity`, a pinned
  per-slot stamp every object declares and `Prepare` zeroes, and the run row's `TEGO_RUN_ACTIVITY` flag, set when
  `stall_after` is bounded. The row was listed at 12 bytes, which it had not been since `flags`: it is 16.

## 4. Functions and contracts

**`cgroup.New(m) enforce.Backend`** — pure construction, no kernel state until `Prepare`.

**`(*Backend).Prepare(ctx, rt, run) (api.Handle, error)`.** Pre: `rt.Tier == TierCgroup` and a run cgroup id. Nothing it creates
keys on the run's cgroup or marks a mount: steps (4)-(6)'s row and marks are `Arm`'s, below. Steps: (1)
`slotTable.acquireGen`; (2) load/pin `cgroup_net`+`cgroup_track` under `/sys/fs/bpf/tego/<bpf_hash>/`, or open an object's
maps and programs from there when another launcher of the build left the whole object (every map, every program
reading only those maps, and its host-wide links; §9), cgroup links created via
`link.AttachCgroup` — link-based multi-attach, no flag (§5 R1) — and pinned under `links/run-<id>/` so they outlive a
killed launcher (E38); (3) populate `net_key`/`cidr_key` from `rt.Net` (`ask` compiled as refused — no ask in
P0, SEMANTICS §3.1) and from `run.Resolvers`, the endpoints the supervisor's port-53 exception covers (supervisor R14:
a TCP and a UDP row on port 53 for each, v4 plus v4-mapped, named `net.resolver`, replacing a declared entry's row on
the same key because the supervisor asks the exception first), or no row at all for a contract with no `net:` section
(§5 R1, R5); (4) at `Arm`, insert `run_key{run.CgroupID}` with `BPF_NOEXIST`, `descendants=1`, re-reading the row on `EEXIST`:
a row with this run's value is `cgroup_track`'s copy and stands, any other is another run's and fails the attach
(`EEXIST` is never success on its own: a run cgroup made under another run's subtree, which that run's
`cgroup_track` had already given its own row, would be recorded as the other run;
`TestInsertRunRefusesAnotherRunsRow`); (5) at `Arm`, scan cgroupfs
under the run's cgroup for pre-existing children (§5 R11); (6) create the fanotify group, and at `Arm` mark every distinct
mount holding a rule, one mark per mount `statx` names (a bind mount is a mount of its own, R8), each asking only for
the permission events a rule there can refuse (R8); (7) start `observe.Recorder`; (8) build the Landlock ruleset fd + seccomp filter (shared
helper, §1). Errors: `ErrSlotsExhausted` (exit 125), `ErrProgramLoad` (verifier log, exit 125), `ErrBuildLock`
(retry). Not idempotent — callers retry the whole `run.Run`, never `Prepare` alone.

**`(*handle).Attach(cgroupID) error`.** `Attach` runs before the agent is created (`prepareEnforcement` precedes the
launcher's start, runtime-launch §4.1), so no process of the run exists yet. Every process the run later has, and
every descendant cgroup, is covered by the attachment, because the kernel runs a program attached to a cgroup for
the sockets of that cgroup's whole subtree (§5 R1, R2); `cgroup_track` keeps the run set current for the tracing
hooks, which is the only thing a later descendant needs added (§5 R11). `link.AttachCgroup` for all eight programs
(six below 6.7, where `connect_unix` and `sendmsg_unix` are not loaded, R7), then for `cgroup/sock_create`
and `cgroup/setsockopt` (`attachSocketPrograms`, R4): ten links, eight below 6.7, each pinned as it attaches (E38). Right after the first program
that reads `tego_net_owners` is attached, which is when the kernel creates the cgroup's storage value, `Attach` writes
`{cgroup_id, run_idx, flags, gen}` into it with `BPF_EXIST` (§5 R1, R2): `flags` is `TEGO_OWNER_NET_ICMP` when the
contract's `NetSocketPolicy` admits ping sockets, and `gen` the run's generation, which `cgroup/sock_create` stamps on
its record (R5), as `cgroup/setsockopt` does. The storage is keyed by the cgroup id alone, which the kernel shares
between attach types, so the two programs, attached after the batch, read the value already written. The cgroup id is read from the
directory the links go on and must equal the run's, or `Attach` refuses. The storage also carries `relay_cgroup_id`,
this launcher's own cgroup read from `/proc/self/cgroup` under the run's mount; a cgroup it cannot name, or one that is
the run's own or beneath it, refuses the attach (R7). A contract with no `net:` section attaches none of them (R1).
Fatal on error, exit 125. The run's tree is not yet in the cgroup when `Attach` runs: the runtime calls `Attach`
before it starts the agent.

**`(*handle).Arm() error`** (ADR 0021 (2)). The one arming point: the runtime calls it once, after the child stage has
written its control message on pipe A (which the stage does only after its `execve` of the launcher binary has
returned) and before the ack, so the stage's exec comes before it and the agent's first exec after it. It inserts
the run-set row (`Prepare` step 4) and adopts existing descendants (step 5), then marks the mounts (step 6), the
first mark arming the process so that `proc.Start` refuses until `Detach` has removed the marks (R8). A second `Arm`,
or one after `Detach`, is `ErrNotPrepared`; a failure fails the run before `run_start`, and `Detach` removes what it
placed. Pinned by `TestArmIsTheOneArmingPoint` and, against a real stage, `TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck`.

**`(*handle).RefreshNet(rt) error`.** Takes a TTL refresh of the table `Prepare` compiled, the same `net` entries with
new addresses, and moves the run's host rows to them: the rows of addresses no longer resolved are deleted, then
every row the refreshed table produces is written, so an address both resolutions share never loses its row. An
entry the refresh leaves without an address keeps its previous ones (supervisor R8a). A table whose entries differ in
anything but their addresses is `ErrRefreshShape` and changes nothing, and so is a new address for an entry no lookup
re-resolves (a literal address, `Static`, or an entry with no host), since its addresses are what the contract admits
and the supervisor's set never moves them. The runtime's DNS worker calls it, through `enforce.NetRefresher`, on
each tick where the entries' addresses the set gives it (`dns.Set.Refreshed`) differ from the ones it last handed,
starting from those `Prepare` was given, and again on the next tick when it failed. The table it hands over, and
the one `Prepare` is given, hold no address the contract refuses for the name in any `agent-contract.md` R18 class
(loopback, link-local and metadata, multicast, the machine's `denied_resolved_addresses`, a private address after a
public first answer, and this host's own interface addresses): the runtime filters each out, into the entry's
`Denied`, with the run table's `ResolvedDenied` and a snapshot of this host's addresses of its own, taken as often
as the supervisor's, so a name rebound to `169.254.169.254` or to one of this host's addresses never becomes a
row admitting it, and the worker follows the host's address changes as well as DNS changes. An
address the host gains or drops moves the rows on the worker's next tick with no lookup; one that is an entry's only
address when the host takes it stays a row, since an entry a refresh leaves empty keeps its rows (above), and
agent-contract R18 gives the condition that closes it. While the two writes are in progress the rows
`Detach` removes cover both sets, and a refresh after `Detach` is `ErrNotPrepared` (§6 E7, §8 I5, I10).

**`(*handle).WaitListener(ctx) error`.** Returns once the workers of the run's fanotify listener have answered every
event they held and handed on what they recorded for each, or with `ctx`'s error if it ends first; with no
listener, or one whose loop never ran, it returns nil at once. `RunListener` returns before those workers when
its listener fails, and they end within three of E16's deadlines after that (§6 E35), so a caller that waits here
between the run group's `Wait` and its final drain writes every line they record. `internal/runtime`'s `shutdown`
calls it there through `api.ListenerWaiter`, bounded by its `killTimeout` (E35).

**`(*handle).Detach()/Close() error`.** Idempotent, safe after a partial `Prepare` (errors joined, not first-fail).
Removes: links, this run's rows from every map (by tracked cgroup-id set, never a full scan), fanotify marks+fd,
the `run_idx` slot (returned only once every referencing row is gone). Then attempts `LOCK_EX|LOCK_NB` on the
build lock; on success, unpins and detaches (last launcher out).

**`observe.New(...) *Recorder`** — opens the named build's pinned ring buffer and lost counter (or takes the
caller's reader, which is how the unit tests run the whole pipeline with no kernel) and builds `dirIndex`; it
starts nothing. `AddProcessHook` is called between `New` and `Start`.

**`(*Recorder).Start(ctx, run) error`.** Pre: `trace` programs already attached host-wide once (tracepoints/fentry
are global hooks, not per-cgroup; filtering is entirely the in-kernel `run_set` lookup, §5 R2). One goroutine
blocks in `ringbuf.Reader.Read()`, dispatches by `ev_hdr.kind`, non-blocking send to `out` (buffered 4096,
`docs/P0-DESIGN.md` §2.4 — a full channel bumps a drop counter distinct from the kernel lost counter, §7). Any read
error is fatal, propagated via `errgroup`, never swallowed. Not idempotent; blocks until `ctx` cancellation. Each
read waits at most `Options.ReadInterval` (`DefaultReadInterval`, 50 ms) or until the next aggregate flush,
whichever is sooner, and hands out what the ring holds when it ends: `trace_proc` submits its opens, file
operations and connects without waking the reader (`BPF_RB_NO_WAKEUP`) unless the ring is an eighth full, and
wakes it for every exec, every exit and an open of a file named `libssl.so*` (`BPF_RB_FORCE_WAKEUP`), so an open
waits for the reader's timer at most and the process cache and the uprobe source's attach at exec or at a libssl's
open wait for nothing (§9's recorder cost; `TestSamplesWithNoWakeupAreReadOnTheReadInterval`,
`TestTraceProcWakesItsReaderOnlyWhereItMust`). No sample is lost to the timer: the ring holds what the reader has
not read, and `Stop`'s final drain reads whatever is left.

**`(*Recorder).Stop() error`** — halts the drain goroutine without closing the ring, drains what the ring still
holds, reads the lost counter one last time, flushes every open (non-empty) aggregate as a final `fs` event, closes
the ring, and only then closes the counter: a run that ends inside its flush window still reports the drops of that
window as `ringbuf-full`. Closing the counter with the reader made that last read fail on a closed descriptor,
silently. The final drain (as built, 2026-09-23; capture-derive.md edge case #28) runs once the drain goroutine has
returned: `ringbuf.Reader.Flush` wakes it, and it returns at its next sample, so it ends promptly however busy the
ring is. The run calls `Stop` once its cgroup is empty (runtime-launch.md §4.1 step 13), so every sample of the run is
on the ring then, within the bytes the ring holds when the drain begins; the drain reads that many bytes and no
further, because a process that outlived the run's cgroup wait can keep the run's ring from ever being empty. Its reads do not wait. It records
samples for `Options.StopDrain` (2 s) and past it only counts them, the run's own into `gap what=record
why=ringbuf-undrained count=n`, so it is bounded by the ring's size and not by the hooks' work. Cancelling the run's
context halts the goroutine the same way and leaves the ring to `Stop`: the run cancels its workers before it knows
its processes are gone; neither `Stop` nor cancellation closes the reader before the final drain, so the samples
still on the ring — the exits and opens that end a run, and the hook calls they drive — are read. Two limits:
(1) on the cancellation path (a failed worker, a cancelling caller) the run waits for a killed tree on a context of
its own, bounded by `killTimeout` (10 s, runtime-launch.md §4.1 step 12), not on its already-cancelled one; a tree
that outlasts even that, a process in uninterruptible sleep, can still produce a sample after the drain, and the
run records `gap what=record why=ringbuf-undrained` with no count for it (§7). (2) "Records" means handed to the
run's events queue, and the run keeps writing the queue to the ledger while its sources stop; the queue is still
bounded, so a drain that outruns the ledger by more than its 4096-slot depth is counted as `gap what=record
why=channel-full`, as mid-run.

**Changes.**
- 2026-09-23, `Recorder.Stop`: the final drain reads the ring before it closes; the killed tree is waited for on a
  context of its own; the queue is written to the ledger while sources stop.
- 2026-09-23, `RefreshNet` (fail-closed): rows exclude every R18 class and this host's own
  addresses, and follow the host's address changes.
- 2026-09-24, `Prepare` step (4): `EEXIST` on the run row is re-read, not taken as success.
- `Attach`: the run's tree is not in the cgroup before `Attach` (the `CLONE_INTO_CGROUP` statement withdrawn).
- 2026-09-24 (rulecheck): §4 `RefreshNet`'s R18 named with the document that defines it; wording otherwise unchanged.
- 2026-09-29, `Prepare`, `Arm` (ADR 0021 (2), (4)): steps (4)-(6)'s run-set row, adoption and marks move to `Arm`,
  after the child stage's `execve` and before the ack; `Prepare` no longer opens or checks the stage's binary and
  refuses a run with no cgroup id up front.
- 2026-10-16, `Attach` (ADR 0018 PR 2): `cgroup/sock_create` is attached and pinned after the
  CGROUP_SOCK_ADDR batch, and the owner value carries `flags` (ping sockets) and `gen`.

## 5. Business rules

**R1 — Upgrade self-scoping, by attachment.** A network program decides for the run its *attachment* belongs to, and
nothing else: it reads that run from `tego_net_owners`, the cgroup storage of the cgroup it was attached to, which
`Attach` configures (§4). It never asks which cgroup the *caller* is in. The kernel selects a `CGROUP_SOCK_ADDR`
program array by the socket's cgroup (`sock_cgroup_ptr(&sk->sk_cgrp_data)` in `__cgroup_bpf_run_filter_sock_addr`,
fixed when the socket is created), so the run's program runs for every connect on a socket the run created, and
the caller may be the seccomp supervisor relaying that connect from its own process (supervisor R9, I2) — whose
cgroup is not the run's. Each build reads its own pinned storage map and runs only where that build attached it,
so a build can never decide for another build's run, and an attachment whose storage is still zero (the moment
between the first link and `Attach`'s write, before any process of the run exists) refuses, fail-closed.
A lookup of the caller's `bpf_get_current_cgroup_id()` in the run set would name the supervisor for every relayed
connect, miss, and return the neutral `1`, so no connect of a supervised agent would be decided in the kernel
(supervisor.md's "R9 vs enforce-cgroup-observe R5" entry; `TestNetVerdictOnRealKernel`). Attachment here is
link-based (`link.AttachCgroup`; `cilium/ebpf/link`'s `CgroupOptions` exposes only `Path`/`Attach`/`Program`, no
flags field), and link-based cgroup attachment is inherently multi: any number of independent links may target one
cgroup+attach-type at once, and the kernel ANDs `CGROUP_SOCK_ADDR` return codes across them to reach the final
verdict — a property of the attach type itself, not of `BPF_F_ALLOW_MULTI`/`BPF_F_ALLOW_OVERRIDE` (those flags
belong to the legacy `BPF_PROG_ATTACH` syscall path this component never uses). Two coexisting `bpf_hash` builds'
links therefore coexist and AND automatically; neither can block the other's cgroups. The same AND is what a run
nested inside another run's cgroup gets: both attachments' programs run for its sockets, each with its own run's
storage, and both must allow. Generalizes ARCHITECTURE §6's fmod_ret rule (`return 0`) to the cgroup-hook family,
where the neutral value `1` is now returned only by R4's protocol guard and R6's run with no listener control.
A run whose contract has **no `net:` section** attaches none of the eight programs (`RuleMaps.Unrestricted`):
SEMANTICS §1 reads that as "deny nothing", the supervisor admits every destination under it, and both read that bit
from `agent.RuleTable.NetUnrestricted`, the one predicate for it (agent-contract R15); the inherited Landlock ruleset
handles no network right. Attaching the programs with no rows would refuse, with `EPERM` in the kernel, every
connect the supervisor relayed on the agent's socket. As root: `TestNetUnrestrictedOnRealKernel`.

**R2 — No ancestor walk at hook time.** A tracing or uprobe hook does one `bpf_map_lookup_elem(run_set, cgroup_id)`
keyed by the current task's cgroup; membership is materialized ahead of time by `cgroup_mkdir` — no in-kernel walk
ever. A network hook does no membership lookup at all: `bpf_get_local_storage` hands it the attach point's
`tego_net_owners` value, and the kernel has already done the only subtree test there is by running programs
attached to a cgroup for the sockets of its descendants (R1).

**R3 — Network verdict precedence.** Exact `net_key` hit wins; else longest-prefix `cidr_key` hit wins; else
refused (`net-not-allowed`). Each row carries the verdict and rule of the entries covering it, composed by SEMANTICS
§5's overlap rule (a refusing covering entry, else the first declared): an exact row is covered by the entries naming
its address and every prefix containing it, a prefix row by every prefix containing it (`BuildRuleMaps`). The row
the lookup reads is then covered by exactly the entries covering the destination, so the kernel answers as
`Evaluate` and the supervisor do (`TestNetPrecedenceMatchesEvaluate`). `ask` entries compile as refused (SEMANTICS §3.1); P0 has no gate, so no verdict is
ever raised after the kernel decides.

**R4 — Connect vs send.** `connect4/6` decides `connect()` for TCP and UDP sockets, and for no others.
`sendmsg4/6` decides each unconnected UDP datagram independently — both race-free.

The hook is gated on the **protocol**, not on the socket type, and the gate is narrower than "not `SOCK_RAW`":
`inet_dgram_connect` and `__inet_stream_connect` (`net/ipv4/af_inet.c`) call it only under
`BPF_CGROUP_PRE_CONNECT_ENABLED(sk)`, which tests `sk->sk_prot->pre_connect`, and the introducing commit
(`d74bad4e74ee`, "bpf: Hooks for sys_connect" — "Support is added for IPv4 and IPv6, for TCP and UDP") assigns
`.pre_connect` to exactly four `struct proto`s: `tcp_prot`, `tcpv6_prot`, `udp_prot`, `udpv6_prot`. Every other
AF_INET/AF_INET6 protocol therefore never reaches `connect4/6` at all — raw and ICMP datagram sockets as
already stated, and equally **SCTP** (`IPPROTO_SCTP`) and **UDP-Lite** (`IPPROTO_UDPLITE`), both of which an
unprivileged process can open and both of which autoload their module on first use. All of them are covered
only by the record-only `security_socket_connect` fentry, never enforced — a stated P0 gap, recorded not
refused, and wider than the raw/ICMP wording implied. (The same reading says `bpf/cgroup_net.bpf.c`'s
`if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return TEGO_SOCK_OK;` is not what closes the gap: for
`connect4/6` nothing that branch excludes ever arrives, and for `sendmsg4/6` it is what lets an unconnected UDP-Lite
datagram through undecided, because `udplite_prot` shares `udp_sendmsg` and with it the `UDP4_SENDMSG` hook. The
file's comment used to say "`inet_dgram_connect` calls it for every protocol", the opposite of the gate; it now
states the gate and the UDP-Lite datagram path.)

The gap is closed where the socket is made, never at connect or send (ADR 0018). Under a `net:` section the
inherited tier-1 filter decides `socket(2)` and `socketpair(2)` on their scalar arguments (ADR 0018 PR 1, enforce-landlock
E30), a plane mode's `socket_create` decides every family on every path (PR 3, enforce-plane R14), and
`cgroup/sock_create` (`BPF_CGROUP_INET_SOCK_CREATE`, ADR 0018 PR 2) decides every inet socket on any path to
`inet_create`, whatever the filter saw: an `io_uring` `IORING_OP_SOCKET`, or anything else that reaches
`__sock_create` past the filter. All three apply ADR 0018 (1)'s one allowlist, the C spelling of which is
`bpf/include/socket_allow.h`'s `tego_socket_allowed` (the plane's and this program's), held to the filter's arm and
to the table by `internal/bpf`'s `SocketAllowed` (`TestSocketAllowedIsTheADR0018Table`,
`TestFilterSocketArmIsTheKernelAllowlist`, and as root `TestSockCreateRefusesInetSocketsOutsideTheAllowlist`).
`cgroup/sock_create`:
- reads its run from `tego_net_owners` (R1) and refuses, unrecorded, while that storage is unconfigured;
- admits the allowlist's triples, ping sockets as the owner's `TEGO_OWNER_NET_ICMP` says (the contract's
  `NetSocketPolicy`, which the filter and the plane's slot header read too);
- decides the whole protocol number, never `(__u8)ctx->protocol`, so MPTCP (262) is not TCP and `IPPROTO_SMC` (256) is
  not protocol 0; MPTCP on this path is refused and recorded (the filter's silent MPTCP arm is for `socket(2)`'s
  probes, which never reach here);
- refuses with the kernel's `EPERM` (`return 0`, I3; no `bpf_set_retval`), after writing its own record (R5);
- sees no family but AF_INET and AF_INET6: `BPF_CGROUP_RUN_PROG_INET_SOCK` runs only in `inet_create` and
  `inet6_create`, which is ADR 0018 (5)'s stated residual, and why `io_uring: true` stays refused at the fanotify
  fallback.
The recorder writes the program's record as one `refused` line (`observe.handleSockCreate`). The line is spelled as
the supervisor's and the plane's socket refusals are: `op: socket`, the family, type and protocol as `target`,
`reason: net-not-allowed`, `rule: unmatched`. Its payload carries `mechanism: cgroup` and no `decision_plane`
(spec/record/v1, additive). It is kept under `record: off`, and a record of another generation is dropped as every
record is. A record with another reason, or of a triple the allowlist admits without an ICMP entry, cannot be the
program's: its line is still written and a `malformed-record` gap is counted.
*Attached 2026-10-16 (ADR 0018 PR 2):* `Attach` attaches it to the run's cgroup after the
CGROUP_SOCK_ADDR batch and pins it with the run's links (ADR 0020 (1)), wherever that batch attaches: every tier-2 mode
and tier 3, not only the fanotify fallback (amending ADR 0018 (5)). With a plane mode the plane's
`socket_create` runs first, in `__sock_create` before `inet_create`, and this program ANDs the same inet verdict from the
same `NetSocketPolicy`. The attach is required: its attach type (4.10) and `bpf_link` attach (5.7) are below the floor,
an `EPERM` is `ErrCgroupAttachConflict` (E36), and doctor's D7 row `cgroup/sock_create` gates tier `cgroup` like
`connect4`'s. A run reports the bound as `NetworkGuarantees.SocketFamilies` and the capability row
`net.socket_families`: the inherited filter's socket arm with io_uring refused and this program attached, or a plane
mode's `socket_create`; `net.assurance: kernel` requires it (network-controls). Root cells:
`TestSockCreateIsAttachedAndRefusesOutsideTheAllowlist` (the owner's flags and gen, the pin, SCTP, UDP-Lite, MPTCP 262
and SMC 256 `EPERM` with one record each on the run's ring), `TestSockCreateRunsAreANDedWhenNested`,
`TestNetLinksOutliveTheLauncher` (the link refuses after the launcher is killed) and, through `tego run` on the
fallback with a test build's io_uring seam, `TestIOUringSocketsMeetTheKernelBackstops` (inline, `IOSQE_ASYNC`
and SQPOLL submissions, one `refused` line each with `mechanism: cgroup`).
*Amended 2026-10-17 (ADR 0018 (7)):* a socket the allowlist admitted could still become one of
another family after it was made: `setsockopt(SOL_TCP, TCP_ULP, "smc")` on an unconnected TCP socket, with the smc
module loaded, builds an `AF_SMC` socket in its place as a kernel socket (`smc_ulp_init`), which no `socket(2)` arm,
no `cgroup/sock_create` and no plane `socket_create` sees. Under a `net:` section every ULP name is now refused: the
inherited filter notifies `SOL_TCP`/`TCP_ULP` and the supervisor answers `ENOENT` with a line (enforce-landlock E30),
and `cgroup/setsockopt` (`BPF_CGROUP_SETSOCKOPT`, 5.3) is attached and pinned beside `cgroup/sock_create`, required
like it (D7 row `cgroup/setsockopt`), for every path the filter does not see: the kernel runs it from
`do_sock_setsockopt` for every option set on the run's sockets, io_uring's `SOCKET_URING_OP_SETSOCKOPT` (6.7+)
included. It:
- reads its run from `tego_net_owners` and refuses, unrecorded, while that storage is unconfigured, as
  `cgroup/sock_create` does;
- passes every option but `TCP_ULP` untouched, the kernel's copy of the value included, so another program in the
  chain keeps what it rewrote, save the documented rule for a value longer than the kernel shows a program (`PAGE_SIZE`):
  handed back with `optlen` 0, so the kernel uses the caller's value as with no program attached (5.11 to 6.4 answer
  `EFAULT` otherwise);
- refuses `TCP_ULP` with the kernel's `EPERM` (`return 0`, I3), after writing its own record (R5): `TEGO_EV_SOCKOPT`
  (`struct tego_ev_sockopt`: level, option, the caller's `optlen` and the first 15 bytes of the kernel's own copy of
  the value, which is what the kernel then reads), which the recorder writes as a `refused` line, `op: setsockopt`,
  `target: TCP_ULP "<name>"` (the name cut at `optlen` and its first NUL, `record.SocketOption`, the supervisor's
  spelling too), `reason: net-not-allowed`, `rule: unmatched`, `mechanism: cgroup`; a record of another option or
  reason is a `malformed-record` gap and its line is still written (`observe.handleSockopt`).
The run's `SocketFamilies` now needs both programs attached, and on top of them the inherited filter's arm (no
io_uring) or a plane mode's `socket_create` (io_uring admitted). Root cells: `TestSetsockoptRefusesEveryTCPULP`,
`TestSetsockoptRefusesTCPULPThroughIOURing` (inline, async, SQPOLL), `TestSetsockoptCountsALostRecord`, and the run
cells above extended with the pin and a `TCP_ULP` refusal and record. The same
shape is why systemd documents that `IPAddressAllow=`/`IPAddressDeny=` "apply only to AF_INET and AF_INET6 sockets"
(systemd.resource-control(5)).

**R5 — Reason breadcrumb, not duplicate recording.** `connect4/6`/`sendmsg4/6` write `reason_val` on every
decision, keyed by the run's own cgroup id from `tego_net_owners` (R1), and never push a ring-buffer event.
*Amended 2026-10-05 (ADR 0018 PR 2):* `cgroup/sock_create` is the one network program that does. No recorder or
supervisor sees a socket's creation, so a refusal of it would otherwise have no line (ADR 0015); it reserves its own
`TEGO_EV_SOCK_CREATE` (`struct tego_ev_sock`: family, `sk_type`, the whole protocol) on the run's ring, found by the
owner's `run_idx` (`tego_ring_of`) and stamped with the owner's `gen` and `cgroup_id`, never the caller's, under
`record: off` too, and counts a missing ring or a failed reserve in `tego_lost` at the run's slot (I7). Its run is
the attachment's storage, not a run-set lookup, so `bpf/tests`' `TestRunSetLookupFirst` names it as the one program
that reserves after its storage read and configured guard rather than after `tego_run_lookup`. *Amended
2026-10-17 (ADR 0018 (7)):* `cgroup/setsockopt` records the same way, for the same reason (no recorder or supervisor
sees an option set past the filter), `TEGO_EV_SOCKOPT` on the run's ring; `TestRunSetLookupFirst` names it beside
`cgroup/sock_create`.
*Reconciled with supervisor R9/I2 (this is where the two documents disagreed):* the inherited tier-1 seccomp filter
still notifies on `connect`/`sendto`/`sendmsg`, and the supervisor does **not** answer `CONTINUE` for a connect —
it decides, then relays the allowed connect from its own process on a `pidfd_getfd` duplicate (supervisor R9, I2),
because continuing would hand the kernel a `sockaddr` a sibling thread can rewrite after the decision. That relay is
still a connect on the run's socket, so the run's `connect4/6` runs for it (R1) and decides it again in the kernel:
the kernel's verdict is an AND with the supervisor's, and a destination this program refuses fails the relayed
connect with `EPERM`, which the supervisor returns as the real result (supervisor I3). An unconnected datagram
the supervisor answers `CONTINUE` for (supervisor R13b) is sent by the agent itself and decided by `sendmsg4/6` the
same way.

Because the kernel decides every connect the supervisor relays, its rows have to admit everything the supervisor
admits, including what the supervisor admits on the runtime's authority rather than the contract's. There are three
such things, and each has its own kernel half. **The resolver exception** (supervisor R14, SEMANTICS §5): the
run's resolver endpoints, `Run.Resolvers`, become a TCP and a UDP row on port 53 each, v4 plus v4-mapped, named
`net.resolver` (§4 `Prepare` step 3); glibc and Go connect their UDP query sockets, so without them every tier-2 run
whose contract does not name its nameserver lost DNS (`TestNetVerdictOnRealKernel` relays exactly that connect). **A
contract with no `net:` section** attaches no network program (R1). **A host entry's refreshed addresses**
(supervisor R8) are moved into the rows by `RefreshNet` (§4, E7).

**An unspecified destination is refused.** The kernel sends a connect or datagram to `0.0.0.0`, `::` or
`::ffff:0.0.0.0` to this host (`tcp_v6_connect` turns `::` into `::1`, or into `::ffff:127.0.0.1` from a socket bound
to a v4-mapped address; the v4 route lookup takes `0.0.0.0` to `127.0.0.1`), so decided against the rows as written
an entry such as `::/0:P` would admit loopback on `P`, which it does not name. `tego_net_decide` refuses such a key
before the lookup (`tego_addr_unspecified`), and the supervisor's `dns.Set.Match` matches nothing for it, so both
tiers refuse it and the ledger agrees with the kernel.
**A v6 prefix does not decide v4-mapped destinations.** An IPv6 entry wide enough to hold `::ffff:0:0/96` would
decide a v4-mapped connect6 by itself, where the supervisor unwraps the address and no v6 prefix contains an IPv4
one; `BuildRuleMaps` adds a refusing row at `::ffff:0:0/96` for it, unless an IPv4 entry's mapped twin holds that
key, so mapped destinations follow the IPv4 rows. **`cgroup_track` acts only on the unified hierarchy.** Its
tracepoints fire for every hierarchy, and a cgroup v1 hierarchy (net_cls, a container's `name=systemd`) numbers its
kernfs nodes from its own idr, so a v1 directory could carry the run's unified id, and its mkdir or rmdir would
insert a row with the run's slot or delete the run's own rows, silently ending the run's kernel record and the
uprobe capture that filters on them. Both programs return at once unless `cgrp->root->hierarchy_id` is 0. **The
connect record reads only what the caller passed.** `security_socket_connect`'s record reads the port and address
only when `addrlen` covers them (on 5.14 a two-byte `addrlen` would leak kernel stack bytes into the ledger): a
connect with `addrlen < 2`, whose family is not the caller's either, and an `AF_INET` one shorter than
`sizeof(struct sockaddr_in)` or an `AF_INET6` one shorter than `SIN6_LEN_RFC2133` (24), which name no destination,
are not recorded (each fails in the protocol's own length check; recorded, the short one was a line naming
`0.0.0.0:0`), and the supervisor keeps its own line for them (supervisor R7, `TestConnectRecordNeedsTheFamilysAddress`, `TestIntegrationShortConnectIsNotRecorded`). **A unix connect is not in the kernel record.** Its name is unresolved at that hook, and the
record of a unix connect is the inherited tier-1 supervisor's, which names the socket; the kernel record writes no
second line for it (`TestIntegrationUnixConnectIsLeftToTheSupervisor`). **An IP connect the supervisor continues is
recorded here alone.** With no `net:` section the supervisor answers every connect `CONTINUE` (supervisor R7), so the
agent's own task makes it and this record writes its line; while the run's recorder reads (`observe.Recorder.Reading`:
it found its run's row and its drain has not failed), the supervisor writes none for an `AF_INET`/`AF_INET6` connect
it continued, so each connect has one line, this one, with the kernel's copy of the address. That line is named as the
supervisor's would have been: the recorder asks the run's supervisor (`Options.ContinuedNet`, `supervisor.Loop.ContinuedNet`)
for the rule, host and verdict of an IP destination it continues, so a query to a resolver on port 53 is
`net.resolver`, the capture listener `net.capture[…]`, an address the resolved-address check refuses for its entry
`unmatched`, and each is `allow`; `matchNet` names a sample only where the supervisor continues nothing (a `net:`
section, the `models[]` guard) or none runs (`TestRecorderNamesAContinuedConnectAsTheSupervisor`). A connect the supervisor
relays (a `net:` section, the `models[]` guard) runs from the launcher's cgroup, which no row names, and one it
refuses never reaches the hook: their line is the supervisor's alone. Where no recorder reads, the supervisor keeps its
line (`TestTier2ConnectHasOneLine`, `TestEveryConnectHasExactlyOneLine`). **A NAME_MAX name is recorded whole.** A
255-byte name fills the 256-byte buffer with its NUL; a name is whole when the read took its `d_name.len` bytes and
the NUL (and an exec path when no 256th byte follows). Pinned as root in the KVM guest by `bpf_edges_integration_test.go` and in unit by
`TestMappedDestinationsFollowTheIPv4Rows` and `dns.TestMatchRefusesAnUnspecifiedDestination`.

*What is built and what is not.* The three kernel halves are built and tested as root, and the runtime
feeds both that need it: `prepareEnforcement` (`internal/runtime/run.go`) reads the resolver list once
(`runResolvers`) and hands the same slice to `enforce.RunRef.Resolvers`, which the adapter copies into `cgroup.Run`,
and to the supervisor's `dns.Set`; and the run's DNS worker (`refreshDNS`) calls `RefreshNet` with
`dns.Set.Refreshed`'s table whenever its addresses differ from those the tier last received (E7, §4 `RefreshNet`). A resolver the runtime was given in
its v4-mapped form, and an entry address in that form, get the `AF_INET` row too, since the supervisor compares both
unwrapped. As root in the KVM guest, a DNS query to the machine's resolver from a tier-2 run gets its answer
(`TestTier2RunEndToEnd`) rather than meeting `EPERM` while the ledger records it allowed. The reading half is
built too: after a connect it relayed fails with `EPERM`, the supervisor asks the tier (`Handle.KernelNet`,
through `enforce.KernelNetReader` and `supervisor.Options.KernelNet`) for the breadcrumb under the run's cgroup id,
and a refusal it names becomes the line's verdict, rule and reason, where the supervisor had recorded its own
allow for a connect that never happened. The breadcrumb answers only when it is this run's slot, a connect, on the
same protocol (the relayed socket's, `tcp` or `udp`) to the same destination (a v4-mapped address unmapped), and its `mono_ns` is no more than 50 ms
(`BreadcrumbStale`) older than the notification; otherwise the line is `observed`, never a misattribution (§6 E5).
One that says the kernel allowed the destination leaves the `EPERM` to something outside tego, and the
supervisor's allow stands. A datagram the supervisor continues is sent by the agent and its result never reaches
the supervisor, so a `sendmsg4/6` refusal is not read back (`TestKernelNetReadsTheBreadcrumb`,
`TestRelayedConnectCarriesTheKernelsRefusal`, and as root `TestNetVerdictOnRealKernel`).

**R6 — `bind4/6` decide a declared `net.listen`.** Both programs attach (parity with the `CGROUP_INET*` family, one
attach batch; none of the batch attaches under a contract with no `net:` section, R1). A run with no listener control
returns `1`; otherwise `tego_bind_decide` reads the run from `tego_net_owners` and refuses an address without a
`tego_bind_exact` grant ([network-controls](network-controls.md)).

**R7 — Unix sockets: `connect_unix` and `sendmsg_unix`, 6.7+.** The two programs decide a unix destination by the
name the caller passed, and only ever narrow what the inherited tier-1 path decides: the kernel ANDs them with the
seccomp supervisor, which stays the primary decision and the only one below 6.7. The uapi `struct bpf_sock_addr`
has no path member, but `bpf_cast_to_kern_ctx` (6.2) turns the context into the kernel's `struct bpf_sock_addr_kern`,
whose `uaddr`/`uaddrlen` are the kernel's own copy of the caller's `sockaddr_un` (`move_addr_to_kernel`, or
`____sys_sendmsg`'s copy of `msg_name`), read through `bpf_rdonly_cast`; the upstream selftest
`connect_unix_prog.c` reads `sun_path` the same way. The copy is race-free: no thread of the caller can rewrite it
after the hook reads it, which is what closes supervisor R13b's datagram TOCTOU for unix sends. The reads are
untrusted BTF pointer loads, which need `CAP_PERFMON` or `CAP_SYS_ADMIN`; tier 2 holds both, and the programs load
under `integrity` and `confidentiality` lockdown alike (6.17, 2026-09-23). The decision
(`bpf/cgroup_net.bpf.c` `tego_unix_decide`, rows from `BuildRuleMaps`):

- an attachment whose storage is not configured refuses (R1);
- an **abstract** name is admitted when a `unix:@name` entry names exactly its bytes and length, NUL bytes included
  (supervisor E5), and, on a connect, when it consumes the one-connect grant the supervisor made after a person
  approved that name (*added 2026-10-19, supervisor R11c*): `tego_unix_approvals`, keyed by the slot, the
  slot's gen in the run set and the socket's cookie, holds the approved name and a deadline a second ahead
  (`Handle.GrantUnix`); a live grant of exactly that name is taken once and removed, and the supervisor revokes it
  when its relay returns. Detach and `purgeSlot` (a reclaiming `Prepare`, the reaper) remove every grant of the slot,
  and a row a missed purge left names a gen no later run of the slot has (`TestUnixApprovalOnRealKernel`,
  `TestPlaneUnixApprovalOnRealKernel`, `TestUnixApprovalRowsPurgedOnRealMaps`). The reaper's purge
  (`purgeDeadSlots`) loads every pinned map `purgeSlot` purges, both grant maps (`tego_unix_approvals`, and
  `tego_connect_approvals`, the one-shot credits of an approved TCP connect or UDP connect or addressed datagram,
  network-controls R6 and supervisor R13d, keyed by slot, gen, socket cookie, family, protocol, address and port and
  serialized per key by `creditRows`, whose revoke reports a credit left untaken; *amended 2026-10-20:* this list called it the TCP grant map) and the network controls' with them
  (`TestApprovalGrantsReapedWithTheirDeadLauncher`);
  *amended 2026-10-19:* it loaded neither the connect grant map nor
  the network controls' maps, so a dead launcher's rows there waited for the slot's next `Prepare`. A pathname needs none: the relay
  names the inode it resolved as `/proc/self/fd/<n>`, admitted below;
- an **absolute** pathname is admitted when it is spelled canonically (no empty, `.` or `..` component) and either a
  `unix:` entry names its cleaned path, or the nearest filesystem entry at or above it is a write entry (SEMANTICS §5's
  implicit admit; any other nearest entry, or none, refuses) — the supervisor's name check (`decideUnix`, R11), with
  the same entries: every `fs` entry but `watch` at its declared path, a `unix:` entry before any filesystem entry,
  and the first declared of two entries at one path. The write entry's row admits any name under it: the program
  cannot see which process bound a socket, so it does not hold supervisor R11a's rule that the implicit admit is for
  a socket the run bound (added 2026-10-16). The supervisor decides every unix connect and addressed datagram first
  and refuses a socket there the run did not bind, so the row is a wider backstop, reached only by a datagram whose
  name, or the file it leads to, changed between that decision and the kernel's lookup — a sibling thread rewriting
  the name, a process of the run renaming a file or swapping a symlink onto it (supervisor R11a's residual). A refusing entry with no write
  entry at or above it gets no row, since every row above it refuses too and a name no row covers is refused (the trie, `UnixRowsMax` rows, is
  shared by every run of a build). Nor, in a run a decision plane decides, does a `deny_read` file the plane compacted
  (ADR 0043 D6): the trie answers it by the write entry above, as it answers a covered name made after compile, while
  the plane refuses the run a socket at a covered name and the file's unlink and rename, and the supervisor keeps the
  entry (added 2026-10-27). A non-canonical spelling is refused, fail-closed, where the
  supervisor cleans it lexically: matched as bytes, `<write entry>/../x` or `<write entry>/.//<deny_read entry>/x`
  would take the write entry's verdict for a socket elsewhere;
- the name `/proc/self/fd/<digits>` is admitted on a **connect** from `relay_cgroup_id`, the launcher's own cgroup,
  and from no other caller: it is how the supervisor's relay connects the agent's socket to the inode it resolved
  and admitted (supervisor R11), and the name means something only in the relaying process. From any other cgroup,
  the agent's included, it is an ordinary absolute name. This is the one use of the caller's cgroup in these
  programs; it selects no run and no row (R1);
- a **relative** name, which resolves against a cwd the program cannot read: a datagram's is left to tier 1, which
  decides it on the name and refuses it with `EACCES` when the policy refuses it (supervisor R13b), and a connect's
  is refused, because the supervisor relays every connect by the inode
  it resolved and never passes a relative name on;
- no breadcrumb is written: `tego_reason` is shaped for an address and a port, and nothing reads one yet (R5).

What stays with tier 1: the resolved socket. The path lookup runs after the hook, so a symlink under a write entry,
or a listed name that now names another socket, is the supervisor's resolved-socket check's for a connect (R11). A
datagram is continued rather than relayed (supervisor R13b), so the agent's own send resolves the name under the
Landlock domain it inherits from tier 1. At Landlock ABI 9 (Linux 7.1) and above that domain's `RESOLVE_UNIX`
backstop checks the socket the name resolves to (enforce-landlock R21: a rule on the inode each pathname `unix:`
entry named at `Prepare`, and a grant under every write entry), so a symlink out of a write entry, or another
socket moved under a listed name outside every write entry, is refused. Below ABI 9 nothing checks it, at tier 2
as at tier 1: the stated supervisor R13b limit, narrowed here to relative names and to names that resolve elsewhere. No
kernel in the test matrix has ABI 9 yet (its newest row is Fedora's 7.0), so the ABI-9 half rests on
enforce-landlock R21 and is not verified by a guest run. A consequence to know: an unlisted datagram destination
the agent's libraries try, such as `/dev/log`, is refused with `EPERM` in the kernel on 6.7+, where below 6.7 it is
recorded and sent.
What the record says of a unix datagram still comes from the supervisor alone, which continues the send and writes
its own verdict with `best_effort` (supervisor R13b), so on 6.7+ its line can disagree with the kernel in two ways:
a send `sendmsg_unix` refused carries `best_effort`, which says "recorded without enforcing" of a refusal the
kernel did enforce; and a non-canonical name the supervisor cleans and admits, such as `<write entry>/./x.sock`,
is recorded `allow` although `sendmsg_unix` refused it with `EPERM`. A reader cannot tell these lines from tier 1's
until the per-run record of which path decided exists (below; built since as `run_start.net_guarantees`). *Amended 2026-10-05:*
both disagreements are closed. The runtime hands the supervisor the errno each attached program refuses a datagram
with (`Handle.KernelDatagrams`: `EPERM` with `sendmsg_unix` attached, `EACCES` where the plane's `socket_sendmsg`
decides in its place, and `EPERM` for UDP under `sendmsg4` and `sendmsg6`), and the supervisor refuses, with that
errno, a datagram the program would refuse: an unlisted name, and a name not spelled canonically, by this section's
rule (supervisor R13b). The datagram's one line is that refusal, without `best_effort`, and the agent sees the
errno the program gave it before. UDP had the same split, found by the same cell: an unlisted UDP destination was
recorded refused with `best_effort` beside `sendmsg4`'s `EPERM`. An admitted datagram is still continued, so the
kernel decides its own copy and its line keeps `best_effort`; a relative name is still left to tier 1, which since
2026-10-16 refuses it itself, with `EACCES`, when the policy refuses it, as it refuses every refused datagram no
program decides (supervisor R13b). As root in the guests: `TestTier2DatagramLineIsTheKernels` (one line per datagram, the kernel's errno, on 6.17 with
`sendmsg_unix` and below 6.7 with step D).
A pathname `unix:` entry longer than `sun_path` once cleaned, which a contract can hold because the parser checks
the 108 bytes before it expands `~/`, gets no row and is reported skipped (`SkipUnixLong`): no absolute name can
equal it, and a relative name, the only kind that can, is never looked up by these programs, so tier 1 decides it
on every kernel; such a contract runs at tier 2 on every kernel.
Nested runs: an outer run's `connect_unix` sees an inner supervisor's relay name from a cgroup that is not its
launcher's and refuses it, fail-closed. Below 6.7 the kernel checks a program's expected attach type when the
program is *loaded* (`bpf_prog_load_check_attach`), so `Prepare` loads a trivial `BPF_CGROUP_UNIX_CONNECT` program
first and, on `EINVAL`, leaves both unix programs out of `cgroup_net` before loading the object (the unix attach
types arrived together in 6.7; before, the object failed whole there, and tier 2 with it). `tego doctor` treats
`cgroup/connect_unix` and `cgroup/sendmsg_unix` as optional for tier `cgroup` below 6.7 (`hook.optional`,
`HookResult.Absent`) and says in the capability matrix's note that unix sockets fall back to the seccomp supervisor
there; on 6.7+ a unix program that does not load withholds the tier, as `Prepare` would fail loading it. Below
6.7 `tego doctor` and `tego run` offer tier `cgroup`, since this backend runs there. `Handle.Capabilities` keeps
`net.unix` for a run with a unix entry (the inherited path enforces the entry), and takes
`net.unix_abstract_scope` from the inherited Landlock handle rather than the static column: no program of this tier
refuses an abstract unix name, the scope in the ruleset the child applies does, from Landlock ABI 6 on
(`enforce-landlock.md` R7; added 2026-09-23 with the row). Recording
per run which path decided is built: `run_start.net_guarantees.unix` (record minor 4, `docs/p0/record-ledger.md`) is
true exactly when the run's own kernel programs decide unix names, `connect_unix` and `sendmsg_unix` attached or the
plane's `socket_connect` and `socket_sendmsg` loaded (`Handle.NetworkGuarantees`, `internal/runtime/enforce/cgroup/network.go`;
written by `internal/runtime`'s `networkGuaranteeLine`), and false where the names fall to the supervisor. As root on 2026-09-23: `TestUnixVerdictOnRealKernel` (every case above,
the relay admitted from the launcher's cgroup and refused from another cgroup and from inside the run, rows gone
after `Detach`) and `TestTier2UnixEndToEnd` (the real supervisor's relayed connect to a declared socket succeeds,
an unlisted datagram is refused with `EPERM`, one to a socket the run bound under its write entry leaves) pass on
the test machine's 6.17, Ubuntu 24.04's 6.8, Debian 13's and AL2023's 6.12 and Fedora's 7.0 (`test/vm/root-suites.sh` with
`TEGO_VM_KERNEL=matrix-<row>`); on AL2023's 6.1 and RHEL 9's 5.14 the programs are left out, `tego doctor` offers
tier `cgroup`, and `TestTier2RunEndToEnd` and `TestTier2UnixEndToEnd` pass there, the unlisted datagram leaving as
tier 1 records it. RHEL 9's BTF names `BPF_CGROUP_UNIX_CONNECT` in `enum bpf_attach_type` and refuses a program of
that type, so only the load probe, never the enum, says whether the hooks exist.

**R8 — Fanotify enforces opens; `security_file_open` records opens, independently.** Marks exist only on mounts
holding an `fs` rule — an unruled mount gets zero overhead. `security_file_open` (fexit, cgroup-filtered, R9) fires
on every open regardless of mount, and is the only complete signal for read aggregation (E18) and `fs.watch`
individual events (E56). Losing one does not stop the other.
The open decision (`decideOpen`) refuses a path under a `deny_read` entry unless a `write` entry with a longer path
covers it. A `watch` entry takes part in no decision here: it grants nothing (SEMANTICS §7), and reopening under it
would make, say, `<target>/logs` readable under a `deny_read` nested in a write entry while `Evaluate` answers
`refused`.
*Name entries* (ADR 0043 D7, the fallback): an open the path entries allow is refused when a name entry covers the
opened file (`decide.ListenerOpenName`: the decision core's `NameIndex` asked of the canonical path the event's
descriptor reads back, its folded final component, its scopes and dependency directories by path, D3's exemption by
path), `read-denied` whatever the open's mode, named per D8 (the entry's own rule: no `deny_read` entry is at such a
path, or the path half would have refused it); a climb that cannot decide within the walk's bound is refused
`path-unresolved`, as the root model at tier cgroup refuses it. Each scope's mount and every mount point beneath the
scope are marked for `FAN_OPEN_PERM`, as a `deny_read` entry's are, and a mount table that cannot be read refuses
`Prepare` (`ErrMountTable`); a policy with a name entry is one that can refuse an open (`canRefuse`).
(A table with no name entry marks no scope for one; until 2026-10-27 a build switch, `agent.NameEntriesEnforced`, kept every product build there.)
*An unlinked file's path is decided under both spellings* (ADR 0043 C0). The readlink of an event's descriptor reads
`<path> (deleted)` for a file unlinked or renamed over while its open waited in `FAN_OPEN_PERM`; that spelling is
beneath no file-level `deny_read` entry and has no covered final name, so such an open of a `deny_read` file went
through. The open and the exec decisions, and `decide.ListenerOpenRefused`, which the supervisor's advisory
write-open verdict and `Evaluate` ask, decide such a path under that spelling and the one without the suffix and
refuse when either refuses (an exec is allowed only when both are); a file whose real name ends in the suffix is
decided under the shorter spelling too, the stricter side (`TestListenerDecidesTheUnlinkedSpelling`).
*A path that cannot be read back is refused for the run* (SEMANTICS §2). The readlink of the event's descriptor
fails for a canonical path longer than `PATH_MAX` (`ENAMETOOLONG`; a deep tree opened through directory descriptors
reaches one). Where the policy has an entry that could refuse the event, a `deny_read` entry for an open or an exec
list for an exec, the event is refused `path-unresolved` under the `unmatched` rule for an opener in the run and for
one whose membership went unread, with `gap what=enforce why=fanotify-path-unresolved` naming the error, and
allowed for an opener outside the run. Where no entry could refuse it, it is allowed with that gap. It had been
allowed with the gap alone, the run's read of a `deny_read` file given away
(`TestDecideEventRefusesAnUnresolvedPathForTheRun`).
The listener reads the opened file's path back from the event's descriptor, which the kernel gives in canonical
form, every symlink followed. So each entry is matched as compiled **and** with its symlinks followed: an exec
entry's `Path` and its `PT_INTERP` loader (`/bin/sh` runs as `/usr/bin/dash`, `/lib64/ld-linux-x86-64.so.2` as
`/usr/lib/x86_64-linux-gnu/...`), resolved at `Prepare`, which is when the inherited Landlock ruleset opens the same
entry and pins the inode it resolves to; and an `fs` entry's `Resolved`, the subtree it governs (agent-contract R7,
E8). An exec entry is matched by these paths, not by the file's `(device, inode)`: one inode can carry many names,
and a name the contract did not write is refused even when it is a hard link of one it did (uutils coreutils ships
its applets as hard links of one multi-call binary, so an inode match for `ls` would admit `rm`; `perl5.40.1` is
`perl`'s). That is the fail-closed side of the two, and Landlock's `EXECUTE`, granted by inode, still stands beside
it. The exec check refuses an exec no entry names, and nothing when the contract has **no `exec:` section**:
SEMANTICS §1's "deny nothing", read off `Contract.Exec == nil` exactly as the Landlock builder, the supervisor and
`Evaluate` read it (a table with no contract stays restricted); such a contract marks no mount for exec. No exec is admitted that no entry names, tego's own binary included: the group has no mark until the
run is armed (ADR 0021 (2)), after the child stage's `execve` of the launcher binary, so that exec, the run's first,
inside its cgroup, is never an event here, and every exec the group sees in the run is the agent's. Compared as
compiled strings alone and refusing whatever no entry named, the check refused `/bin/sh` and every dynamically
linked binary (the loader refused, exit 126). `TestTier2RunEndToEnd` is the acceptance: an unmodified
`-tags tegobpf` binary runs such a contract to the end.
*Marks are placed after the stage's exec, and no process starts while they exist* (ADR 0021 (2), (3)). `Prepare`
creates the group with no mark. `Arm`, which the runtime calls once the stage has written its control message on
pipe A (it writes it only after its `execve` has returned) and before the ack, marks the mounts and inserts the
run-set row (R11); the agent does not exist until the ack, so it meets both from its first `execve`. Marked at
`Prepare`, as they were, the marks existed while the launcher started the stage: Go's `os/exec` suspends the forking
thread until the child's `execve` is past its point of no return, the Go runtime cannot stop the world while that
thread is suspended, and the `execve`'s permission event, which only the same process answers, deadlocked the
launcher whenever a garbage collection began in that window, with every open on the marked mounts, host-wide,
behind it (E39: measured 6 stalls in 45 guest runs of `TestTier2RunEndToEnd` on AL2023's 6.12). An ignore mark on the
stage's binary kept that one file out of the group; it needed a statically linked, non-PIE launcher (the loader
opened in the same window), it hid every read of the binary from a `deny_read` entry covering it (so such a run was
refused, `ErrStageDenied`), and it did nothing for a second tego build or another listener's opens in the window.
All three are gone: the ignore mark, the admission by identity, `checkStage`, `ErrStageLinked` and `ErrStageDenied`
are removed (ADR 0021 (4)), a dynamically linked or PIE `-tags tegobpf` build runs the tier (`enforce.Buildable`
checks the objects only), and a `deny_read` over the tego binary is decided like any other file.
The group's first mark arms the process (`internal/platform/proc.Arm`), and `unmarkAll`, or the group's close, disarms
it: while armed, `proc.Start`, the one process start of non-test code (lint: `depguard` bans `os/exec` and
`forbidigo` the other starts outside `internal/platform/proc`), refuses with `ErrArmed`. Every start is also a reviewed
site (ADR 0021 (6)): `forbidigo` refuses a call of `proc.Start`, or of `cgroup.StartHelper` and `StartHelperExec`, the
one wrapper over it that tego's detached helpers start through, from a file `.golangci.yml` has no start-site
exclusion for, and `TestEveryProcessStartSiteIsListed` holds the same list by function and by count, each row saying
when its start runs against `Arm`. It follows a start one function out, which no lint rule can: an unexported
function that makes one of these starts (`startHelperIn`, `startHelperProcess`, `startOnKeptThread`, the reaper's,
the uprobe detacher's, doctor's) is followed by its bare name in its own package's directory, so a call of it from
another file of that package is a row too, whose relation says when that caller runs, and the function's own row is
`guarded`. A new start, E70's privileged-exec broker for one, needs a row, and an exclusion in `.golangci.yml` when
its call is one lint names. The child stage and the run's reaper have started before arming; the helpers the tier
starts (linger, ring trim, the uprobe detacher) start after `Detach` has closed the group.
`TestTier2ArmsAfterTheStageExec` is the acceptance, as root in the guest: tego, a hard link of it under
`deny_read: ["./out/tools/"]` and outside `exec.allow`, runs the run to the end, no exec line names the stage's exec,
the first is the agent's, and the agent's read of the binary by that name is refused with a `source=fanotify` line.
`TestStageExecUnderGCNeverWaitsOnItsOwnGroup` repeats the stage start under a busy collector with the order above.
*One mark per mount, not per device.* `FAN_MARK_MOUNT` marks the one mount a path resides on, and every bind mount
of a filesystem shares its source's device, so paths collapsed by `st_dev` would leave, say, a `deny_read` entry
under a bind of the root filesystem (`/data` bound from `/srv/data`) beside an exec entry on `/` unmarked. The paths
are collapsed by the mount `statx(2)` names (`STATX_MNT_ID_UNIQUE` from 6.8, which no mount reuses in a boot, else
`STATX_MNT_ID`, 5.8). A path whose mount `statx` cannot name is kept by name rather than dropped: below 5.8 that at
worst marks one mount twice, and a path removed since compile fails its mark, which refuses the run. `FAN_MARK_FILESYSTEM` would cover every mount of the filesystem in one
mark, but it widens the scope E34 already accepts to every mount of that superblock on the host, containers' bind
mounts included, so it was not chosen. As root in the KVM guest (6.17), a tmpfs mounted at one path and bound at a
second, with a `deny_read` entry under each: both opens are refused and counted; with a device collapse,
only the first mount was marked and the open through the second succeeded with no event
(`TestFanotifyMarksEveryBindMount`, `TestDistinctMountsKeysByMountNotDevice`). A mount that appears after
`Prepare` is still unmarked (E24 says why the agent cannot make one; `FAN_MNT_ATTACH`, 6.15, could report the host's).
A `deny_read` entry's marks include every mount point strictly beneath it, from `/proc/self/mountinfo` read and
parsed once per `Prepare` (`mountPointsUnderFrom`; the `.env` scan's entries are many): a mark covers one mount, and Landlock leaves an entry nested in a write entry
unenforced, so a tmpfs or a second disk mounted beneath a denied tree would otherwise be read with no refusal while
the record said refused. A mount table that cannot be read refuses `Prepare` with `ErrMountTable` for a table
with a `deny_read` entry, never a policy marking none of the submounts (I7). A tier-3 run has no listener and
builds no policy, so it reads no mount table here (enforce-plane R12 decides when its plane needs one). A mount the host makes beneath the
tree after `Prepare` (autofs, a systemd automount) stays unmarked.
*A mark asks only for what can be refused there, and what the path allows is answered on the read loop.* A mark
asking for both permission events on a mount marked for exec entries alone (in the KVM guest, the root filesystem
where `python3` lives) would hold every open of every process for a decision `decideOpen` could only answer with an
allow: kill test 4's pip install paid a round trip on each of its opens (§9). Two rules, and neither changes a
verdict:
(1) A mark asks for `FAN_OPEN_PERM` only on a mount where a `deny_read` entry can refuse an open: the entry's own
mount, and the mount of any exec path an entry covers (a `deny_read` on `/opt` covers `/opt/tools`, a mount of its
own that an exec entry marked). It asks for `FAN_OPEN_EXEC_PERM` on every marked mount while the exec check can
refuse, and on none under a contract with no `exec:` section (`markMasks`; `TestMarkMasksAskOnlyForWhatCanBeRefused`,
`TestPrepareMarksEachMountForTheEventsItCanRefuse`, and as root `TestExecOnlyMarkAsksForNoOpenEvent`, which reads
the mark's mask from the group's fdinfo and opens a file there 50 times with no event).
(2) An event its path alone allows is answered on the read loop (`settleByPath`), not by a worker (E35).
*No directory is ignored.* An evictable ignore mark (`FAN_MARK_IGNORE`, `FAN_OPEN_PERM|FAN_EVENT_ON_CHILD`) on the
directory of an allowed open whenever the policy allows every child there, so that directory's later opens never
leave the kernel, is not fail-closed and is not used. An ignore mark belongs to the directory's inode, not to the
path the verdict was given for, and it moves with the directory: renamed into a `deny_read` tree, by the agent or by
any process on the host (the user's shell, a credential tool), or carried there by the rename of an ancestor, the
directory keeps the mark, and no open under its new name is asked about. As root in the 6.17 guest with such a
mark, a file a process outside the run created there after the rename, which no name had ever made readable, was read by the run with no refusal and no line, and the run's own
create in the denied tree was allowed (`TestDirectoryMovedIntoADeniedTreeIsStillAsked`, which fails with the mark
restored). Nothing in fanotify can take the mark off before an open through the new name: `FAN_MOVE_SELF` and
`FAN_RENAME` are notifications, read after the rename has happened, and a directory moved with an ancestor raises
neither for itself. The marks were also charged, like every mark, to root's `fs.fanotify.max_user_marks`, and a cap
per listener bounds no total across concurrent runs. So every open on a mount a `deny_read` entry can refuse opens
on is asked about, and §9 records what that costs. **Condition** for sparing the opens
the policy allows there: a way to drop such a mark before any open through the directory's new name, which
fanotify does not have (a rename permission event would be one), or the decision made in the kernel with no
listener to skip, which is tier 3's BPF LSM path.
*The host-wide share of the marks.* Each run holds one fanotify group and one mark per marked mount, all charged
to root, against quotas that every other fanotify user of root on the host draws on as
well: `fs.fanotify.max_user_groups` (128 by default) and `fs.fanotify.max_user_marks` (as many inode marks as
1% of memory holds, from 8,192 to 1,048,576). A host running that many tier-2 runs at once, together with whatever else of root watches files,
uses them up; `Prepare` or `Arm` then refuses the run with `ErrFanotify`, naming the setting (§7), and never runs it
without its marks (`TestFanotifyQuotaFailuresNameTheirSetting`).
*A refused create leaves its file behind, empty.* An `open(2)` with `O_CREAT` of a new path
under a `deny_read` entry is refused here with `EPERM` and a refusal line, and an empty file is still left at that
path. The kernel creates the inode during the open's lookup, before `do_dentry_open` raises `FAN_OPEN_PERM`, and a
permission event can refuse the open but cannot undo the create. The content stays refused: no descriptor was
returned, so nothing was written through that open, and a later open of the file is asked about like any other.
What allowed the create is the inherited Landlock ruleset: a `write` entry above the denied tree, the case this
listener exists for (enforce-landlock R4), grants making a file there, and creating one is a write, which stays
Landlock's to refuse, like a delete, a rename and a mkdir, which this package only records (R9), and a mknod,
which it does not see. As root in the
6.17 guest, `TestDirectoryMovedIntoADeniedTreeIsStillAsked`'s own create in the denied tree is refused with a line
and leaves the file there, empty; the test checks that a file so left is empty.
`Evaluate`'s `cgroup` column answers such a write as this listener does, `refused`/`read-denied` under the
`deny_read` entry unless a longer `write` entry reopens the path, not from the Landlock union. A delete, rename or
mkdir stays the union's.
*Amended 2026-10-17 (ADR 0021 (5), ADR 0028 S3):* the empty file above is this listener's
own behaviour when nothing refuses the create first, which in a tier-cgroup run no longer happens beneath a
`deny_read` nested in a `write` entry. There the supervisor's listener fallback (`fallbackMutation`,
internal/runtime/supervisor/fs.go; supervisor R15d for a move) refuses a create, a creat, a write or truncating
open, a truncate, a delete, a rename or link into the tree, a mknod, a symlink and a mkdir with `EACCES` before
the kernel acts, so no file is created and no `FAN_OPEN_PERM` is raised for it (`TestFallbackMutationConverges`;
the conformance fixture's cells under the nested `deny_read`, which fail as a fail-open with `fallbackMutation`
disabled). "Stays Landlock's to refuse" and "this package only records" hold for this package's own programs, not
for the run. `Evaluate`'s `cgroup` column refuses the same mutations through the root walk before the Landlock
union (internal/policy/decide/evaluate.go), so "a delete, rename or mkdir stays the union's" is withdrawn.
`TestDirectoryMovedIntoADeniedTreeIsStillAsked` drives this package's listener without the supervisor, which is
why its create still leaves the file.

**R9 — Opens and file operations: Landlock enforces, `trace_proc` records the kernel's own verdict, from raw
identifiers, never a resolved path but an open's.** The fs programs are fexit programs (ADR 0016 (3), as built
2026-09-29) on every `security_` function where the run's inherited Landlock domain can refuse: `security_file_open`,
`security_path_mknod`, `_mkdir`, `_rmdir`, `_unlink`, `_rename`, `_link`, `_symlink`, `_truncate`, and
`security_file_truncate` where the kernel has it (6.2+; the backend leaves the program out of the load below, where
`security_path_truncate` sees those calls). Each runs after the function returned and records its signed return:
the answer of the whole LSM chain, Landlock's included, which on kernels up to 6.12 also includes fanotify's
permission answers (`security_file_open` returned `fsnotify_open_perm`'s there) and on no kernel IMA's or anything
checked after the function. The recorder maps it (`decide.ChainFS`): 0 is `allow`; a `-EACCES`, `-EPERM` or
`-EXDEV` the tier's model explains (`decide.InferFS` refuses the same action) is `refused` with the model's reason
and entry; anything else is `observed` with `errno` and `by: other` in the payload, never `refused` with a reason
from REASON-CHANNEL's closed set, which names Tego's refusals only. The model decides no verdict it can see: it only
explains a refusal, and names the entry. A line says which produced its verdict (`verdict_from: chain|model`):
`model` is a record that carries no return (`ret_ok` 0), and a read under an unenforced `deny_read` entry, which the
listener answers and, from 6.13, outside the chain (R8). A refusal is recorded under `record: off` too: the program
skips its reserve for `record: off` only when the chain allowed, and the recorder keeps the lines Tego's refusals
make of them (`TestRecordOffRecordsTheChainsRefusals`). `security_socket_connect` stays fentry: it returns before
`connect4/6` decide, so its return never holds the cgroup verdict (R4, R5).
*Which producer writes the line* (supervisor R7a): this recorder, for every fs action its hooks see, and the run's
supervisor writes none for such an action it continued, handing this recorder its naming instead
(`Options.ContinuedFS`), which names a record the directory index cannot (a directory no entry is, a rename's or a
link's other end) with the supervisor's spellings and rule, the chain's return staying the verdict and the
supervisor's the model that explains a refusal. An allowed modification is named by the entry whose grant allowed it
(`decide.GrantName`), as `compile --test` names it, not by a `deny_read` or `watch` entry nearer to the path; a
write-open outside every entry that the chain refused is Landlock's refusal, `unmatched`. An open the fanotify
listener refused after Landlock let it through is the listener's line, and this recorder writes none
(`decide.ListenerOpenRefused`, or once name entries are enforced `decide.ListenerOpenName` (ADR 0043 D7), unless the
chain returned `EACCES` or the mount is unmarked, E24; the marked mounts include each name entry's scope's then).
That holds only on the fallback: where a plane mode decides the run there is no listener, so no open is left to
one, and a read under an unenforced `deny_read` entry keeps the chain's answer, the plane's (amended 2026-10-27: an open the plane let through, at a name its inode exemption allowed or of a file its rows did not
key, was dropped or recorded refused by the path model). A
plane refusal by a name entry (a `rule_idx` tagged `PlaneRuleName`) of a file with a `deny_read` entry at its
canonical path is named by that entry (ADR 0043 D8's first choice), an expansion entry compaction dropped from the
rows; otherwise by the name entry's own rule. While the supervisor
writes every exec's line (`Options.SupervisorExecs`), this recorder writes no exec line and keeps its process cache
and hooks. *Amended 2026-10-25 (ADR 0069):* an `O_PATH` open is no action this recorder or the listener
sees: `do_dentry_open` returns for it before `security_file_open` and the fanotify permission event, and the
decision plane's only open hook is `file_open`. So where the filter notifies one (`record: full`, a read gate, held
reads), the supervisor writes its line even while this recorder reads, `allow` with the marker ` (O_PATH: reads
nothing)` beneath a `deny_read`, and leaves a tombstone in place of a naming (supervisor R7a); before, it handed the
naming to this recorder, which never wrote the line, and with no recorder reading wrote `refused` for an open the
kernel let through.
*One action, one line.* An `O_CREAT` open asks `security_path_mknod` in `may_o_create` before it knows the file is
there, and a refusal there only clears `O_CREAT`, so a regular-file, no-device mknod is held in the task's storage
(`tego_task_scratch`, a `TASK_STORAGE` map the object pins by name): a `security_file_open` with `O_CREAT` of the
same dentry drops it (the open went ahead, and its line, with `created: true` when it made the file, is the action's), and anything
else — a `mknod(2)` (an open of its file without `O_CREAT` is not its own), or an `O_CREAT` open that failed
there — leaves it to be emitted with its own return as an
`open` line with `O_CREAT`. An `O_TRUNC` open of an existing regular file that the chain allowed is held too, and the
truncate hook that follows (`security_file_truncate`, or `security_path_truncate` below 6.2) on the same dentry
writes its return into it and emits it: a truncate the chain refuses is that open's line. A truncate of another
dentry is not the open's (the open failed after the chain, in the filesystem's `->open`, fanotify's answer from 6.13
or `security_file_post_open`): the open is emitted as the allow the chain answered and the truncate is its own
line. A held record not consumed is emitted by the
task's next recorded event or at the exit of its thread. An allowed `O_CREAT` open that `security_inode_create` or
the filesystem then fails, and an `O_EXCL` create of a file that was there, are recorded as the allowed mknod the
chain answered. Files the kernel opens on a task's behalf are skipped: every file with `FMODE_NOACCOUNT` (bit 29 on
every kernel from 5.14 through 7.0), which every stacking filesystem's backing file carries (with `FMODE_BACKING`,
6.5+, whose bit moved from 25 to 24 in 6.14) and below 6.5 the overlay real file `open_with_fake_path` opens, whose
user path the task's own open already recorded; and every file on a private clone of a mount (`mnt_ns`
`MNT_NS_INTERNAL`, the plane's `tego_internal_mount`, enforce-plane §2.7 condition 1), where overlayfs' copy-up
opens the lower file and the new upper one with a plain `dentry_open` in the task, after the task's own open of the
merged file, so a first write to a lower file is one line, the user path. An overlay open whose real file's open
then fails is recorded as the overlay open the chain allowed.
No path string is read but an open's: `bpf_d_path` from a non-LSM tracing program is gated by
`btf_allowlist_d_path`, a small fixed `BTF_SET` including `security_file_open` and `security_path_truncate` but
excluding every other `security_path_*` **on every kernel version** (R10). Each file-operation program reads
instead, via `BPF_CORE_READ` off its BTF args, the parent directory's `(dev, inode)` and the final path component's
raw bytes (`d_name`) into `ev_fsop` (§2.3), and the truncate programs share that layout. `Recorder` names the path
and the entry in userspace, looking `(dev, dir_ino)` up in `dirIndex` (§2.4), a plain Go map built once at
`Prepare` from the compiled `RuleTable` (`O_PATH`-open + `fstat` each declared dir), never a kernel
`BPF_MAP_TYPE_INODE_STORAGE` (ADR 0010 stays tier-3-only): a hit yields the entry and `<entry path>/<name>`; a miss
(nested descendant, symlinked alias, a second end's parent no `fs` rule names directly) yields the raw
`dev:ino/name` and `attribution.confidence: unattributed`, with the chain's verdict (`observed` where the record
carries none). `dirIndex` identity inherits ADR 0005's own caveat (btrfs subvolume `st_dev` reuse, overlayfs
numbering) — bounded, record-only, never enforcement (Landlock owns that decision via its own kernel-side ancestry
walk, ARCHITECTURE §10).
*On btrfs, and on an overlayfs of one filesystem, nothing resolves, and the run says so.* The record carries the
parent's super block `s_dev`; `dirIndex` is keyed by `stat(2)`'s `st_dev`, and the two are equal only where
`getattr` reports the super block's device. btrfs reports the subvolume's anonymous device
(`BTRFS_I(inode)->root->anon_dev`) and never the super block's, and an overlayfs whose layers share one filesystem
reports the layer's, so every unlink, rename and mkdir under such an entry misses. Following ADR 0025, which rejects `(super block, inode)` keys because btrfs subvolumes repeat inode
numbers under one super block (a key could name a nearer entry than the true one), no key is guessed for them:
`newRuleIndex` compares each declared path's `st_dev` with its mount's super block device (`statx`'s mount id,
then `/proc/self/mountinfo`'s `major:minor`, which `fs/proc_namespace.c` prints from `sb->s_dev`), leaves out an
entry where the two differ, and the run records `gap what=record why=dir-unindexed count=<entries>` once when its
recorder starts reading; an operation beneath such an entry is `dir-unresolved`, `observed`, as any miss is
(`TestDirIndexLeavesOutAnEntryStatDoesNotNameBySuperBlock`, `TestRecorderSaysWhichEntriesItCannotIndex`, and as
root `TestIntegrationFSOpsResolveThroughTheDirectoryIndex`). Resolving them needs an identity the kernel's records
and userspace share there, which is ADR 0025's inode-pointer plane at tier 3, not this index.
*A rename, and a link, is modelled at both ends.* Landlock refuses a rename whose destination directory grants no
write (and, across directories, no `REFER`), so the source's model alone would explain an `EXDEV`/`EACCES` from the
destination as no refusal of Tego's. The second end's `(dev2, dir_ino2)` is looked up as the source's is: a hit
whose entry `inferFS` refuses a write under explains the refusal as `rename-outside-contract` (a link's as
`write-outside-contract`) naming that entry; a miss leaves the model with no answer (`observed` on a record with no
return). *Amended 2026-10-17:* the Landlock ruleset every
enforcing tier keeps refuses with `EXDEV` what the plane's `path_link` and `path_rename` allow: a link whose source
directory has no `REFER` (a file-level write entry linked elsewhere) and a link or rename into a place where the file
gains a right (an `exec.allow` directory's `EXECUTE`). The model explains both by the decision core's Landlock rules
(`decide.LandlockLinkRefusal`, `decide.RenameGainedBy` on the index), named as tier 1's line and `compile --test` name
them, where the line said `observed` by another mechanism (`TestRecorderNamesTheLandlockLinkRefusal`). An observe run
installs no ruleset, and the model refuses nothing there. *Amended 2026-10-17:* a
rename's no-gain rule is the kernel's (supervisor R17's amendment): nothing within one directory, and across
directories the new name's directory against the moved object, never a rule on the name it replaces, so a chain
refusal of a rename onto an `exec.allow` file entry is another mechanism's (`observed`, `by: other`), not
`rename-outside-contract`. A rename sample does not say whether it moved a directory, so the object is compared as
one, every right counting; no compiled table differs between the readings, since every write entry carries the whole
write set. *Amended 2026-10-17:* the floor's directory rights are part of
the model for a rename and an unlink at every enforcing tier: `REFER` on both ends' directories and the no-gain rule
for a rename (`decide.LandlockRenameRefusal`), `REMOVE_*` on the directory for an unlink or rmdir
(`decide.LandlockDeleteRefusal`), asked before the ends' own entries and named by the directory that lacks the right,
as tier 1's line and `compile --test` name them. At tier 3 the plane's hooks decide on the objects, so a file-level
write entry's own rename or unlink, which the floor refuses with `EACCES`, read `observed` by another mechanism. Each
end is the name the syscall acts on, its directory canonicalized and its final component not followed, so a symlink
fs entry's own name is the symlink. And the exec grants' rights are those of the inodes the index held when it was
built, before the agent ran (`decide.HoldExecGrants`), matched against each end and its directories by `lstat` in
this process's view: after the agent moves an `exec.allow` directory within a write entry, a chain `EXDEV` on a rename
or a link into its new name is the ruleset's (`TestRecorderExplainsReferByTheHeldInode`,
`TestRecorderNamesTheLandlockLinkRefusal`). The same held inodes explain a chain refusal of an exec's open: an exec
Evaluate matches by an entry whose name no longer holds the inode the builder granted `EXECUTE` to is granted by
nothing, so the refusal is the ruleset's, `refused`, `unmatched`, `exec-not-allowed`, as the supervisor's line says
(supervisor.md R16b: `dirHeld` for a directory entry, `execIDs` for a file entry); it read `observed` under the
entry, by another mechanism. That holds for a directory entry (after `mv out/bin out/old; mkdir out/bin`;
`TestRecorderExecOpenFollowsTheHeldDirectory`, the conformance cell `refer/exec-in-recreated-exec-name`) and for a
file entry whose name holds another inode (an atomic replace of a declared binary, or its directory moved away and
another renamed onto it; `TestRecorderExecOpenFollowsTheHeldFile`, `refer/exec-replaced-exec-file-entry`), at the
plane axes. The recorder runs after the syscall, so the held inodes are matched when the sample is processed, not
when the kernel decided: a tree the agent changed again in between (the held inode moved back under the name before
the recorder drained the sample) leaves the line at the declared names' answer, `observed` by another mechanism. The
supervisor's `dirHeld` and `execIDs` match the inodes when the notification arrives, before it continues a granted
exec for Landlock's EXECUTE to decide on the inode (supervisor.md R16b); only the notifying thread is stopped, so
another task of the run that renames or replaces the entry between that stat and the kernel's `do_open_execat` can
still make tier 1's line differ, in a shorter window than the recorder's. The floor's explanations of a rename, a link
and an unlink take the sample's ends as `bpf_d_path` gives them, landed, and never rewrite one by a link's declared
spelling (`decide.LandlockRenameRefusalBy`, `LandlockLinkRefusalBy`, `LandlockDeleteRefusal`; agent-contract R15).
`dirIndex` is keyed under each entry's canonical path (`FSRule.Resolved`), and a hit yields `<canonical entry
path>/<name>`, the spelling `bpf_d_path` gives an open.
*The entry that names an action does not decide its verdict.*
The nearest entry of any kind names the event, `watch` and implicit entries included (SEMANTICS §7), but the model's
verdict, of an open as of a file operation, is `decide.FSDecider`'s (`decide.InferFS`), the chooser
`Evaluate` decides by: a read by the nearest `write` or `deny_read` entry (a `write` entry nested at an enforced
`deny_read` target granting by Landlock's union), a modification by the nearest entry that is not a `watch`: the
naming entry deciding would record a read of the run's own ledger under the built-in `deny_read` on `~/.tego` as
`allow` under `fs.implicit`, and a write under `watch: [/work/logs]` nested in `write: [/work]` as `refused`, both
against what the tier did.
At tier 2 the model of an unlink's or rename's verdict (each end of a rename) is `FSDecider` asked of the **parent
directory** of the path, where the inherited Landlock ruleset checks `REMOVE_FILE`/`REMOVE_DIR` and `REFER`: asked of
the path itself it would not explain Landlock's refusal of the unlink of a write entry's own path (`write: [./out]`,
`rm -rf out`), which `Evaluate` answers `refused`. Tier 3's hooks decide on the path, and are asked of it. `FSDecider`, like every walk
of `Evaluate`, first rewrites a prefix equal to a symlinked entry's declared path into its resolved path
(agent-contract R15).

**R10 — No kernel-version split for tier 2's record programs, but `security_file_truncate`.** ARCHITECTURE §10's
5.11/6.8 sleepable-hook version split (`bpf_d_path_allowed`) is scoped to **BPF LSM programs** (tier 3 only,
`BPF_PROG_TYPE_LSM`) — it does not apply here. `security_file_open`'s fexit program is in `btf_allowlist_d_path`
unconditionally and may call `bpf_d_path` on every kernel this project supports (5.14+); the file-operation programs
never call it (R9). Every function's prototype is the same from 5.14 through 7.0 (security/security.c at v5.14,
v6.1, v6.8, v6.12, v6.17 and v7.0, checked 2026-09-29), and each fexit program declares all of it, because its
return is read from the slot after the last argument (`TestAttachTargetsResolve` fails a program that declares
fewer). The one split is `security_file_truncate`, added in 6.2: below it the backend leaves that program out of
the load (`bpf.OptionalTracePrograms`) and doctor's D7 row is optional, and `security_path_truncate` sees
`ftruncate(2)` and an `O_TRUNC` open's truncate there. Where a record carries no return (`ret_ok` 0) the recorder
falls back to the tier's model and says so (`verdict_from: model`); every kernel of the matrix (RHEL 9's 5.14,
AL2023's 6.1, 6.8, 6.12, 6.17, 7.0) has a BPF trampoline on x86_64 and so the fexit programs wherever fentry ran
(arm64 has no trampoline below 6.0, where neither loads). **Two builds of `trace_proc`, one per reader** (ADR 0016's
variant for `lockdown=confidentiality`, ADR 0024's tier-2 note): `lockdown=confidentiality` refuses
`bpf_probe_read_kernel` (and the legacy `bpf_probe_read`) at load on every kernel, 6.17 included. `trace` reads
through CO-RE probe reads; `tracerd` (`TEGO_TRACE_RDONLY=1`) makes none, reading fields by direct loads off the
programs' BTF arguments and kernel strings (an exec's filename, a dentry's name, a symlink's target) a byte at a time
through `bpf_rdonly_cast` in a `bpf_loop`. `bpf.Load` hands out `tracerd` wherever the kernel's BTF has
`bpf_rdonly_cast` and `bpf_loop` (6.2+, RHEL 9.8's backports), whatever the lockdown, and `trace` elsewhere
(`bpf.ChooseReader`, the plane's rule); both are one object with one set of programs and maps, pinned under one
`bpf_hash`. `cgroup_track` reads by direct loads and `cgroup_net` by `bpf_rdonly_cast` in their one build, so they
load under every lockdown. `bpf_probe_read_user` (argv, capture's buffers) is not refused by lockdown; cilium/ebpf
turned it into `bpf_probe_read` when its own feature test for `bpf_probe_read_kernel` failed under lockdown, which
`internal/bpf` fixes to present (every supported kernel has the helper). **Condition:** a kernel under
`lockdown=confidentiality` whose BTF lacks `bpf_rdonly_cast` or `bpf_loop` (AL2023's 6.1) has no build that loads:
`Prepare` refuses with `ErrProgramLoad` naming lockdown before creating anything, and doctor's D7 fails tier
`cgroup`'s rows with that cause (limits-check-doctor-cli R27 D7), so tier selection never picks the tier there.

**R11 — Descendants are P0-scoped to the run's own cgroup subtree.** `cgroup_mkdir` (`SEC("tp_btf/cgroup_mkdir")`,
BTF args `(struct cgroup *cgrp, const char *path)`) fires before `kernfs_activate()` (verified, ARCHITECTURE §4.1):
reads the new cgroup's kernfs id and its parent's id, looks the parent up in `run_set`, inserts
`{new_id→parent's run_val}` with `BPF_NOEXIST` (mirrors ADR 0010's "re-read on `EEXIST`"). `cgroup_rmdir` deletes
it. At `Prepare`, userspace scans cgroupfs under the run's own cgroup for children that already exist, closing the
same race for anything created before attach. **Cross-daemon lineage adoption and the Docker-proxy pre-created
parent (E42/E43) are P2** — out of scope here (R11).

**R12 — `run_idx` is a dense per-host slot, never the string run id.** Freed only after every map row referencing
it is gone (`Detach` removes the run's rows, then releases the slot, and holds the slot when a removal failed). The
slot's rings are not freed with it: they stay for the slot's next run, which drains them before its own row exists,
and every record carries the generation of the row its program found (`tego_run.gen`, the slot's epoch: one more
than the slot's last run's, never 0, kept in the slot table across release, so it repeats only after 2^31 - 1 runs of
that one slot; the low half of the run's cgroup id served before, and repeats once kernfs's idr wraps), so a run's recorder and capture source drop a record of the
slot's previous run that the drain did not reach (ADR 0026 (6) as amended; `TestTheSlotsNextRunReusesItsRings`,
`TestRecorderDropsTheSlotsPreviousRun`, `TestSourceDropsTheSlotsPreviousRun`, and as root
`TestIntegrationAReusedRingHidesThePreviousRun`). A slot reclaimed from a launcher that died without a `Detach` is
scrubbed of that launcher's rows, and its counters zeroed, before the new run's are written (§6 E32) — the maps are pinned, so a crash leaves rows behind that no `Detach` will ever remove. A slot any
`tego_run_set` row still carries is never handed out, free or held by a dead launcher (ADR 0026 (6),
`TestSlotACarriedSlotStaysHeld`): `Prepare` reads the build's pinned run set before it loads anything, so the slot
of an orphan that outlived its launcher stays held, and no new run's ring receives that orphan's samples. Slots come
only from the slot table in `/run/tego` (ADR 0034).

**R13 — Aggregation window.** Non-watched, non-`deny_read` reads accumulate in `aggTable` keyed `(exec_id, rule)`,
flushed as one `fs` event on `sched_process_exit` (final count) and every 5s while still running. `deny_read` and
`fs.watch` paths are never aggregated — each is its own immediate `fs` event.
The table holds at most 4096 buckets (`DefaultAggregateLimit`): a read that would open one more flushes every bucket
at once, before the 5 s window ends, and the run records `gap what=record why=aggregate-overflow`, counted once per
forced flush; counts stay exact, only split across more lines.
The 5 s window, and the lost-counter poll that shares it, is checked after every sample as well as when a read
finds the ring empty: a busy run's producers can keep its ring from ever running dry, and a
live process's counts and the kernel's drops must not wait for its exit or `Stop`
(`TestRecorderPeriodicFlushUnderANeverEmptyRing`).
Under `record: full` nothing is aggregated (SEMANTICS §7): each read is its own `fs` event, with the file it opened
and the verdict its aggregate would have carried, as tier 1 records each read under `full`. The inherited tier-1
filter notifies every read under `full` at this tier too, so a `full` run's reads are two lines each, the supervisor's and this one, as its execs and
connects already are. Bounded as every other event is: the recorder emits into the run's queue, which drops and
counts `channel-full` past its depth rather than grow (`TestRecorderRecordFullDisablesAggregation`).
A bucket's `path` is its entry's path; an `unmatched` bucket has no entry to name and names the deepest directory
holding every file it counted (the file itself while it counted one), never the first file it saw, which would read
`count=200 path=/usr/lib/python3.12/os.py` as two hundred reads of one file.
The directory, not a sample file, because it is true of every read the count covers and costs one string a bucket
(`TestAggTableNamesTheDirectoryItsReadsLieUnder`).

**R14 — Pin/detach follows the shared build lock exactly as ARCHITECTURE §6 states**, applied to the six kernel
maps this component owns (`run_set`, `net_key`, `cidr_key`, `reason`, ring buffer, lost counter — §2.2/§2.3, five
rows of §3's 12-row table since `net_key`/`cidr_key` share one), programs and links — the table's other seven rows
are not pinned/detached by this rule. One `bpf_hash` directory and lock file for the whole component.
Every removal of a build returns only once the kernel has released the build's links (`teardown`): each link is
opened before its pin is removed and that descriptor closed after, which makes the removing process's close(2) the
last reference where the pin's release is immediate (6.17), and the removal then waits, bounded by 30 s, until the
kernel has freed every program those links ran, which it does only after it has released each link over them. The
last launcher out removes its own shared links' pins before closing their descriptors, and waits once it holds no
descriptor of the build. Removing the pins happens under the exclusive lock, and nothing of the build can be adopted
after it.
*Amended 2026-10-19:* the last launcher out closed each host-wide link's
descriptor before it removed the pin (§9's change (4)), and every other removal (`gc --builds`, the linger timer's
sweep, a reaper's `ReapBuild`, `Prepare`'s and `tego stop`'s sweep of a build whose timer cannot start) removed the
pins alone, so the pin's removal dropped the last reference, and the kernel released the links after the removal
returned: from a workqueue on 6.8, 6.12 and 6.17 (`bpf_link_put` defers there), after an RCU grace period on RHEL 9's
5.14 (its bpf filesystem frees an inode from an RCU callback; this paragraph had said 5.14 frees in the launcher,
which `TestBuildRemovalReleasesLinksBeforeReturn` refutes). The next run's load waited for that release in
`bpf_trampoline_get`, 1.4 to 3.3 s of a cold start on 6.17 (enforce-plane §10.1, gate G-H2). The removal now takes
that time itself, off any run's path where the build lingers (ADR 0022: the timer's sweep), and on the last run's
way out where `bpf.linger` is 0. A pin this process cannot open as a link is removed alone, as before, and a program
something outside the removal still holds after 30 s is left to the kernel, as every removal was before. Two
departures from the earlier plan: the order is not its tracing links first, then the plane's, then the cgroup
links, but the decision planes' directories first, because a plane must be gone before any map of the build it reads
(enforce-plane R20), then the capture probes' and the build's own links in directory order, then its programs and
maps; and the fallback logs nothing. The order cannot change the outcome: the wait covers every program a removed
link ran, whichever link the kernel released first. The fallback needs no line: its causes are a pin already gone, a
pin that is not a link and one the remover may not open, the removals that reach it (`gc --builds`, the linger
timer's helper, a reaper) have no run whose log could take it, and its only effect is the timing every removal had
before, which the cold attribution measures (enforce-plane §10.1, gate G-H2).
`TestBuildRemovalReleasesLinksBeforeReturn` (the sweep, a reaper and the last launcher out) and
`TestPlaneRemovalReleasesLinksBeforeReturn` (with the plane) found 17 of the build's programs, and 43 with an LSM
plane, still held when the removal returned on 6.17 before, and on 5.14 every link too; none now.
*Amended 2026-10-05:* the build's pins are removed links first, then programs, then maps, and a
link pin that cannot be removed keeps the programs and maps (`pinLayout.remove`, and `unpin` for the links a
launcher did not attach, such as the listener links of a run without a listen contract); maps first left links over
maps no launcher held when a sweep was killed or failed between the two. A launcher adopts a pinned host-wide link
only when it runs the launcher's own program or one reading only the launcher's maps (`attachShared`, as plane links
are under enforce-plane R20); any other is unpinned and the launcher's own attached, and one that cannot be unpinned
fails the load. Adopted blind, a stale `sys_exit_execve` link set `ExecOutcomes` and the supervisor handed failed
execs to programs over a dead run set that reported none (`TestStaleSharedLinkOverARecreatedBuildIsNotAdopted`,
`TestPinRemovalKeepsMapsUnderALinkItCannotUnpin`).
*Amended 2026-10-05:* a host-wide program is attached the way its attach kind says, and
`bpf.AttachTrace` is the only code that acts on a kind: `attachShared` and every integration fixture that loads
`trace_proc` attach through it. The kind follows from the name (`bpf.AttachKindOf`): the syscall-result programs
of `bpf.ListenerTracepoints` and `bpf.ExecResultTracepoints` (`sys_exit_execve`, `sys_exit_execveat`,
`sys_exit_bind`, `sys_exit_listen`) are `BPF_PROG_TYPE_TRACEPOINT` programs attached by `link.Tracepoint` on their
`syscalls` event, every other program of `bpf.TrackPrograms` and
`bpf.TracePrograms` is a `BPF_PROG_TYPE_TRACING` program (raw tracepoint, fentry, fexit) attached by
`link.AttachTracing`, and a name in neither list, a missing program and a program of the other type are refused
with the program named, before the kernel is asked. What the library answers an attach is returned unwrapped,
because `bpf.ExecResultAttachUnavailable` reads its text, and a refusal of the helper's own is a failed load
for every program, never the optional exec-result link the machine declined
(`TestAttachRefusalIsNotAnOptionalLinkFallback`). The observe fixtures had kept a copy of the choice from
when the exec-result programs were the only tracepoints, and attached the listener programs as tracing, so fifteen
tests of the tegobpf observe suite failed on each boot as root in the guest with "invalid program type
TracePoint, expected Tracing" (`TestTraceProgramsAttachByTheirProgramType` holds each program's kind to the type and
event its `SEC()` compiles to, in both builds of `trace_proc` and in `cgroup_track`;
`TestAttachKindOfNamesEveryHostWideTracingProgram`, `TestAttachTraceRefusesBeforeAskingTheKernel`).

The last launcher out removes nothing when the machine's `bpf.linger` is above 0 (ADR 0022, default 5m): it stamps
the build lock's mtime and, once it holds nothing, starts the build's timer, `tego __bpf-linger` (one per build, by
a `bpf-<hash>.timer` flock; a hash that is not one path component is a usage error, as for `tego __ring-trim`),
which sleeps until the lock's mtime (read through the verified state directory's descriptor) plus the linger, and
exits once its build is gone (`TestTheTimerSleepsOutTheLingerThenRemovesItsBuild`,
`TestTheTimerBacksOffWhileALauncherHoldsItsBuild`, `TestTheHelpersRefuseANameThatIsNoBuildHash`). While a launcher
holds the build it looks again a linger later, a second at least, at its own build only (its build lock taken
exclusively for a moment, as a sweep's look does), and sweeps again only at the deadline the launcher's last-out
stamp sets: the launcher left no earlier than the look that found it, so ADR 0022 (8)'s bound holds for a linger
under a minute too (`TestTheTimerKeepsTheBoundWhenALauncherLeavesWithinTheLinger`: 10 s, left at +1 s, removed by
+12 s; `TestTheTimerBacksOffALingerWithASecondsFloorAndProbesOnlyItsOwnBuild`). A build whose run set names a live
cgroup or cannot be read is asked about a linger later, a minute at least; between those looks it reads the build
lock's mtime once a linger, a second at least, and a new stamp there (the reaper's, once it purged the run, or a launcher
leaving last) is a new deadline it waits out from there, so the bound holds when the last run was an orphan too
(`TestTheTimerKeepsTheBoundWhenTheRunItWaitedForIsReaped`: 10 s, reaped at +1 s, removed by +12 s). A timer whose build is gone lets its timer
lock go before it looks whether the build was made again; if it was, it takes the lock again (by a name that still
leads to the file it locks, as the build lock is taken) and keeps going, unless the new launcher's timer holds it
(`TestTheTimerTakesItsBuildBackWhenItIsMadeAgainAsItExits`,
`TestTheTimerLeavesABuildMadeAgainToTheTimerThatHoldsItsLock`). It removes the build (`SweepBuilds`) only when its lock can be taken exclusively, its
run set names no cgroup that exists (rows of vanished cgroups are deleted first, an id only when two listings 50 ms
apart both miss it, since `cgroup_mkdir` inserts a descendant's row before its directory is visible; keys only, the
one layout every build shares), and it has been idle for the linger; past two lingering builds the ones idle longest go. A
sweep that keeps a build because its run set names a live cgroup stamps the build lock's mtime, since the build is not
idle, so later sweeps list the cgroup tree for it again only a linger on, not at every `Prepare`
(`TestASweepThatKeepsALiveBuildLooksAgainOnlyALingerLater`). The timer
runs in `tego.slice/helpers.scope` at the cgroup2 root (`cgroup.StartHelper`), not the launcher's cgroup, so
stopping the launcher's unit, CI job or scope does not kill it (one that cannot be put there starts in the
launcher's cgroup with `TEGO_HELPER_UNPLACED` naming why; that includes a cgroup2 mount that is not the tree
`/proc/self/cgroup` names, case 39, asked before any directory is made, so root in a cgroupns-private container
handed the host's `/sys/fs/cgroup` makes no `tego.slice` in the host's tree). A timer that dies anyway is made up for:
every `Prepare`, once it holds its own build's lock, starts the timer again of each other build idle past its linger
whose timer it does not show running, and leaves the removal to it, off the run's path
(`TestPrepareRearmsTheTimerOfABuildWhoseTimerDied`, `TestIntegrationABuildWhoseTimerDiedIsRemovedAtTheNextPrepare`:
removed within 3 s, `prepare.lock-slot` under 50 ms); a build whose timer runs, in its second of slack past the
deadline, keeps it (`TestPrepareLeavesAnExpiredBuildToItsLiveTimer`). `Prepare` reads a timer's liveness from the pid
the timer wrote into its timer file: a process whose command line is `<exe> __bpf-linger <hash>` and whose four uids
in `/proc/<pid>/status` are 0 (`TestIsTimerProcessReadsUidsAndCommandLine`, `TestIsTimerProcessKnowsARealTimer`),
never by taking the timer or build lock, which would make a timer starting in that moment exit, and not from
`/proc/locks`, whose read waits for an RCU grace period (29 to 60 ms a read on 6.1, where the pass took 48 ms of the 50 ms slot; ADR 0022 note 2026-10-16). A
timer it does not show, and a build a launcher holds, get a timer that exits on the timer lock or waits for the
launcher. A pass off the run's path (`tego stop`) reads `/proc/locks` for the builds that show no timer, at most once
(`TestParseProcLocksReadsHeldFlocksOnly`, `FuzzProcLocks`, `TestTheLockTableShowsAHeldFlock`,
`TestRearmTimersReadsTheLockTableOnlyForABuildWithNoTimerShown`), and gives none to a build a launcher holds; a table
that cannot be read shows no holder. Only a build whose timer cannot be started (an exec that fails, a test
binary with no stage binary) is removed by `Prepare` itself (`TestPrepareRemovesAnExpiredBuildWhoseTimerCannotStart`).
At a `bpf.linger` of 0, under which no build has a timer, `Prepare` starts none and removes each other build that no
launcher holds itself, as before the re-arm (`TestPrepareAtLingerZeroStartsNoTimer`). A timer a launcher starts is
reaped by it when it exits, so none stays a zombie of a long run (`TestStartHelperReapsItsHelper`).
A timer writes its pid into its timer file, and asks for a busy timer lock once more 5 ms later, since
`removeStaleState` holds a gone build's timer file for a moment (`TestATimerAsksForABusyTimerLockOnceMore`). `Prepare`
leaves builds inside their linger, and the lingering cap, to the timer, the reaper, `tego stop` and gc
(`TestPrepareLeavesBuildsInsideTheirLingerAlone`). A root `tego stop` starts the timers the same way, of builds
inside their linger too, since (8) bounds a build's stay only while its timer lives (`cgroup.RearmTimers`,
`TestRearmTimersStartsTheTimerOfEveryBuildWithout`, `TestIntegrationStopRearmsABuildWhoseTimerDied`;
limits-check-doctor-cli.md R29). A root `tego doctor` sweeps the other builds as gc does. A root
`tego gc` sweeps the same way, `--builds` without the idle condition. At `bpf.linger: 0` the last launcher out removes the
build itself, under the same run-set condition. A run within the linger adopts the build and pays no load, verify,
attach or detach. Its rings are the runs', removed with each run (R12), so an idle build holds no ring (E33 is
withdrawn). `tego doctor` lists each build with its run rings (ADR 0022 (8), ADR 0026 (2)).

**R15 — Reason-breadcrumb teardown ordering.** `Detach` removes this run's cgroup links *before* the cgroup's
`reason` row (§4), so once links are gone no new breadcrumb can be written and the row is stable once deleted. A
straggling seccomp notification reaching the tier-1 handler *after* that deletion (asynchronous from this
teardown) finds a `reason` lookup miss — treated like R5's staleness case (fall back to `observed`, never
block/fail the task). Distinct from R12/I5: the `reason` row can be gone while the `run_idx` slot is still held.

**R16 — `record.ringbuf` is validated before any map is created.** `spec/config/v0` requires a power-of-two,
page-size multiple (`BPF_MAP_TYPE_RINGBUF`'s kernel requirement). `Prepare` checks this before calling into
`cilium/ebpf` rather than letting the kernel's `-EINVAL` surface as an opaque `ErrProgramLoad`: a violating value
fails fast with `ErrRingbufSize` (exit 125). A run that captures with uprobes also needs `record.ringbuf` of at least
128 KiB (`CaptureRingMin`, two of `uprobe_ssl`'s largest record, `sizeof(tego_ev_ssl)` at `TEGO_SSL_CHUNK_MAX`
plus its header, rounded up), because the probe reserves a whole size-class record with no smaller fallback and a
smaller ring would drop every chunk of that class; a smaller value refuses such a run with `ErrRingbufSize` before
anything is created (`TestPrepareRefusesACaptureRingTooSmallForAChunk`). It sizes each run's own record ring, and its capture ring when it
captures with uprobes (default 2 MiB; a `record: off` run's record ring is a fixed 256 KiB), and is honoured from
`/etc/tego/config.yaml` only, as `bpf.ring_budget` is: both size root's kernel memory, which an invoking user's
layer must not (`TestRingSizesAreTheAdministrators`). `Prepare` makes the run's rings ready before its run-set row.
When its slot holds a record ring of the run's size, and a capture ring of it exactly when the run captures with
uprobes, it drains and reuses them under `/run/tego/rings.lock` held shared: no ring is created, inserted or
removed, since every update of a ring outer waits for an RCU grace period (7-15 ms on 6.17, ADR 0026 (6) as
amended). A ring of another size, or a capture ring the run does not want, is removed first, and one that cannot be
drained is replaced (`TestAReusedSlotGetsOnlyTheRingsItsRunMayUse`, `TestARingThatCannotBeDrainedIsReplaced`).
What is still missing is placed under the lock held exclusively: `Prepare` removes the rings of builds none of whose
launchers is running, and the state files of builds that are gone (`TestAPlacementReclaimsTheRingsOfIdleBuilds`,
`TestStaleStateOfGoneBuildsIsRemoved`), sums the `memlock` of every live ring of every build (a ring removed during
the walk is not counted, one whose charge cannot be read is an error, `TestRingUseWhileRingsComeAndGo`), and places
the record ring. When it does not fit, every ring at a slot no live launcher holds and no run-set row carries gives
its room back, this build's pool included, and the count is taken again (`TestAShortBudgetReclaimsEveryRingNoRunHolds`).
Only this binary's own build has its run set's rows read for the slots they carry; of another build the keys alone
are read (ADR 0022 (5)), and one whose run set has any row keeps every ring
(`TestRingReclaimReadsOnlyTheKeysOfAnotherBuildsRunSet`);
a record ring that still does not fit refuses the run with `ErrRingBudget` (exit 125, naming the charge, the use,
the budget and the fix). The capture ring is left out when it would pass the budget (`Handle.CaptureRefused`): the
run goes on, its uprobe source records `mechanism-unavailable` naming the budget, and a run with a token, cost or
repeats budget is refused by the runtime (limits-check-doctor-cli.md R32) (`TestPrepareGivesEachRunItsOwnRings`,
`TestPrepareRefusesPastTheRingBudget`, `TestACaptureRingPastTheBudgetIsLeftOut`, and as root
`TestPlaceRingOnARealOuter`). A build's rings stay at its lowest eight slots when their runs end; a run above them
starts `tego __ring-trim`, which removes its build's rings above the pool that no run holds once its slot is free,
at `Detach` and at a `Prepare` that failed after placing them (`TestASlotAboveThePoolHasItsRingsTrimmed`,
`TestPrepareFailingAbovePoolTrimsItsRings`); the trimmer starts in `tego.slice/helpers.scope` as the timer does
(R14), so stopping the launcher's unit or CI job does not kill it (`TestTheRingTrimmerIsAHelper`), and `tego gc --builds` removes every ring no run holds
(`TestReclaimTakesOnlyRingsNoRunHolds`).

**R17 — one spelling of `rule`.** Every `rule` this tier stamps — the recorder's ring-buffer events, the fanotify
listener's refusals, and the name a `rule_idx` in `tego_net_exact`/`tego_net_cidr` or a reason breadcrumb resolves
to through `RuleMaps.Rules` — is `agent.FSRule/NetRule/ExecRule.RuleName()`, or `unmatched` when no entry covered
the action. `RuleName` spells the entry the contract's author declared (`fs.deny_read[~/.ssh]`,
`net[api.github.com:443]`, `exec[python3]`), which is what spec/record/v1/README.md means by "the declared entry or
`unmatched`" and what `tego drift` registers the declared side from; a position in the compiled list
(`net.allow[2]`), the bare declared text with no section, and a section name with no entry (`exec.allow`) are each a
second vocabulary that leaves the two sides unable to match.

`RuleMaps.Rules` stays an index → name mapping and is never inverted. Two entries may therefore share a name — a
glob that expanded to several paths keeps the glob text on every match, and Load admits a duplicated entry with a
warning — which is the intended reading: a reader of a contract counts declared entries, not positions, and `drift`
collapses them into one bucket. The rows those entries produce still merge by key, fail-closed, exactly as R3 says.

**Changes.**
- 2026-10-25, R9 (ADR 0069): an `O_PATH` open, which reaches no hook of this recorder nor the
  listener, is the supervisor's line at tier 2 and 3 even while the recorder reads (R9's amendment), `allow` with the
  `O_PATH` marker beneath a `deny_read`; it was handed to the recorder and lost, or recorded `refused`
  (`TestHeldReadsOPathAtARootTier`; on the kernel, `TestIntegrationHeldReadsAtRootTier`'s O_PATH run).
- 2026-10-20, R9 (ADR 0029 (4)): the rename rule the model explains a
  chain `EXDEV` by is named as the code asks it, `RenameGainedBy` on the index; `decide.RenameGains`, a wrapper that
  only decide's tests called, moved into decide's test files. No line changed.
- 2026-10-20, R7: `tego_connect_approvals` is named for what it holds
  since 2026-10-19, the one-shot credits of an approved TCP connect or UDP connect or addressed datagram (network-controls
  R6, supervisor R13d), with its key, `creditRows` and the revoke's untaken report; this list and R7 called it the TCP
  one-connect grants. No behaviour changed.
- 2026-10-27, R9: the recorder leaves an open to the fanotify listener only on the
  fallback; in a plane mode it writes the line of an open the plane let through at a name the listener's rule covers,
  and keeps the chain's answer for a read under an unenforced `deny_read` entry
  (`TestRecorderWritesTheLineOfAnOpenThePlaneAllowed`, `TestPlaneAllowedNestedDenyReadKeepsTheChainsAnswer`).
- 2026-10-27, R8 (ADR 0043 C11): the listener's name half applies in every build: a table with name
  entries (every contract's built-in `.env` pair over its scan roots) marks each scope's mounts for `FAN_OPEN_PERM`
  and refuses an open of a covered name, so a fallback run opens a permission group for such a table even with no
  other `fs` entry. The build switch `agent.NameEntriesEnforced` is gone.
- 2026-10-27, R8 (ADR 0043 C0 and D7's fallback): the open decision refuses an open of a file a name
  entry covers, beneath its scopes, whose mounts and submounts are marked for `FAN_OPEN_PERM` (behind
  `agent.NameEntriesEnforced`); and a path read back as `<path> (deleted)` is decided under both spellings, refused
  when either refuses, for opens and execs, a defect of file-level `deny_read` entries (the `.env` expansion's
  included) that let an open of a file renamed over or unlinked during its wait through.
- 2026-10-19, R7 and the reaper: `purgeDeadSlots` loads every
  pinned map `purgeSlot` purges, the connect grants (`tego_connect_approvals`), the net timeline and the
  network controls' maps among them; it purged a dead launcher's unix grants only, and nothing ran its purge through
  the reaper's own map loading (`TestApprovalGrantsReapedWithTheirDeadLauncher`).
- 2026-10-19, R7 (supervisor R11c): `connect_unix` admits an abstract name no entry lists on a connect that
  consumes the one-connect grant of a person's approval (`tego_unix_approvals`, by slot, gen and socket cookie); it
  refused every such connect, so an approved abstract name could not be relayed at tier 2.
- 2026-10-17, R9: the model explains a chain `EXDEV` on a link or a rename by the
  Landlock ruleset's `REFER` rules (`decide.LandlockLinkRefusal`, `decide.RenameGains`), so such a line is `refused`,
  not `observed` by another mechanism.
- 2026-10-17, R9: a rename's no-gain rule compares the new name's directory with the
  moved object across directories only, as `hook_path_rename` does; the object of a rename sample is compared as a
  directory.
- 2026-10-17, R9: the model asks the floor's directory rights of a
  rename and an unlink first, at every enforcing tier, takes each end unfollowed, and asks the exec grants by the inodes
  held before the agent ran; a file-level entry's own rename or unlink refused at tier 3 is `refused`, not `observed`.
  A chain refusal of an exec's open beneath an `exec.allow` directory's recreated name is `refused`, `unmatched`, by
  the held inodes, not `observed` under the directory entry.
- 2026-10-17, R9: a chain refusal of an exec of an `exec.allow` file entry
  whose name holds another inode is `refused`, `unmatched`, by the held inodes, as a directory entry's is; R9 says the
  recorder matches the held inodes when it processes the sample, so a tree changed back before then leaves the line
  `observed`.
- 2026-10-17, R9: the floor's explanations take a sample's ends as
  landed and rewrite none by a declared link, so a chain refusal of an unlink in a directory that replaced a declared
  link is not blamed on Landlock; R9 no longer says tier 1's held-inode match has no window: it stats when the
  notification arrives, and another task of the run can change the tree before the kernel's open.
- 2026-09-30, R8: an open on a private clone of a mount (overlayfs' copy-up of a lower file) is not
  recorded; a first write to a lower file was three open lines, two with layer-relative paths
  (`TestRecorderSkipsPrivateCloneOpens`, `TestIntegrationOverlayCopyUpIsOneLine`).
- 2026-09-30, R5: an IP connect whose `addrlen` is shorter than its family's address is not
  recorded; it was recorded as `0.0.0.0:0`.
- 2026-09-30, R12: a run's gen is its slot's epoch (`slotTable.acquireGen`), not the low half of its cgroup id, which
  repeats once kernfs's idr wraps (`TestSlotEpochAdvancesAndSurvivesRelease`, `TestPlaneFillCarriesTheSlotEpoch`).
- 2026-09-29, R7 and §6 E1 (T15): below 6.7 a plane-mode run's unix names are decided by the plane's step D hooks
  from these rows (enforce-plane §2.11); the canonical-spelling rule and the relay name check moved to `include/common.h`,
  shared by both.
- 2026-09-29, R9: the recorder's reason table (`observe.ReasonFor`) is `enum tego_reason_code`'s numbering
  (`bpf.ReasonCode`), held to `bpf/include/events.h` by `TestReasonTableIsEventsH`. It numbered `record.Reasons` in
  their own order, which agreed with the kernel for codes 0 to 7 only (8 net-not-allowed read `exec-gate`, 9 net-http
  `net-gate`, 10 to 12, the plane's, `net-http`, `ask-denied`, `ask-timeout`). No ledger line was mislabelled: the
  table is read only for a record whose header says refused, and before TIER3-PLAN T9 no ring record did (the
  network programs' refusals go through the breadcrumb, whose reader uses `bpf.ReasonCode`, R5), while T9's plane
  lines are named without it.
- 2026-09-23, R7: unix names decided in the kernel on 6.7+ via `bpf_cast_to_kern_ctx`; `/dev/log`-style unlisted
  datagrams refused there; an over-long `unix:` entry gets no row instead of failing `Prepare`; doctor treats the unix hooks as optional below 6.7; `net.unix` kept in `Handle.Capabilities`.
- 2026-09-23, R8: stage exec exempted by an ignore mark; a dynamically linked or PIE launcher refused
  (`ErrStageLinked`), and one under a `deny_read` entry (`ErrStageDenied`); one mark per mount by `statx` mount id;
  marks ask only for what can be refused, path-allowed events answered on the read loop; directory ignore marks
  withdrawn the same day.
- 2026-09-23, R14 (§9 costs): link descriptors closed before pins are removed.
- 2026-09-24, R14 (ADR 0022 steps 1–3): the build lingers for `bpf.linger` after its last run and is removed by its
  timer or `tego gc`, never under a run its run set names.
- 2026-09-24, R12, R14, R16 (ADR 0026 (1)-(6)): a ring per run from `record.ringbuf` (`/etc` only, 2 MiB) under
  `bpf.ring_budget`; carried slots not handed out; E33's re-creation of an idle build withdrawn.
- 2026-09-25, R12, R16 (ADR 0026 (6) as amended, L4): a slot's rings stay for its next run,
  drained and filtered by the generation every record carries, instead of being created and removed per run; the
  rings above a build's pool are trimmed off the run's path, and rings no run holds are reclaimed when room is short
  and by `gc --builds`; idle builds' rings and gone builds' state files are removed at a placing `Prepare`; the ring
  walk tolerates a ring removed under it; a program that finds its row and no record ring counts the miss.
- 2026-09-28, R16: a `Prepare` that fails after placing rings above the pool has them trimmed.
- 2026-09-29, R16: a uprobe-capturing run refuses a `record.ringbuf` below 128 KiB (`CaptureRingMin`).
- 2026-09-28, R14: `helpers.scope` is made only where the mount agrees with `/proc/self/cgroup`
  (case 39).
- 2026-09-29, R14: the timer refuses a hash that is not one path component, as the ring trimmer
  does; it made state files named by it.
- 2026-09-29, R16: the ring trimmer starts in `helpers.scope`, as the timer and the probe detacher
  do; it ran in the launcher's cgroup.
- Undated, R1: attachment-scoped ownership (`tego_net_owners`) replaces the caller's cgroup lookup; no `net:`
  section attaches no program.
- 2026-09-24, R5: unspecified destinations refused; v6 prefixes do
  not decide v4-mapped destinations; `cgroup_track` on the unified hierarchy only; connect record reads only what
  `addrlen` covers, nothing below 2 bytes; unix connect left to the supervisor; NAME_MAX names whole.
- 2026-09-24, R5 (one line per connect): an IP connect the supervisor continues is recorded here alone while the
  recorder reads.
- 2026-09-24, R5: that line's rule, host and verdict come from the supervisor's own lookup (`net.resolver`, not
  `unmatched`).
- 2026-09-24, R8: marks cover mount points beneath a `deny_read` entry.
- 2026-09-24, R8: `watch` entries take no part in `decideOpen`; `Evaluate`'s
  `cgroup` column answers a refused create as the listener does.
- 2026-09-24, R9: btrfs/overlayfs entries unindexed with a gap; rename decided at both ends; canonical keys; verdict from
  `FSDecider`; unlink/rename asked of the parent directory.
- 2026-09-24, R13: flush checked after every sample; no aggregation under
  `record: full`; `unmatched` buckets name their directory.
- 2026-09-29, R9 (supervisor R7a): the recorder owns the fs lines its hooks see, named by the supervisor where its
  index cannot and by the granting entry when allowed; the listener's refusals and every exec are not its lines.
- 2026-09-24 (rulecheck): the R13b the tier-2 unix-name limit cites named with the document that defines it; wording otherwise unchanged.
- 2026-09-24, build lifetime: the linger timer runs in tego's helper cgroup, and every `Prepare` and
  a root `doctor` sweep builds whose timer died.
- 2026-09-28, R8, R9 (ADR 0028 S1): the listener's open and exec decisions and the recorder's inference are the
  decision core's (`decide.ListenerOpen`, `decide.ListenerExec`, `decide.InferFS`).
- 2026-09-29, R5: the breadcrumb is read back; a kernel refusal of a relayed connect is the line's verdict and reason.
- 2026-09-29, R5 (tier 2): the breadcrumb answers only for the relayed socket's protocol.
- 2026-09-29, R13 (recorder): the 4096-bucket cap and its `aggregate-overflow` flush stated.
- 2026-09-29, R14 (tier 2): a run-set row is deleted only when two cgroup listings 50 ms apart miss
  its cgroup, so a descendant mid-`mkdir` keeps its row.
- 2026-09-29, R3 (tier 2): rows composed by SEMANTICS §5's overlap rule, so the kernel, `Evaluate` and
  the supervisor name one entry for a destination several entries cover.
- 2026-09-29, R9, R10, §2.3, §2.4 (ADR 0016 step 2): the fs programs are fexit on the ten `security_` functions and
  record the LSM chain's return; the line's verdict is that return (`decide.ChainFS`), with the model explaining a
  refusal or standing in where a record carries none (`verdict_from`); unexplained refusals are `observed`, `by:
  other`; refusals are recorded under `record: off`; one line per action through the task-storage hold; backing
  files skipped; `inferred` withdrawn.
- 2026-09-29, R9: a held `O_TRUNC` open is taken only by the truncate of its own dentry, and
  a held create is dropped only by an `O_CREAT` open, so a failed open and a `mknod(2)` keep their own lines.
- 2026-09-29, R8 (ADR 0021 (2)-(4)): marks placed at `Arm`, after the stage's `execve`; no process start while they
  exist (`proc.Start`); the stage's ignore mark, admission by identity, `checkStage`, `ErrStageLinked` and
  `ErrStageDenied` removed, so a dynamic or PIE build runs the tier and a `deny_read` over tego is decided.
- 2026-09-29, R10, R11 (ADR 0024's tier-2 note): `trace_proc` built twice, `tracerd` with no kernel probe read and
  picked where the kernel's BTF has `bpf_rdonly_cast` and `bpf_loop`; `cgroup_track` reads by direct loads; tier 2
  loads under `lockdown=confidentiality` there and is refused naming lockdown where no build loads.
- 2026-09-29, R16 (kernel matrix): `uprobe_ssl`'s user read is clamped to its size class right at the call, so
  the object loads on 6.1 and 6.8 too; a run with a tokens budget is no longer refused there (exit 125) for want of
  capture.
- 2026-09-29, R8 (tier 2): the mount table the submount marks come from is read once per `Prepare`,
  not once per `deny_read` entry and spelling.
- 2026-09-29, R12, R14 (tier 2): the slot purge and the run-set walk step through a walk restarted by
  another run's deletion instead of aborting past `max_entries` and failing `Prepare`.
- 2026-09-30, R14: a sweep that keeps a build for a live run stamps its lock, so each `Prepare`'s
  sweep no longer walks the whole cgroup tree for every other build an orphaned run keeps.
- 2026-09-30, R14: `Prepare`'s sweep removes only builds idle past the linger, never one
  past the lingering cap, so no removal runs on a run's start path unless a helper died.
- 2026-09-30, R16: ring reclaim reads another build's run set by its keys only; one with
  a row keeps every ring.
- 2026-09-30, R8: a path the listener cannot read back is refused `path-unresolved` for the run
  where an entry could refuse the event, no longer allowed with a gap.
- 2026-09-30, R8: an unreadable mount table refuses `Prepare` (`ErrMountTable`) for a table with a
  `deny_read` entry, no longer marking none of its submounts with nothing recorded.
- 2026-09-30, R8: a tier-3 run builds no listener policy and reads no mount table for it, so an
  unreadable table no longer refuses a `deny_read`-only contract at tier 3.
- 2026-10-05, R14: a pinned host-wide link is adopted only over this launcher's maps, and a
  build's pins are removed links first, keeping the maps under a link that cannot be unpinned.
- 2026-10-05, R14: one `bpf.AttachTrace` attaches every host-wide program, as a tracepoint for
  the syscall-result programs and as a tracing program for the rest; the observe fixtures' own copy of that choice,
  which attached the listener programs as tracing, is gone.
- 2026-10-05, R14 (ADR 0022 D1, D2, D4): the timer backs off a held build a linger (a second at least, no longer a
  minute) and looks at its own build only, so a linger under a minute keeps (8)'s bound; once its build is gone it
  lets its lock go and takes the build back if it was made again meanwhile; it reads the build lock's mtime through
  the verified state directory.
- 2026-10-06, R14 (ADR 0022): `Prepare` starts a dead timer again instead of removing the expired build
  on the run's start path, and leaves a build whose timer is running alone; liveness is read from `/proc/locks`. The
  timer writes its pid into its timer file and asks for a busy timer lock once more.
- 2026-10-20, R14 (ADR 0022 (8)): the timer's back-off for a build a live run keeps reads the build
  lock's mtime once a linger between its minute-apart looks at the run set; a build whose last run was an orphan, with
  a linger under a minute, stayed attached up to a minute after its reaper purged the run.
- 2026-10-16, R14 (ADR 0022): a root `tego stop` starts the timer of every build no launcher holds whose
  timer is not running (`cgroup.RearmTimers`).
- 2026-10-16, R14 (ADR 0022): `Prepare` reads a timer's liveness from the pid in its timer file, not from
  `/proc/locks`, whose read (29 to 60 ms on 6.1) made the pass 48 ms of the 50 ms `prepare.lock-slot` there (now 2.7 to 4.2 ms); a build a launcher holds that shows no timer
  gets one.
- 2026-10-17, R14 (ADR 0022): at a `bpf.linger` of 0 `Prepare`'s pass starts no timer and removes
  the builds no launcher holds itself, as before; a helper a launcher starts is reaped when it exits.
- 2026-10-19, R14 (ADR 0022): the re-arm pass (`cgroup.RearmTimers`) refuses a state directory of
  the caller's own beside pins under the host's bpffs with `ErrHostState` before it lists a build, as every other
  entry point there does (`TestHostPinsLockOnlyInTheHostStateDir`).
- 2026-10-05, R4, R5 (ADR 0018 PR 2): `cgroup/sock_create` is built and loaded with `cgroup_net`; it
  decides with `include/socket_allow.h`, the plane's allowlist, and is the one network program that records (its own
  `TEGO_EV_SOCK_CREATE`). R4's "neither exists" is withdrawn: the filter half has trapped `socket(2)` since PR 1
  (2026-09-24). Attaching it with the run's links is the next step; until then the filter and a plane
  mode's `socket_create` are what refuse these sockets at tier 2.
- 2026-10-05, R4 (ADR 0018 PR 2): the recorder writes `cgroup/sock_create`'s record as one `refused` socket line with
  `mechanism: cgroup` (`TestRecorderNamesSockCreateRefusals`, `TestRecorderSockCreateRecordOutOfShapeIsAGap`,
  `TestRecorderDropsAnotherGensSockCreateRecord`).
- 2026-10-05, R8 (ADR 0021 (6)): every process start is a reviewed site. `forbidigo` refuses `proc.Start`,
  `cgroup.StartHelper` and `cgroup.StartHelperExec` outside the files `.golangci.yml` names, and
  `TestEveryProcessStartSiteIsListed` holds the list by function and count with each start's relation to `Arm`, so a
  start from a supervisor's ask handler, the shape E70 would take, fails lint and the test before it can fail at run
  time with `ErrArmed`.
- 2026-10-06, R8 (ADR 0021 (6)): the list follows a start one function out. An unexported function that makes one of
  those starts (`startHelperIn`, `startHelperProcess`, `startOnKeptThread`, the reaper's, the uprobe detacher's and
  doctor's) is followed by its bare name in its own package's directory, since no `forbidigo` pattern names a bare
  unexported function: a new call of it from another file, an arm-time path for one, passed lint and the test. Each
  caller is now a row with its own relation (`Handle.parkRings`, `startTimerProcess`, `StartHelper`,
  `Launcher.Start` and the rest), and a function's own row is `guarded`. A file needs a `.golangci.yml` exclusion only
  for a call lint names, so `rings.go` has a row and none, and `TestLintExclusionsAreTheStartSites` refuses any other
  exclusion that includes `forbidigo`.
- 2026-10-05, R7: a datagram `sendmsg_unix`, the plane's `socket_sendmsg` or
  `sendmsg4`/`6` refuses has one line, the supervisor's refusal with the program's errno, no longer a `best_effort`
  line (or an `allow` for a non-canonical unix name) beside the kernel's refusal (`Handle.KernelDatagrams`).
- 2026-10-16, R4 (ADR 0018 PR 2): `cgroup/sock_create` is attached and pinned with the run's links
  wherever they attach, required, with doctor's D7 row; the run reports `SocketFamilies` and
  `net.socket_families`, which `net.assurance: kernel` requires. "Not attached yet" withdrawn.
- 2026-10-17, R4, R5 (ADR 0018 (7)): `TCP_ULP` turned an admitted TCP socket into `AF_SMC` past every
  creation hook; `cgroup/setsockopt` refuses it on any path, records its own line, is attached and pinned beside
  `cgroup/sock_create` and required, and `SocketFamilies` needs it.
- 2026-10-06, R7: "recording per run which path decided ... is not built" is
  withdrawn: `run_start.net_guarantees.unix` (record minor 4) is that record, written from `Handle.NetworkGuarantees`.
- 2026-10-17, R8 (ADR 0021 (5), ADR 0028 S3): the refused-create paragraph's empty file is the
  listener's alone; in a tier-cgroup run the supervisor refuses a create, delete, rename, link, mknod, symlink or
  mkdir beneath a `deny_read` nested in a `write` entry before the kernel acts, and `Evaluate`'s `cgroup` column
  refuses them through the root walk. "A delete, rename or mkdir stays the union's" is withdrawn.
- 2026-10-19, R14, §9: every removal of a build returns only once the kernel
  has released the build's links (`teardown`: each link opened, unpinned and closed, then a wait, at most 30 s, until
  the kernel has freed the programs they ran), and the last launcher out of a build that does not linger removes its
  shared links' pins before closing their descriptors; §9's change (4), the reverse order, is withdrawn, and so is
  R14's "RHEL 9's 5.14 frees in the launcher". The next run's load no longer waits for a removed build's trampolines
  (enforce-plane §10.1).
- 2026-10-19, R14: the amendment records where the teardown departs from the earlier plan: the
  planes' links go first (R20), not the tracing links, and the fallback to the plain unlink logs nothing; neither
  changes what a removal leaves.

## 6. Edge cases

1. Kernel <6.7 + a `unix:` entry: `connect_unix` and `sendmsg_unix` unavailable — not loaded, not attached (R7); falls back to
   tier-1 seccomp, where an addressed datagram is decided on its name, refused with `EACCES` when the policy refuses
   it and otherwise continued (supervisor R13b, amended 2026-10-16; it was recorded and sent). `tego doctor`'s capability
   matrix note says so, and the run's own record does: `run_start.net_guarantees.unix` is false (R7's per-run path). *Amended 2026-09-29 (T15):* where
   tier cgroup runs in a plane mode, the plane's `socket_connect` and `socket_sendmsg` decide those names below 6.7 by
   R7's rule and rows, with `EACCES` (enforce-plane §2.11); this case is the fanotify fallback's only.
2. Any refusal via fanotify, on any kernel: plain `FAN_DENY` → coarse `EPERM` (where a Landlock refusal of a read or
   an exec reports `EACCES`); the reason record still carries the precise code. `FAN_DENY_ERRNO` cannot change
   that for this listener. It arrived in 6.14, not 6.13, and `process_access_response`
   (fs/notify/fanotify/fanotify_user.c, 6.14 through current mainline) accepts a custom errno only from a
   `FAN_CLASS_PRE_CONTENT` group and only one of `EIO`, `EPERM`, `EBUSY`, `ETXTBSY`, `EAGAIN`, `ENOSPC` or
   `EDQUOT`, answering `EINVAL` to anything else; 6.13 and earlier reject every errno bit. The listener is a
   `FAN_CLASS_CONTENT` group, `EACCES` is on no kernel's list, and the one listed code a policy refusal could
   honestly carry is `EPERM`, which `FAN_DENY` already yields. So every refusal is the bare `FAN_DENY`, with no
   errno bits and no probe for them: no kernel delivers a precise errno to this group, and a write with errno bits
   is rejected with `EINVAL`. The design was chosen between the two that work: a
   `FAN_CLASS_PRE_CONTENT` group (6.14+) could send `EPERM` explicitly, which is what the bare `FAN_DENY` already
   yields on every kernel, so the class change buys nothing and costs the 6.1 floor. Verified as root on 6.17 in the
   KVM guest: `TestFanotifyRefusesDeniedRead` sees the refused open fail with `EPERM`.
3. `bpf` happens to be an active LSM on a tier-2 host anyway: no effect — fentry is `BPF_TRACE_FENTRY`, orthogonal
   to LSM registration; tier 3 availability is decided elsewhere.
4. `bpf_d_path` truncates a long path: `path_ok=0`, event recorded as `"<truncated>"` + `gap why=path-truncated`.
   The event is always its own, `rule: unmatched`, `verdict: observed`: the file is unknown and may be a
   `deny_read` file the kernel refused. A truncated read is never counted into its process's `unmatched` aggregate
   (R13), whose line says `allow`, and a truncated exec path is never matched, since it is only a prefix of the path
   the process exec'd (`TestRecorderTruncatedReadIsNotAnAllowedAggregate`, `TestRecorderTruncatedExecIsNotMatched`).
   An exec whose `bprm->filename` the kernel could not read at all (no path, reason `PATH_UNRESOLVED`) is recorded
   the same way, `"<truncated>"` with its `path-truncated` gap, never matched as the path `""`
   (`TestRecorderUnreadableExecNameIsAGap`).
5. Two threads connect concurrently in one run (the breadcrumb is one row per run, keyed by the run's cgroup id,
   R5): `reason_val` is last-write-wins; the supervisor's read of it (`Handle.KernelNet`) takes it only for the same
   protocol and destination and no more than 50 ms older than the notification, and the line is otherwise `observed` rather than
   a wrong attribution — enforcement itself is unaffected.
6. A cgroup is created then destroyed before a task joins: impossible to race by construction (R11's ordering);
   a create-then-immediate-rmdir just deletes the row it added, net zero.
7. Declared host's IP changes mid-run (DNS TTL): the supervisor re-resolves the entry on its TTL and matches against
   the new set (supervisor R8), and relays the connect on the agent's socket, which the run's `connect4/6` decides
   too (R1, R5). The rows therefore follow the supervisor's set through `RefreshNet` (§4): only addresses may change,
   an address both sets share keeps its row throughout, and an entry the refresh leaves without an address keeps its
   old ones (supervisor R8a). Tested by `TestRefreshNetFollowsARotatedHost` and its siblings, and as root by
   `TestNetRefreshOnRealKernel`, and the runtime's half by `TestDNSRefreshMovesTheTiersRows`: the run's DNS worker
   hands the tier each refresh whose addresses differ from those the tier last received (§4 `RefreshNet`), which a
   refresh that changed an entry's addresses makes, and so does a change in this host's own addresses, which the
   runtime's filter keeps out of the rows (agent-contract R18). Tier 2 re-resolves at runtime; a run does not keep
   deciding by the IP resolved at start. Between the supervisor's swap and `RefreshNet`'s write (the same pass of the worker, or its next tick after a
   failed write) the kernel still refuses a connect to the new address, the fail-closed side; an address the refresh
   dropped is refused by the supervisor from its swap on, whatever the rows still hold.
8. Overlapping exact host:port and CIDR rule: the exact row is read first (R3), regardless of insertion order, and
   holds the composition of both entries (a refusing one, else the first declared).
9. A refused exec never reaches `sched_process_exec` at all — the `exec` refusal event comes from seccomp or
   `FAN_OPEN_EXEC_PERM`, not from this component.
10. `pids` cap kills the cgroup while a fanotify permission decision is in flight: the kernel's own task teardown
    unblocks the opener; the listener must not fail on writing a response to a pid that's already gone (`ESRCH` or
    `ENOENT` swallowed, not fatal, and logged to the run's own log at debug, once per errno, so a killed busy cgroup
    cannot flood it: `TestResponseForAGoneOpenerIsLoggedOncePerClass`).
11. `run_set` at 4096 rows: a new descendant's `cgroup_mkdir` insert fails with `-E2BIG` (not `-ENOSPC`).
    Before attempting the event, BPF increments the preallocated `tego_tracking_failed` counter at the
    run slot, including under `record: off`. An independent runtime watchdog reads it before releasing
    the child, every 50 ms while running, and once after workers drain. A nonzero counter or a read failure
    ends the run with reason `error` and kills its cgroup; a received event can stop it sooner. Shutdown
    writes `gap what=enforce why=cgroup-tracking-failed` directly to the ledger. Missing/full event rings
    and unavailable recording cannot hide this failure. The slot counter is reset during `Prepare` and
    reclaimed with the other per-slot counters. Tracing, uprobe and decision-plane hooks have no membership
    row for the descendant until shutdown. Network attachments still govern descendant sockets independently
    of `run_set`. This remains asynchronous userspace containment, not atomic refusal of cgroup creation;
    scheduler delays can extend the nominal polling interval.

12. 4096 concurrent runs, slot exhaustion: `Prepare` returns `ErrSlotsExhausted`, exit 125, no partial state left.
13. `Recorder` restarts mid-run (process cache lost): next event for an uncached pid rebuilds from `/proc`; only
    unflushed aggregate counts since the last flush are lost, kernel decisions are unaffected.
14. PID reuse racing a lagging `sched_process_exec` for the new occupant: `exec_id` (`pid+start_boot_ns`)
    disambiguates; a cache hit whose `StartBootNS` mismatches is treated as a miss, rebuilt from `/proc`.
    For that check to run, every open, file-operation and connect record carries its process's start time (`start_ns`, the thread
    group leader's `start_boottime`) and an exec its parent's (`parent_start_ns`): an open is looked up by it, a parent
    is named only when the cached entry is that process, an exit flushes the exec id its own start time names and
    evicts only that process, and a `/proc` rebuild that finds the pid's next process gives the sample its own id
    and caches nothing (`TestRecorderAReusedPidIsNotTheOldProcess`, `TestProcCacheRebuildOfAnExitedProcess`, and as
    root `TestIntegrationEveryRecordNamesItsProcessStart`).
15. Fanotify listener dies with permission events queued: kernel fail-open on fd close (documented default,
    opposite of seccomp's fail-closed) — mitigated by treating the goroutine's death as fatal to the whole run
    (`errgroup` → `cgroup.kill` immediately); a small residual auto-allow window is a stated P0 limit.
    A listener whose context is cancelled, which is how every run ends, removes its marks before it stops
    reading, then reads and decides whatever the group already holds until it is empty, lets its workers answer
    every event read, and closes the group last (`loop`, `drain`). No new event can enter a group with no mark, so
    from the moment the loop decides to stop no opener on the host waits on it, and an event that entered before
    then gets the answer the contract gives it, a refusal included, rather than the allow a close would give it.
    Only an opener that passed a mark in the instant it was removed and queued after the last read is released
    by the close with an allow. A listener that stops on an error (a failed read, the overdue ceiling of E34)
    removes its marks first as well, but reads no further: what its group holds is released by the close, as
    the first sentence says, while the run is cancelled and its cgroup killed (§7). The marks are never left to
    `Close` after the workers finish: every open on a marked mount in between would wait on a group nobody read and
    then be released with an allow nobody decided (`TestListenerRemovesItsMarksBeforeItStopsAnswering`).
    A launcher that is `SIGKILL`ed does not stop its listener at all; its group closes when the last descriptor
    to it closes, which is the launcher's own unless another process holds a copy. None that outlives the
    launcher can: the group is opened `FAN_CLOEXEC`, so no process past its `execve` holds it (the agent's
    processes, which outlive a killed launcher, E38), and the one process that holds a copy before its `execve`,
    the child stage in its vfork window, dies with the launcher by `PR_SET_PDEATHSIG`, as `launch.Launcher`
    starts it. `TestKilledListenerReleasesTheMount` kills a listener holding an exec in its decision, with such a
    child and a surviving one, and the mount answers at once; with `FAN_CLOEXEC` removed the survivor kept the
    group and every open on the mount stayed blocked. What of the run outlives a killed launcher then runs with
    its opens and execs undecided by fanotify until the run's reaper kills it, milliseconds after the launcher's
    pidfd becomes readable (ADR 0020 (3)); Landlock and the pinned network programs still hold meanwhile (E38).
    In this fanotify fallback a run whose reaper cannot be started does not start (exit 125, ADR 0020 (4));
    the residual is a launcher and its reaper killed together, after which the window lasts until the next sweep.
16. A single fanotify decision exceeds its response deadline (listener alive but slow): answered `FAN_ALLOW` at
    the deadline (matches the kernel's own bias) with `gap why=fanotify-timeout`; default deadline 500ms, a P0
    constant independent of `ask.timeout` (no ask in P0).
17. A symlink inside a marked mount resolves outside any marked mount: no fanotify event fires (mount-scoped
    marking is a hard boundary); recorded only via `security_file_open`'s unconditional path (R8); `compile` warns
    on symlinks crossing a ruled mount boundary.
18. Non-UTF-8 bytes in a path/argv: decoded with `strings.ToValidUTF8` replacement for display only — the
    in-kernel decision already happened on raw bytes and is never affected.
    The recorder's own inference matches the raw bytes, never the replaced string (which would let a read under a
    `deny_read` entry whose name holds such a byte name no entry and be recorded `allow`). A path is kept as the
    kernel's bytes and matched as them; the ledger line is still valid
    UTF-8, because `encoding/json` replaces the byte when the payload is marshalled (`TestPathBytesAreMatchedRaw`).
    `bpf.GoString` says it is for display only.
19. Path/`sun_path` longer than the fixed buffers: an open's `path[256]` truncates with `path_ok=0` (#4);
    `sun_path` cannot exceed 108 bytes in the kernel's own `sockaddr_un`, so this case cannot occur for unix.
20. Clock step (NTP, suspend/resume) mid-run: every kernel timestamp is `bpf_ktime_get_ns()` (boot-time
    monotonic), never wall clock; readers sort/attribute by `mono_ns`, never the wall-clock `ts`.
21. Two runs `Prepare` at the same instant on one host: the build lock never blocks concurrent `LOCK_SH` holders;
    slot allocation must be safe across launcher *processes* (kernel-shared array CAS, not Go-process-local — §11).
22. Binary upgrade mid-run: two `bpf_hash` directories, fully separate map instances and `run_idx` spaces; both
    builds' `cgroup_track` programs see the same `cgroup_mkdir` tracepoint but each only writes its own map,
    harmlessly.
23. `record: off`: `observe.Recorder` still runs (enforcement doesn't depend on recording) but every handler is a
    near-no-op past decoding `kind`; `sched_process_exit` still evicts the process cache to bound memory; the ring
    buffer and lost-counter mechanism stay wired for `gap` accounting.
    Each of the run's samples is also reported as activity (`Options.Activity`, set by the runtime through
    `SetActivity` for a `record: off` run): the budget watcher's stall check reads activity from the lines the
    pipeline carries, and with no line for an allowed exec, open or connect a tier-2 agent busy with allowed work
    would read as idle and be killed for stalling. The supervisor reports each notification it answers the same way
    at tier 1. *Amended 2026-10-19:* under `record: off` the samples left are refusals, execs and
    exits: trace_proc returns before the reserve for an allowed open, file operation or connect, so "each of the run's
    samples" never covered that work, and an agent at tier 2 or 3 that only read files (or wrote ones a plane mode
    decides, which leave the seccomp notify set) was killed for stalling. Each of those returns now stamps the run's
    slot of `tego_activity` instead, one 16-byte slot and no ring, for a run whose row carries `TEGO_RUN_ACTIVITY` (a
    `stall_after` bounds it); the run's recorder reads the slot once a tick for the watcher (`LastActivity`,
    `TestActivityStampPerSlot`, `TestAReadingAgentUnderRecordOffIsNotAStall`). A run with no stall budget is not
    stamped and costs one test of a byte the program has already loaded. A stamped one reads the jiffies on each
    such action and the clock once a jiffy: measured in `tego_file_open`'s own run time (`TestActivityStampCost`,
    docs/BENCHMARKS.md), +4.2 ns an open on 6.17 and +4.8 ns on 6.1, under the rig's resolution and inside the record-off
    plan's +25 ns and +40 ns.
    The exit record is the thread group's, made by its last thread, the one that finds `signal->live` at 0
    (`do_exit` decrements it before the tracepoint), with the status `wait(2)` reports and the leader's start time,
    never the leader's own exit: a leader that ends with `pthread_exit` leaves its threads running, and the process
    must not be evicted, its reads flushed as final, or the uprobe source and step tracker told it is gone while it
    goes on (nor on an `execve` from another thread). Two threads that end at one instant can both find the count at 0, so the recorder handles one process's exit once
    (`TestIntegrationExitIsTheThreadGroups`, `TestRecorderHandlesAProcessExitOnce`).
24. A `write` rule directory bind-mounted elsewhere after `Prepare`: cannot occur — Landlock already refuses
    `mount(2)` inside a run (SEMANTICS §10), so no new mount instance can appear mid-run to need a late mark.
    **Condition:** this holds only because the filter refuses new mount and user namespaces (SEMANTICS §10):
    `unshare(CLONE_NEWUSER|CLONE_NEWNS)` would make unmarked copies of every mount, where a `deny_read` fanotify
    alone enforced is read (reproduced on 6.17).
    The host can still mount beneath a `deny_read` entry after `Prepare` (autofs, a systemd automount), and that
    mount is on no mark (§5 R8). A read there of an entry the Landlock ruleset leaves unenforced, which the listener
    alone refuses, is made. So the recorder reads the mount table when it is built, after `Prepare`, and takes the
    super block devices of each such entry's own mount and of every mount point beneath it, the mounts the listener
    marked; a read under such an entry on another device is stamped `observed`
    (`TestUnenforcedDenyReadOnAnUnmarkedMountIsObserved`). What it cannot tell apart: a record carries the device, not
    the mount, so a later bind mount of an already-marked filesystem beneath the entry is still stamped `refused`
    while unmarked, and a mount made between `Prepare` and the recorder's construction counts as marked.
    *Amended 2026-10-19 (ADR 0017 space 5, a known fail-open disclosed until fixed):* a bind mount made
    **before** the run, of a `deny_read` directory onto a name beneath a granted sibling (`pub/alias` bound from
    `secret/`), is read through that name in the fanotify mode: the alias is a mount of its own beneath no `deny_read`
    path, so no mark asks for its opens, and the kernel record says `allow unmatched` (what happened). Tier landlock
    allows the same read as its recorded limitation (enforce-landlock E32 (ii)); the decision plane refuses it by inode.
    `compile` warns on mount points; until the listener decides the open by the file's identity (ADR 0010, ADR 0025)
    or marks every mount of a marked filesystem, a `deny_read` that must hold against such an alias needs a plane mode
    or tier bpflsm. `test/conformance` `mounts-bind/read-bind-alias-nested` carries it as a `finding` at cgroup, failing
    once fixed.
25. A 200-argument exec: `argv[512]` truncates with a trailing marker + `gap why=argv-truncated`; exec-allow
    matching depends only on `path`/`script` (read separately, bounded by `PATH_MAX`), never full argv.
    The buffer is `TEGO_ARGV_MAX`, 512 bytes. An argv the probe could not read is recorded empty and marked
    truncated, with the same gap, never as an exec with no arguments (`TestExecArgvReadFailureIsMarked`).
26. Operator manually `rmdir`s a run's cgroup outside `tego`: cgroup v2 refuses `rmdir` while any task is in it,
    so it succeeds only once the run is empty; `cgroup_rmdir` then deletes the `run_set` row and the record stops
    for it. A socket that outlives its tasks keeps the cgroup (and so its links and storage) referenced, and its
    network stays decided (R1). Recording, not enforcement, is what this self-inflicted P0 case loses, same class
    as deleting any live kernel resource out from under a process. No task still alive can make the removal fail
    open for network: neither cgroup v2 nor R1 allows it.
27. `doctor`'s kernel-feature probe and `Prepare`'s later execution run on different kernels: cannot happen in any
    P0 deployment shape (one process, one host).
28. `record.ringbuf` in the machine config is not a power-of-two page multiple (e.g. `3MiB`): caught by `Prepare`'s
    validation before map creation (R16) — `ErrRingbufSize`, exit 125, distinct from `ErrProgramLoad`.
29. Binary upgrade mid-run, extended (amends E22): unlike R1's cgroup-hook family, tracing attachments have no
    "neutral return" to opt out with — both coexisting `bpf_hash` builds' `trace`/`cgroup_track` programs run
    host-wide for every exec/exit/open/fsop/connect event during the whole upgrade window, each filtering via its
    own `run_set` lookup (R2). Ring-buffer traffic and process-cache/aggregation work roughly doubles for the
    *entire host*, not just the upgrading run's cgroup; §9's per-path budgets are per-build, not a bound on this —
    a stated, bounded coexistence cost, not a defect. Measured 2026-09-24 (`TestTwoBuildsCoexistWithoutInterference`,
    root, tegobpf, the 6.17 KVM guest): two builds' objects pinned and attached side by side, each run decided by
    its own contract (each allows the port the other refuses) with its breadcrumb in its own reason map, neither
    run set holding the other's run, and the old build's teardown leaving the new build's pins and verdicts as they
    were. The cost to a process in no run, per `open(2)`+`close(2)`: 2.74 µs with no build attached, 3.20 µs with
    one, 3.19 µs with two — the second build's run-set misses are within the noise of one such loop; the doubled
    ring traffic of processes inside runs is not measured.
30. bpffs not mounted, or not where `Prepare` expects, at pin time: `open()` fails `ENOENT`/`ENXIO` before any
    program load — a distinct `ErrBpffsUnavailable` (exit 125, names the mount point and the `mount -t bpf bpf
    /sys/fs/bpf` fix), never folded into the generic verifier-rejection `ErrProgramLoad` bucket (§7).
31. A kernel type, member or enum value that a program reads through a CO-RE relocation is missing from a
    kernel's BTF. At load this surfaces as `ErrProgramLoad`, with the field only in the verifier tail. The
    component's own map keys (`run_key`, `net_key`, `cidr_key`, `reason_key`, §2.2) are in the object's BTF,
    not the kernel's, so they are never relocated. `doctor`'s BTF probe (D2, limits-check-doctor-cli.md R27)
    checks ahead of load and names what is missing. It parses the kernel's BTF and reads the list from the
    CO-RE relocations of every object the binary carries: the tier-2 objects and capture's `uprobe_ssl`. For
    each relocation it finds the type by name (the `___flavor` suffix dropped), each member by name (through
    anonymous members, as the loader does) and each enum value. A missing one fails D2 with the field named,
    for example `field task_struct.start_boottime not in the kernel's BTF (trace_proc: ...)`. The unix
    programs' own relocations are left out, since R7 runs the tier without them on a kernel that lacks them.
    This matters for kernels below the tested floor, given ARCHITECTURE §14's untested-ABI caveat for RHEL 9's
    5.14 (`TestBTFProbeNamesAMissingField`, `TestCORENeedsOfTheObjects`, and `TestCORENeedsMatchTheRelocations`,
    which checks that the fields D2 names are the relocations `btf.CORERelocate` poisons).
32. A launcher is `SIGKILL`ed (OOM, CI timeout) and never runs `Detach`, so its verdict rows stay in the pinned
    `net_key`/`cidr_key` maps while the slot table reclaims its `run_idx` from the dead owner (one whose pid is gone,
    reused with another start time, or an unreaped zombie, `TestAZombieOwnerIsNotAlive`): `Prepare` deletes
    every row keyed by the slot it was handed *before* writing the run's own (R12, I5). Without that scrub the
    reclaim is fail-*open* — `connect4/6` hits the dead run's `allow` row on `(run_idx, family, proto, port,
    addr)` alone and the breadcrumb files the allow under the dead run's `rule_idx`. A scrub that fails aborts
    `Prepare` rather than starting the run beside the leftovers. The dead run's `run_set` rows are deliberately
    left: they are keyed by cgroup id, which the kernel does not reuse, and removing one would only take the
    last policy off tasks that outlived their launcher (E26). While such a row exists its slot is not handed out
    at all (R12, ADR 0026 (6)); once its cgroup is gone, its counters are zeroed with its rows, and its rings,
    drained, go to the next run of the slot, whose readers drop what the dead run's processes wrote by generation.
33. *(withdrawn) 2026-09-24 (ADR 0026).* `record.ringbuf` disagreeing with the size a build already pinned
    (`ErrRingbufPinned`) cannot happen: no ring is the build's. Each run's ring is created at its own `Prepare`
    from the machine config, or reused from the slot's previous run when it has the same size (ADR 0026 (6) as
    amended).
34. **A marked mount is the whole filesystem, and on an ordinary box that is `/`.** `FAN_MARK_MOUNT` marks the
    mount a path resides on — "if pathname is not itself a mount point, the mount containing pathname will be
    marked. All directories, subdirectories, and the contained files of the mount will be monitored"
    (`fanotify_mark(2)`) — so a `deny_read` on `~/.ssh` or an `exec.allow` on `/usr/bin/python3` marks the root
    filesystem. From the moment `Prepare`'s step 7 returns until the run ends, every `open(2)` and `execve(2)`
    by every process on that mount — `systemd`, `sshd`, the user's shell, unrelated containers — is held in
    `fanotify_get_response` until this listener answers it. ClamAV refuses to let its users configure exactly
    this: `OnAccessIncludePath` cannot take `/` because "key system files may have their access blocked to key
    processes at the kernel level, which will result in a system lockup", and `OnAccessPrevention` is
    disallowed with a mount path for the same reason (docs.clamav.net/manual/OnAccess.html).
    **This is accepted, not avoided, and here is why the obvious narrowing is wrong.** Inode marks
    (`FAN_MARK_INODE` + `FAN_EVENT_ON_CHILD`, which is what `doctor`'s probe uses) cover only "the immediate
    children of marked directories … events are not generated for children of the subdirectories of marked
    directories. To monitor complete directory trees it is necessary to mark the relevant mount or filesystem"
    (`fanotify_mark(2)`) — so a `deny_read` tree would need every subdirectory marked and would still fail open
    for a subdirectory the agent creates mid-run. Worse, exec denial inverts: R8's `exec.allow` refuses the
    binaries the contract did **not** name, which requires seeing every `FAN_OPEN_EXEC_PERM` on the mount;
    marking only the allowed binaries would make exec denial a silent no-op. Mount marks are therefore load
    bearing for `CapExecDeny`, and refusing to mark `/` would be a fail-open on both `CapReadDeny` and
    `CapExecDeny` on nearly every host.
    What bounds the cost instead is the decision path, and both bounds are in the code: `decideEvent` resolves
    the path and applies the in-memory policy **before** reading `/proc/<pid>/cgroup`, because the membership
    check can only ever turn a refusal into an allow — so the host's `FAN_OPEN_PERM` traffic on paths no
    `deny_read` entry covers, which is nearly all of it, pays one `readlink` and a policy lookup (E35 bounds its cost) and never touches
    procfs; and a decision that can wait happens on a bounded worker pool rather than on the read loop (E35),
    while one the path alone settles is answered by the read loop itself (R8).
    `BenchmarkDecideEventOffTheRun` measures the first of those on the host's own opens: ~1.7 µs and 4 allocations per open with the path decided first, against
    ~9.7 µs and 13 allocations when the `/proc/<pid>/cgroup` read comes first (i7-10870H), and for those opens
    the procfs read — the one that can block in D state — is not merely faster but gone.
    **That ordering spares most opens, not execs.** `FAN_OPEN_EXEC_PERM` is in the same mask, and R8's exec denial
    refuses by default, so an `execve` of any binary the contract did not name never reaches the early allow:
    every such exec on the marked mount, the host's included (systemd, sshd, the user's shell, unrelated
    containers), still does the `/proc/<pid>/cgroup` read, after the `readlink` and the policy lookup. Only execs
    of binaries an exec entry covers (the command, `exec.allow` and MCP server entries, and their interpreters,
    by compiled or resolved path, R8) are allowed before it, by whichever process runs them, and under a contract
    with no `exec:` section every exec is, since nothing is refused. Membership is the only thing separating a host exec
    from the run's, and `/proc` is the only place it is known, so no ordering removes that read: checking
    membership first for execs would spare an unnamed exec the `readlink` and the lookup, never the procfs read,
    and would add the read to every exec of a named binary. The same read sits in front of every open of a path
    a `deny_read` entry covers and no longer `write` entry reopens (`decideOpen` allows those before
    the lookup), whoever makes it: the run, or a host process such as the user's own `ssh` reading `~/.ssh`. A procfs read that stalls there holds its exec or open for up to E16's deadline once a
    worker takes it, then allows it with a `gap`, and occupies one of the `fanotifyWorkers` slots meanwhile.
    Kernels before 6.8 serve `/proc/<pid>/cgroup` (`proc_cgroup_show`) under the global `cgroup_mutex`; 6.8
    moved it to RCU. So on 5.14 through 6.7 one held mutex stalls every such exec and every such open at once,
    not one of them, and past `fanotifyWorkers` of them the other opens on the marked mount queue behind them
    within E35's bound: E35 isolates a stall only while fewer than `fanotifyWorkers` decisions share it.
    A stalled read also outlives its deadline, because nothing interrupts a read blocked in the kernel. `handle`
    answers at the deadline, closes the event's descriptor right after the answer (the stalled read does not
    use it: `decideEvent` reads through that descriptor only before the membership read, in its `readlink` and,
    for an exec, the `fstat` beside it, and a verdict reached after the deadline is discarded), and leaves the
    decision running. The one other read through it, the image identity supervisor R7a's line needs (a
    `statx` with `AT_STATX_DONT_SYNC`, so NFS and FUSE answer from their caches), runs first on the same
    goroutine, never on the worker; a deadline that comes while it is still waiting leaves the close to that
    goroutine, which then decides nothing, so a stalled filesystem holds no worker past the deadline. Until its read returns, each such
    decision keeps its goroutine, a second one waiting to uncount it, the `/proc/<pid>/cgroup` descriptor the
    read goes through, and the OS thread blocked in that read. A held mutex adds one per membership read a
    worker starts: up to `fanotifyWorkers` per deadline, 32 a second at the 500 ms default, a rate the run's own
    agent can supply by running unnamed binaries, since E16 allows those with a `gap` while the stall lasts.
    Unbounded, that reaches the launcher's nearest thread limit, and the launcher aborts there: the Go runtime
    at `runtime/debug.SetMaxThreads` (10,000 by default, about five minutes at that rate), and also, earlier on a
    small host, wherever `clone(2)` fails with `EAGAIN` and the runtime throws `newosproc` — a `pids.max` on the
    launcher's own cgroup chain or `kernel.threads-max`. systemd's `DefaultTasksMax` puts a `pids.max` at 15% of
    `min(pid_max, threads-max)`, about 1,229 tasks per GiB of RAM, so a 2 GiB host allows about 2,458 and a 3 GiB
    host about 3,686. (`RLIMIT_NPROC` cannot bind: `copy_process` exempts a task holding `CAP_SYS_ADMIN`, which
    `fanotify_init` requires of this listener.) An aborted launcher runs no teardown, as in E38: its group closes,
    the kernel releases every pending event as an allow (E15), and the tier-2 file refusals end for whatever of
    the run outlives it. **Bounded instead:** `handle` counts each decision it answers at the deadline and
    uncounts it when the decision returns, and `loop` checks that count between reads. The ceiling it checks
    against is sized when the listener starts: `threadBudget` measures the smallest headroom of the Go limit (less
    the process's own threads), every `pids.max` on the launcher's cgroup chain (less `pids.current`) and
    `kernel.threads-max` (less the threads that exist, `/proc/loadavg`), and `overdueCeilingFor` takes the ceiling
    so that it plus the overshoot below fits in half of that headroom, capped at `fanotifyOverdueCeiling`
    (1,024). A headroom that cannot hold even a ceiling of `fanotifyWorkers` (below 224 threads) refuses to start
    the listener, so `Prepare` fails before the agent exists — fail-closed, rather than a listener that could
    reach the abort. Once more than the ceiling are outstanding, `loop` records `gap why=fanotify-overdue-ceiling`
    with the count and the ceiling, then stops and returns `ErrListenerDied`, which cancels the run and kills its
    cgroup (§7) with the teardown an abort would skip. Only decisions already past their deadline count, so no
    verdict changes before the cap trips and a lookup that returns in time is never affected by it. Because the
    check falls between reads, every event already read is still decided and answered (I8), and the count can pass
    the ceiling by at most one read's records plus the `2 × fanotifyWorkers` already queued or deciding. A read
    now returns at most `fanReadBatch` (64) records rather than a 64 KiB buffer's 2,730, so that overshoot is 96:
    at the 1,024 cap, 1,120 blocked threads at most, where it used to be 3,786 and so past a 2 or 3 GiB host's
    task limit. The measurement is a snapshot: tasks the rest of the launcher's cgroup adds later come out of the
    same headroom, which is what the half kept back is for. At 32 a second the 1,024 cap trips after about half a
    minute of steady stalls, and later by at most one read's hand-off (`ceil(64 / fanotifyWorkers)` deadlines, 2 s
    at the default); a `cgroup_mutex` held that long is a host fault, and the run ends rather than carrying on
    through E16's allows. The ceiling is not a fixed 1,024 sized only against Go's 10,000-thread limit. At the trip
    the run is cancelled and its cgroup killed, but `run_end` does not say `reason=error` today (§7, "Fanotify
    listener dies").
    **Where the kernel has it, the membership read is a cgroup id, not procfs.** Everything above about
    `/proc/<pid>/cgroup` is what the listener reads on a kernel without `PIDFD_GET_INFO`'s cgroup id, and where the
    id path below has no answer. Where the kernel has it, `inRun` opens a pidfd for the opener and reads
    `PIDFD_INFO_CGROUPID`, the cgroup id, under RCU, with no text and no `cgroup_mutex`. Whether it has it is found
    by asking, never by version: the ioctl is upstream from 6.13, and RHEL 9's 5.14 (5.14.0-687) answers it by
    backport. A kernel without it refuses it one of two ways, and both latch the id path off for the listener's
    life, so such a kernel pays for the question once, not on every event (`pidfdInfoErr`): `ENOTTY` below 6.11,
    where a pidfd has no ioctl handler (Ubuntu 24.04's 6.8, AL2023's 6.1), and `EINVAL` on 6.11 and 6.12, whose
    handler serves the namespace ioctls alone and refuses any non-zero argument before it looks at the command
    (Debian 13's and AL2023's 6.12). On a kernel with the ioctl, `EINVAL` means a NULL or undersized struct, which
    is never passed. The run's own id answers at once. Any other id is named once through cgroupfs
    (`open_by_handle_at` with the kernfs handle of that id, under a descriptor of the cgroup2 mount, and the path of
    the descriptor it opens), compared with the run's path, and the answer kept for the listener's life: a cgroup
    never moves in the hierarchy (cgroup v2 has no rename, and cgroup v1's keeps the parent) and kernfs never
    reissues an id within a boot, so what one id answered is what it keeps answering. The cache starts over past
    4,096 ids. Whatever else this path cannot answer goes to `/proc/<pid>/cgroup` as before, and the id path is
    asked again on the next event: an opener that is gone (`ESRCH`, which the kernel also returns for a pid outside
    the caller's pid-namespace hierarchy, not `EREMOTE`, on every kernel from 6.13 to 6.17), a cgroup removed before
    it was named (`ESTALE`), a cgroup outside the mount the run's path is relative to, or no `CAP_DAC_READ_SEARCH`
    for the handle. Measured as root in the KVM guest (6.17, 2 vCPUs, 20,000 iterations, three runs): the membership
    read for a host process 6.2–7.4 µs and 8 allocations by procfs, 1.2 µs and none by id (`BenchmarkMembership`);
    the round trip of an open refused after the membership read 58–64 µs and 24 allocations before, 47–50 µs and 16
    after (`BenchmarkFanotifyRoundTrip`); `TestRunMembersMatchesProc` checks that both paths agree for a process in
    the run, in a descendant, outside it, for the launcher and for pid 1, and passes as root on the 6.17 of this
    box, Fedora's 7.0 and RHEL 9's 5.14. On a kernel without the ioctl (the matrix's 6.12, 6.8 and 6.1 rows) it
    takes no skip: it checks that the id path answers nothing and latches once, and that `/proc` tells the run, its
    descendant and an outside process apart (that branch has not yet run, as it needs root on such a kernel).
    Latching on `ENOTTY` alone would read 6.11's and 6.12's `EINVAL` as a failure of that one event rather than of
    the kernel, and ask the id path again on every event there (a pidfd, a failed ioctl and a close before each
    `/proc` read); `TestPidfdInfoErrorsThatMeanNoIoctl` pins both errnos. The id path does not change the overdue ceiling, on
    whatever kernel carries it: its reads take no `cgroup_mutex`, so they are not among the stalls the ceiling
    bounds, which happen on the procfs path alone, and that path, where it is still taken, is bounded as above.
    The residual cost — one round trip through a userspace listener on every exec on the marked mount, and on
    every open on a mount a `deny_read` entry can refuse opens on, plus that membership read on host execs of
    unnamed binaries and host opens under a `deny_read` path — is a stated P0 limit, not a defect, and is the
    strongest argument for the tier-3 BPF LSM path where the decision stays in the kernel. A mark asks only for the
    events a rule there can refuse (R8), and §9 records what that and the read loop's own answer took off kill
    test 4's run. Ignoring a directory's opens once one of them was allowed is not done, because the ignore moves
    with the directory into a denied tree (R8, "No directory is ignored").
35. **The per-decision deadline of E16 does not bound what an opener waits.** The kernel blocks a permission
    event's opener in `fanotify_get_response` with `TASK_KILLABLE|TASK_FREEZABLE`: only `SIGKILL` releases it,
    and nothing times it out kernel-side ("permission events that have been read are kept in an internal list
    of the fanotify group until either a permission decision has been taken … or the fanotify file descriptor
    is closed", `fanotify(7)`). Were the read loop to decide, E16's 500 ms would bound one decision and nothing
    would bound the queue behind it: the opener at position N of a read batch would wait N deadlines, so one decision
    stuck on a D-state `/proc` read (an unreachable NFS mount, a frozen container) would stop every open on the
    marked mount for as long as it took — E34's lockup, reached from the listener side. `loop` therefore reads,
    answers only what the path alone allows (`settleByPath`: a readlink of its own descriptor and the in-memory
    policy, which read no procfs file of another process, so no stall of the kind above can reach the loop
    through them), and dispatches every other event; `fanotifyWorkers` decisions run concurrently, each still bounded by E16. The aggregate
    bound is `ceil(queued / fanotifyWorkers) × deadline`, not `queued × deadline` as it would be with the read loop
    deciding. A saturated pool still
    queues — the hand-off blocks rather than auto-allowing, because allowing on backpressure would let the
    agent flood opens to walk past a `deny_read` entry — so the bound is a bound, not a guarantee of 500 ms.
    E34 names one stall that fills the pool by itself: before 6.8 every membership read through
    `/proc/<pid>/cgroup` waits on the same `cgroup_mutex` (a kernel with `PIDFD_GET_INFO`'s cgroup id, such as
    RHEL 9's 5.14, takes that path only where the id path has no answer). With the loop answering what the path
    allows, an allowed open waits for no worker while the pool alone is full, and waits for a deadline again only
    once the pool and its queue are both full and the loop's own hand-off blocks, behind which it reads nothing
    (`TestListenerLoopQueuesOpensBehindExecsStalledOnMembership`).
    **What the loop's own answer costs is bounded by the path, not by the policy.** The loop gives the path
    verdict for every open and exec a mark reports, by any process on the host, one event at a time, and the
    number of entries it is given against is not the contract author's to bound: the built-in `.env` scan writes a
    `deny_read` entry for every `.env` file under the project root, up to 50,000 (agent-contract R6 and §3),
    the agent can create those files in an earlier run, and each entry marks its mount, usually `/`, for opens. So
    the lookup (`decide.PathIndex`) costs one map lookup of the path and at most one of each of its components, whatever the
    number of entries: an allowed open 0.18–0.20 µs and a refused one 0.36–0.40 µs at 20, 1,000 and 50,000 entries alike
    (i7-10870H, `BenchmarkDecideOpenByEntryCount`; `TestDecideOpenCostDoesNotGrowWithEntries` fails with the walk
    restored, and `TestPathSetMatchesTheWalk` checks the index against the walk on 3,000 random entry sets, 40
    paths each). A path is at most `PATH_MAX` long, so that bounds the loop's share of each event.
    What the loop can still wait on is the filesystem of the file an event names: `read(2)` on the group opens
    each event's file for the listener, in the loop, with that filesystem's own open (FUSE sends `OPEN` to its
    daemon, NFSv4 sends `OPEN` to its server unless it holds a delegation). A daemon or server that stops answering
    opens therefore stops the loop, and every opener on the marked mounts behind it, at its next event on that
    filesystem; a mark on such a mount has always carried that risk, and a `deny_read` entry on a home directory
    mounted over NFS is the ordinary way to get one. The close of an event the loop answered is not the loop's:
    closing runs the filesystem's flush and release, which can send `FLUSH` (FUSE) or `CLOSE` (NFSv4) and wait for
    the reply, so a server that answered the listener's `OPEN` and then stopped, a partition right after the open,
    would hold a loop that closed in that close, and every opener on every marked mount behind it, even if no
    further event on its filesystem ever came. The loop answers the opener first and hands the descriptor to one
    closer goroutine (`fdCloser`), and so does each worker with the events it answers, so such a close holds
    nothing but the closes queued after it: no opener and no worker. That queue is capped at `fdCloserCap` (1,024)
    descriptors, or a quarter of the soft `RLIMIT_NOFILE` where that is less (`closeBacklogFor`): `loop` checks it
    between reads, beside the overdue count, and at the cap reads nothing more until the closer holds at most half
    the cap (`fdCloser.catchUp`). When that has not happened within E16's deadline, `loop` records `gap
    what=enforce why=fanotify-close-backlog` and returns `ErrListenerDied` at once, so the run is killed (§7). A
    close held for good therefore ends the run after about a thousand more answered events and one deadline, rather
    than holding every opener on the host; the deadline is the most the wait adds to what any opener waits,
    since the loop reads nothing while it waits. Closes that are only slow do not reach the cap, a slow network
    mount's included: where a close is a request its filesystem waits on (`FLUSH`, `CLOSE`), the open that gave
    the loop the event's descriptor was one too (FUSE's `OPEN` unless the daemon declined opens, NFSv4's `OPEN`
    unless a delegation is held, which spares the `CLOSE` as well), paid by the loop's own read, so the closer
    spends on a descriptor about what the loop spent getting it, with nothing else to do, once it has a processor.
    A closer that has the processor the wait gives it and still does not close half the cap within a deadline has
    a close that stopped answering, or a filesystem that answers its closes far slower than its opens, and ending
    the run is then the fail-closed side. (The code comment on `fdCloserCap` gives the reason above, not that a
    close takes microseconds on a filesystem that answers, which is untrue of the NFSv4 and FUSE closes the closer
    exists for.)
    At the cap `loop` waits for its closer (`catchUp`) before giving the group up, because a backlog at the cap can
    also mean a closer that has not run. The loop answers what the path allows on its own goroutine and blocks
    nowhere while events keep coming: its poll, read and response write return at once and keep its processor, and
    the Go runtime runs a goroutine a wake-up readied there only once the running one blocks, or after 10 ms, when it
    preempts it. Where every processor is busy, the closer does not run, and the backlog reaches the cap with nothing
    held. Measured with a loop that gave the group up at once: as root in the 2-vCPU guest,
    `BenchmarkFanotifyRoundTrip`'s allowed opens, made by the benchmark's own goroutine, ended the listener at the cap
    in every run on the test machine's 6.17.0-41, Ubuntu 24.04's 6.8.0-142 and the GitHub runner's 6.17.0-1022-azure kernels;
    on the last, with GOMAXPROCS 1 or 2 in every run and with 3 or 4 in none, on 2 vCPUs and on 4 alike. The refused
    opens after it were then let through (the benchmark's refused case opened its `deny_read` file), and `ci.yml`'s
    `bpf-load` failed on it once its bpftool step ran (a GitHub-hosted runner can have 2 vCPUs).
    GOMAXPROCS is the machine's CPU count or a container's CPU limit, so a launcher with one processor, or with two
    while another of its goroutines keeps the second busy, is in the same position, and an agent's burst of opens
    could end its own run. Blocking in `catchUp` hands the processor to the closer, which closes a thousand
    descriptors that answer in about a millisecond, and the loop reads on. In the same guest, the allowed round trip
    on 6.17.0-41 is 18.7–19.8 µs with the wait, as without the cap (§9), and 16.0–18.0 µs on 6.8.
    `TestLoopWaitsAtTheCapForItsCloser` holds the first close until the loop waits at a cap of 4, lets it go, and
    gets the next open answered with no gap; it fails with the loop giving the group up at the cap at once. As root,
    `TestFanotifyAllowedOpensKeepTheListener` makes 60,000 allowed opens from the test's own goroutine with GOMAXPROCS
    2 and then finds the `deny_read` file still refused: with the wait, 6 runs of 6 passed on 6.17.0-1022-azure; with
    the loop giving up at once, the listener ended in 6 of 6, after 2,793 to 38,543 opens.
    `TestLoopGivesUpAtTheCloseBacklogCap` and, as root, `TestHeldCloseEndsTheListenerBeforeTheDescriptorLimit` still
    end the listener at the cap behind a held close, one deadline later.
    The queue needs its cap: the descriptor limit does not bound it safely. At that limit the read that filled the
    table would still hand its other events to the workers, where a refusal's membership read failing with `EMFILE`
    must not be answered allow, and a `loop` that, on that error as on every fatal one, removed its marks and then
    waited for the closer held in the one close would leave the run going on with nothing asking about its opens and
    no line saying so (measured as root in the 6.17 guest, soft limit 512: after 502 allowed host opens behind one
    held close the read failed with `EMFILE`, `loop` had not returned 3 s later, and a process of the run read its
    `deny_read` file with errno 0). So a
    fatal `loop` returns at once and leaves its workers' last answers, the group's close and the closer's queue to
    a goroutine of their own (what that leaves behind is below); the backlog is capped as above; and a membership
    read that fails keeps the refusal (the end of this item). The marks it removes first come down by one
    `fanotify_mark(FAN_MARK_FLUSH|FAN_MARK_MOUNT)` call, which the kernel takes before it resolves any path
    (`do_fanotify_mark`) and which removes every mark of the group, all of them mount marks
    (R8), so the return waits on no marked filesystem. It names no path at all, which a lookup would refuse with
    `EBADF`, and as root it removes the marks on the 5.14 floor (the `rhel-9` row) as on 6.17
    (`TestUnmarkAllFlushesOnlyTheMountMarks`, below). The marks are never removed one mount at a time with
    `FAN_MARK_REMOVE`, which names the mount's root: the kernel walks that path and checks read permission on it
    (`fanotify_find_path`) before it removes anything. On NFS that check is a `GETATTR` once the root's cached
    attributes have expired, and on FUSE with `default_permissions` it is one too, so a server that stopped
    answering, the very way a close comes to be held and the backlog to fill, could hold the fatal `loop` in its
    unmark, and a cancelled one before `run_end`, while whatever marks Go's map order had removed first were already
    down: the fail-open above reached through the mark removal instead of the close. It was not reproduced against a
    real NFS server; the kernel paths are v6.17's. `TestLoopRemovesItsMarksWithoutNamingAPath` holds every call that names a path, as that `GETATTR`
    would be held, and fails for a fatal and a cancelled `loop` with the per-mount removal restored; as root in the
    6.17 guest, `TestUnmarkAllFlushesOnlyTheMountMarks` reads the group's `fdinfo` and finds the mount marks gone
    and none of another kind, the process disarmed, and an open on the mount answered with no reader, and fails with
    `FAN_MARK_MOUNT` left off the flush. `TestLoopClosesASettledDescriptorOffTheLoop` holds the first close and gets
    the next open answered, and fails with the close back on the loop; `TestWorkersCloseThroughTheCloser` fails
    with a worker closing its own descriptor; `TestFatalLoopReturnsWhileACloseIsHeld` fails with a fatal `loop`
    waiting for its closer, and `TestLoopGivesUpAtTheCloseBacklogCap` with that or with no cap. As root in the 6.17
    guest, `TestHeldCloseEndsTheListenerBeforeTheDescriptorLimit` (soft limit 512, so a cap of 128, one close held)
    sees the listener end after 128 allowed opens with no host open refused; with no cap, after 501 allowed opens
    the next got `EPERM` from the kernel, and with a `loop` that waits for its closer it had not returned after 5,000.
    The hand-off costs the allowed round trip 1–2 µs: 17.6–19.5 µs against 15.9–17.6 µs with the close on the loop, as root in the 6.17 guest
    (1536 MiB, 2 vCPUs, six runs of 20,000 opens each over two boots, the two builds alternating,
    `BenchmarkFanotifyRoundTrip`).
    `loop` answers what the path alone allows as well as reading and dispatching (R8, §9), by the `decide.PathIndex` lookup,
    never a walk of every entry (0.5 µs an allowed open against 20 entries, 21 µs against 1,000 and 1.7–1.9 ms
    against 50,000, which would hold every open on a mount so marked, host-wide, to about 550 a second), and it never
    closes an answered descriptor itself, which is the stall described above.
    **A membership read that fails keeps the refusal.** `decideEvent` reads membership only for an event its path
    refuses. If that read fails for any reason but the opener having exited (`ErrProcGone`, E10), whether `EMFILE`,
    `ENFILE`, a `/proc` file of an unexpected shape or anything else, the opener is not known to be outside the run,
    so the refusal stands: `FAN_DENY`, the refusal event, and beside it `gap what=enforce
    why=fanotify-membership-unread` naming the error, since that event's pid is one the listener could not place,
    never an allow with `gap why=fanotify-path-unresolved`, which would give the run's refusal away whenever the read
    failed.
    The cost falls on a host process that opens a path the contract refuses, or, under an exec list, execs a binary it
    does not name, and only while membership reads fail. `TestDecideEventKeepsTheRefusalWhenMembershipIsUnread` (a
    stubbed `EMFILE`) and `TestDecideEventKeepsTheRefusalAtTheDescriptorLimit` (this test process's own descriptor
    table filled, its own cgroup the run's) fail with the allow restored.
    **What a listener leaves behind.** A fatal `loop` returns before its workers and its closer have finished, so
    the goroutine it leaves to finish them, its workers and its closer can outlive `RunListener`, `Detach` and
    `run.Run` (§9). The workers end within E16's deadline for each event they hold: `loop` has closed their queue,
    which holds at most `fanotifyWorkers` events beside the `fanotifyWorkers` in hand, so the last of them ends no
    later than three deadlines (1.5 s) after `loop` returned, and the event descriptors they hold stay open until
    each is answered. The closer, and every descriptor it still holds, lasts as long as a close it holds is held.
    And after either kind of `loop` has returned, a decision answered at E16's deadline goes on running until its
    read returns, with its goroutine, the waiter `handle` left for it and its own pidfd or `/proc/<pid>/cgroup`
    descriptor (E34's ceiling, which `loop` checks between reads, bounds how many). Two things follow for the
    record. Whatever a worker records (a refusal, or a `fanotify-timeout`, `fanotify-response-failed` or
    `fanotify-membership-unread` gap) reaches the run's queue when it is decided, which can be after
    `internal/runtime`'s final drain (`shutdown`: stop the sources, join the group, drain, then `run_end`), and such
    a line is never written. So a fatal `loop`, before it returns and so before that drain, records `gap
    what=enforce why=fanotify-listener-abandoned count=n`, n being the events its workers hold then, queued or in
    hand: the most events whose lines (a refusal, a gap, or both for a refusal whose membership went unread) can be
    missing, since a worker that finishes before the drain has its lines written as well
    (`TestFailedLoopCountsWhatItsWorkersHold` holds two decisions as `loop` fails, and fails with the gap removed).
    And a worker still deciding can answer after `Detach` closed the group; its response is then not written
    (`groupMu`, I8), the close lets that open through, and the worker emits `gap why=fanotify-response-failed` and
    no refusal event, since a refusal is recorded only once its `FAN_DENY` is written
    (`TestNoRefusalIsRecordedForADenyNeverWritten`, which fails with the refusal recorded whatever the write did).
    Only `Detach` closes the group under a worker (`loop`'s own close waits for its workers, and `Prepare`'s undo
    runs before any exists), and `Detach` runs after the final drain, so that gap is not written either; its event
    is one the `fanotify-listener-abandoned` line counted. A response that fails to be written while the run is
    live, for any other reason, is the case whose `fanotify-response-failed` gap reaches the ledger. The loss itself
    is closed because `internal/runtime` waits for the workers before its final drain: `Handle.WaitListener` returns once the workers a `loop` left behind have ended
    (three deadlines at most, as above), or with its context's error
    (`TestWaitListenerWaitsForAFailedListenersWorkers`), and `shutdown` calls it between `group.Wait` and
    `pipe.drain`, bounded by `killTimeout` (`TestIntegrationListenerWorkersAreWaitedForBeforeTheDrain`). The
    `fanotify-listener-abandoned` line still goes out, and counts events whose lines were, in the ordinary case,
    written after all; only a worker still running past that bound can lose its line.
    A cancelled `loop` joins its workers and closes its group before it returns, and waits for its closer up to
    `fanCloserJoinTimeout` (10 s, the runtime's own `killTimeout`); past that it returns and leaves the closer to
    finish on its own; an unbounded wait would let a close its filesystem never answered hold `RunListener`, the
    run's `group.Wait`, `run_end`, `Detach` and the build lock for as long as it was held
    (`TestCancelledLoopReturnsWhileACloseIsHeld` fails with that wait). With no mark left, such a close holds no
    opener either way.
36. **A third party already holds an exclusive cgroup attachment at or above the run's cgroup.**
    `__cgroup_bpf_attach` (kernel/bpf/cgroup.c) refuses with `-EPERM` when `hierarchy_allows_attach()` finds an
    ancestor holding a program for the same attach type attached the legacy way with no flags — `BPF_PROG_ATTACH`
    with neither `BPF_F_ALLOW_MULTI` nor `BPF_F_ALLOW_OVERRIDE`, which is `bpftool`'s default — and again when
    the target cgroup's existing programs carry different flags. A `bpf_link` is internally `ALLOW_MULTI`, so
    both checks apply to it, and one `bpftool cgroup attach /sys/fs/cgroup connect4 pinned …` blocks every
    Tego run on that host until it is detached. R1 reasons only about the other direction (that Tego's links
    cannot displace anyone else's). Reported as `ErrCgroupAttachConflict`, whose message names the cause and
    `bpftool cgroup tree` as the diagnosis, and names the alternative reading of `EPERM` (a launcher without
    `cap_bpf`/`cap_net_admin`) second — never folded into the opaque `ErrProgramLoad` bucket. systemd documents
    the same contract from the other side: it installs its IP filters with `BPF_F_ALLOW_MULTI` "so that your
    program can install additional ones" (systemd.io/CGROUP_DELEGATION). *Built 2026-10-16:* doctor's D7 is the pre-run probe. It attaches each cgroup program to a scratch cgroup in the
    subtree runs live in, so such a program fails the row first, and the row's detail names the cause in the words
    of `ErrCgroupAttachConflict` (one helper, `cgroup.AttachConflictHint`, so the two cannot drift). As root, with a
    stand-in attached the legacy way above: `TestD7NamesALegacyExclusiveAttachAbove` (the `connect4`,
    `sock_create` and, from 2026-10-17, `setsockopt` rows) and `TestAttachNamesALegacyExclusiveProgramAbove` (a run's
    `Attach`).
37. **A permission event the kernel cannot allocate fails *closed*, silently.** `fanotify_handle_event` skips
    the overflow record for permission events — "we don't queue overflow events for permission events as there
    the access is denied and so no event is in fact lost" — and the allocation failure becomes the opener's
    errno. So under memory pressure this group's mark refuses opens, with no event delivered, no ledger entry,
    no `gap` and no attribution; on a mount mark (E34) those refusals land on unrelated host processes. This is
    the one fanotify failure in this design that is not fail-open, and Tego cannot observe or explain it.
    `FAN_UNLIMITED_QUEUE` handles the other half (no 16384-event cap, so no queue overflow), and the
    `FAN_Q_OVERFLOW` branch in `handle` is therefore unreachable while `fanPermMask` holds only permission
    events; it is kept as I11 defence for a mask that later adds a notification-class event, not as live code.
    Shrinking the mark scope is what would bound the damage, and E34 says why that is not available.
    **Unreachable while the group has an unlimited queue, and not tested.** `fanotify_alloc_event` allocates with
    `__GFP_NOFAIL` for a group whose `max_events` is `UINT_MAX`, which `FAN_UNLIMITED_QUEUE` sets ("for queues with
    unlimited length lost events are not expected and can possibly have security implications"; read in the v5.14
    and v6.17 sources, so on every matrix kernel), so for this group the allocation does not fail and the
    `-ENOMEM` branch above is not taken; the charge to the listener's memcg goes over its limit instead. A test
    needs fault injection into that allocation (`CONFIG_FAULT_INJECTION`/`failslab`), which neither the development
    box's 6.17 nor the matrix kernels are built with, and `__GFP_NOFAIL` bypasses `failslab` anyway. **Condition:**
    the group keeps `FAN_UNLIMITED_QUEUE` (a change to a bounded queue makes this case live, and then needs a test
    on a fault-injection kernel that an allocation failure refuses the open with `ENOMEM` and nothing else).
38. **The launcher is `SIGKILL`ed: the run's tier-2 network policy stays in the kernel (ADR 0020).** A `bpf_link`
    is freed when its last referencing fd closes (kernel commit `af6eea57437a`), so the run's cgroup links (ten,
    eight below 6.7, `cgroup/sock_create`'s and `cgroup/setsockopt`'s among them) are pinned under
    `<bpf_hash>/links/run-<id>/` as they attach, and `Detach` unpins them. A launcher killed outright leaves
    `connect4/6`, `sendmsg4/6`, `bind4/6`, `connect_unix`, `sendmsg_unix`, `sock_create` and `setsockopt` attached to the run's
    cgroup, with the run's `run_set` row and verdict rows, for as long as any process of the run lives
    (`PR_SET_PDEATHSIG` reaches the direct child, not its already-forked descendants). The run's reaper, which the
    launcher started after `Prepare` (`docs/p0/runtime-launch.md` §6 case 13), then kills the cgroup, waits for
    it to empty, writes `run_end reason=orphaned`, removes the cgroup, and only then unpins `links/run-<id>` and
    purges the rows (`PurgeRun`, which itself refuses while a cgroup of the run's id exists); a reaper killed
    with its launcher leaves the same to the next `run`/`stop`/`gc` sweep, which purges once it has removed the
    scope. A run whose cgroup cannot be removed keeps its links and rows, and its slot stays carried. Landlock,
    seccomp and the cgroup limit files were never link-scoped (runtime-launch I7).
    `TestNetLinksOutliveTheLauncher`, `TestTier2ReaperEndsAnOrphanOnlyOnceItsTreeIsGone`,
    `TestTier2AReapersDeathLeavesTheRunToTheSweep` (root).
39. **Two tier-2 runs at once, and the two-run freeze.** Every run's group marks the mount of `/` (E34), so each
    launcher's opens and execs wait on the other's listener as well as its own, and a listener that stops answering
    holds every open and exec on the machine until its group closes. Two runs of one build started 0–20 ms apart
    froze a KVM guest whole, 3 times in about 250 pairs, with `timeout -s QUIT -k 5 40` unable to end the
    launchers and the guest shell's own `sleep` never returning. **Attributed, by reproduction, to R8's stage-exec
    deadlock.** Removing `startFanotify`'s `exempt` call from the fixed tree reproduces the symptoms with stacks that
    name the wait: `test/vm/tier2-pairs.sh` froze the
    guest at pair 5, and in a second guest at pair 14 (6.17, two vCPUs). Its watchdog, which
    needs no open or exec on `/`, names the wait: the stage in `fanotify_get_response`, from `execve`'s
    `do_open_execat`; its launcher's forking thread in `clone3`'s vfork wait (`kernel_clone`,
    `wait_for_completion_state`); every other thread of that launcher parked in `futex` while the runtime stops the
    world for a collection; and the other launcher in `openat`, waiting on the first one's group, the only group
    marking `/` at that moment. `SIGQUIT` did not end the stuck launcher in five seconds, since the runtime's own
    crash path waits on the stopped world too, and a `-k 5` never sent its `SIGKILL`: Ubuntu 25.10's
    `timeout` is uutils coreutils 0.2.2, which does not (on the host, `timeout -s QUIT -k 2 1` over a shell that
    ignores `SIGQUIT` ran until the shell's own 10 s sleep ended). A `SIGKILL` from the watchdog ended the launcher,
    and the guest's next exec went through at once: the stage's copy of the group's descriptor, the one other
    process that held it, died with the launcher (E15). With the exemption there was no stall in 1,000 pairs of a
    build with that revision's listener, marks and membership, under the watchdog in the same guest: 400 plain and
    280 under `timeout`, every launcher exiting 0, and 320 with one launcher `SIGKILL`ed 100–900 ms after it
    started, the other exiting 0 each time; nor in 120 more (40 of each kind) once the lock around the membership's
    mount descriptor was added. Nor in 280 pairs (the same three kinds) and 120 pairs of two copies of one binary on
    the tree just before it, nor in 480 more on a later re-run.
    That exemption, by `(device, inode)` of each launcher's own binary, covered two runs of one tego file only:
    **not two tego files, nor any other permission listener.** A stage exec'd from another file (another build, or
    a copy of the same build at another inode) raised an event in this group, answered at once, but only while this
    launcher could run its listener, which it cannot while its own forking thread sits in its own vfork window with a
    collection pending; and any fanotify permission listener whose group sees the stage's exec and whose decision
    path opens a file on a mount this run marks closed the same cycle with one tego run.
    **Closed by ordering (ADR 0021, 2026-09-29).** The marks are placed after the stage's `execve` returns and before
    the handshake releases it to exec the agent (`Arm`, R8), and while any mark of the group exists the launcher
    starts no process: `internal/platform/proc.Start`, the one process start of non-test code, refuses while the
    process is armed, and lint keeps every start going through it. No group therefore holds marks while its own
    launcher is in a vfork window, so no listener's answer waits on its own launcher's collection, whatever file
    the stage was exec'd from and whatever other listener is on the host; the exemption is removed. The stage's own
    opens between its `execve` and the ack are not decided by the group; they are tego's code, not the agent's.
    `TestStageExecUnderGCNeverWaitsOnItsOwnGroup` pins the order: 60 stage starts with the collector running without
    pause, each started with no mark, marked once it has exec'd, a process start refused while marked, and its
    first open as the agent refused by the group. The rejected alternatives: a stage exec'd from a sealed memfd (not
    small: a per-run copy, `stageFilter`, the inherited descriptor, a fallback where `vm.memfd_noexec` is 2, the
    exemption kept for it), and a listener in a process that never forks (a second process and IPC in the TCB,
    E40 untouched). **Condition:** ADR 0021's `tier2-pairs.sh` runs (two copies of one build at two inodes, and a
    third-party listener whose decisions open files on `/`, 1,000 pairs each in GUEST and on MATRIX's AL2023 6.12
    under the watchdog) and the two-run reproduction (500 pairs) are still to be recorded here; `make
    vm-pairs` runs them (variants `two-inodes`, `third-party`, `guest-freeze` and `pie`, §10).
40. **A stopped launcher holds every open on its marked mounts.** E15's rule, that a listener answers every event
    its group was sent or removes its marks before it stops answering, has no answer for a launcher that is stopped
    rather than ended: its marks stay, nothing reads its group, and every open and exec on the marked mount of `/`
    (E34) waits in `fanotify_get_response` until the launcher continues or the waiter is killed. E16's deadline does
    not bound it, since that deadline starts when an event is read. The ways a launcher stops: `SIGTSTP` from its
    terminal (Ctrl-Z on `sudo tego run --tier cgroup`; the terminal, or `sudo` relaying it, delivers it to the
    launcher's process group, ARCHITECTURE §6), which the launcher leaves at its default action, since
    `launch.HandledSignals` covers `TERM`, `HUP`, `USR1`, `USR2`, `INT` and `QUIT` only; `SIGTTIN` and `SIGTTOU` the
    same way; `SIGSTOP`; a debugger that stops it; and the cgroup freezer on a cgroup that holds it. After Ctrl-Z
    the shell that takes the terminal back can still run `fg`, a builtin that opens nothing, but nothing it has to
    exec from `/`, and neither can a new `sshd` login. Continuing answers every event still queued in the group
    with its decision, a refusal included. An event the listener had already read and was still deciding when it
    stopped is the exception: E16's deadline started at that read and runs on the monotonic clock, which keeps
    counting while the process is stopped (so does `CLOCK_BOOTTIME`; the CPU-time clocks, which a process can also
    wait on, leave the stop out but leave out the time the decision spends blocked as well, a slow `/proc` read
    among it, so no clock measures a decision's elapsed time without the stop), so on `SIGCONT` the deadline has
    usually passed, `handle` can take the timer's branch, and that one open is allowed with `gap what=enforce
    why=fanotify-timeout` rather than decided. With decisions of a few microseconds the window is the instant of the
    stop; a decision that blocks (a slow `/proc` read, E34) widens it. It is stated rather than closed: the open is
    not held, and the gap records that it was not decided (continuing does lose it: a helper whose decision took
    300 ms, stopped 100 ms into it and continued 1 s later, allowed the open in 5 of 5 rounds on 6.17). The
    condition that closes it is either of two. One is a `handle` that never
    allows a decision a stop interrupted by a deadline that expired during the stop: on expiry, before it allows,
    it confirms that no stop and continue fell between the read and the expiry, through something the stop itself
    changes and that cannot run behind the timer. `SIGCONT` delivered through `signal.Notify` does not meet that
    on its own: a continue wakes every thread of the process at once, one of them takes the signal into Go's
    handler while another can already run the expired timer, and `os/signal` hands the notification to its channel
    from a goroutine of its own afterwards, so a `handle` that selects on its timer and that channel can take the
    timer first and allow the open. The other is tier 3, whose decisions are made in the kernel with no listener to
    stop.
    `TestStoppedListenerHoldsItsMountUntilContinued` stops a helper's listener with `SIGSTOP`, and an open under its
    `deny_read` entry, made after the stop and so still queued, waits the 3 s the test gives it, then is refused on
    `SIGCONT`. `docs/p0/runtime-launch.md` §6
    case 14 says a `SIGSTOP`ped launcher leaves the agent "still enforced by Landlock/cgroup (kernel-resident,
    launcher-independent)"; at tier `cgroup` the fanotify half of the file and exec rules is neither, and what waits
    while the launcher is stopped is the host; that case is corrected there. **The job-control stops are closed in
    the launcher** (`runtime-launch.md` R9a): a launcher whose handle owns
    this listener ignores `SIGTSTP`, `SIGTTIN` and `SIGTTOU` (`launch.HoldJobControl`, called by `Launcher.Start`
    before the clone), and the child stage sets them back to `SIG_DFL` before it execs the agent, since an ignored
    disposition would otherwise pass to the agent across `execve`. Ignored rather than caught, because of a
    constraint catching carries: a background process that catches `SIGTTIN` or `SIGTTOU` and then reads its
    terminal, or writes to it with `tostop` set, has the signal sent to its whole process group, the agent's
    included, and the call fails with `-ERESTARTSYS` (`__tty_check_change`, `drivers/tty/tty_jobctrl.c`), which
    `SA_RESTART`, the flag Go installs its handlers with, restarts, so the call signals the group again and spins;
    with `SIG_IGN` the kernel answers a background read with `EIO` and lets a background write through. Ctrl-Z
    stops the agent, which gets its own copy of the signal, and leaves the launcher answering and the terminal with
    the run (`TestJobControlStopsTheAgentNotATier2Launcher`). **Not covered, with its conditions:** the window
    between `Prepare` placing the marks and `Start` does not exist (the marks go down at `Arm`, after `Start`'s
    `HoldJobControl`); the stops that cannot be ignored, below, are not covered. Taking the marks down for the stop and placing them again on `SIGCONT` is not the
    alternative: an agent process that left the launcher's process group would go on running with its file and exec
    rules unenforced, which is fail-open. `SIGSTOP`, a debugger and the freezer cannot be caught; closing them needs
    the file and exec decisions out of a stoppable userspace process, which is tier 3's BPF LSM path. Until then
    they are a stated tier-2 hazard: a tier-`cgroup` launcher is ended, never stopped.

**Changes.**
- 2026-09-30, E25: an argv the exec probe could not read is marked truncated.
- 2026-09-30: the stale to-do to call `HoldJobControl` before `prepareEnforcement` removed; the marks go down at `Arm`, after `Start`'s hold.
- 2026-09-22, E2: no kernel delivers `FAN_DENY_ERRNO` to this group; every refusal is the bare `FAN_DENY`
  (the "<6.13" wording withdrawn).
- 2026-09-29, E33 (rulecheck): heading marked `(withdrawn)`, the marker `tools/rulecheck` leaves out of its counts.
- 2026-09-23, E34: the overdue ceiling is sized from the thread budget; the `EINVAL` of 6.11/6.12 latches the id
  path off; marks ask only for refusable events.
- 2026-09-23, E35: the read loop answers path-allowed events by an index lookup; the closer takes
  every close, capped by `fdCloserCap`; a fatal `loop` returns at once and flushes mount marks by one call naming
  no path; a failed membership read keeps the refusal; workers are waited for before the final drain; a cancelled
  `loop`'s closer wait is bounded.
- 2026-09-23, E40: a continued stop can allow one open with a `fanotify-timeout` gap; the
  job-control stops are ignored by the launcher (runtime-launch.md R9a).
- 2026-09-24, E35: at the close-backlog cap `loop` waits one deadline for its closer before giving up.
- 2026-09-29, E34: the exec-line identity read runs under the deadline on the decision's
  goroutine (`statx`, `AT_STATX_DONT_SYNC`), not on the worker; whichever of it and the deadline comes second closes.
- 2026-09-29, E5 (tier 2): the breadcrumb must name the relayed socket's protocol too.
- 2026-09-24, E4: a truncated path is its own `unmatched`/`observed` event.
- 2026-09-24, E4: an exec whose name the kernel could not read is recorded as a truncated one.
- Undated, E7: tier 2 re-resolves through `RefreshNet`; "keeps deciding by the IP resolved at start" withdrawn.
- 2026-09-24, E11, E25: `-E2BIG`, no ledger gap for a full `run_set`; argv buffer 512.
- 2026-09-24, E14: every record carries its process start time.
- Undated, E15: marks removed before the loop stops reading.
- 2026-09-24, E18: paths matched as raw bytes.
- 2026-09-24, E23: samples report activity under
  `record: off`; the exit record is the thread group's.
- 2026-10-19, E23: an allowed open, file operation or connect, of which `record: off` keeps no sample,
  stamps `tego_activity` for a stall-bounded run; "each of the run's samples" alone left that work invisible.
- 2026-09-24, E24: holds only while mount and user namespaces
  are refused; a read on a host mount made after `Prepare` is `observed`.
- 2026-09-24, E32, E33 (ADR 0026 (6)): a carried slot is not handed out and a reclaimed one loses its rings; E33
  withdrawn.
- 2026-09-25, E32, E33 (ADR 0026 (6) as amended): a reclaimed slot's rings are drained and reused, not removed.
- Undated, E11, E26: no network fail-open through a `run_set` miss.
- 2026-09-28, E35 (ADR 0028 S1): the listener's index is the decision core's `decide.PathIndex`.
- 2026-09-29, E5, E10: the 50 ms staleness rule is the reader's; a gone opener's response is logged once per errno.
- 2026-09-29, E31: D2 checks, by name, the kernel types and fields the objects' CO-RE relocations read ("should check" made so).
- 2026-09-29, E38, E15, I5 (ADR 0020): run links pinned; a reaper, or the next sweep, purges a killed launcher's
  run once its cgroup is removed; the fallback refuses a run without a reaper.
- 2026-09-29, E39 (ADR 0021): closed by ordering, for every tego file and every other listener; the pairs runs
  ADR 0021 names are a condition.
- 2026-09-29, E19: an open record has no `path2`.
- 2026-09-30, E32: an unreaped zombie slot owner is dead, so its slot is purged and reclaimed.
- 2026-10-16, E36, E38: D7 is the pre-run probe and names a conflict as `Attach` does
  (`cgroup.AttachConflictHint`); "Not covered: a pre-run probe" withdrawn. The pinned links are nine, seven below 6.7.
- 2026-10-17, E36, E38 (ADR 0018 (7)): ten links, eight below 6.7, with `cgroup/setsockopt`; the list of
  what a killed launcher leaves attached names `sendmsg_unix`, `sock_create` and `setsockopt` too.
- 2026-10-06, E36, edge case 1: E36's pre-run probe is D7's scratch-cgroup attach,
  which exists; only naming the cause in D7's failure is open. Edge case 1's run record is
  `run_start.net_guarantees.unix`, no longer "not built". §7's "`connect_unix`/`sendmsg_unix` absent" row's ledger
  cell says the same: that field is false, or true where the plane's `socket_connect` and `socket_sendmsg` decide
  in a plane mode, no longer "none in the run's record yet".

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | Exit/event |
|---|---|---|---|---|
| Program load rejected | `ebpf.LoadCollection` error | abort `Prepare`, no partial pins (deferred cleanup per step) | none (pre-`run_start`) | exit 125, `<file>:<line>: bpf program load failed: <verifier tail> [enforce-load]` |
| Verdict map at capacity | userspace pre-check at insert (`Prepare`) / durable per-slot failure counter plus optional kernel event | `Prepare`: `ErrMapFull`, exit 125; kernel-side: independent watchdog kills the run even with a missing/full ring (E11) | `gap what=enforce why=cgroup-tracking-failed` and `run_end reason=error` | real membership-insert fault injection with record off and absent/full rings |
| Ring buffer full | lost-counter diff >0 per drain | keep draining, never block producers | `gap what=record why=ringbuf-full count=n` | none |
| Read-aggregation table at its 4096-bucket cap (R13) | `aggTable.add` reports full | flush every bucket at once and keep aggregating | `gap what=record why=aggregate-overflow count=<forced flushes>` | none |
| Samples of the run still on the ring when `Stop`'s final drain has spent `StopDrain` (§4 `Stop`) | the drain's clock | count the run's samples up to the bytes the ring held when the drain began, record none of them | `gap what=record why=ringbuf-undrained count=n` | none |
| The run's cgroup still holds processes `killTimeout` after a run killed it (cancelled, or its `WaitEmpty` failed for any reason, such as an unreadable `cgroup.events`), so the final drain can begin before their last samples (§4 `Stop`) | `WaitEmpty` on the bounded context fails | stop the sources anyway; a sample produced after the drain began is not read | `gap what=record why=ringbuf-undrained`, no `count` (how many is unknowable), unless the recorder reads nothing for the run and has said `kernel-record-unavailable` | none |
| The launcher is in a pid namespace of its own, or a time namespace that offsets its clocks: the ring's pids are the initial namespace's and its readings `bpf_ktime_get_ns()`'s, so every sample would name the wrong process, or carry a clock reading on another clock than this process's | recorder `Start` (`hostNamespaces`: `/proc/self/ns/pid`'s inode against `PROC_PID_INIT_INO`, `/proc/self/timens_offsets`) | read nothing, feed no hook; the run continues | `gap what=record why=kernel-record-unavailable` | none |
| A sample on the run's ring carries another slot (no program writes one there; a guard) | the sample's `run_idx` | drop it, feed it to no hook, keep draining | none | none |
| The run's cgroup has no `tego_run_set` row, the run names no cgroup, or the run's slot holds no ring (§2 "Run scope") | recorder `Start` | read nothing, feed no hook; the run continues | `gap what=record why=kernel-record-unavailable` | none |
| A read of the ring fails mid-run | `ReadInto` returns an error that is not the deadline, a flush or a close | the drain ends and the run continues; `OnError` logs the error to `tego.log` when it happens, and `Stop` returns it | `gap what=record why=kernel-record-failed` | none |
| Events channel full | non-blocking send fails | local drop counter, flushed on next success | `gap what=record why=events-channel-full count=n` | none |
| Fanotify listener dies | `errgroup` goroutine returns error, which `loop` returns as soon as it fails, its marks down by one flush that names no path, without waiting on its workers or a close (E35) | cancel run context, `cgroup.kill`; the workers answer what they hold within E16's deadline each, after `RunListener` returned (E35) | `run_end reason=error`, `detail=enforce-listener: <err>` — see the note below this table. `internal/runtime` waits for those workers (`WaitListener`, bounded by `killTimeout`) before the run's final drain, so their lines are written; only a worker past that bound can lose one, and the next row counts the events it can be for (E35) | exit 125 (`reason=error`, `identity.ExitCode`) |
| The listener dies while its workers hold permission events, queued or in hand (E35) | `loop`'s count of them, read as it returns | `loop` records the gap before it returns, so before the final drain; the workers answer those events afterwards | `gap what=enforce why=fanotify-listener-abandoned count=n`, n the most events whose lines the run's ledger can be missing, then as for a dead listener | as for a dead listener |
| Fanotify deadline exceeded | per-request timer | `FAN_ALLOW`, never block the opener | `gap why=fanotify-timeout` | none, run continues |
| More decisions answered at the deadline are still running than the listener's ceiling (sized from the thread budget, at most `fanotifyOverdueCeiling`, E34) | `handle`'s count of them, checked by `loop` between reads | `loop` records the gap, then returns `ErrListenerDied`; from there as for a dead listener: cancel run context, `cgroup.kill` | `gap what=enforce why=fanotify-overdue-ceiling count=n`, then as for a dead listener | as for a dead listener |
| The closer holds as many answered events' descriptors as it may: `fdCloserCap`, or a quarter of the soft `RLIMIT_NOFILE` where that is less, and does not close half of them within E16's deadline (E35) | the closer's count, checked by `loop` between reads, then `fdCloser.catchUp`, which `loop` waits in, reading nothing, until the closer holds half the cap or the deadline passes | `loop` records the gap, then returns `ErrListenerDied` at once; from there as for a dead listener | `gap what=enforce why=fanotify-close-backlog count=n`, then as for a dead listener | as for a dead listener |
| A membership read fails, for any reason but the opener's exit, on an event its path refuses (E35) | `inRun`'s error | `FAN_DENY`: the refusal stands; the run continues | the refusal event, and `gap what=enforce why=fanotify-membership-unread` | none, run continues |
| The thread budget cannot hold even the smallest overdue ceiling (E34) | `newFanotifyListener`, measuring `threadBudget` before `fanotify_init` | `ErrFanotify`; `Prepare` fails and unwinds (I10) | none (pre-`run_start`) | exit 125, naming the limit that bound it |
| Build lock contended on exit | `flock` `LOCK_EX` fails | another launcher still active; this one's per-run rows are removed regardless | none | none — normal multi-run operation |
| The cgroup mount a sweep, `PurgeRun` or a run-set scrub lists cgroups under is missing, is not cgroup2, or its walk's root cannot be read | `cgroupIDs`: statfs magic `CGROUP2_SUPER_MAGIC`, then the walk | no listing, never an empty one: no run-set row is deleted, a sweep keeps the build (`its run set cannot be read`), `PurgeRun` removes nothing | none | the caller's error (`tego gc`, `tego doctor`, the reaper) |
| The launcher is not in the initial pid namespace: a slot's owner is a pid read back in `/proc`, while the slot table and the run_idx space are host-wide | opening the slot table (`selfOwner`: `/proc/self/ns/pid`'s inode against `PROC_PID_INIT_INO`; a link that cannot be read counts as another namespace) | abort `Prepare` before a slot is taken; `PurgeRun` purges no slot | none (pre-`run_start`) | exit 125, `ErrPidNamespace` |
| `/proc` read races an exited pid | `ENOENT` | record with `exec_id: "unknown"`, `attribution.confidence: unattributed` | the action event, degraded attribution | none |
| `ev_fsop`'s `(dev,dir_ino)` misses `dirIndex` (§5 R9) | userspace map lookup at decode time | record the event with raw `dev:ino/name`, `attribution.confidence: unattributed` — never a guessed verdict | the `fs` event, degraded attribution | none |
| `record.ringbuf` fails power-of-two/page-multiple validation (§5 R16) | `Prepare`, before any map create | abort `Prepare`, no partial pins | none (pre-`run_start`) | exit 125, `ErrRingbufSize` |
| The run's record ring would take the host's live rings past `bpf.ring_budget` (§5 R16) | `placeRings`, under `/run/tego/rings.lock`, from the `memlock` of every build's live rings | abort `Prepare` before the run-set row, no ring left, slot released | none (pre-`run_start`) | exit 125, `ErrRingBudget`, naming the ring's charge, the use, the budget and the fix |
| The run's capture ring would pass `bpf.ring_budget` (§5 R16) | `placeRings`, after the record ring | leave it out (`Handle.CaptureRefused`); the run goes on | the uprobe source's `gap what=capture why=mechanism-unavailable binary=uprobe` | none; with a token, cost or repeats budget the runtime refuses the run, exit 125 `[capture-unavailable]` (limits-check-doctor-cli.md R32) |
| bpffs not mounted at the pin path (E30) | pin `open()` `ENOENT`/`ENXIO` | abort `Prepare`, no partial pins | none (pre-`run_start`) | exit 125, `ErrBpffsUnavailable` |
| A cgroup at or above the run's already holds an exclusive attachment for one of the ten attach types (E36) | `EPERM` from `link.AttachCgroup` | abort `Attach`, no partial attachment (`detachCgroup` closes what did attach) | none (pre-`run_start`) | `ErrCgroupAttachConflict`, naming `bpftool cgroup tree` — never the opaque `ErrProgramLoad` bucket |
| `connect_unix`/`sendmsg_unix` absent: the kernel predates the unix sockaddr attach types (below 6.7, E1, R7) | `Prepare`'s probe load of a trivial program with `BPF_CGROUP_UNIX_CONNECT` answers `EINVAL` (the kernel checks the attach type at load); `doctor` reports both rows absent and optional, with the matrix note | both are left out of `cgroup_net` before the load, and not attached; the other six load and attach; never fails the run | `run_start.net_guarantees.unix` is false (R7's per-run record, written from `Handle.NetworkGuarantees`), or true where tier cgroup runs in a plane mode and the plane's `socket_connect` and `socket_sendmsg` decide those names | none — unix connects and datagrams stay with tier 1 |
| The launcher's own cgroup cannot be named, or is the run's cgroup or beneath it (R7) | `Attach`, reading `/proc/self/cgroup` under the run's mount | refuse the attach: `connect_unix` could not tell the supervisor's relay from the agent | none (pre-`run_start`) | exit 125, `ErrNotPrepared` naming the cgroup |
| A refreshed table changes more than addresses, or moves a literal-address or host-less entry (§4 `RefreshNet`) | `RefreshNet` compares every entry but its addresses, and those entries' addresses too | the refresh is refused, the rows stay as they were | none | `ErrRefreshShape` to the caller, which logs it and retries on its next tick; the run continues |
| Root's fanotify quotas are used up, by concurrent runs or by other fanotify users of root on the host (§5 R8, "the host-wide share of the marks") | `fanotify_init` answers `EMFILE` (`fs.fanotify.max_user_groups`) in `startFanotify` (step 6), or `fanotify_mark` answers `ENOSPC` (`fs.fanotify.max_user_marks`) for a mount mark in `Arm` | abort `Prepare`, and unwind everything already created (§8 I10); at `Arm`, fail the run before `run_start`, the stage killed before its ack and `Detach` removing what was placed; the run never starts without its marks | none (pre-`run_start`) | exit 125, `ErrFanotify`, naming the setting that ran out |
| A process start in this launcher while its group holds marks (ADR 0021 (3), §5 R8) | `internal/platform/proc.Start` finds the process armed | the start is refused with `proc.ErrArmed` and nothing forks; every start the run needs (the child stage) comes before `Arm`, and the helpers after `Detach`, so this is a bug, never a run's path | none | the error names the command; a child stage refused so is `launch.ErrClone`, exit 125 |
| A `RefreshNet` write fails (a row cannot be deleted, or the map is at capacity) | the `bpf(2)` error | the error goes to the caller; until `Detach` the rows it removes cover both the old and the new set (§8 I5) | none | the run continues on whatever rows the kernel holds |
| `tego_net_owners` cannot be written after the first deciding link (§4 `Attach`) | `BPF_EXIST` update fails | abort `Attach`; the attached links refuse every connect meanwhile (storage still zero, R1) | none (pre-`run_start`) | exit 125, `ErrProgramLoad` naming the map and the cgroup |

**Note on "Fanotify listener dies" (what `run_end` says).** `RunListener`'s error reaches the run's group
(`group.Go`, `internal/runtime/group.go`), which stores it, wraps it with the member's name and cancels; `awaitExit`
then fails the run with `reason=error` and the group's error as `detail` (`enforce-listener: <err>`) before it kills the
cgroup; `shutdown` does the same for a group error that is not a cancellation. `fail` is first-wins, so the `SIGKILL`
the launcher reads afterwards does not replace it. The run ends exit 125 (`identity.ExitCode` for `reason=error`)
(`TestShutdownEndsWithErrorWhenAWorkerFailedAfterTheAgentExited`, runtime-launch.md R8). The listener's own last word,
for the overdue case, is the `gap why=fanotify-overdue-ceiling` line above.

**Changes.**
- 2026-09-30 (runtime): a `WaitEmpty` failure that is not the run context ending is killed and waited for again, like the cancelled path.
- Undated, "Fanotify listener dies": `run_end` records `reason=error`, `detail=enforce-listener: <err>`, exit 125,
  as `internal/runtime` writes it (2026-09-29: the row and note said `reason=exit`, 137, and asked for the mapping).
- 2026-09-24, close-backlog row: the one-deadline wait for the closer added.
- 2026-09-24: a launcher in its own pid or time namespace reads nothing, with
  `kernel-record-unavailable`.
- 2026-09-24: a failed ring read mid-run records `kernel-record-failed`.
- 2026-09-29 (recorder): the read-aggregation cap's `aggregate-overflow` row added.
- 2026-09-24 (ADR 0026): the foreign-row and `ErrRingbufPinned` rows withdrawn; `ErrRingBudget` and the capture
  ring left out added; a run with no ring reads nothing.
- 2026-09-29 (ADR 0021): the stage-identity, `ErrStageLinked`, `ErrStageDenied` and ignore-mark rows withdrawn; a
  mark refused at `Arm` and a process start while armed added.
- 2026-09-29: a cgroup mount that cannot be shown to be cgroup2 fails the listing, never
  lists an empty tree.
- 2026-09-29: a launcher outside the initial pid namespace is refused at the slot table,
  whose owners are pids.
- 2026-10-16: the attach-conflict row counts nine attach types, `cgroup/sock_create`'s included.
- 2026-10-17 (ADR 0018 (7)): ten, `cgroup/setsockopt`'s included.

## 8. Invariants

**I1.** Every tracing and uprobe hook does at most one `bpf_map_lookup_elem` keyed by `bpf_get_current_cgroup_id()`
before anything else (R2); a miss is a no-op. Every network hook reads its run from the attach point's
`tego_net_owners` storage and never from the caller's cgroup (R1); the one that records, `cgroup/sock_create`,
reserves only after that storage read and its configured guard (R5). Checked by static greps over `bpf/*.bpf.c` in
`bpf/tests` (`TestRunSetLookupFirst`, `TestNetDecisionReadsTheAttachmentNotTheCaller`,
`TestSockCreateIsTheAllowlistOnTheAttachmentsRun`).

**I2.** No program reads a struct field beyond its declared 6.1 prototype (ARCHITECTURE §11.1, extended to
fentry/fexit/tracepoint programs), and an fexit program declares all of its function's arguments, since its return
follows the last one (R10). Enforced by `doctor`'s per-hook BTF argument-count probe before load and by
`internal/bpf`'s `TestAttachTargetsResolve`.

**I3.** A `CGROUP_SOCK_ADDR` program returns only `0` or `1` — exactly two `return` statements plus R4's protocol
guard, checked in `bpf/tests`. *Amended 2026-10-05:* the network budget added a refusal, so `tego_net_decide` has
exactly two allow returns (R4's guard, the allow verdict) and two refusals (the verdict, the connection budget);
`tego_unix_decide` one of each; `tego_bind_decide` two allows (no listener control, a granted address) and four
refusals. `TestCgroupProgramsReturnOnlyZeroOrOne` counts them and also checks the values returned by the packet,
sockops and `sock_release` programs `cgroup_net.bpf.c` includes from `net_packet.h` and `net_budget.h`; an earlier change had
dropped the counts and those headers were never scanned. *Amended 2026-10-05 (ADR 0018 PR 2):* `cgroup/sock_create`,
a `CGROUP_SOCK` program, and from 2026-10-17 `cgroup/setsockopt`, a `CGROUP_SOCKOPT` one (one allow, every option
but `TCP_ULP`, and the same three refusals), are held to the same two values: one allow (the allowlist's triple) and three refusals (an
unconfigured attachment, a refusal whose record could not be reserved, a recorded refusal).

**I4.** The ledger's `net` verdict for a `connect4/6`-decided connect always matches the real syscall result (R5).
Half of it holds and is tested: the breadcrumb matches the syscall's result for TCP connects relayed from outside
the run on the run's socket, over IPv4 and IPv6, and for a descendant cgroup's connect; the run's own TCP connects
and unconnected UDP datagrams are checked against the contract by their syscall result alone
(`TestNetVerdictOnRealKernel`, root, a handful of fixed destinations rather than the 1,000 randomized connects this
line once promised). The other half — the ledger line — is built (R5's reader `KernelNet`): a
relayed connect the kernel refused is recorded with the kernel's refusal and its reason
(`TestRelayedConnectCarriesTheKernelsRefusal`, `internal/runtime/supervisor`, unprivileged; and on the real
kernel `TestNetVerdictOnRealKernel`, root, the `KernelNet` subtests).

**I5.** `run_idx` is never reused while any row anywhere still references it (R12). Enforced by `Detach`'s
ordering plus a race-detector test starting/stopping 100 runs back-to-back. Two paths reach the index without
that ordering, and both are closed: a `Detach` whose row removal *failed* keeps the slot allocated instead of
freeing it anyway (the process holds it until it exits, so nothing is leaked permanently), and a slot reclaimed
from a launcher that died without any `Detach` at all is scrubbed of the leftover rows before the new run's own
are written (E32). A ring is kernel state keyed by the slot too, but it carries no decision: it outlives the run
and goes to the slot's next run, drained, whose readers take only records of their own generation; a slot a
run-set row still carries is not handed out, and its rings are never reclaimed (R12, ADR 0026 (6) as amended). The run_idx in a cgroup's `tego_net_owners` value outlives `Detach` until the kernel frees the
cgroup, and the kernel offers no delete for it; it is never read again, because only this run's own links read it,
`Detach` closes them before anything else (R15), and a killed launcher's pinned links go only once the run's
cgroup is removed (E38).

**I6.** A cgroup a task can join always already has a `run_set` row when it belongs to a live run (R11). Enforced
by the kernel's tracepoint-before-activation guarantee plus a 500-nested-cgroup integration test asserting zero
unmatched decisions (`TestEveryNestedCgroupIsInTheRunSetBeforeATaskCanJoinIt`, root, tegobpf: each of a chain of
500 cgroups nested under a live run's has the run's row when its `mkdir` returns, and connects from the middle and
the bottom of the chain are decided by the run's programs; passed in the 6.17 KVM guest, 2026-09-24).

**I7.** The ring buffer never blocks a kernel-side producer (ARCHITECTURE §15.3): `bpf_ringbuf_reserve`/`submit`
only, lost-counter bump on failure, never a retry loop.

**I8.** Every fanotify permission event gets a response before deadline or process re-entry — no branch of
`fanotifyListener.loop`, or of the workers it dispatches to (E35), returns without a paired write. Two orderings
are part of the invariant rather than incidental to it, because a response is matched to its pending event by
descriptor *number* and the kernel reissues a freed number to the next event it delivers: the response is written
**before** the event descriptor is closed (`fanotify(7)`'s example closes `metadata->fd` only after the `write`),
and `loop`'s teardown drains its workers **before** closing the group, so no decision in flight turns into a write
to a closed group. On a fatal path that teardown runs after `loop` has returned (E35), and `Detach` can close the
group first; a response due after the close is then not written at all (`groupMu`), since the close has released
its opener and the group's number may name another file by then (`TestNoResponseIsWrittenToAClosedGroup`), and
a refusal so left unwritten is not recorded as a refusal (`TestNoRefusalIsRecordedForADenyNeverWritten`). The
worker emits `gap why=fanotify-response-failed` for it instead, but `Detach` runs after `internal/runtime`'s final
drain, so that gap is not written either: the event is counted in the `gap why=fanotify-listener-abandoned` line
the failed `loop` recorded before it returned (E35). A response that fails to be written while the run is live,
for any other reason, is the case whose `fanotify-response-failed` gap reaches the ledger. A third belongs to it for the openers that have not reached the listener yet: a cancelled
`loop` removes its marks **before** it stops reading, and reads until its group is empty, so an event that entered the
group is read and answered with its decision, and none can enter after save one: an opener that passed a mark in
the instant it was removed (the removal returns before the kernel frees the mark) and queued after the last read,
which the close releases with an allow nobody decided (E15). A launcher that is stopped rather than ended
answers nothing and removes nothing until it continues (E40); once it continues, an event still queued gets its
decision, and one it was deciding when it stopped has usually passed E16's deadline, which kept running, and is
allowed with `gap why=fanotify-timeout`. Linted (no early return past an unresponded
`metadata`) and tested by holding a response in a blocked `write(2)` and asserting the event descriptor is still
open at that instant (`TestHandleRespondsBeforeClosingTheEventDescriptor`), by an event that reaches the group as
its mark comes down and still gets its refusal (`TestListenerRemovesItsMarksBeforeItStopsAnswering`), by an open
after the group has closed going through (`TestFanotifyListenerDeathFailsOpen`), and, as root, by a listener killed
with an exec held in its decision whose mount answers at once (`TestKilledListenerReleasesTheMount`) and by a
stopped listener whose held open, queued after the stop, gets its refusal once it continues
(`TestStoppedListenerHoldsItsMountUntilContinued`). Not tested: an opener blocked in a decision that the group's
close releases; `TestFanotifyListenerDeathFailsOpen` closes the group before its opener starts.

**I9.** No *kernel* map here keys on a `(device, inode)` pair (ADR 0005/0010 stay tier-3-only): a kernel decision
uses either raw network bytes or, for `ev_open`, `security_file_open`'s own `bpf_d_path` string (R10) — never a
stat pair. The only `(dev,inode)`-keyed structure here is `dirIndex` (§2.4), a plain Go map, userspace-only,
record-only, never kernel-consulted (R9). Checked by a static check over `*.bpf.c` here.

**I10.** `Detach`/`Close` are idempotent after any partial `Prepare` failure. Tested by failing each of the eight
`Prepare` steps in turn and asserting no panic and no leaked pin. "No leaked pin" needs the unwind to unpin, not
just to close: a pinned link stays attached host-wide after the descriptor that made it is gone, so the load
step's undo asks the build lock the same last-out question `Detach` does and unpins when the answer is yes
(R14). A launcher told it is not last holds nothing afterwards: Linux converts an flock by dropping the shared hold
before trying the exclusive one, and taking the shared hold back would make two launchers of one build that leave
together each answer no, so nobody would unpin and the build's host-wide links and ring would stay attached.
Exactly one of two departures is last (`TestTwoDeparturesExactlyOneIsLast`).

**I11.** Every reader of kernel- or process-controlled bytes here (fanotify metadata, `/proc` fields, ring-buffer
records, path/sockaddr bytes) has a Go fuzz target (ARCHITECTURE §7/§16).

**I12.** Never imports `enforce/landlock`, `enforce/bpflsm`, `internal/check`, `internal/serve`
(`docs/REPO-LAYOUT.md`), enforced by `depguard` (`.golangci.yml` rule `cgroup-observe-imports`) over the non-test
files of `internal/runtime/enforce/cgroup` and `internal/runtime/observe`.

**Changes.**
- 2026-09-23, I8: an unwritten refusal is counted by `fanotify-listener-abandoned`, not recorded as
  a `fanotify-response-failed` gap; the test claim corrected to what `TestFanotifyListenerDeathFailsOpen` does.
- 2026-09-24, I10: a launcher told it is not last does not retake its shared hold.
- 2026-09-24, I5 (ADR 0026 (6)): rings keyed by the slot hold it as rows do.
- 2026-09-25, I5 (ADR 0026 (6) as amended): rings outlive the slot's run; generations, not removal, keep runs apart.
- 2026-09-24, I12: the `depguard` rule it cited did not exist; `cgroup-observe-imports` added.
- 2026-09-29, I4: the ledger half is built and tested; "R5's reader, which is not built" removed.
- 2026-09-30, I11, I12: moved above this list so `tools/rulecheck` reads them as rules.
- 2026-10-05, I1, I3 (ADR 0018 PR 2): `cgroup/sock_create` returns only 0 or 1, counted; it is I1's one named
  exception, its run read from owner storage before its reserve.
- 2026-10-17, I1, I3 (ADR 0018 (7)): `cgroup/setsockopt` too: one allow, three refusals, and I1's second named
  exception.

## 9. Conventions and best practices

- **SPDX + licence** on every owned `bpf/*.bpf.c`: `// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)` and
  `char _license[] SEC("license") = "Dual BSD/GPL";` (`bpf/README.md`) — without it every probe/kfunc call and any
  LSM-adjacent program is refused at load.
- **One file per concern, matching the existing layout:** `cgroup_net.bpf.c` (all eight `CGROUP_SOCK_ADDR`
  programs, sharing every map → one `CgroupnetObjects`), `cgroup_track.bpf.c` (the two tracepoints),
  `trace_proc.bpf.c` (tracepoints + ten record-only fexit and one fentry → one `TraceObjects`, matching the existing `trace`
  `go:generate` target).
- `bpf/include/common.h`/`events.h` are the single source of truth for every shared struct; never hand-duplicate
  on the Go side — bpf2go `-type` generates it.
- **Naming:** `Recorder`, `Backend`, `handle`, `fanotifyListener`, `procCache`, `aggTable` — short, concept-named,
  no `util`/`manager`/`helper`. C `SEC()` names match the kernel attach point exactly (`SEC("cgroup/connect4")`,
  `SEC("tp_btf/cgroup_mkdir")`, `SEC("fexit/security_file_open")`).
- **Errors:** sentinel `var Err*` per package, `%w`-wrapped; refusal reasons are `record.Reason` values only, never
  mixed with `agent.Diagnostic` codes.
- **Goroutines:** one owns the ring buffer, one owns the fanotify loop; both in the same `errgroup`/`context` as
  every other run worker. The loop starts its workers and its closer (E35), which are not in the group. A
  cancelled loop joins its workers and closes its group before `RunListener` returns, and joins its closer too
  unless a close the closer holds is still waiting on its filesystem after `fanCloserJoinTimeout` (10 s). A loop
  that fails (E15) returns at once, its marks removed by one call that names no path, and joins none of them, so
  its run can be killed without waiting on a marked filesystem: the goroutine it leaves to finish them, its workers
  (within E16's deadline for each event they hold, three deadlines at most) and its closer (for as long as a close
  it holds is held) can outlive `RunListener`, `Detach` and `run.Run`, and what those workers record then can miss
  the run's final drain, which the loop's `fanotify-listener-abandoned` gap counts and `WaitListener` waits out
  (E35). On either path, a decision answered at E16's deadline keeps its goroutine and the waiter `handle` left
  for it until its read returns, past `RunListener`, `Detach` and `run.Run` alike; E34's ceiling bounds how many.
- **Resource lifetimes:** every fd opened here is closed by the function that opened it, by a `Handle` whose
  `Close` closes it, or, for an answered event's descriptor, by the listener's closer (E35). Three kinds survive
  `Detach` besides the kernel-refcounted shared pins. The closer's: after a failed loop, or a cancelled one whose
  closer was still held at `fanCloserJoinTimeout`, it keeps a held close's descriptor and every one queued behind
  it open until that close returns. The workers': after a failed loop, the descriptors of the events they still
  hold, up to `fanotifyWorkers` in hand and as many queued, stay open until each is answered, three E16 deadlines
  at most. And a decision answered at the deadline, on either path, keeps its own pidfd or `/proc/<pid>/cgroup`
  descriptor until its read returns, E34's ceiling bounding how many (E35).
- **Fuzzing (I11):** corpora seeded from `test/fixtures/ledger` and captured `/proc`/fanotify byte layouts; decode
  logic only, never against a live kernel.
- **Benchmarks:** one per hot path against `docs/P0-DESIGN.md` §9's numbers (cgroup socket <1µs, fanotify round
  trip <30µs, ring buffer drain throughput), run in CI as a regression gate. *2026-10-16 (ADR 0018 PR 2):*
  `cgroup/sock_create`'s cost on an admitted socket is the perf suite's `socket.excess.cgroup_ns` (limit 2000 ns, target
  300 ns): 66 ns best-of-nine (3,140 against 3,074 ns a socket+close; medians 3,427 against 3,187 ns) in the 6.17
  guest, `make vm-perf -checks socket`; on a loaded host (load average 26 on 16 CPUs, the landlock loop at 11,920 ns) a
  second run printed `TARGET-MISS` at 769 ns, within the limit (ADR 0018's note). One more link and pin left the warm
  start within the suite's noise (the root modes over landlock 28 to 31 ms with it, 27 to 44 ms in two runs without
  it). *2026-10-17 (ADR 0018 (7)):* `cgroup/setsockopt`'s cost on an option it passes is `setsockopt.excess.cgroup_ns`
  (limit 2000 ns, target 300 ns), the same check's setsockopt(TCP_NODELAY) loop: 161, 155, 228 and 259 ns in four
  runs of the 6.17 guest on a loaded host (load average 4 to 20), whose `socket.excess.cgroup_ns` was 164, 302
  (`TARGET-MISS`), 235 and 174 ns. The warm start's `attach` phase, the run's links and pins, was 0.7 to 1.0 ms with
  both socket programs against 0.6 to 0.8 ms without them (ADR 0018's note). The fanotify round trip is
  `BenchmarkFanotifyRoundTrip` (root, `integration` tag). First measurement, 2026-09-22, as root in the 2-vCPU
  `test/vm/kvm-run.sh` guest on this project's i7-10870H laptop (6.17, three runs of 20,000 opens): an open on an
  unmarked mount ~1.2 µs; on the marked mount, allowed on the path ~45 µs; refused after the membership read
  ~56 µs. That is ~44 µs of round trip for the allowed open, **over the 30 µs budget** in that guest. A VM on a
  loaded laptop inflates the cross-CPU wakeups each open pays for (opener → listener's poll → worker goroutine →
  decision goroutine → response → opener), so the number that settles the budget is a bare-metal root run, which
  `ci.yml`'s `bpf-load` job reports on every push; if it is over there too, the hand-offs per event are what to cut (§6 E34,
  E35 bound the design, not these hops). `docs/BENCHMARKS.md` records rows, and this one belongs there.
  *Second measurement, 2026-09-23, the hand-offs cut:* an allowed open is now answered by the read loop itself
  (opener → listener's poll → readlink and policy → response → opener; R8), and in the same guest
  (1536 MiB, 2 vCPUs, two runs of 20,000 opens each) the allowed-on-the-path round trip is 18–19 µs on 6.17 and
  13–16 µs on every other matrix kernel (5.14, 6.1, 6.8, both 6.12s, 7.0), **under the 30 µs budget**; with the read
  loop's answer reverted in a private copy it was 43–45 µs again on 6.17. The refused open, which still reads
  membership on a worker under E16's deadline, is unchanged at 47–59 µs. *Third, the same day:* the
  descriptor of an answered open is closed by a closer goroutine rather than by the loop (E35), which costs the
  allowed round trip 1–2 µs: 17.6–19.5 µs on 6.17 against 15.9–17.6 µs with the close on the loop, six runs of
  20,000 each over two boots, the two builds alternating in one guest; still under the 30 µs budget. The policy
  lookup the loop makes costs the same whatever the number of entries (E35), so these figures no longer hold only
  for a small policy. *Fourth, 2026-09-24:* from the closer's cap until the loop waited there (E35), the benchmark
  did not complete with GOMAXPROCS 2: its allowed opens ended the listener at the cap. With
  the wait, in the same guest (three runs of 20,000 opens a boot, two boots on 6.17.0-41 and on 6.17.0-1022-azure,
  one on 6.8.0-142), the allowed-on-the-path round trip is 18.7–19.8 µs on 6.17.0-41, 16.0–18.0 µs on 6.8.0-142 and
  21.6–27.2 µs on the GitHub runner's 6.17.0-1022-azure, and the refused one 49.2–50.0, 56.2–61.0 and 51.9–64.3 µs.
- **Cost of a run at tier `cgroup` (kill test 4).** The 2026-09-23 acceptance run
  measured this tier's own cost, with `doctor`'s program probe out of the way, at 0.3–1.6 s a run plus
  70–110 µs an open, and kill test 4's pip kind failed the 2× bound of kill test 4 on four of seven kernels. Profiled as root in
  the KVM guest (1536 MiB, 2 vCPUs, the probe read from a cache in a private measuring build and never shipped;
  `strace -f -T` of whole runs, and a test binary timing each step of `Prepare`, `Detach` and `Close`), the time
  went here:
  - *Per open:* every mark asked for `FAN_OPEN_PERM`, so under kill test 4's contract, whose only mark is the root
    filesystem for its exec entries, every open of the run and of the host was a round trip through the listener
    for a decision that could only allow it: 35–45 µs each, three goroutine hand-offs and a timer among it. The
    recorder's share rode on that round trip: 20,000 opens cost 0.3–0.7 s more with `record: off` and 1.7–2.7 s
    more at `record: summary`, against 30–40 ms bare, and with the round trip gone the second is 0.15 s at most
    (below). That second part is the recorder's. *Why the two compounded*, measured
    afterwards on 6.17 in the same guest: an agent timing 20,000 opens of one file inside itself, two runs a
    case, the launcher's context switches from `getrusage` (its children's less the agent's own), and the
    programs' own time from `kernel.bpf_stats_enabled`. Each sample the recorder's program on
    `security_file_open` writes (`record: summary`) wakes the recorder's ring reader whenever the reader has
    already consumed everything before it (`bpf_ringbuf_submit` with no flag), and an opener held for the
    listener's answer gives the reader that time between any two opens. So under a mark that asks about opens
    every sample woke it: with the answer on the read loop, the launcher's voluntary context switches rose by one
    per open (about 21,500 at `off`, 42,000 at `summary`), where opens nobody asks about let the samples batch
    (7,000–7,600 wakeups for 20,000 samples). The program itself takes 45–72 ns a call that writes nothing
    (`off`, or an open outside the run), 1.2 µs a call that writes a sample, and 2.9 µs where each sample also
    queues that wakeup; the reader's handling of one sample at a time adds 4.6 µs of the launcher's CPU an open,
    against 2 µs where the samples batch. With the decision on a worker, as before this change, an asked open
    already woke about two of the launcher's threads (43,000 switches at `off`), and at `summary` about five
    (100,000–110,000): the reader's wakeup, landing among the read loop, the worker, the decision goroutine and
    its timer on two vCPUs, cost three more thread wakeups a sample rather than one, and the open went from
    35–40 µs to 108–125 µs. Answered on the read loop, the same asked open takes 19–20 µs at `off` and 24–25 µs
    at `summary`, against 1.3 µs with no tego, so recording adds about 5 µs an open under the mark; an open no
    mark asks about pays less (26 ms for the 20,000 with no tego, 34–36 ms at `off`, 60–64 ms at `summary`).
    What was left is the recorder's own: a sample per open and a reader woken per sample where opens are slow.
    *The wakeups taken out (2026-09-23):* `trace_proc` submits its opens, file operations and connects
    with `BPF_RB_NO_WAKEUP` unless the ring is an eighth full, forces the wakeup for execs, exits and opens of a
    `libssl.so*`, and the reader reads at least every 50 ms (§4 `Start`). The same method, as root in the KVM guest
    (1536 MiB, 2 vCPUs), HEAD's build and this one alternating in one guest per kernel, two runs a case, an agent
    timing 20,000 opens of one file at tier `cgroup` (ms for the 20,000, and the launcher's voluntary context
    switches):

    | Kernel | no tego | no mark asks, `summary`: HEAD → this build | no mark asks, `off` | a `deny_read` on the mount, `summary`: HEAD → this build | same, `off` |
    |---|---|---|---|---|---|
    | 6.17 | 26–27 | 62–64 (7,956–9,090 switches) → 43 (794–876) | 34–42 | 430–512 → 469–472 | 414–448 |
    | Ubuntu 24.04 (6.8) | 25 | 72–73 (10,766–10,847) → 42–44 (970–1,154) | 32–38 | 474–505 → 383–385 | 352–377 |
    | AL2023 (6.12) | 21–24 | 63–73 (10,690–10,810) → 48 (1,000–1,057) | 35–41 | 523–553 → 447–453 | 325–489 |

    An open no mark asks about now costs `summary` 0.4–0.5 µs over `off` rather than 1.1–1.9 µs, and the
    launcher's context switches for the 20,000 fall to what a run of no opens makes (700–1,900). Under a mark the reader's wakeup no longer lands among the listener's threads;
    what `summary` still adds there is inside the noise of the round trip on 6.8 and 6.12 and not measurably
    smaller on 6.17. `TestTraceProcWakesItsReaderOnlyWhereItMust` pins the flags and
    `TestSamplesWithNoWakeupAreReadOnTheReadInterval` the timed read; the record-only programs load, and the kernel
    record's end-to-end tests pass, as root on all six matrix kernels. On Fedora's 7.0,
    `TestIntegrationTwoRunsUnderLoad` (replaced by `TestIntegrationConcurrentRunsOfOneBuild`, ADR 0026) loses
    r-A's samples with no `ringbuf-full` count in 6 of 40 subtests with
    HEAD's build and this one alike (`r-A has 88411 opens and 0 lost`) and in none of 40 on 6.17: it is not this
    change's, and it stays open, a sample lost with no count, which the record must never have (§7's ring rows).
  - *Per run, fixed:* loading and verifying the three objects, 90–130 ms, whatever else of the build was already
    pinned; attaching the nine host-wide links, 12–50 ms on 6.17 and 6.12 but 0.5–0.7 s on Ubuntu 24.04's 6.8, where
    each of the five fentry attaches waits out an RCU Tasks grace period (about 120 ms each); and detaching them at
    the last launcher's `close(2)`, 0.47–0.50 s on 6.17 and 6.8 and 0.87 s on AL2023's 6.12: four of the five fentry
    links take 110–200 ms each in the kernel's ftrace unregistration, which serialises them under its lock (closing
    them from five goroutines at once took 0.66 s). The marks: one mount per rule's mount, never more than the
    contract needs; no candidate there.
  What changed (R8, R14, `newBPFKernel`): (1) each mark asks only for the events a rule
  on its mount can refuse, so an exec-only mount raises no open event; (2) the read loop answers what the path alone
  allows; (3) a launcher that finds the build's objects pinned whole opens them instead of loading its own copies
  (`adoptObject`), which spares a run that overlaps another (kill tests 1 and 7 start two) the 90–130 ms load; (4) the
  last launcher out closes each host-wide link's descriptor before removing its pin, so the kernel detaches the link
  from a worker and the launcher does not wait for it (on 6.8 and later; 5.14 and 6.1 free it in the launcher either
  way). (4) is reversed 2026-10-19 (R14's amendment): the next run's load waited for that worker's
  detach, so a removal now returns only once the kernel has released the build's links, and only a build that does
  not linger (`bpf.linger: 0`) is removed by its last launcher. 5.14 did not free in the launcher either: its bpf
  filesystem releases a pin after an RCU grace period. A fifth, ignoring a directory's opens once one of them was allowed, was withdrawn because the ignore
  moves with the directory into a denied tree (R8); the last column below is what its absence costs. Measured with the same probe-cached builds before and after, same guests, one `tego run` of kill test 4's
  kind of contract (`record: summary`, one write directory, `python3`, `bash`, `true` allowed), in ms:

  | Kernel | `true`, 2 s apart: before → after | `true`, back to back (runs 2–5) | 20,000 opens, extra over 0 opens: before → after | same, with a `deny_read` entry on the files' mount (after) |
  |---|---|---|---|---|
  | 6.17 | 830–931 → 287–439 | 878–908 → 870–1,050 | 2,180–2,540 → 0–140 | 485–520 |
  | Ubuntu 24.04 (6.8) | 1,230–1,349 → 750–810 | 1,438–1,601 → 1,313–1,362 | 2,520–2,720 → 0 | 410–495 |
  | Debian 13 (6.12) | 984–1,094 → 296–453 | 1,055–1,185 → 968–1,106 | 1,870–1,970 → 0–90 | 360–415 |
  | AL2023 (6.12) | 1,353–1,754 → 367–374 | 1,424–1,662 → 1,359–1,635 | 1,660–1,770 → 0–140 | 390–435 |
  | AL2023 (6.1) | 1,551–1,586 → 1,472–1,609 | 1,345–1,595 → 1,427–1,462 | 1,690–1,810 → 0 | 400–520 |
  | RHEL 9 (5.14) | 894–908 → 873–928 | 1,564–1,606 → 1,552–1,568 | 2,480–2,560 → 0–10 | 350–400 |
  | Fedora (7.0) | 277–293 → 264–273 | 286–314 → 261–288 | 1,840–1,930 → 0 | 405–425 |

  The last column was measured with the entry in the files' own directory, where no directory was ignored even
  while that change was in; with it out, where on the mount the entry sits makes no difference, since every open
  there is asked about. On 6.17, measured again once it was out, two runs each: 485–493 ms with the entry in the
  files' directory and 486–495 ms with it in another directory of the same mount, 382–397 ms for either at
  `record: off`, against 26 ms for the 20,000 opens with no tego.

  The record is unchanged: the same ledger lines, in kind and count, before and after (a 20,000-open run's 25
  lines, its reads aggregated into one `fs` event). **Keeping the budget honest — what is left, and where:**
  - A run that follows another within the detach's own time (0.5–0.9 s) pays that detach: the kernel finishes it
    while the next launcher loads or attaches its fentry programs, which wait for it. So the back-to-back column is
    no better than before, and the saving is the isolated run's, and whatever of the detach overlaps the time between
    two runs. A first `tego run` at tier `landlock` within that window waits as well, where `bpf` is an active LSM,
    in `doctor`'s LSM probe (0.65–1.2 s once, then 75–330 ms); that probe belongs to tier selection
    (limits-check-doctor-cli R27).
  - Ubuntu 24.04's 6.8 still pays about 0.5 s of fentry attach on every run no other run overlaps, and RHEL 9's
    5.14 and AL2023's 6.1 still pay the detach in the launcher, since the pin's removal frees the links there
    in the process that removes it.
  - The load, 90–130 ms, stays for a run no other overlaps; loading the three objects in parallel would save at
    most the two cgroup-unix programs' 20 ms each, and was not taken.
  - Every open on a mount a `deny_read` entry marks costs a round trip through the listener, by any process on the
    host, for as long as the run lasts: 13–19 µs without the recorder (the second measurement above), and on 6.17
    19 µs an open at `record: off` and 24–25 µs at `record: summary` (the last column). On an ordinary box that
    is the root filesystem, where the home directory's built-in `deny_read` entries (`~/.ssh`, `~/.npmrc`) sit
    with everything else. R8 names the condition for sparing the opens the policy allows there.
    The kill test 4 rows below paid none of it, since the guest's home held none of those paths; with `~/.ssh`
    there, the pip run took about 100 ms more on 6.17 (the note under the table).
  **Condition for the rest:** a run that starts right after another pays neither the attach nor the detach of the
  five fentry links only if the build stays attached between runs, which ARCHITECTURE §6 and R14 rule out today: the
  last launcher out detaches, so that no Tego program stays in the kernel once no run needs it. Keeping it
  attached until a sweep or a reboot, or handing the links to `tegod` (ARCHITECTURE §15.7), is ARCHITECTURE §15.7's
  decision, and it trades an idle build's programs and pinned maps for
  0.5–1.3 s a run on these kernels.
  *2026-09-29 (ADR 0016 step 2):* the rows above measured five fentry links; the record now attaches ten fexit
  programs (nine below 6.2) and connect's fentry. ADR 0016's measurement at seven programs is +130, +145 and +103 ns
  per host open on 6.17, 6.8 and 6.1 while a build is attached, against +46, +61 and +88 for fentry; attach, detach
  and per-call cost at the ten are not measured yet (open, ADR 0016 step 2).
  **Kill test 4, pip kind, as root** (`test/e2e/kt4-ordinary.sh` unchanged, the probe cached in both builds, HEAD's
  build and this one run one after the other in one guest per row; baseline median / under-tego median / 2×
  budget, ms):

  | Kernel | tier `landlock` (this build) | tier `cgroup`: HEAD → this build |
  |---|---|---|
  | 6.17 | PASS 20/20 — 1893 / 2309 / 3786 | FAIL 7/20 — 1875 / 3610 / 3750 → **PASS 20/20** — 1887 / 3361 / 3774 |
  | Ubuntu 24.04 (6.8) | PASS 20/20 — 1852 / 2010 / 3704 | FAIL 2/20 — 1901 / 3714 / 3802 → **PASS 20/20** — 1912 / 3512 / 3824 |
  | AL2023 (6.12) | PASS 20/20 — 1802 / 2208 / 3604 | FAIL 0/20 — 1805 / 4620 / 3610 → FAIL 1/20 — 1801 / 4213 / 3602 |

  *What these rows leave out.* `kvm-run.sh --sudo` gives the invoking user an
  empty home in the guest, so the rows ran with no `~/.ssh`, no `~/.npmrc` and no project `.env`: none of the
  built-in `deny_read` entries named a path that exists, kill test 4's contract marked no mount for
  `FAN_OPEN_PERM`, and the pip run's opens were asked about by nobody. On an ordinary developer box `~/.ssh` alone
  marks the root filesystem (or `/home`) for opens, and every open of the run on that mount pays the round trip
  above. We measured what that adds, as root on 6.17 (1536 MiB, 2 vCPUs, `--sudo`, the tegobpf
  build before the lookup and the closer of E35): the pip workload at tier `cgroup` took a median of 2715 ms with
  the empty home, 2706 ms with a `~/.ssh` and the work directory on a tmpfs (another mount, so its opens are not
  asked about), and 2811 ms with a `~/.ssh` and the work directory on the root filesystem, as on Ubuntu, where
  `/tmp` is on `/`: about 100 ms, inside 6.17's 2× bound. It was not measured on 6.8 or on AL2023's 6.12, whose
  row is over its bound already. *Measured since, with the recorder's wakeups taken out (above):* kill test 4's pip
  kind at tier `cgroup`, 20 runs, as root on each row's own kernel, HEAD's build and this one in one guest, first with
  the empty home and the work directory on `/tmp` (a tmpfs), then with a `~/.ssh` in the home and the work
  directory under `/var/tmp` on the root filesystem, where the launcher's group then marks `/` for
  `FAN_OPEN_PERM` as well (read back from its `fdinfo`: mask `0x50000`, against `0x40000` with the empty home);
  baseline median / under-tego median / 2× budget, ms:

  | Kernel | empty home: HEAD → this build | `~/.ssh`, work on `/`: HEAD → this build |
  |---|---|---|
  | Ubuntu 24.04 (6.8) | PASS 20/20 — 1784 / 3410 / 3568 → PASS 20/20 — 1777 / 3314 / 3554 | FAIL 15/20 — 1780 / 3419 / 3560 → PASS 19/20 — 1745 / 3408 / 3490 |
  | AL2023 (6.12) | FAIL 0/20 — 1704 / 4214 / 3408 → FAIL 0/20 — 1682 / 3963 / 3364 | FAIL 0/20 — 1690 / 4266 / 3380 → FAIL 0/20 — 1689 / 4219 / 3378 |

  So the 6.8 row's PASS holds with a `~/.ssh` in the home, by 82 ms of a 3,490 ms budget and with one run of twenty
  over it: it is a PASS at the edge, not the margin of the empty-home row.

  AL2023's 6.12 is still over, and the pip workload itself says by how much and where (4 runs each, ms): bare
  1742–1796, tier `landlock` 2103–2192, tier `cgroup` 2308–2426 at `record: off` and 3185–3356 at `record: summary`,
  each run 3 s after the last; back to back, 3250–4534 at `record: summary`. On 6.17 the same are 1833–1859,
  1970–2262, 2132–2601 and 2641–2717. So two things remain, and either one alone brings AL2023's 6.12 under its
  bound: the detach a back-to-back run inherits (about 1 s there, the condition above), and the recorder at
  `record: summary`, 0.75–0.95 s of the pip run on AL2023's 6.12 with no permission round trip left in the way. The
  second is not this component's: the launcher's own CPU time rises by only 0.06–0.09 s with it (utime and stime of
  the launcher, sampled through the run; its voluntary context switches rose in one of two runs), so the time is
  spent outside the launcher's userspace, in the record-only programs or in what their samples cost the agent,
  measured next. With the recorder's wakeups taken out, that time is not the recorder's. Taking out the wakeups moved kill test 4 on AL2023's 6.12 from a 4,214 to a 3,963 ms median,
  still over its 3,364 ms budget (the table above). What `record: summary` switches on there is the uprobe capture
  source, which `record: off` leaves idle (capture-derive R4: it places no probe for such a run): a zero-open run of
  `true` at tier `cgroup` took 1,802–1,856 ms with `capture: auto` at `record: summary`, against 302–410 ms with
  `capture: off` at `summary` and 334–407 ms with `capture: auto` at `off` (three runs each, this build; on 6.8 the
  same are 834–853, 734–758 and 763–806). Traced with `strace -f -T` on 6.12, the run with the uprobe source spends
  0.9–1.1 s closing its uprobe perf-event descriptors and 0.35–0.43 s closing their links, one at a time, each
  close waiting 60–170 ms in the kernel; with `capture: off` there are none. That is the host libssl's probes,
  which `Start` pre-attaches for every recording run and `Stop` detaches (capture-derive R4, R8). **Condition** for
  kill test 4 at tier `cgroup` on AL2023's 6.12: `internal/runtime/capture/uprobe` cuts
  the per-run cost of placing and removing those probes on 6.12, for example by removing them concurrently so the
  kernel's waits overlap, or by keeping them placed between runs as the build's links would be (ARCHITECTURE §6's
  decision above); or the build stays attached between runs; then kill test 4 there again, with `doctor`'s probe as
  tier selection runs it.
- **Doc comments:** every exported symbol names its normative source (`spec/...` or `docs/ARCHITECTURE.md §N`).

**Changes.**
- 2026-09-23, Goroutines and Resource lifetimes: a failed loop's workers, closer and deadline-answered
  decisions can outlive `run.Run`; the "none outlives cancellation" statement withdrawn.
- 2026-09-23, Benchmarks and Cost: second and third round-trip measurements; recorder wakeups taken out; kill
  test 4 rows and what they leave out (empty home).
- 2026-09-24, Benchmarks: fourth measurement, with the loop's wait at the close-backlog cap.
- 2026-09-24 (rulecheck): R18 named with the document that defines it; wording otherwise unchanged.
- 2026-09-29, §10: the R12/R16 evidence names the ring-reuse tests that exist; the two ring tests the redesign replaced are gone from the list. rulecheck now fails a cited test name no function declares.
- 2026-10-17, Benchmarks (ADR 0018 (7)): `cgroup/setsockopt`'s cost (`setsockopt.excess.cgroup_ns`), four more runs of
  `socket.excess.cgroup_ns` on a loaded host, and the warm start's `attach` phase with and without the two programs.

Warm startup descriptor capacity (2026-10-01): before opening the build's maps, programs and links, the launcher
best-effort reserves a 256-entry descriptor table by duplicating its held build-lock descriptor with
`F_DUPFD_CLOEXEC` at minimum 128 and immediately closing the duplicate. Linux expands a descriptor table shared
by threads through an RCU grace period; actual AL2023 6.1 runs paused at both FD 64 and FD 128, regardless of
which pinned object was opened there. One reservation consolidates those growth waits. It does not replace an
existing descriptor, release the original flock, change `RLIMIT_NOFILE`, or weaken adoption checks. Failure is
an optimization miss and leaves ordinary allocation in place. `TestReserveBPFDescriptors` checks capacity,
occupied descriptors, lock retention, no descriptor leaks, and a restrictive limit in isolated subprocesses.
*Amended 2026-10-05:* this paragraph said minimum 255; `reserveBPFDescriptors` asks 128,
which also grows a smaller table to 256 entries, and two concurrent reservations land at 128 and 129 in that one
table, where 255 puts the second at 256 and forces another expansion (`TestReserveBPFDescriptors/async-concurrent`).
There are two reservations: the CLI starts an asynchronous one that borrows its stderr descriptor
(`StartDescriptorReservation`, overlapping compilation and backend selection, so it opens no BPF object or lock),
and the loader keeps the synchronous one over its held build-lock descriptor as a barrier and fallback.

## 10. Tests

**Unit:** `net_key`/`cidr_key` precedence table (R3, E8); slot allocator concurrency (E21); `/proc` fallback and
pid-reuse disambiguation (E13/E14); aggregation flush timing (R13); path truncation/UTF-8 (E4/E18/E19/E25); reason
breadcrumb staleness (R5/E5) and reason-row-miss-after-Detach (R15); `dirIndex` hit/miss inference from `ev_fsop`
(R9); `record.ringbuf` power-of-two/page-multiple validation (R16, E28); per-run rings placed before the run-set
row, under the ring budget, reused by the slot's next run and reclaimed from idle builds, and a carried slot not
handed out (R12, R16, `TestPrepareGivesEachRunItsOwnRings`, `TestPrepareRefusesPastTheRingBudget`,
`TestACaptureRingPastTheBudgetIsLeftOut`, `TestTheSlotsNextRunReusesItsRings`,
`TestAPlacementReclaimsTheRingsOfIdleBuilds`, `TestSlotACarriedSlotStaysHeld`);
every program writes only its run's own ring and counts a loss at its slot (`TestRecordsGoToTheRunsOwnRing`);
2, 8 and 32 concurrent runs of one build each recorded whole and only their own, as root on the real objects
(`TestIntegrationConcurrentRunsOfOneBuild`) and end to end (`TestTier2ConcurrentRunsOfOneBuild`); ring-buffer decode for every `ev_kind`
incl. malformed/short records; lost-counter diffing. Fanotify, with a pipe or socket pair standing in for the
group: every refusal is exactly the `FAN_DENY` word, with no errno or other bit (E2; `fanotify_test.go`,
`fanotify_loop_test.go`, `fanotify_concurrency_test.go`); response-deadline fail-open (E16, `fanotify_test.go`);
one slow decision does not hold up the next opener, `fanotifyWorkers` execs stalled on one membership read make an
allowed open wait for a worker that E16's deadline frees, an exec answered at its deadline has its event descriptor
closed right after the answer while its read is still stalled and stays counted as overdue until the read returns,
and one overdue decision more than the ceiling makes `loop` return `ErrListenerDied` while exactly the ceiling does
not (E34, E35, `fanotify_concurrency_test.go`); on both of `handle`'s branches the response is written before the
event descriptor is closed (I8); the listener constructor itself sizes its ceiling from the measured thread budget,
and it and `Prepare` refuse a host too small for any ceiling before a group exists (E34,
`TestListenerConstructorSizesItsCeiling`, on a fake procfs and cgroupfs); a stopping listener removes its marks
before it stops reading, and an event the group holds then gets the answer decided for it, not the close's allow
(E15, `TestListenerRemovesItsMarksBeforeItStopsAnswering`); the read loop answers what the path alone allows,
without a worker and past a held pool, and still reads nothing more once its hand-off blocks (R8, E35,
`TestLoopAnswersAPathAllowedEventWithoutAWorker`, `TestSettleByPathLeavesEverythingElseToAWorker`,
`TestListenerLoopQueuesOpensBehindExecsStalledOnMembership`), the listener the constructor builds does so
(`TestNewListenerSettlesOnTheLoop`, with `fanotify_init` stubbed), and a close of an answered descriptor that
waits holds no later event (E35, `TestLoopClosesASettledDescriptorOffTheLoop`), nor a worker
(`TestWorkersCloseThroughTheCloser`); a fatal `loop` returns while a close is held, a cancelled one waits for it
only up to its bound, and the closer's backlog ends
the listener at its cap with a line, long before the descriptor limit (E35, `TestFatalLoopReturnsWhileACloseIsHeld`,
`TestCancelledLoopReturnsWhileACloseIsHeld`, `TestLoopGivesUpAtTheCloseBacklogCap`, `TestCloseBacklogFor`, and as
root `TestHeldCloseEndsTheListenerBeforeTheDescriptorLimit`), while at the cap a closer that only lacked a processor
is waited for and catches up (E35, `TestLoopWaitsAtTheCapForItsCloser`, and as root
`TestFanotifyAllowedOpensKeepTheListener`); a refusal whose `FAN_DENY` was never written is not
recorded as one (E35, `TestNoRefusalIsRecordedForADenyNeverWritten`); a membership read that fails keeps the refusal (E35,
`TestDecideEventKeepsTheRefusalWhenMembershipIsUnread`, `TestDecideEventKeepsTheRefusalAtTheDescriptorLimit`); the
path verdict costs the same
at 20 and at 50,000 `deny_read` entries and gives the entry a walk of every entry gives (E35,
`TestDecideOpenCostDoesNotGrowWithEntries`, `TestPathSetMatchesTheWalk`, `BenchmarkDecideOpenByEntryCount`),
and `Prepare` asks `statx` about each path to mark once, however many entries name it
(`TestGroupByMountAsksOncePerPath`); a group or mark refused for want of root's
fanotify quota fails with `ErrFanotify` naming the setting that ran out (R8, §7,
`TestFanotifyQuotaFailuresNameTheirSetting`); each mark asks only for the events a rule on its mount can refuse
(R8, `TestMarkMasksAskOnlyForWhatCanBeRefused`, `TestPrepareMarksEachMountForTheEventsItCanRefuse`); the last
launcher out of a build that does not linger removes a host-wide link's pin before closing its descriptor, and every
removal of a build returns only once the kernel has released its links and their programs (R14, §9,
`TestUnpinRemovesEachSharedLinksPinBeforeClosingIt`, `TestUnpinLinkFallsBackToTheUnlink`,
`TestTeardownWaitsUntilTheKernelFreesThePrograms`, and as root
`TestBuildRemovalReleasesLinksBeforeReturn`, `TestPlaneRemovalReleasesLinksBeforeReturn`); every host-wide program has the attach kind its compiled type
calls for, the syscall-result programs tracepoint and the rest tracing, in both builds of `trace_proc` and in
`cgroup_track`, and `bpf.AttachTrace` refuses a program with no kind or the wrong type before asking the kernel (R14,
`TestTraceProgramsAttachByTheirProgramType`, `TestAttachKindOfNamesEveryHostWideTracingProgram`,
`TestAttachTraceRefusesBeforeAskingTheKernel`, and in `enforce/cgroup` that such a refusal fails the load even
for an exec-result program, `TestAttachRefusalIsNotAnOptionalLinkFallback`); the paths to mark collapse by the mount a lookup
names, never by device, and a path with no readable mount is kept by name (R8, `mounts_test.go`, with the lookup
injected, so these pin the collapse and not the key). That the key is the mount `statx` names and not the device
is pinned unprivileged only on a host that shows two reachable mounts of one device
(`TestDistinctMountsSeparatesThisHostsMountsOfOneDevice`, from `/proc/self/mountinfo`; an Ubuntu host with snapd
has such pairs, the KVM guest has none and skips), and on every host as root by `TestFanotifyMarksEveryBindMount`
below. Membership answered by cgroup id, the run's own at once and any other once named, never asked again of a
kernel that refuses the ioctl, whether with `ENOTTY` or `EINVAL` (`TestPidfdInfoErrorsThatMeanNoIoctl`), and left
to `/proc/<pid>/cgroup` for an exited opener or a cgroup that cannot be named (E34, `members_test.go`, with this
host's own pidfd cgroup id checked against its cgroup directory, which skips on a kernel without the ioctl).
Kernel rows against what the supervisor
admits (R1, R5, E7; `rules_test.go`, `netparity_test.go`): port-53 rows for the run's resolvers, named
`net.resolver`, winning over a declared entry on the same key and none for an endpoint off port 53; no rows and no
attachment under a contract with no `net:` section, while an empty `net:` section and a table with no contract stay
restricted; `RefreshNet` moving a rotated host's rows without dropping a shared address, keeping an entry's
addresses when the refresh brings none, keeping the resolver rows, refusing a changed entry and a moved literal or
host-less entry, leaving nothing behind when it fails part way, and writing nothing after `Detach`; a resolver or an
entry address given only in its v4-mapped form keyed as the IPv4 destination too
(`TestBuildRuleMapsMappedOnlyResolver`). The exec check against the files a run really executes (R8,
`stage_test.go`): a symlinked binary, a relative link, a loader and a directory entry through a link matched by
their canonical paths, a deny_read reached through its `Resolved` target, no refusal under a contract with no
`exec:` section, a hard link of a named binary refused, and no exec admitted that no entry names, the launcher's own
binary's first exec in the run included (`TestDecideEventAdmitsNoStageExec`). The arming point (ADR 0021):
`Prepare` leaves no run-set row and no mark, `Arm` places both with the process armed, a process start is refused
until `Detach` disarms it (`TestArmIsTheOneArmingPoint`), and a contract that marks nothing arms nothing
(`TestArmWithoutAGroupArmsNothing`); in `internal/runtime`, `TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck`
finds, at `Arm`, the one child running the tego binary, exec'd and not yet acked, and
`TestIntegrationFailedArmFailsTheRunBeforeTheAgent` a failed `Arm` ending the run before `run_start`. As root,
`TestTier2ArmsAfterTheStageExec` is R8's acceptance for it; it, the two arming tests and the four freeze tests below
(`TestStageExecUnderGCNeverWaitsOnItsOwnGroup`, `TestKilledListenerReleasesTheMount`,
`TestUnmarkAllFlushesOnlyTheMountMarks`, `TestStoppedListenerHoldsItsMountUntilContinued`) are in
`test/vm/root-must-pass.txt`, so a skip of any of them fails CI's root-suites job. Every process start is a reviewed
site (ADR 0021 (6)): `TestEveryProcessStartSiteIsListed`, in `internal/platform/proc`, reads every Go file of the
module and fails on a call of `proc.Start`, `cgroup.StartHelper` or `cgroup.StartHelperExec`, or of an unexported
function that makes one of them, that its list does not name by function and by count, with each start's relation to
`Arm`; `TestStartSiteScanSeesEveryWayToNameAStart`, `TestFollowedStartFuncsComeFromTheRows` and
`TestStartSiteProblemsNameWhatIsWrong` hold the scan, the functions it follows and the comparison to what they are for
on a tree of their own, and `TestLintExclusionsAreTheStartSites` holds `.golangci.yml`'s start-site rule and
exclusions to the same list.

**BPF map-logic (`bpf/tests`):** LPM prefixlen formula across CIDR widths /0–/32 and /0–/128; `run_set`
self-scoping (R1) with two synthetic builds; `bpftool` load test of every object on the CI kernel (`ci.yml` job
`bpf-load`), and the per-program `cilium/ebpf` load on each `test/vm` row (`vm-matrix.yml`) (I2, I3). Static source checks that need no clang: a network decision never
keyed by the caller (R1), context members read by value (the verifier refuses a load through a moved context
pointer), no map named like a struct (bpf2go `-type`), and an architecture target for every object that reads
registers (`internal/bpf/gen_test.go`).

**Generation (`ci.yml` job `bpf-gen`):** regenerates the committed bpf2go output with the pinned clang and fails on
any difference, then builds and runs the unprivileged `tegobpf` tests (layout parity, object shape, CO-RE
relocations against the runner's BTF).

**Integration** (`//go:build integration`, root, VM):
- `net_integration_test.go` (`TestNetVerdictOnRealKernel`, `TestNetHelper`, `TestNetRefreshOnRealKernel`): real cgroup attach, exact/CIDR/unmatched-refused table (I4); connect-vs-sendmsg UDP split
  (R4); raw-socket gap recorded only, never refused.
- `nestedrunset_integration_test.go` (`TestEveryNestedCgroupIsInTheRunSetBeforeATaskCanJoinIt`, I6) and
  `rmdir_integration_test.go` (`TestRmdirOfANestedCgroupDeletesItsRunSetRow`, E6, E26): rapid nested cgroup spawn and
  immediate rmdir; `net_integration_test.go` ("E11 a descendant cgroup is decided by the run's attachment"): the
  capacity case.
- `integration_test.go` (needs `CAP_SYS_ADMIN`, skips without it): a refused open reports `EPERM`, never `EACCES`
  (E2); an open after the group has closed is not left blocked (E15). An opener already blocked when the listener
  dies is observed only as one that dies with its launcher (the child in its vfork window in
  `TestKilledListenerReleasesTheMount`); one the close releases is not yet observed by any test.
- `mounts_integration_test.go` (root): `TestFanotifyMarksEveryBindMount`, R8's mark per mount — one tmpfs mounted
  at two paths, a `deny_read` entry under each, both refused. It is the test that pins the key on every host: with
  `distinctMountsBy` keyed on `st_dev`, every unit test of the dedup passes and this one fails.
- `freeze_integration_test.go` (root): the two-run freeze and E15 against the kernel, each with a helper process holding the
  group on a tmpfs of its own. `TestStageExecUnderGCNeverWaitsOnItsOwnGroup` starts the stage binary
  60 times in the launcher's order (no mark while it execs, marked once it reports, a process start refused while
  marked, its first open as the agent refused) while the collector runs without pause; should a stage exec wait on
  the group again the helper stops, the test names the wait from its stacks, and the mount answers again once the helper is killed. `TestKilledListenerReleasesTheMount` kills a
  listener holding an exec in its decision, beside a child that outlives it, and the mount answers at once.
  `TestStoppedListenerHoldsItsMountUntilContinued` is E40's hazard: a `SIGSTOP`ped listener's mount holds an open
  under its `deny_read` entry, made after the stop, and `SIGCONT` answers it with the refusal.
- `startcost_integration_test.go` (root; §9): `TestSecondLauncherAdoptsTheBuildsPinnedObjects`, a second launcher
  of the build runs the first's pinned programs (by program id) and the last one out still removes the build;
  `TestExecOnlyMarkAsksForNoOpenEvent`, an exec-only contract's mark carries `FAN_OPEN_EXEC_PERM` alone (from the
  group's fdinfo) and 50 opens there raise no event; `TestDirectoryMovedIntoADeniedTreeIsStillAsked`, a directory
  the run read a file in, then renamed into a `deny_read` tree and given a new file there by a process outside the
  run, is refused to the run for both files and for a create of its own, with a line each, and a file the refused
  create leaves there is empty (R8, "No directory is ignored" and its note on a refused create); it fails, never skips, on
  any failure to mark but the missing privilege.
- `members_integration_test.go` (root; it skips only without it): `TestRunMembersMatchesProc`. On a kernel with
  `PIDFD_GET_INFO`'s cgroup id, the id path and `/proc/<pid>/cgroup` agreeing for processes in the run, in a
  descendant, outside it, the launcher and pid 1, and handing an exited opener and a removed cgroup to `/proc`; on
  one without it (6.12, 6.8, 6.1), the id path answering nothing and latching once, and `/proc` telling the run, its
  descendant and an outside process apart. `BenchmarkMembership` against `BenchmarkFanotifyRoundTrip` (E34).
- `test/vm/tier2-pairs.sh` (the KVM guest, as if under sudo): pairs of `tego run --tier cgroup` started 0-20 ms
  apart, plain, under `timeout`, with one launcher `SIGKILL`ed each pair, or of two builds, under a watchdog that
  needs no open or exec on the marked root and prints every task's kernel stack and every process's fanotify marks
  when a pair stops making progress, then kills the launchers and reports whether the guest moves again (E39). It
  pins the decision plane (`PLANE`, through the test-hooks build's `TEGO_TEST_PLANE`; `fanotify` by default, so a
  host where a plane mode passes still runs the fallback) and judges each pair once, from all of its evidence,
  before its ledgers are removed (*amended 2026-10-19; ADR 0021's note of that name holds the
  table). The pair first settles: a killed launcher's reaper closes its run after the launcher's wait returned (ADR
  0020 (3)), so the judgement waits up to `SETTLE` seconds for every started run's `run_end`. Every started run must
  then name that `decision_plane`, refuse the agent's read of a `deny_read` file on `/` nested in a write entry at
  most once and only by that plane's mechanism (`source` `fanotify` on the fallback, `mechanism` `plane` otherwise),
  hold no other verdict on the file and no exec line of the stage, and be one launcher's by `run_start`'s
  `launcher_pid` (under `timeout`, the pid the launcher wrote before it exec'd). Each launcher then gets one verdict
  from its exit status, whether the kill phase's `SIGKILL` targeted it, its own run and its output (the agent's
  `PAIRS-READ opened|refused` and the secret's content), and nothing outside the table passes: `complete` (exit 0,
  one refusal, `run_end` reason `exit`, the agent saying refused), the target's `killed-early`, `killed-in-run` or
  `killed-read` (exit 137), or `failed`, which fails the pair. `killed-read` is E15's stated window on the fallback:
  the agent of the launcher the kill ended runs undecided by fanotify until the reaper kills it, so its read may go
  through; it passes only in a run that never refused the file and that its reaper closed (`run_end` reason
  `orphaned`), and is counted (`killed_reads` in `PAIRS-DONE`, a warning in `summary.json`), never passed as
  refused. The same read beside the run's refusal, in a run its launcher closed, or on a plane (which outlives its
  launcher, ADR 0020) fails the pair.
  The kill phase draws its kill point from the previous pair's length, counts the kills that landed and those that
  hit a started run in `PAIRS-DONE` (the targeted launcher's killed verdicts only), and fails when fewer than `KILL_MIN`
  percent (50) of the pairs lost a launcher. `COPY_B=1` runs the pair's launchers
  from two inodes, `LISTENER=` starts `test/vm/cmd/permlistener` beside them (the watchdog kills it after the
  launchers, separately, so a report says whose group held), and `SELF_DENY=1` first runs a contract that denies
  reading the launcher's own binary (ADR 0021 (4)), whose agent must also see its open refused.
  `tier2-pairs_test.sh` runs the assertion, the self-deny run, the loop and the
  setup functions over fixture ledgers, stand-in launchers and stand-in listeners. `test/vm/pairs.sh` (`make vm-pairs`) is the host
  driver: it builds a static and a `-buildmode=pie` test-hooks tegobpf binary (refusing to boot unless
  `test/vm/cmd/elfinterp` finds a loader and `ET_DYN` in the PIE and none in the static build) and the listener,
  boots one guest per variant (`two-inodes`, `third-party`, `guest-freeze`, `pie`, `plane-control`) and boot, and reads
  each console into a `summary.json` that passes only with every phase's `PAIRS-DONE n/n` and no watchdog line
  (`pairs_test.sh` holds it to stand-ins). `TestPrepareOnRealKernel` runs the whole of `Prepare`, `Attach` and
  `Detach` against the real objects; it decides whether it may run from the effective capability set, never from
  the load's error, because the verifier's own refusal is `EACCES` ("permission denied") and a skip keyed on that
  text hid every verifier rejection as a skip.
- `net_integration_test.go` (root): `TestNetVerdictOnRealKernel` — the run's own connects and datagrams, a connect
  relayed from outside the run on a `pidfd_getfd` duplicate of the run's socket (supervisor R9), a resolver query
  relayed the same way on a UDP socket (allowed under `net.resolver`; port 53 on another address refused), and a
  descendant cgroup with its run-set row removed, each refused or allowed as the contract says, with the breadcrumb
  under the run's cgroup id agreeing (R1, R5, E11, I4). `TestNetUnrestrictedOnRealKernel` — under a contract with
  no `net:` section a relayed connect, the run's own connect and a datagram all pass and no breadcrumb is written
  (R1). `TestNetRefreshOnRealKernel` — a rotated host is refused until `RefreshNet`, then allowed at the new
  address and refused at the old (E7).
- `e2e_integration_test.go` (root under sudo, tegobpf suite): `TestTier2RunEndToEnd`, the tier's acceptance — an
  unmodified `-tags tegobpf` binary runs `tego run --tier cgroup` of an ordinary contract that names no tego
  binary to exit 0; a write outside the contract is refused and recorded, a `deny_read` under a writable parent is
  refused by fanotify (`EPERM`, `source=fanotify`), a DNS query to the machine's resolver is admitted and answered
  (`net.resolver`), and a connect to an undeclared host is refused. As root under `test/vm/run-in-vm.sh` on
  2026-09-22 it passed on Ubuntu 24.04's 6.8, Debian 13's and AL2023's 6.12, the test machine's 6.17 and Fedora's 7.0, and
  skipped on AL2023's 6.1 and RHEL 9's 5.14, where doctor offered no tier `cgroup` (R7's open item, closed
  2026-09-23: with the unix hooks optional below 6.7 it passes as root on both, `TEGO_VM_KERNEL=matrix-al2023` and
  `matrix-rhel-9` through `test/vm/root-suites.sh`).
- `internal/bpf/load_integration_test.go` (root): every program of every object loaded on its own, so a verifier
  rejection names its program (this is how `connect6`/`sendmsg6` were found refused), then each object whole;
  `connect_unix` and `sendmsg_unix` are skipped on a kernel below 6.7, as the backend leaves them out there.
- `unix_integration_test.go` (root, tegobpf suite): `TestUnixVerdictOnRealKernel`, R7 in the running kernel — and
  `unix_e2e_integration_test.go`: `TestTier2UnixEndToEnd`, R7 through `tego run --tier cgroup` with the real
  supervisor. `unix_rules_test.go` pins the rows to the supervisor's name check without a kernel.
- `events_test.go` and `fsop_integration_test.go`: synthetic workload (opens, exec tree, unlink/rename) through to `record.Event`s against a
  golden fixture, asserting `ev_fsop` never carries a resolved path and `dirIndex` inference matches the fixture's
  rules (R9); identical attach behavior for the `path_*` fexit programs on every kernel target (R10). As built:
  `chain_test.go`'s unit cells (the chain's return is the verdict, the model explains or stands in, record: off keeps
  Tego's refusals) and, as root, `chain_integration_test.go`'s `TestIntegrationChainReturnIsTheVerdict`: a
  Landlock-refused read, create and unlink recorded `refused` from the chain's `-EACCES`, a Landlock-refused
  truncate the contract grants `observed` with `by: other`, one line per action (ADR 0016 step 2).
- `upgrade_integration_test.go` (root, tegobpf suite): `TestTwoBuildsCoexistWithoutInterference`, two coexisting
  `bpf_hash` builds (the same objects under two `Options.Hash` identities), disjoint contracts, no cross-build
  interference in verdicts, breadcrumbs or run sets, and the old build's teardown leaving the new one intact (E22,
  R1); it logs the per-open cost to a process in no run with zero, one and two builds attached, the numbers E29
  states. It was cited here before it existed (2026-09-24).
- `nestedrunset_integration_test.go` (root, tegobpf suite): `TestEveryNestedCgroupIsInTheRunSetBeforeATaskCanJoinIt`,
  I6's 500-nested-cgroup test, likewise cited before it existed.

**E2E:** feeds kill test 1 (identity/attribution — `run_idx` disjointness), 2 (capture gap explanation — this
component's `gap what=record`), 3 (overhead — against `docs/P0-DESIGN.md` §9's per-path budgets).

**Kernel matrix (`test/vm`):** every program loaded and functionally probed on Ubuntu 24.04 (6.8), Debian 13
(6.12), AL2023 default (6.1) and `kernel6.12`, Fedora (6.8–7.0); asserts every target attaches every record-only
fexit program (`security_file_truncate`'s from 6.2) and the connect fentry, and that the file-operation ones always
emit raw `(dev,ino,name)`, never `bpf_d_path` (R9/R10, one version split, like R7's gated `connect_unix`; E31's
relocation check runs here too).
RHEL 9's 5.14 is a tested matrix row (`rhel-9`) below the upstream 6.1 floor, run with its backports
(spec/backend/CAPABILITIES.md's minimum-kernel row; `tego doctor` D1 still reports it below the floor): this component's suites pass there, `cgroup/connect_unix` and `cgroup/sendmsg_unix` absent by
design and `fexit/security_file_truncate` held back by version (test/vm/README.md's 2026-09-29 table).
The `test/vm/kvm-run.sh` guest can boot any kernel image placed in its cache (`TEGO_VM_KERNEL`), which is how the
6.1 floor was exercised as root without the matrix: Debian 12's `6.1.0-50-amd64` (6.1.176). Every program but
`connect_unix` loads there, the backend's root tests pass, and a build without §7's `connect_unix` row fails
`TestPrepareOnRealKernel` with "cgroup_net: load program: invalid argument", which is what the 6.1 source's
`bpf_prog_load_check_attach` says: the attach type is checked at load, below 6.7 it is unknown, and the object failed
whole. Every other row but RHEL 9 was then run the same way, as root, on 2026-09-22, booting the distro kernel
`test/vm/fetch-kernel.py` caches (`TEGO_VM_KERNEL=matrix-<row>`), with the committed objects: `internal/bpf`'s
`TestObjectsLoadOnThisKernel` and `TestCORERelocationsResolve`, and this package's
`TestPrepareOnRealKernel`, `TestNetVerdictOnRealKernel`, `TestNetUnrestrictedOnRealKernel`,
`TestNetRefreshOnRealKernel` and the five `TestFanotify*` tests. All of them pass on ubuntu-24.04 (6.8.0-142),
debian-13 (6.12.107), al2023 (6.1.186, `connect_unix` skipped in the load test as the backend leaves it out),
al2023-6.12 (6.12.103) and fedora-7.0 (7.0.14), as they do on Debian 12's 6.1.0-50 and the test machine's 6.17.0-41.
`vm-matrix.yml` runs the load test and the four backend tests on every row but RHEL 9. The load test drops
`connect_unix` below 6.7 on its own, so the backend's own drop is guarded only by a row below 6.7 running
`TestPrepareOnRealKernel`, which is al2023's: with the call removed from `newBPFKernel`, that test fails there with
"cgroup_net: load program: invalid argument".

**Third-party listener (`test/vm/cmd/permlistener`):** E39's third-party condition needs a permission listener that is not
Tego's, and the conformance suite's space 6 needs one that refuses a file. The helper has two modes: `allow-touch`, whose
decisions open and read files on the marked mount before they answer `FAN_ALLOW` (the cycle E39 closes by ordering), and
`deny -path P`, which answers `FAN_DENY` to one file (the ledger line for that open depends on the kernel, ADR 0016 (3)). It
answers its own opens on its reader, lets an event through at its own 10 s deadline and counts it `late`, and answers each event
once. Unit tests stand a socketpair in for the group; four root tests run it against the kernel on a tmpfs of their own
(`TestIntegrationDenyRefusesOneFileAndNoOther`, `TestIntegrationAllowTouchDecidesOnTheMarkedMountWithoutDeadlock`,
`TestIntegrationADecisionThatStallsIsLetThroughAtTheDeadline`, `TestIntegrationStopReleasesAnOpenerMidDecision`).
test/vm/README.md describes it.

**Fixtures:** one golden `events.jsonl` slice per kind produced here (`exec`, `fs` aggregated and individual,
`net` allow/refused/observed, `gap` per `why`), added to `spec/record/v1/fixtures/` and `test/fixtures/ledger/`.

**Changes.**
- 2026-09-29, matrix tests: `TestRingbufResize` (removed with the shared ring, ADR 0026) no longer named among the
  root load tests; `scripts/check-skiplists.sh` now holds every test a workflow names to a func in the tree.
- 2026-09-29, R9: a delete/rename/mkdir of a direct child is named by the nearest entry of `<dir>/<name>` (a `watch` or
  `deny_read` child outranks the indexed directory's entry), as `matchFS` names it (`TestMatchDirNamesTheNearestEntry`).

- 2026-09-30, test plan: the Integration list names the test files that exist (`net_integration_test.go`,
  `nestedrunset_integration_test.go`, `rmdir_integration_test.go`), not `cgroup_net_test.go` / `cgroup_track_test.go`.
- 2026-10-05, test plan (E39's third-party listener): the helper ADR 0021's pairs runs name is built, `test/vm/cmd/permlistener`,
  in two modes, `allow-touch` and `deny`. The pairs runs themselves are still to be recorded (E39's Condition).
- 2026-10-05, test plan (ADR 0021 (6)): the start-site tests (`TestEveryProcessStartSiteIsListed` and its three
  companions, `internal/platform/proc/sites_test.go`) hold every process start to a reviewed site.
- 2026-10-06, test plan (ADR 0021 (6)): `TestFollowedStartFuncsComeFromTheRows` is a fourth companion, for the
  unexported functions the scan follows; the scan test's plantings find a bare `startHelperIn`, `startHelperProcess`
  and `startOnKeptThread` in their own directories and not the same names elsewhere.
- 2026-10-05, test plan (ADR 0021 (2), (3)): the two arming tests and the four freeze tests are held by
  `test/vm/root-must-pass.txt`, so a skip of any of them, which `go test` reports as a pass, fails CI's root-suites job.
- 2026-10-06, kernel matrix: RHEL 9's 5.14 is a matrix row whose suites pass, not "below this
  project's 6.1 tested floor".
- 2026-10-16, kernel matrix: RHEL 9's 5.14 is a tested row below the upstream 6.1 floor, not "one of the
  tested floors", which doctor's D1 contradicted there.
- 2026-10-06, §11: the exec-producer question is answered as built (ADR 0016 step
  3, `observe.Options.SupervisorExecs`), not "decided, not yet built".
- 2026-10-19, test plan (E39's condition): `tier2-pairs.sh` runs the fallback it claims to and proves it per pair
  from the ledgers (`PLANE`, the refusal of a nested `deny_read` by the plane's mechanism, `run_end`, no stage exec
  line), with `COPY_B`, `LISTENER` and `SELF_DENY` for ADR 0021's two-inode, third-party and PIE runs. The runs
  themselves are still to be recorded (E39's Condition).
- 2026-10-19, test plan (E39's condition, ADR 0021 C4): `test/vm/pairs.sh` and `make vm-pairs` run the variants
  per guest and boot and read each console into `summary.json`; the PIE build is checked to be one before any guest
  boots. A `PLANE=auto` phase that ran the fallback fails `plane-control` and is a warning for `pie`.
- 2026-10-19, test plan (E39's condition): a 50-pair smoke of every variant on GUEST 6.17, both
  boots, passed with every pair's ledger asserted and no watchdog line (1,100 pairs; ADR 0021's
  note). `pie` ran at its full count there, so ADR 0021's PIE condition is met on GUEST; E39's runs at full count
  (1,000 two-inode and third-party pairs, 500 of the two-run reproduction) are still to be recorded here.
- 2026-10-19, test plan (E39's condition): `tier2-pairs.sh` ties each run to its launcher by
  `launcher_pid` (a killed launcher's complete run had stood in for the survivor's), reads the launchers' output for
  the secret and the self-deny agent's own answer, and its kill phase now kills across the run's life and counts
  the kills that landed (a 6.17 probe at the old 100-900 ms killed a launcher in 4 of 30 pairs).
- 2026-10-19, test plan (E39's condition): a kill-mode pair passes only when both launchers exited
  0 but the one its `SIGKILL` targeted, which may exit 137; a survivor that failed had passed with its run owed
  nothing, and the other launcher's 137 (tego's exit for a cgroup-killed agent) had counted as a landed kill. The
  kill point's draw is tested on its own (ADR 0021's note). The killed launcher's agent reading
  the secret on the fallback, which the 6.17 smoke saw in 2 of 4 kill phases and the first version had made a failure, is
  E15's window: counted and warned, and a failure on a plane.
- 2026-10-19, test plan (E39's condition): `tier2-pairs.sh` judges a pair by one table over each
  launcher's whole evidence, after the pair settled, instead of excuses granted in one place on checks made in
  another. Its first version excused a killed launcher's read without its run, so a run whose ledger said the
  listener refused the read that went through passed; held to the table, the harness before this change
  passed 366 of 4,800 evidence combinations the table fails, and none the other way (ADR 0021's note). The watchdog's report now prints the pair's ledgers as they stand and asks the launchers for their
  goroutines with `SIGABRT` (`GOTRACEBACK=all`): `tego run` forwards `SIGQUIT` to its agent and lives on, so the
  report's `SIGQUIT` had never printed a launcher's goroutines.
- 2026-10-27, §5 (ADR 0043 C8's recorder half): an open the fanotify listener refused by a name entry is
  the listener's line, the marked mounts include the name scopes', and a plane refusal by a name entry of a file with
  a `deny_read` entry at its path is named by that entry. Nothing changes while `agent.NameEntriesEnforced` is false.
  Tests: `TestPlaneNameRefusalNamesTheRule`, `TestRecorderLeavesListenerNameRefusalsToTheListener`.
- 2026-10-27, §5 R7's unix rows (ADR 0043 D6): in a run a decision plane decides, a
  `deny_read` file the plane compacted gets no unix row pair, and Prepare chooses the plane before it builds the rows
  (`RefreshNet` passes the same plane rows). Each such file had two rows of the trie every run of a build shares, so a
  project with 4,500 `.env` files beneath a write entry (9,006 rows against `UnixRowsMax` 4,096) was refused at
  Prepare though the plane held it. The listener's run keeps every pair. Since 2026-10-27 every product build
  enforces name entries (the switch the entry above names is gone). Test: `TestUnixRowsLeaveOutTheFilesThePlaneCompacted`;
  guest: `TestCompactedTableStaysAtBPFLSM`.

## 11. Open questions

- **Which producer owns an `exec` line at tier 2 (decided; built by ADR 0016 step 3, see the answer below).** Both the seccomp supervisor and
  this recorder record every `execve` of a task that carries the run's filter, so one `execve` becomes two
  `exec` lines. SEMANTICS §4 says there is one line per `execve` and that its argv and script path come from
  the seccomp notification. The decision is that the **supervisor owns** the line for every task that carries
  the run's filter (every task descended from the agent), and the recorder writes an `exec` line only for a task
  the filter never covered (a process an adopted container put in a descendant cgroup). The recorder still
  consumes every exec sample for its process cache. Both producers already name the process with the same
  `exec_id` (`proc.ExecID`), so the two lines of one `execve` can be paired until then. Buildable once the
  `sched_process_exec` record says whether the task runs under the run's filter. One way: `trace_proc.bpf.c`
  keeps the `task->seccomp.filter` pointer of the run's first exec in a per-run map and marks a later exec
  whose filter chain (`->prev`, bounded walk) reaches it. `handleExec` then records the line only when that
  mark is absent. *Answered 2026-10-06:* built by ADR 0016 step 3's producer table, without the
  filter mark: the supervisor writes the line of every exec, and the recorder, told so before it starts
  (`observe.Options.SupervisorExecs`, set by `internal/runtime/run_capture.go`), writes none and keeps its process
  cache; where the plane decides the run's execs the line is the kernel's instead (`spec/record/v1/README.md`,
  enforce-plane §2.19). A task the filter never covered is what container adoption (FEATURES E42, E43) brings, and
  that is schema-only, so the mark waits for it.
- **`connect_unix`'s exact context (answered 2026-09-23, R7).** The hook exposes the caller's raw `sun_path` bytes,
  through `bpf_cast_to_kern_ctx` and `bpf_rdonly_cast` of `uaddr`, not the peer's resolved identity: the lookup runs
  after the hook. SEMANTICS' "resolved socket" is therefore the supervisor's (R11) for connects, and the programs
  decide names only; the userspace realpath compromise is the supervisor's resolved-socket check, not a kernel one.
- **`FAN_REPORT_FID`/`FAN_REPORT_PIDFD` combinability with `*_PERM` events** across 6.1–6.13, and whether
  `metadata->fd` stays populated for permission events with `FAN_REPORT_FID` set — needed for the inode-object
  resolution R8/R9 assume. Not settled by any normative doc; a `doctor` functional probe should decide it per
  kernel.
- **P0-authored constants** (fanotify deadline 500ms; 4096-row map/slot sizing, E11/E12) are not drawn from
  `spec/config/v0` (no such keys exist there) — whether they belong in a future config/contract version is open.


## Resolved conflicts
Resolved (2026-09-22): P0 tier 2 materializes the run's own cgroup subtree only; cross-daemon adoption is P2 (P0-DESIGN §0). `bpf/README.md` now describes `trace_proc.bpf.c` as fentry on the `security_*` dispatchers.
