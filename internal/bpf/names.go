// SPDX-License-Identifier: Apache-2.0

package bpf

// Object names one compiled C file each. They are the keys of Load and the names the pin directory and the
// build hash are computed over (docs/p0/enforce-cgroup-observe.md §2.1, §3).
const (
	// ObjectCgroupNet is bpf/cgroup_net.bpf.c: the eight CGROUP_SOCK_ADDR programs of tier 2.
	ObjectCgroupNet Object = "cgroup_net"
	// ObjectCgroupTrack is bpf/cgroup_track.bpf.c: cgroup_mkdir/cgroup_rmdir descendant materialization.
	ObjectCgroupTrack Object = "cgroup_track"
	// ObjectTraceProc is bpf/trace_proc.bpf.c: the record-only tracepoints, fexit programs and connect's fentry.
	ObjectTraceProc Object = "trace_proc"
)

// Object is the name of one compiled BPF object.
type Object string

// String returns the object's name.
func (o Object) String() string { return string(o) }

// Map names, shared by the three tier-2 objects through bpf/include/maps.h. Every one of them is pinned by name
// under /sys/fs/bpf/tego/<bpf_hash>/maps, so the objects of one build share a single instance (§3, §5 R14).
const (
	// MapRunSet is the host-wide cgroup id -> run membership map every hook consults exactly once.
	MapRunSet = "tego_run_set"
	// MapNetExact is the exact host:port verdict map, keyed by NetKey.
	MapNetExact = "tego_net_exact"
	// MapNetCIDR is the longest-prefix CIDR verdict trie, keyed by NetLPMKey.
	MapNetCIDR = "tego_net_cidr"
	// MapReason is the network breadcrumb, one row per run keyed by the run's own cgroup id (§5 R5).
	MapReason = "tego_reason_map"
	// MapEvents is the record's ring outer: a HASH_OF_MAPS from run_idx to the run's own ring buffer, which every
	// record-only program writes to (ADR 0026 (1)).
	MapEvents = "tego_events"
	// MapLost counts each run's failed record reserves, an ARRAY of u64 indexed by run_idx (§8 I7, ADR 0026 (4)).
	MapLost = "tego_lost"
	// MapTrackingFailed counts failed descendant membership insertions independently of ring delivery.
	MapTrackingFailed = "tego_tracking_failed"
	// MapCaptureEvents is capture's ring outer, MapEvents's shape: a run's capture ring at its run_idx, present
	// only for a run whose capture is uprobe (ADR 0026 (3)). It is deliberately not MapEvents: the record's drain
	// and capture's reader never contend for one ring, and neither has to skip the other's records.
	MapCaptureEvents = "tego_capture_events"
	// MapCaptureLost counts each run's failed capture reserves by run_idx: MapLost's shape, kept apart so the
	// record and capture each report their own drops (ADR 0026 (4)).
	MapCaptureLost = "tego_capture_lost"
	// MapCaptureMiss counts, by run_idx, the probe hits of a run that has no capture ring: the TLS calls of a
	// capture: off run, which the probes shared by the build's runs see and do not capture (ADR 0026 (3)).
	MapCaptureMiss = "tego_capture_miss"
	// MapActivity is each run's activity stamp by run_idx, an ARRAY of ActivitySlot (a bpf_ktime_get_ns,
	// CLOCK_MONOTONIC, reading and its jiffy): trace_proc stamps a stall-bounded run's allowed actions under record:
	// off there, and the TLS probes its calls that moved bytes in every mode (RunActivity; limits R4). The run's
	// watcher pulls it once a tick (ActivityAt).
	MapActivity = "tego_activity"
)

// SharedMaps lists every map pinned by name, in the order a pin directory is created and removed.
var SharedMaps = []string{MapRunSet, MapNetExact, MapNetCIDR, MapReason, MapEvents, MapLost, MapTrackingFailed, MapCaptureEvents,
	MapCaptureLost, MapCaptureMiss, MapActivity}

// RingMaps are the two ring outers, each keyed by run_idx (ADR 0026 (1)).
var RingMaps = []string{MapEvents, MapCaptureEvents}

// SlotCounters are the per-run counters indexed by run_idx, which Prepare zeroes for a run's slot so the run
// counts its own drops and misses from its own start (ADR 0026 (4)), and the activity stamp, zeroed for the same
// reason: a stamp the slot's previous run left reads as nothing to the next.
var SlotCounters = []string{MapLost, MapTrackingFailed, MapCaptureLost, MapCaptureMiss, MapActivity}

// MapNetOwners is the cgroup storage the network programs read their run from, one NetOwner per cgroup they
// are attached to (§5 R1, R2). Only ObjectCgroupNet defines it, as only ObjectUprobeSSL defines CaptureMaps;
// it is pinned by name beside SharedMaps.
const MapNetOwners = "tego_net_owners"

// MapUnixNames is the unix socket name trie connect_unix and sendmsg_unix decide by, keyed by UnixKey and
// holding NetVerdict values (§5 R7). Only ObjectCgroupNet defines it; it is pinned by name beside SharedMaps.
const MapUnixNames = "tego_unix_names"

// MapUnixApprovals holds the one-connect grants of approved abstract names (supervisor R11c), keyed by
// UnixApprovalKey and holding UnixCredit values; connect_unix and the plane's socket_connect read it beside
// MapUnixNames. Only ObjectCgroupNet and the plane define it; it is pinned by name beside SharedMaps.
const MapUnixApprovals = "tego_unix_approvals"

// NetMaps lists the maps only ObjectCgroupNet defines, in pin order.
var NetMaps = append([]string{MapNetOwners, MapUnixNames, MapUnixApprovals, MapNetTimeline}, NetControlMaps...)

// Program names in ObjectCgroupNet. All eight attach to one cgroup, each to its own attach type (§5 R1);
// ProgConnectUnix and ProgSendmsgUnix only on 6.7+, below which the backend does not load them (§5 R7).
const (
	// ProgConnect4 decides every AF_INET connect(2) of a run's cgroup.
	ProgConnect4 = "tego_cg_connect4"
	// ProgConnect6 decides every AF_INET6 connect(2).
	ProgConnect6 = "tego_cg_connect6"
	// ProgSendmsg4 decides each unconnected IPv4 UDP datagram (§5 R4).
	ProgSendmsg4 = "tego_cg_sendmsg4"
	// ProgSendmsg6 decides each unconnected IPv6 UDP datagram.
	ProgSendmsg6 = "tego_cg_sendmsg6"
	// ProgBind4 is the IPv4 bind placeholder that always allows (§5 R6).
	ProgBind4 = "tego_cg_bind4"
	// ProgBind6 is the IPv6 bind placeholder that always allows (§5 R6).
	ProgBind6 = "tego_cg_bind6"
	// ProgConnectUnix decides every AF_UNIX connect(2) by the name it carries (6.7+, §5 R7).
	ProgConnectUnix = "tego_cg_connect_unix"
	// ProgSendmsgUnix decides each addressed AF_UNIX datagram by the name it carries (6.7+, §5 R7).
	ProgSendmsgUnix = "tego_cg_sendmsg_unix"
)

// ProgSockCreate is ObjectCgroupNet's cgroup/sock_create program (BPF_PROG_TYPE_CGROUP_SOCK): it refuses an inet
// socket outside ADR 0018's allowlist on any path to inet_create and records its own refusal (KindSockCreate;
// docs/p0/enforce-cgroup-observe.md §5 R4, R5). It reads the attachment's NetOwner, as the CGROUP_SOCK_ADDR programs
// do, and is not one of them: it attaches with AttachCGroupInetSockCreate, so it is not in CgroupPrograms.
const ProgSockCreate = "tego_cg_sock_create"

// ProgSetsockopt is ObjectCgroupNet's cgroup/setsockopt program (BPF_PROG_TYPE_CGROUP_SOCKOPT): it refuses
// setsockopt(SOL_TCP, TCP_ULP), which turned a socket the allowlist admitted into another family in place, on any path
// to the protocol's setsockopt (io_uring's SOCKET_URING_OP_SETSOCKOPT, which the seccomp filter never sees), and
// records its own refusal (KindSockopt; ADR 0018 (7)). It reads the attachment's NetOwner too.
const ProgSetsockopt = "tego_cg_setsockopt"

// SocketPrograms lists ObjectCgroupNet's programs that bound which sockets a run has (ADR 0018 PR 2 and (7)), in
// attach order: cgroup/sock_create, which decides an inet socket's creation, and cgroup/setsockopt, which decides
// the upper-layer protocol that would make it another. Neither is a CGROUP_SOCK_ADDR program.
var SocketPrograms = []string{ProgSockCreate, ProgSetsockopt}

// UnixPrograms are the programs of ObjectCgroupNet whose attach types the kernel knows from 6.7 on. It checks
// a program's expected attach type when the program is loaded, so below 6.7 these two are left out of the
// object before it is loaded, and the other six load and attach (§5 R7, §6 E1).
var UnixPrograms = []string{ProgConnectUnix, ProgSendmsgUnix}

// Program names in ObjectCgroupTrack.
const (
	// ProgCgroupMkdir materializes a descendant cgroup into the run set (§5 R11).
	ProgCgroupMkdir = "tego_cgroup_mkdir"
	// ProgCgroupRmdir removes a descendant's row and its breadcrumb.
	ProgCgroupRmdir = "tego_cgroup_rmdir"
)

// Program names in ObjectTraceProc. All are record-only (§5 R8, R9, R10); the fs ones are fexit programs that
// carry the LSM chain's return (ADR 0016 (3)).
const (
	// ProgSchedExec records one exec per successful execve, after the binfmt search (a #! script
	// gives one record, not one per stage), and anchors every exec id.
	ProgSchedExec = "tego_sched_exec"
	// ProgExecResult and ProgExecatResult record negative exec syscall returns.
	ProgExecResult = "tego_exec_result"
	// ProgBindResult clears per-task listener creation state after every bind.
	ProgBindResult   = "tego_bind_result"
	ProgListenResult = "tego_listen_result"
	// ProgURingBindResult and ProgURingListenResult are the same producers for IORING_OP_BIND and
	// IORING_OP_LISTEN (6.11+), which exit no bind or listen syscall: fexit programs on io_bind and io_listen
	// (enforce-plane §2.20). Both are among OptionalTracePrograms.
	ProgURingBindResult   = "tego_uring_bind_result"
	ProgURingListenResult = "tego_uring_listen_result"
	ProgExecatResult      = "tego_execat_result"
	// ProgSchedExit records a process's exit and evicts its process-cache row.
	ProgSchedExit = "tego_sched_exit"
	// ProgFileOpen records every open with a resolved bpf_d_path string (§5 R10).
	ProgFileOpen = "tego_file_open"
	// ProgPathUnlink records an unlink as raw (dev, dir inode, name) (§5 R9).
	ProgPathUnlink = "tego_path_unlink"
	// ProgPathRename records both sides of a rename as raw identifiers (§5 R9).
	ProgPathRename = "tego_path_rename"
	// ProgPathMkdir records a mkdir as raw identifiers (§5 R9).
	ProgPathMkdir = "tego_path_mkdir"
	// ProgPathMknod records a mknod(2), or an O_CREAT open's create when it is the action's outcome (ADR 0016).
	ProgPathMknod = "tego_path_mknod"
	// ProgPathRmdir records an rmdir as raw identifiers.
	ProgPathRmdir = "tego_path_rmdir"
	// ProgPathLink records both names of a link as raw identifiers.
	ProgPathLink = "tego_path_link"
	// ProgPathSymlink records a symlink's new name and its target.
	ProgPathSymlink = "tego_path_symlink"
	// ProgPathTruncate records truncate(2), and below 6.2 ftruncate(2) and an O_TRUNC open's truncate.
	ProgPathTruncate = "tego_path_truncate"
	// ProgFileTruncate records ftruncate(2) and an O_TRUNC open's truncate from 6.2, the kernel that added the
	// hook; it is one of OptionalTracePrograms.
	ProgFileTruncate = "tego_file_truncate"
	// ProgSocketConnect records every connect, including the raw sockets no cgroup hook sees (§5 R4).
	ProgSocketConnect = "tego_socket_connect"
)

// CgroupPrograms lists the eight CGROUP_SOCK_ADDR programs in attach order.
var CgroupPrograms = []string{ProgConnect4, ProgConnect6, ProgSendmsg4, ProgSendmsg6, ProgBind4, ProgBind6,
	ProgConnectUnix, ProgSendmsgUnix}

// TrackPrograms lists the two cgroup lifecycle programs.
var TrackPrograms = []string{ProgCgroupMkdir, ProgCgroupRmdir}

// TracePrograms lists the record-only programs.
var TracePrograms = []string{ProgSchedExec, ProgSchedExit, ProgFileOpen, ProgPathUnlink, ProgPathRename, ProgPathMkdir,
	ProgPathMknod, ProgPathRmdir, ProgPathLink, ProgPathSymlink, ProgPathTruncate, ProgFileTruncate, ProgSocketConnect,
	ProgExecResult, ProgExecatResult, ProgBindResult, ProgListenResult, ProgURingBindResult, ProgURingListenResult}

// ListenerTracepoints are mandatory when explicit listener control is requested.
// Their task-state cleanup remains required even with record:off.
var ListenerTracepoints = map[string]string{ProgBindResult: "sys_exit_bind", ProgListenResult: "sys_exit_listen"}

// ListenerURingPrograms are the io_uring terminal producers of the same listener records, by the kernel function
// each fexit wraps. Like ListenerTracepoints they are loaded only for explicit listener control, and then required
// wherever the kernel has the function: a kernel without it has no IORING_OP_BIND or IORING_OP_LISTEN.
var ListenerURingPrograms = map[string]string{ProgURingBindResult: "io_bind", ProgURingListenResult: "io_listen"}

// ExecResultTracepoints are optional syscall tracepoints. Without both hooks,
// the supervisor decides every exec (no fast handover), a failed exec's errno
// is not recorded, and where the plane decides the run's execs an allowed
// exec's line is still the recorder's, with the supervisor's naming.
var ExecResultTracepoints = map[string]string{
	ProgExecResult: "sys_exit_execve", ProgExecatResult: "sys_exit_execveat",
}

// OptionalTracePrograms are the programs of ObjectTraceProc whose kernel function not every supported kernel has:
// security_file_truncate arrived in 6.2. Where the kernel's BTF has no such function the backend leaves the
// program out of the load and does not attach it, and what it would record goes through security_path_truncate
// there, which the kernel calls instead (ADR 0016 (3)). io_bind and io_listen arrived in 6.11 with the opcodes
// whose results ListenerURingPrograms record.
var OptionalTracePrograms = map[string]string{ProgFileTruncate: "security_file_truncate",
	ProgURingBindResult: "io_bind", ProgURingListenResult: "io_listen"}

// MapTaskScratch is the task storage the fexit programs hold a record in until a later hook of the same task
// finishes it (ADR 0016 (3), struct tego_held). Only ObjectTraceProc defines it; it is pinned by name beside
// SharedMaps.
const MapTaskScratch = "tego_task_scratch"

// TraceMaps lists the maps ObjectTraceProc defines beyond SharedMaps, in pin order: its own task storage, and the
// plane's decision scratch (MapPlaneScratch), which the plane writes and the fexit programs read (TIER3-PLAN T9), and
// the plane's exec-pin state (MapPlaneExecArmed), whose pin seq the exec record carries (ADR 0048 (8)).
// Both objects declare the scratch and pin it by name beside SharedMaps, so whichever loads second reuses it.
var TraceMaps = []string{MapTaskScratch, MapPlaneScratch, MapPlaneExecArmed}
