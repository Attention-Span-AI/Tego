// SPDX-License-Identifier: Apache-2.0

package bpf

import "structs"

// Capacities and widths mirrored from bpf/include/events.h (docs/p0/enforce-cgroup-observe.md §3, §6 E11, E12).
const (
	// MaxSlots bounds the dense per-host run_idx space; allocation beyond it is ErrSlotsExhausted (§6 E12).
	MaxSlots = 4096
	// RunSetMax is the run_set map's row count: live runs plus their materialized descendants (§6 E11).
	RunSetMax = 4096
	// NetRowsMax is the row count of each of the exact and CIDR verdict maps.
	NetRowsMax = 4096
	// CgroupMax is the reason map's row count: one per live run, keyed by its cgroup id.
	CgroupMax = 4096
	// MaxRules bounds the rule_idx space an event may carry.
	MaxRules = 65535
	// PathMax is the fixed width of a path buffer in an event.
	PathMax = 256
	// NameMax is the fixed width of a final-component buffer in an fsop event.
	NameMax = 256
	// ArgvMax is the fixed width of the NUL-separated argv buffer in an exec event.
	ArgvMax = 512
	// CommLen is the width of a task comm.
	CommLen = 16
	// EventsVersion is the value every event header carries; a decoder rejects anything else.
	EventsVersion = 4
)

// LPM prefix arithmetic. The CIDR trie's key is a fixed run_idx/family/proto/port header followed by the
// address, and prefixlen counts bits over everything after prefixlen itself — so the header is always matched
// whole and only the address varies in width (§2.2).
const (
	// LPMHeaderBits is the width of the fixed header the trie always matches: run_idx, family, proto, port.
	LPMHeaderBits = 64
	// LPMMaxBits is the widest prefix the trie holds: the header plus a full IPv6 address. A lookup always
	// asks for this width and the trie answers with the longest stored prefix that matches.
	LPMMaxBits = LPMHeaderBits + 128
)

// Kind is the event discriminator in an event header (bpf/include/events.h, enum tego_kind).
type Kind uint16

// The event kinds this component produces. SSLChunk and SSLClose belong to capture/uprobe and are listed for
// completeness.
const (
	KindExec        Kind = 1
	KindExit        Kind = 2
	KindOpen        Kind = 3
	KindUnlink      Kind = 4
	KindRename      Kind = 5
	KindMkdir       Kind = 6
	KindConnect     Kind = 7
	KindSendmsg     Kind = 8
	KindBind        Kind = 9
	KindCgroupMkdir Kind = 10
	KindCgroupRmdir Kind = 11
	KindSSLChunk    Kind = 12
	KindSSLClose    Kind = 13
	// KindMknod through KindTruncate are the file operations ADR 0016 step 2 added, each an FSOpEvent read at
	// fexit with the LSM chain's return.
	KindMknod    Kind = 14
	KindRmdir    Kind = 15
	KindLink     Kind = 16
	KindSymlink  Kind = 17
	KindTruncate Kind = 18
	// KindPlaneExec is the decision plane's own refusal sample (PlaneEvent) on bprm_check, the one hook the
	// plane decides at that no recorder fexit wraps (docs/p0/enforce-plane.md R23, TIER3-PLAN T9).
	KindPlaneExec Kind = 19
	// KindPlaneAttr and KindPlaneSocket are the plane's own refusal samples (PlaneEvent) on step B's hooks no
	// recorder fexit wraps (TIER3-PLAN T13): an attribute change (chmod, chown, xattr, ACL) named by its
	// directory's (Dev, DirIno) and final component, and a socket named by its family, type and protocol.
	KindPlaneAttr   Kind = 20
	KindPlaneSocket Kind = 21
	// KindPlaneMap is the plane's own refusal sample (PlaneEvent) on step C's mmap_file and file_mprotect
	// (TIER3-PLAN T14): an executable mapping named as KindPlaneAttr names a file, or with no name.
	KindPlaneMap Kind = 22
	// KindPlaneFS is the plane's own refusal sample (PlaneEvent) on a hook a recorder fexit wraps whose fexit the
	// build did not attach (MapPlaneRecorded; docs/p0/enforce-plane.md §7, R23, TIER3-PLAN T9b): file_open or a
	// file operation, named by its directory's (Dev, DirIno) and final component, with file_open's f_flags.
	KindPlaneFS Kind = 23
	// KindExecResult is the terminal negative return of execve or execveat, after all refusal fragments.
	KindExecResult   Kind = 24
	KindPlaneControl Kind = 25
	KindBindResult   Kind = 26
	KindListenResult Kind = 27
	// KindSockCreate is cgroup/sock_create's own refusal (SockEvent) of an inet socket outside ADR 0018's
	// allowlist (docs/p0/enforce-cgroup-observe.md §5 R4, R5): the one line of a socket no other mechanism saw.
	KindSockCreate Kind = 28
	// KindSockopt is cgroup/setsockopt's own refusal (SockoptEvent) of setsockopt(SOL_TCP, TCP_ULP) on a path the
	// seccomp filter does not see (ADR 0018 (7)): the one line of an upper-layer protocol no other mechanism saw.
	KindSockopt Kind = 29
	// KindPlaneExecKill is the plane's kill sample (ExecKillEvent; ADR 0048 (3) P2): sched_process_exec found an
	// exec's mapped argument area differing from its pin, unreadable, or no pin armed, and sent SIGKILL before the new
	// image's first instruction.
	KindPlaneExecKill Kind = 30
	// KindPlaneExecHeld is the plane's held sample (ExecHeldEvent; ADR 0048 (8)): sched_process_exec checked a pinned
	// exec's mapped argument area and it matched. Every exec of a pinned slot that sched_process_exec checks has
	// exactly one of this and KindPlaneExecKill.
	KindPlaneExecHeld Kind = 31
)

// String names the kind for diagnostics; an unknown value prints its number.
func (k Kind) String() string {
	switch k {
	case KindExec:
		return "exec"
	case KindExit:
		return "exit"
	case KindOpen:
		return "open"
	case KindUnlink:
		return "unlink"
	case KindRename:
		return "rename"
	case KindMkdir:
		return "mkdir"
	case KindConnect:
		return "connect"
	case KindSendmsg:
		return "sendmsg"
	case KindBind:
		return "bind"
	case KindCgroupMkdir:
		return "cgroup_mkdir"
	case KindCgroupRmdir:
		return "cgroup_rmdir"
	case KindSSLChunk:
		return "ssl_chunk"
	case KindSSLClose:
		return "ssl_close"
	case KindMknod:
		return "mknod"
	case KindRmdir:
		return "rmdir"
	case KindLink:
		return "link"
	case KindSymlink:
		return "symlink"
	case KindTruncate:
		return "truncate"
	case KindPlaneExec:
		return "plane_exec"
	case KindPlaneAttr:
		return "plane_attr"
	case KindPlaneSocket:
		return "plane_socket"
	case KindPlaneMap:
		return "plane_map"
	case KindPlaneFS:
		return "plane_fs"
	case KindExecResult:
		return "exec_result"
	case KindPlaneControl:
		return "plane_control"
	case KindBindResult:
		return "bind_result"
	case KindListenResult:
		return "listen_result"
	case KindSockCreate:
		return "sock_create"
	case KindSockopt:
		return "sockopt"
	case KindPlaneExecKill:
		return "plane_exec_kill"
	case KindPlaneExecHeld:
		return "plane_exec_held"
	default:
		return "kind(" + itoa(uint64(k)) + ")"
	}
}

// IsFSOp reports whether a kind is one of the file operations an FSOpEvent carries.
func (k Kind) IsFSOp() bool {
	switch k {
	case KindUnlink, KindRename, KindMkdir, KindMknod, KindRmdir, KindLink, KindSymlink, KindTruncate:
		return true
	}
	return false
}

// Verdict is the kernel-side verdict byte (enum tego_verdict). Record-only programs always emit Observed.
type Verdict uint8

// The three verdict values.
const (
	VerdictAllow    Verdict = 0
	VerdictRefused  Verdict = 1
	VerdictObserved Verdict = 2
)

// RecordMode is the per-run recording level a run_set row carries (enum tego_record). A program that finds
// Off skips its ring-buffer reserve for the high-volume records (§6 E23).
type RecordMode uint8

// The three record modes.
const (
	RecordOff     RecordMode = 0
	RecordSummary RecordMode = 1
	RecordFull    RecordMode = 2
)

// ReasonCode is the numeric reason a verdict, breadcrumb or event header carries. The kernel never carries
// strings; callers map it to a record.Reason (spec/reason/REASON-CHANNEL.md).
type ReasonCode uint8

// The reason codes bpf/include/events.h defines. ReasonNone means "no reason", which is what an allow carries.
const (
	ReasonNone                  ReasonCode = 0
	ReasonWriteOutsideContract  ReasonCode = 1
	ReasonDeleteOutsideContract ReasonCode = 2
	ReasonRenameOutsideContract ReasonCode = 3
	ReasonMkdirOutsideContract  ReasonCode = 4
	ReasonReadDenied            ReasonCode = 5
	ReasonPathUnresolved        ReasonCode = 6
	ReasonExecNotAllowed        ReasonCode = 7
	ReasonNetNotAllowed         ReasonCode = 8
	ReasonNetHTTP               ReasonCode = 9
	// ReasonRefer, ReasonDenyWriteAncestor and ReasonIdentityMismatch are the decision plane's own
	// (bpf/decide.bpf.c): a REFER refusal, a rename of a deny_write target or one of its ancestors, and a row whose
	// key inode no longer carries the row's identity. The ledger keeps its reason in the closed set and names these
	// in plane_reason (internal/runtime/observe planeReason, TIER3-PLAN T9).
	ReasonRefer             ReasonCode = 10
	ReasonDenyWriteAncestor ReasonCode = 11
	ReasonIdentityMismatch  ReasonCode = 12
	ReasonProcessScope      ReasonCode = 13
	// The exec pins' (ADR 0048 (3) P2, bpf/decide_execpin.h): no pin for the exec at bprm_check or none armed at
	// sched_process_exec; a pinned fact differs; the key, the slot's pin map or the task's storage could not be had;
	// the mapped argument area differs from the covered one; the area could not be read; a guarded exec of a traced
	// task.
	ReasonPinMissing      ReasonCode = 14
	ReasonPinMismatch     ReasonCode = 15
	ReasonPinUnverifiable ReasonCode = 16
	ReasonArgvChanged     ReasonCode = 17
	ReasonArgvUnreadable  ReasonCode = 18
	ReasonExecTraced      ReasonCode = 19
)

// FSOp is the operation code of an FSOpEvent (enum tego_fsop).
type FSOp uint8

// The operations trace_proc records without deciding, each with the LSM chain's return (§5 R9, ADR 0016).
const (
	FSOpUnlink   FSOp = 0
	FSOpRename   FSOp = 1
	FSOpMkdir    FSOp = 2
	FSOpMknod    FSOp = 3
	FSOpRmdir    FSOp = 4
	FSOpLink     FSOp = 5
	FSOpSymlink  FSOp = 6
	FSOpTruncate FSOp = 7
)

// Address families the programs name. vmlinux.h carries no uapi constants, so both sides define them.
const (
	AFUnix  uint8 = 1
	AFInet  uint8 = 2
	AFInet6 uint8 = 10
)

// IP protocol numbers a NetKey carries.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// Run.Plane values (enum tego_run_plane): which mode's programs decide a run. One build's run set holds runs of
// every mode, and both modes of a build can be attached at once, so each program decides only the runs prepared in
// its own mode.
const (
	RunPlaneNone    uint8 = 0
	RunPlaneLSM     uint8 = 1
	RunPlaneFmodRet uint8 = 2
)

// RunListenerResults marks an explicit listener policy prepared in a plane
// mode. Global result tracepoints use this immutable membership flag to avoid
// consuming legacy runs' ring capacity; descendant rows copy it unchanged.
const RunListenerResults uint8 = 1

// RunActivity is TEGO_RUN_ACTIVITY: the run is stall-bounded, so trace_proc's allowed actions under record: off
// and the TLS probes' calls in every mode stamp its slot of MapActivity (limits R4). The backend sets it exactly
// when the run's limits bound stall_after (agent.ResolvedLimits.Bounded), in every record mode; descendant rows
// copy it unchanged.
const RunActivity uint8 = 2

// ActivitySlot is one slot of MapActivity: struct tego_activity_slot, a run's activity stamp. MonoNS is the
// bpf_ktime_get_ns (CLOCK_MONOTONIC) of the first stamped action of the newest jiffy the run acted in, and Jiffies
// that jiffy; an action in the jiffy the slot already names writes nothing, so MonoNS lags the run's newest stamped
// action by at most one jiffy (1 to 10 ms by CONFIG_HZ). Userspace reads MonoNS alone (ActivityAt).
type ActivitySlot struct {
	_       structs.HostLayout
	MonoNS  uint64
	Jiffies uint64
}

// RunPlaneOf is the Run.Plane value of a run prepared in mode m; "" (the fanotify fallback) is RunPlaneNone.
func RunPlaneOf(m PlaneMode) uint8 {
	switch m {
	case PlaneLSM:
		return RunPlaneLSM
	case PlaneFmodRet:
		return RunPlaneFmodRet
	}
	return RunPlaneNone
}

// Run is the run_set value: struct tego_run. One row exists per cgroup of a live run, the run's own scope
// plus every descendant cgroup_track materialized (§5 R11).
type Run struct {
	_ structs.HostLayout
	// RunIdx is the dense per-host slot every verdict row is keyed by (§5 R12).
	RunIdx uint32
	// Descendants is 1 when cgroups created beneath this one inherit the run.
	Descendants uint8
	// Tier is 1 landlock, 2 cgroup, 3 bpflsm.
	Tier uint8
	// Record is the run's RecordMode.
	Record uint8
	// Plane is the decision plane's mode that decides the run (RunPlane*, enum tego_run_plane): a plane program
	// of another mode, or any for RunPlaneNone, returns 0 for the run (docs/p0/enforce-plane.md R18, R22).
	Plane uint8
	// Gen is the run's generation, stamped on every record its programs write (Header.Gen): the slot's rings are
	// reused by its next run, whose reader drops a record of another generation (ADR 0026 (6) as amended). The
	// backend sets it to the slot's epoch (slotTable.acquireGen, ADR 0025 (1)): kept per slot, never 0, and
	// repeated only after 2^31-1 acquires of that slot. It is not taken from the cgroup id, whose low half is a
	// kernfs ino that repeats once the idr wraps.
	Gen   uint32
	Flags uint8
	Pad   [3]uint8
}

// NetOwner is the value of MapNetOwners: struct tego_net_owner, the run one cgroup attachment of the network
// programs enforces. Attach writes it into the cgroup storage the kernel created for the run's cgroup when the
// first deciding program was attached there; a zero CgroupID is an attachment not configured yet, which the
// programs refuse (§5 R1, R2).
type NetOwner struct {
	_ structs.HostLayout
	// CgroupID is the run's own cgroup id: the attach point, the storage's key and the breadcrumb's key.
	CgroupID uint64
	// RunIdx is the slot the verdict rows are keyed by (§5 R12).
	RunIdx uint32
	// Flags are NetOwner* bits: what the run's contract asks of socket creation (cgroup/sock_create, §5 R4).
	Flags uint32
	// RelayCgroupID is the launcher's own cgroup: connect_unix admits a /proc/self/fd/<n> name, the shape
	// the supervisor relays a resolved unix connect under, only from a caller in it (§5 R7, supervisor.md
	// R11). Zero admits it from no one.
	RelayCgroupID uint64
	// Gen is the run's Run.Gen, which cgroup/sock_create stamps on its own refusal record (Header.Gen): it reads
	// the run from this storage, never from the run set, whose row for CgroupID exists only from Arm (§5 R5).
	Gen uint32
	// Pad keeps the value a multiple of 8 bytes; always zero.
	Pad uint32
}

// NetOwnerICMP is NetOwner.Flags' TEGO_OWNER_NET_ICMP: cgroup/sock_create admits ping sockets, because the run's
// net section names an ICMP destination (agent.RuleTable.NetSocketPolicy's ICMP, ADR 0018 (1)).
const NetOwnerICMP uint32 = 0x1

// NetKey is the exact host:port verdict key: struct tego_net_key. Port is host byte order; Addr is network
// byte order with IPv4 in the first four bytes and the rest zero.
type NetKey struct {
	_      structs.HostLayout
	RunIdx uint32
	Family uint8
	Proto  uint8
	Port   uint16
	Addr   [16]byte
}

// NetLPMKey is the CIDR verdict key: struct tego_net_lpm_key. PrefixLen counts bits over everything after
// it, so it is LPMHeaderBits plus the declared CIDR width; a lookup uses LPMMaxBits.
type NetLPMKey struct {
	_         structs.HostLayout
	PrefixLen uint32
	RunIdx    uint32
	Family    uint8
	Proto     uint8
	Port      uint16
	Addr      [16]byte
}

// Unix name key widths, mirrored from bpf/include/events.h (struct tego_unix_key, §5 R7).
const (
	// UnixNameMax is sizeof(sockaddr_un.sun_path), the widest name a unix address carries.
	UnixNameMax = 108
	// UnixHeaderBits is the fixed run_idx/kind/len header the name trie always matches whole.
	UnixHeaderBits = 48
	// UnixMaxBits is the width every lookup asks for: the header and every byte of the name.
	UnixMaxBits = UnixHeaderBits + 8*UnixNameMax
	// UnixRowsMax is the row count of MapUnixNames, shared by every run of a build.
	UnixRowsMax = 4096
)

// The two kinds of unix name a UnixKey holds (enum tego_unix_kind).
const (
	UnixPath     uint8 = 1
	UnixAbstract uint8 = 2
)

// UnixKey is the unix name trie's key: struct tego_unix_key. PrefixLen counts bits over everything after it,
// so the RunIdx/Kind/Len header is always matched whole and only Name varies in width.
type UnixKey struct {
	_         structs.HostLayout
	PrefixLen uint32
	RunIdx    uint32
	// Kind is UnixPath or UnixAbstract.
	Kind uint8
	// Len is an abstract name's sun_path length, its leading NUL included; zero for a pathname.
	Len uint8
	// Name holds the sun_path bytes as the address carries them.
	Name [UnixNameMax]byte
}

// UnixApprovalsMax is the row count of MapUnixApprovals (TEGO_UNIX_APPROVALS_MAX), shared by every run of a build.
const UnixApprovalsMax = 4096

// UnixApprovalKey is MapUnixApprovals' key, struct tego_unix_approval_key: one approved abstract-name connect of
// the socket whose cookie is Cookie, in the run of slot RunIdx at Gen (supervisor R11c).
type UnixApprovalKey struct {
	_      structs.HostLayout
	RunIdx uint32
	Gen    uint32
	Cookie uint64
}

// UnixCredit is MapUnixApprovals' value, struct tego_unix_credit: Credit is 1 until a connect consumes it, and
// the grant is dead after DeadlineNS (CLOCK_MONOTONIC). The approved name is held as a UnixKey's fields, laid out
// flat so the Go struct has the C struct's 136 bytes with no padding of its own; only Kind, Len and Name are read.
type UnixCredit struct {
	_          structs.HostLayout
	Credit     uint64
	DeadlineNS uint64
	PrefixLen  uint32
	RunIdx     uint32
	Kind       uint8
	Len        uint8
	Name       [UnixNameMax]byte
	Pad        [2]byte
}

// NetVerdict is the value of both verdict maps: struct tego_net_verdict.
type NetVerdict struct {
	_ structs.HostLayout
	// Verdict is a Verdict value; only Allow lets the syscall proceed.
	Verdict uint8
	// Reason is the ReasonCode a refusal carries; zero for an allow.
	Reason uint8
	// RuleIdx names the compiled rule the ledger event reports.
	RuleIdx uint16
	// Timeline references a precompiled per-run decision chain; zero is static.
	Timeline uint32
	// DeadlineNS is the first interval's CLOCK_MONOTONIC expiry; zero is forever.
	DeadlineNS uint64
}

// Breadcrumb is a run's record of its last network decision: struct tego_reason, keyed by the run's own cgroup
// id. The supervisor reads it after a relayed connect fails EPERM (cgroup.Handle.KernelNet, §5 R5), and
// discards one whose MonoNS is more than 50 ms older than the notification rather than misattribute it
// (§6 E5).
type Breadcrumb struct {
	_ structs.HostLayout
	// Op is KindConnect or KindSendmsg, narrowed to a byte.
	Op uint8
	// Verdict is a Verdict value.
	Verdict uint8
	// Reason is a ReasonCode.
	Reason uint8
	Family uint8
	Proto  uint8
	Pad0   uint8
	// Port is host byte order.
	Port uint16
	// Addr is network byte order, IPv4 in the first four bytes.
	Addr [16]byte
	// MonoNS is bpf_ktime_get_ns() at the decision: boot monotonic, never wall clock (§6 E20).
	MonoNS  uint64
	RunIdx  uint32
	RuleIdx uint16
	Pad1    uint16
}

// Header is the common ring-buffer event header: struct tego_hdr.
type Header struct {
	_ structs.HostLayout
	// Version is EventsVersion.
	Version uint16
	// Kind discriminates the record that follows.
	Kind uint16
	// Size is the whole record's byte count including this header.
	Size uint32
	// TSMonoNS is bpf_ktime_get_ns() at the event.
	TSMonoNS uint64
	CgroupID uint64
	PID      uint32
	TID      uint32
	PPID     uint32
	RunIdx   uint32
	// Verdict is Observed for every record-only program.
	Verdict uint8
	// Reason is a ReasonCode; PathUnresolved marks a record whose path could not be resolved (§6 E4).
	Reason  uint8
	RuleIdx uint16
	// Gen is Run.Gen of the row the program found.
	Gen uint32
}

// ExecEvent is struct tego_ev_exec: one record per successful execve, after the binfmt search.
type ExecEvent struct {
	_   structs.HostLayout
	Hdr Header
	// ExecStartNS is task->start_boottime, the exec id's third component (spec/identity/RUN-IDENTITY.md).
	ExecStartNS uint64
	// ParentStartNS is the start time of the parent Hdr.PPID names, which tells it from an earlier process of
	// that pid (§6 E14).
	ParentStartNS uint64
	// CwdDev and CwdIno identify the working directory at exec, the base of a relative Path: CwdDev is the
	// kernel's s_dev encoding, like every Dev here.
	CwdDev uint64
	CwdIno uint64
	// OldTID is sched_process_exec's old_pid, the executing thread's id before de_thread can change it.
	OldTID uint32
	Pad0   uint32
	Comm   [CommLen]byte
	// ArgvLen is the number of bytes of Argv that were filled.
	ArgvLen uint32
	// ArgvTruncated is 1 when the vector did not fit (§6 E25).
	ArgvTruncated uint8
	// PathTruncated is 1 when Path did not fit (§6 E4).
	PathTruncated uint8
	// Plane is a PlaneNamed* value: whether the decision plane's bprm_check allowed this exec, and what
	// Hdr.RuleIdx then names (TIER3-PLAN T9).
	Plane uint8
	// Interpreted is 1 when binfmt replaced bprm->interp from its original bprm->filename alias. The mapped
	// argv may then have an interpreter prefix instead of the invocation's original argv[0].
	Interpreted uint8
	Path        [PathMax]byte
	// Argv is NUL-separated, not NUL-terminated as a whole.
	Argv [ArgvMax]byte
	// PinSeq is the seq of the pin the plane held this exec to (ADR 0048 (8)), 0 for none: the task's cur_seq.
	// Whether the pin held is the plane's held or kill sample's to say (ExecHeldEvent, ExecKillEvent), which names the
	// same cur_seq; the ledger folds them by seq.
	PinSeq uint32
	_      uint32
}

// ExecKillEvent is struct tego_ev_exec_kill, the plane's kill sample (KindPlaneExecKill; ADR 0048 (3) P2):
// Hdr.Verdict is VerdictRefused and Hdr.Reason the plane reason (ReasonArgvChanged, ReasonArgvUnreadable,
// ReasonPinMissing or ReasonPinUnverifiable). Argv is the area the new image maps.
type ExecKillEvent struct {
	_   structs.HostLayout
	Hdr Header
	// ExecStartNS is task->start_boottime, as the exec record carries it.
	ExecStartNS uint64
	// OldTID is sched_process_exec's old_pid.
	OldTID uint32
	// Seq is the task's cur_seq, as the exec record's PinSeq reads it: the armed pin's seq, else what the exec's
	// first bprm_check stage left, 0 when the task holds no state of the run.
	Seq uint32
	// KillErr is bpf_send_signal's return: 0 sent; anything else is kill_failed with this error.
	KillErr       int32
	ArgvLen       uint32
	ArgvTruncated uint8
	// Form is the pin's ExecPin form; 0 when none.
	Form        uint8
	Interpreted uint8
	_           [5]uint8
	Argv        [ArgvMax]byte
}

// ExecHeldEvent is struct tego_ev_exec_held, the plane's held sample (KindPlaneExecHeld; ADR 0048 (8)): Hdr.Verdict
// is VerdictAllow and Hdr.Reason 0. The exec record of the same task and start carries Seq as its PinSeq.
type ExecHeldEvent struct {
	_   structs.HostLayout
	Hdr Header
	// ExecStartNS is task->start_boottime, as the exec record carries it.
	ExecStartNS uint64
	// OldTID is sched_process_exec's old_pid.
	OldTID uint32
	// Seq is the seq of the pin the check held the exec to, which is the task's cur_seq.
	Seq uint32
}

// ExitEvent is struct tego_ev_exit: a thread group's last record, made by its last thread to exit.
type ExitEvent struct {
	_   structs.HostLayout
	Hdr Header
	// ExecStartNS disambiguates a lagging exec for a reused pid (§6 E14).
	ExecStartNS uint64
	// Code is the wait(2) exit status.
	Code int32
	// Signal is the terminating signal, zero when none.
	Signal uint32
}

// ExecResultEvent is struct tego_ev_exec_result: a failed execve/execveat's terminal syscall result. Successful
// attempts have an ExecEvent instead. The notified attempt supplies the pathname and argv for this identity.
type ExecResultEvent struct {
	_   structs.HostLayout
	Hdr Header
	// StartNS is the calling thread group's start time, before the failed exec.
	StartNS uint64
	// Ret is the syscall's negative errno, including failures before an image file reached an LSM hook.
	Ret int64
}

// FSEvent is struct tego_ev_fs: an open recorded by fexit/security_file_open, the one hook trace_proc attaches
// to that may resolve a path (§5 R10), with the LSM chain's return (ADR 0016 (3)).
type FSEvent struct {
	_   structs.HostLayout
	Hdr Header
	// StartNS is the opening process's start time, which tells it from an earlier process of its pid (§6 E14).
	StartNS uint64
	Dev     uint64
	// Flags is file->f_flags.
	Flags uint32
	// Ino is the low 32 bits of the opened inode number, informational only.
	Ino uint32
	// PathOk is 0 when bpf_d_path failed or truncated (§6 E4).
	PathOk uint8
	// RetOk is 1 when Ret is the LSM chain's return; 0 means the record carries none.
	RetOk uint8
	// Created is 1 when the open created the file (FMODE_CREATED).
	Created uint8
	// ExecOpen is 1 when file->f_flags carried the kernel-private __FMODE_EXEC bit: an exec image or interpreter.
	ExecOpen uint8
	// Ret is the LSM chain's return, 0 or -errno; for an O_TRUNC open the chain allowed, the truncate hook's.
	Ret  int32
	Path [PathMax]byte
}

// FSOpEvent is struct tego_ev_fsop: an unlink, rename, mkdir, mknod, rmdir, link, symlink or truncate recorded
// as raw identifiers with the LSM chain's return (ADR 0016 (3)). These hooks do not resolve a path, so userspace
// reconstructs one from its own dirIndex and records the event unattributed on a miss (§5 R9, R10).
type FSOpEvent struct {
	_   structs.HostLayout
	Hdr Header
	// StartNS is the acting process's start time (§6 E14).
	StartNS uint64
	// Dev and DirIno identify the parent directory of the affected name.
	Dev    uint64
	DirIno uint64
	// Dev2 and DirIno2 identify a rename destination's or a new link's parent; zero otherwise.
	Dev2    uint64
	DirIno2 uint64
	// Op is an FSOp.
	Op uint8
	// NameOk is 0 when the final component was truncated or unreadable.
	NameOk  uint8
	Name2Ok uint8
	// RetOk and Ret are FSEvent's: the LSM chain's return, and whether the record carries it.
	RetOk uint8
	Ret   int32
	Name  [NameMax]byte
	// Name2 is a rename's or a link's new final component, or a symlink's target.
	Name2 [NameMax]byte
	// DirState and Dir2State are each side's DirState: whether Dir (Dir2) holds its parent directory's path,
	// walked in the kernel for a run a plane mode decides (trace_proc tego_dir_walk).
	DirState  uint8
	Dir2State uint8
	// DirOff and Dir2Off are where each path starts: Dir[DirOff:] with no NUL, empty (DirOff PathMax) for the root.
	DirOff  uint16
	Dir2Off uint16
	Pad     uint16
	Dir     [PathMax]byte
	Dir2    [PathMax]byte
}

// DirState is enum tego_dir_state: what an FSOpEvent's Dir or Dir2 holds.
type DirState uint8

// The DirState values.
const (
	// DirNone: not walked (a run no plane decides, or a kernel without bpf_loop).
	DirNone DirState = 0
	// DirOK: the path is whole.
	DirOK DirState = 1
	// DirLong: longer than PathMax bytes or TEGO_DIR_WALK_MAX components.
	DirLong DirState = 2
	// DirRaced: a component was renamed while the walk read it.
	DirRaced DirState = 3
	// DirUnreachable: disconnected, or not below the task's root.
	DirUnreachable DirState = 4
)

// DirPath is the directory path an FSOpEvent side carries: dir[off:] when state is DirOK and off is in range, and
// ok false otherwise. The root is "".
func DirPath(state uint8, off uint16, dir []byte) (path string, ok bool) {
	if DirState(state) != DirOK || int(off) > len(dir) {
		return "", false
	}
	return string(dir[off:]), true
}

// NetEvent is struct tego_ev_net: the record of a connect, including the raw and ICMP sockets the cgroup
// hooks never see (§5 R4).
type NetEvent struct {
	_   structs.HostLayout
	Hdr Header
	// StartNS is the connecting process's start time (§6 E14).
	StartNS uint64
	Family  uint8
	Proto   uint8
	// Port is host byte order.
	Port uint16
	// Addr is network byte order, IPv4 in the first four bytes.
	Addr [16]byte
	Pad  uint32
}

// SockEvent is struct tego_ev_sock: cgroup/sock_create's refusal of an inet socket outside ADR 0018's allowlist
// (docs/p0/enforce-cgroup-observe.md §5 R4, R5). Hdr.CgroupID is the run's own cgroup (the attachment's), Hdr.Gen
// the owner's gen, Hdr.PPID 0. Type is sk_type, with no SOCK_NONBLOCK or SOCK_CLOEXEC; Protocol is the whole
// number, MPTCP's 262 included.
type SockEvent struct {
	_        structs.HostLayout
	Hdr      Header
	Family   int32
	Type     int32
	Protocol int32
	Pad      uint32
}

// SockoptEvent is struct tego_ev_sockopt: cgroup/setsockopt's refusal of setsockopt(SOL_TCP, TCP_ULP) (ADR 0018
// (7)). Hdr is as SockEvent's. Level and Optname are the option's, Optlen the caller's value length, and Name the
// first bytes of the kernel's own copy of the value, at most Optlen and ULPNameMax, zero-padded: the name the kernel
// would have read.
type SockoptEvent struct {
	_       structs.HostLayout
	Hdr     Header
	Level   int32
	Optname int32
	Optlen  int32
	Pad     uint32
	Name    [16]byte
}

// ULPNameMax is TEGO_ULP_NAME_MAX: the most of a TCP_ULP value the kernel reads as the name, TCP_ULP_NAME_MAX (16)
// less its NUL.
const ULPNameMax = 15

// CgroupEvent is struct tego_ev_cgroup: a descendant materialized or removed by cgroup_track.
type CgroupEvent struct {
	_              structs.HostLayout
	Hdr            Header
	ParentCgroupID uint64
	ChildCgroupID  uint64
	// Err is the run_set insert result: 0 when the row is in place, -E2BIG when the map was full (§6 E11). The
	// recorder records nothing of this record, so that case is not a gap in the ledger (§7).
	Err int32
	Pad uint32
}

// itoa formats a small unsigned integer without pulling strconv into a hot path.
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
