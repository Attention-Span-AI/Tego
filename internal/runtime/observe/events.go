// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// The ring-buffer records are internal/bpf's: ExecEvent, ExitEvent, FSEvent, FSOpEvent, NetEvent and
// CgroupEvent are asserted against bpf/include/events.h field for field, and against bpf2go's own mirror of
// the compiled objects (internal/bpf types_test.go, parity_tegobpf_test.go). This package decodes through
// them rather than keeping offsets of its own. It used to keep its own, and they had drifted from the C
// structs: an open's path was read eight bytes early, an exit's code was the low half of its start time,
// and an unlink, rename or mkdir was decoded as an open, so every tier-2 fs record was garbage while the
// unit tests, built from the same wrong offsets, agreed with them.
const (
	// Version is TEGO_EVENTS_VERSION: the ring-buffer event schema this build decodes.
	Version = bpf.EventsVersion
	// PathMax is TEGO_PATH_MAX, the fixed path buffer of an exec and an open record.
	PathMax = bpf.PathMax
	// NameMax is TEGO_NAME_MAX, the fixed final-component buffer of an unlink, rename or mkdir record.
	NameMax = bpf.NameMax
	// ArgvMax is TEGO_ARGV_MAX, the fixed argv buffer of struct tego_ev_exec.
	ArgvMax = bpf.ArgvMax
	// CommLen is TEGO_COMM_LEN, the kernel's TASK_COMM_LEN.
	CommLen = bpf.CommLen
)

// Byte sizes of the wire structs of bpf/include/events.h, taken from internal/bpf's mirrors.
const (
	// HeaderSize is sizeof(struct tego_hdr).
	HeaderSize = int(unsafe.Sizeof(bpf.Header{}))
	// ExecSize is sizeof(struct tego_ev_exec).
	ExecSize = int(unsafe.Sizeof(bpf.ExecEvent{}))
	// ExecResultSize is a failed exec syscall's terminal result.
	ExecResultSize = int(unsafe.Sizeof(bpf.ExecResultEvent{}))
	// ExitSize is sizeof(struct tego_ev_exit).
	ExitSize = int(unsafe.Sizeof(bpf.ExitEvent{}))
	// FSSize is sizeof(struct tego_ev_fs), an open.
	FSSize = int(unsafe.Sizeof(bpf.FSEvent{}))
	// FSOpSize is sizeof(struct tego_ev_fsop), an unlink, rename or mkdir.
	FSOpSize = int(unsafe.Sizeof(bpf.FSOpEvent{}))
	// NetSize is sizeof(struct tego_ev_net).
	NetSize = int(unsafe.Sizeof(bpf.NetEvent{}))
	// CgroupSize is sizeof(struct tego_ev_cgroup).
	CgroupSize = int(unsafe.Sizeof(bpf.CgroupEvent{}))
	// PlaneSize is sizeof(struct tego_ev_plane).
	PlaneSize = int(unsafe.Sizeof(bpf.PlaneEvent{}))
	// SockSize is sizeof(struct tego_ev_sock).
	SockSize = int(unsafe.Sizeof(bpf.SockEvent{}))
	// SockoptSize is sizeof(struct tego_ev_sockopt).
	SockoptSize = int(unsafe.Sizeof(bpf.SockoptEvent{}))
	// SSLSize is sizeof(struct tego_ev_ssl), the fixed part before the plaintext.
	SSLSize = HeaderSize + 8 + 4 + 1 + 1 + 2
)

// Kind mirrors enum tego_kind of bpf/include/events.h.
type Kind uint16

// The event kinds a program may push onto a run's record ring: the twelve of bpf/include/events.h's first set,
// and the five file operations ADR 0016 step 2 added (13, SSL_CLOSE, is capture's ring's alone).
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
	KindMknod       Kind = 14
	KindRmdir       Kind = 15
	KindLink        Kind = 16
	KindSymlink     Kind = 17
	KindTruncate    Kind = 18
	// KindPlaneExec is the decision plane's own refusal of an exec (struct tego_ev_plane), on bprm_check, which no
	// recorder fexit wraps (TIER3-PLAN T9).
	KindPlaneExec Kind = 19
	// KindPlaneAttr and KindPlaneSocket are the plane's own refusals on step B's hooks no recorder fexit wraps
	// (TIER3-PLAN T13): an attribute change (chmod, chown, xattr, ACL) named as a file operation is, by its
	// directory's (dev, ino) and final component in FSBody, and a socket named by its family, type and protocol.
	KindPlaneAttr   Kind = 20
	KindPlaneSocket Kind = 21
	// KindPlaneMap is the plane's own refusal of an executable mapping on step C's hooks (TIER3-PLAN T14), its file
	// named as KindPlaneAttr's is, or with no name.
	KindPlaneMap Kind = 22
	// KindPlaneFS is the plane's own refusal on a hook a recorder fexit wraps whose fexit the build did not attach
	// (TIER3-PLAN T9b, enforce-plane §7): file_open or a file operation, named as KindPlaneAttr is, with the hook in
	// PlaneBody and file_open's f_flags in FSBody.Flags.
	KindPlaneFS Kind = 23
	// KindExecResult terminates a failed exec syscall, after its image-open or bprm refusal samples.
	KindExecResult   Kind = 24
	KindPlaneControl Kind = 25
	KindBindResult   Kind = 26
	KindListenResult Kind = 27
	// KindSockCreate is cgroup/sock_create's own refusal (struct tego_ev_sock) of an inet socket outside ADR 0018's
	// allowlist (enforce-cgroup-observe §5 R4, R5), named by its family, type and protocol in SockBody.
	KindSockCreate Kind = 28
	// KindSockopt is cgroup/setsockopt's own refusal (struct tego_ev_sockopt) of setsockopt(SOL_TCP, TCP_ULP) (ADR
	// 0018 (7)), named by its option, value length and the name's first bytes in SockoptBody.
	KindSockopt Kind = 29
	// KindPlaneExecKill is the plane's kill of a pinned exec (struct tego_ev_exec_kill; ADR 0048 (3) P2):
	// sched_process_exec found the mapped argument area differing from the exec's pin, unreadable, or no pin armed, and
	// sent SIGKILL before the new image's first instruction. Named in PinBody.
	KindPlaneExecKill Kind = 30
	// KindPlaneExecHeld is the plane's proof that a pinned exec held to its pin (struct tego_ev_exec_held; ADR 0048
	// (8)): the one sample the recorder's fold reads as kernel_pinned. Named in PinBody.
	KindPlaneExecHeld Kind = 31
)

// String names a kind for diagnostics; an unknown value renders as its number.
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
		return fmt.Sprintf("kind(%d)", uint16(k))
	}
}

// Valid reports whether k is one of the declared kinds.
func (k Kind) Valid() bool {
	return (k >= KindExec && k <= KindSSLChunk) || (k >= KindMknod && k <= KindPlaneExecHeld)
}

// IsFSOp reports whether k is a file operation, a struct tego_ev_fsop record.
func (k Kind) IsFSOp() bool { return bpf.Kind(k).IsFSOp() }

// KernelVerdict mirrors enum tego_verdict: what the in-kernel program decided, before userspace
// maps it to a record.Verdict.
type KernelVerdict uint8

// The three kernel verdicts.
const (
	KernelAllow    KernelVerdict = 0
	KernelRefused  KernelVerdict = 1
	KernelObserved KernelVerdict = 2
)

// ErrShortRecord is a ring-buffer sample smaller than the struct its kind declares, or one whose
// header says it is longer than the bytes the kernel handed over. The recorder counts these and
// keeps draining: a malformed sample is a gap, never a crash (docs/ARCHITECTURE.md §15.3).
var ErrShortRecord = errors.New("observe: short ring-buffer record")

// ErrVersion is a sample whose header version this build does not decode.
var ErrVersion = errors.New("observe: unknown event version")

// ErrKind is a sample whose kind is outside enum tego_kind.
var ErrKind = errors.New("observe: unknown event kind")

// Header mirrors struct tego_hdr: the fields every ring-buffer sample starts with.
type Header struct {
	Version  uint16
	Kind     Kind
	Size     uint32 // total bytes of the sample including this header
	MonoNS   uint64 // bpf_ktime_get_ns(), monotonic since boot and immune to clock steps (E20)
	CgroupID uint64
	PID      uint32
	TID      uint32
	PPID     uint32
	RunIdx   uint32
	Verdict  KernelVerdict
	Reason   uint8 // index into the reason table, see ReasonFor
	RuleIdx  uint16
	Gen      uint32 // the generation of the run-set row the program found (bpf.Run.Gen)
}

// ExecBody is the tail of struct tego_ev_exec.
type ExecBody struct {
	StartBootNS uint64 // the process start time half of an exec id
	// ParentStartNS is the start time of the parent the header's PPID names (§6 E14).
	ParentStartNS uint64
	// CwdDev (stat(2)'s encoding, like FSBody's) and CwdIno are the working directory at exec, the base of a
	// relative Path.
	CwdDev uint64
	CwdIno uint64
	// OldTID is the thread that entered exec, before de_thread changed a nonleader's ID.
	OldTID uint32
	Comm   string
	Path   string
	// RawPath is the unmodified kernel filename, before resolveExec joins a relative spelling.
	RawPath       string
	PathTruncated bool
	Argv          []string
	ArgvTruncated bool
	// ArgvLastPartial says the captured argv bytes ended inside their last argument.
	ArgvLastPartial bool
	// Unresolved is set by the recorder, never the decoder: Path is a relative name it could not join to the
	// process's working directory at the exec, or a name with a ".." component (Recorder.resolveExec).
	Unresolved bool
	// Plane is a bpf.PlaneNamed* value: the decision plane's bprm_check allowed this exec, by the exec entry or the
	// exec.allow directory's fs row at Header.RuleIdx (TIER3-PLAN T9).
	Plane uint8
	// Interpreted is the kernel's binfmt interpreter rewrite marker, not a userspace file guess.
	Interpreted bool
	// PinSeq is the seq of the pin the plane held this exec to (ADR 0048 (8)), 0 for none: the recorder folds the
	// plane's held or kill sample of the same seq into this exec's line.
	PinSeq uint32
}

// PlaneBody is struct tego_ev_plane's tail: the plane's own refusal of an exec.
type PlaneBody struct {
	// RuleIdx is the decision's whole rule, bpf.PlaneRuleFSRow included, of which Header.RuleIdx is the low half.
	RuleIdx uint32
	// Hook is the plane hook that refused (enum tego_plane_hook).
	Hook uint16
	// Path is bprm->filename, the spelling the task passed; PathTruncated when it could not be read whole. A
	// KindPlaneAttr or KindPlaneFS record carries its name in FSBody instead, as a file operation does.
	Path          string
	PathTruncated bool
	// Family, Type and Protocol are a KindPlaneSocket record's socket_create arguments.
	Family, Type, Protocol int32
}

// ExitBody is struct tego_ev_exit's tail: the exit of a thread group, made by its last thread.
type ExitBody struct {
	// ExecStartNS is the exiting image's start time, which tells an exit from a lagging exec of a reused
	// pid (§6 E14).
	ExecStartNS uint64
	Code        int32
	Signal      uint32
}

// ExecResultBody is the terminal negative return of execve or execveat.
type ExecResultBody struct{ Ret int64 }

// restarting recognizes Linux-private results exposed by sys_exit before signal
// handling restarts or translates the syscall. They are not userspace errnos.
func (e ExecResultBody) restarting() bool {
	switch e.Ret {
	case -512, -513, -514, -516: // ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK
		return true
	}
	return false
}

// FSBody is the tail of an open (struct tego_ev_fs) or of a file operation (struct tego_ev_fsop): unlink,
// rename, mkdir, mknod, rmdir, link, symlink or truncate.
//
// An open carries the path bpf_d_path resolved and the opened inode's (Dev, Ino). The other three hooks may
// never call bpf_d_path (docs/p0/enforce-cgroup-observe.md §5 R9/R10): they carry the parent directory's
// (Dev, Ino) and the final component in Path, and a rename or a link also its new name's parent (Dev2, Ino2)
// and final component (Path2); userspace resolves them against the rule table's own directory index. A
// symlink's Path2 is its target as the caller wrote it.
//
// Ret is the kernel's LSM chain's return (0 or -errno) and RetOK says the record carries it: the fexit programs
// read it after the security_ function returned (ADR 0016 (3)). A record without it is decided by the tier's
// model, as every record was before. Every Dev
// is in the encoding stat(2) reports, converted from the kernel's s_dev (userDev), because that is what
// the index is built from.
type FSBody struct {
	Flags          uint32
	Ino            uint64
	Dev            uint64
	Path           string
	PathTruncated  bool
	Ino2           uint64
	Dev2           uint64
	Path2          string
	Path2Truncated bool
	Ret            int32
	RetOK          bool
	// Created is set on an open that created its file (FMODE_CREATED).
	Created bool
	// ExecOpen marks an image open, including scripts, interpreters and PT_INTERP loaders.
	ExecOpen bool
	// Dir is a file operation's parent directory by its path, walked in the kernel for a run a plane mode decides
	// (DirWalk bpf.DirOK; "" is the root), and Dir2 a rename's or a link's new name's (Dir2Walk). Any other
	// DirWalk leaves the side to the directory index: bpf.DirNone was not walked, the rest could not be proven.
	Dir      string
	DirWalk  bpf.DirState
	Dir2     string
	Dir2Walk bpf.DirState
}

// NetBody is the tail of struct tego_ev_net.
type NetBody struct {
	Family uint8 // AF_INET (2) or AF_INET6 (10)
	Proto  uint8 // IPPROTO_TCP (6) or IPPROTO_UDP (17)
	Port   uint16
	Addr   [16]byte
}

// SockBody is the tail of struct tego_ev_sock: the socket cgroup/sock_create refused. Type is sk_type, which
// carries no SOCK_NONBLOCK or SOCK_CLOEXEC; Protocol is the whole number the kernel holds.
type SockBody struct {
	Family, Type, Protocol int32
}

// SockoptBody is the tail of struct tego_ev_sockopt: the option, the caller's value length, and the first
// bpf.ULPNameMax bytes of the kernel's copy of the value, which handleSockopt cuts at Optlen and the first NUL.
type SockoptBody struct {
	Level, Optname, Optlen int32
	Name                   [16]byte
}

// CgroupBody is the tail of struct tego_ev_cgroup.
type CgroupBody struct {
	ParentCgroupID uint64
	ChildCgroupID  uint64
	// Err is the run-set insert's result: 0 when the descendant's row is in place (§6 E11).
	Err int32
}

// Record is one decoded ring-buffer sample. Exactly one body is meaningful, named by Header.Kind;
// the others keep their zero value. It is a flat value so a drain loop can decode into one reusable
// Record without allocating a body per event (BenchmarkDecodeInto).
type Record struct {
	Header
	// StartNS is the start time of the process the header's PID names, as the kernel read it when it made the
	// record: an exec's or an exit's own, an open's, file operation's or connect's start_ns. It is what tells
	// that process from an earlier one of the same pid (§6 E14); 0 for the other kinds.
	StartNS    uint64
	Exec       ExecBody
	ExecResult ExecResultBody
	BindResult BindResultBody
	Exit       ExitBody
	FS         FSBody
	Net        NetBody
	Cgroup     CgroupBody
	Plane      PlaneBody
	Sock       SockBody
	Sockopt    SockoptBody
	Pin        PinBody
}

// PinBody is the plane's verdict on a pinned exec at sched_process_exec (KindPlaneExecKill, KindPlaneExecHeld; ADR
// 0048 (8)). Record.StartNS is the exec's task start, as its exec record carries it.
type PinBody struct {
	// OldTID is sched_process_exec's old_pid: the thread that called exec, before de_thread.
	OldTID uint32
	// Seq is the seq the exec record carries as ExecBody.PinSeq (the task's cur_seq): a held sample's pin, and on a
	// kill the armed pin's or what the exec's first bprm_check stage left, 0 when the task holds no state of the run.
	Seq uint32
	// KillErr is bpf_send_signal's error on a kill, 0 when SIGKILL was sent (kill_failed otherwise).
	KillErr int32
	// Form is the pin's execpin form, 0 when none; Interpreted is binfmt's interpreter marker.
	Form        uint8
	Interpreted bool
	// Argv is a kill's mapped argument area as the new image has it, NUL-split; ArgvTruncated marks a vector past
	// the sample's bound, or one that could not be read.
	Argv          []string
	ArgvTruncated bool
}

// DecodeInto decodes one ring-buffer sample into dst, reusing dst's slices where it can. It is
// total: every malformed, short, truncated or unknown sample returns an error and never panics
// (FuzzDecode). Every field is copied out of raw.
func DecodeInto(dst *Record, raw []byte) error {
	if dst == nil {
		return fmt.Errorf("%w: nil destination", ErrShortRecord)
	}
	*dst = Record{Exec: ExecBody{Argv: dst.Exec.Argv[:0]}}
	if len(raw) < HeaderSize {
		return fmt.Errorf("%w: %d bytes, header needs %d", ErrShortRecord, len(raw), HeaderSize)
	}
	e := binary.NativeEndian
	dst.Version = e.Uint16(raw[0:2])
	dst.Kind = Kind(e.Uint16(raw[2:4]))
	dst.Size = e.Uint32(raw[4:8])
	dst.MonoNS = e.Uint64(raw[8:16])
	dst.CgroupID = e.Uint64(raw[16:24])
	dst.PID = e.Uint32(raw[24:28])
	dst.TID = e.Uint32(raw[28:32])
	dst.PPID = e.Uint32(raw[32:36])
	dst.RunIdx = e.Uint32(raw[36:40])
	dst.Verdict = KernelVerdict(raw[40])
	dst.Reason = raw[41]
	dst.RuleIdx = e.Uint16(raw[42:44])
	dst.Gen = e.Uint32(raw[44:48])
	if dst.Version != Version {
		return fmt.Errorf("%w: %d, this build decodes %d", ErrVersion, dst.Version, Version)
	}
	if !dst.Kind.Valid() {
		return fmt.Errorf("%w: %d", ErrKind, uint16(dst.Kind))
	}
	// A header claiming more bytes than arrived means the producer and this build disagree about
	// the layout; trusting len(raw) instead would decode past the fields the producer wrote.
	if int(dst.Size) > len(raw) {
		return fmt.Errorf("%w: header says %d bytes, sample has %d", ErrShortRecord, dst.Size, len(raw))
	}
	if dst.Kind == KindSSLChunk {
		// The one variable-width record: its size is the plaintext's, not a struct's. Only its header is decoded
		// here. The recorder records nothing of an SSL chunk; capture/uprobe reads the body with internal/bpf's
		// own decoder (DecodeSSLChunk).
		if int(dst.Size) >= HeaderSize {
			raw = raw[:dst.Size]
		}
		if len(raw) < SSLSize {
			return short(dst.Kind, len(raw), SSLSize)
		}
		return nil
	}
	// Every other kind is one fixed struct, and a header whose size is not that struct's is a producer
	// this build does not understand; bpf.Decode refuses it rather than read fields at guessed offsets.
	var err error
	switch dst.Kind {
	case KindExec:
		err = decodeExec(dst, raw)
	case KindExit:
		err = decodeExit(dst, raw)
	case KindExecResult:
		err = decodeExecResult(dst, raw)
	case KindBindResult, KindListenResult:
		err = decodeBindResult(dst, raw)
	case KindOpen:
		err = decodeOpen(dst, raw)
	case KindUnlink, KindRename, KindMkdir, KindMknod, KindRmdir, KindLink, KindSymlink, KindTruncate:
		err = decodeFSOp(dst, raw)
	case KindConnect, KindSendmsg, KindBind:
		err = decodeNet(dst, raw)
	case KindCgroupMkdir, KindCgroupRmdir:
		err = decodeCgroup(dst, raw)
	case KindPlaneExec, KindPlaneAttr, KindPlaneSocket, KindPlaneMap, KindPlaneFS, KindPlaneControl:
		err = decodePlane(dst, raw)
	case KindSockCreate:
		err = decodeSock(dst, raw)
	case KindSockopt:
		err = decodeSockopt(dst, raw)
	case KindPlaneExecKill:
		err = decodeExecKill(dst, raw)
	case KindPlaneExecHeld:
		err = decodeExecHeld(dst, raw)
	default:
		return fmt.Errorf("%w: %d", ErrKind, uint16(dst.Kind))
	}
	if err != nil && !errors.Is(err, ErrShortRecord) && !errors.Is(err, ErrKind) && !errors.Is(err, ErrVersion) {
		return fmt.Errorf("%w: %s: %w", ErrShortRecord, dst.Kind, err)
	}
	return err
}

// decodeRecord copies one fixed record through internal/bpf, whose layouts are the checked ones, and turns
// its refusal into this package's sentinel.
func decodeRecord[T bpf.EventRecord](raw []byte) (T, error) {
	v, err := bpf.Decode[T](raw)
	if err != nil {
		return v, fmt.Errorf("%w: %w", ErrShortRecord, err)
	}
	return v, nil
}

// decodeExec reads struct tego_ev_exec's tail.
func decodeExec(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.ExecEvent](raw)
	if err != nil {
		return err
	}
	dst.Exec.StartBootNS, dst.Exec.ParentStartNS = e.ExecStartNS, e.ParentStartNS
	dst.Exec.CwdDev, dst.Exec.CwdIno = userDev(e.CwdDev), e.CwdIno
	dst.Exec.OldTID = e.OldTID
	dst.StartNS = e.ExecStartNS
	dst.Exec.Comm, _ = cstring(e.Comm[:])
	var pathNoNUL bool
	dst.Exec.Path, pathNoNUL = cstring(e.Path[:])
	dst.Exec.RawPath = dst.Exec.Path
	dst.Exec.PathTruncated = pathNoNUL || e.PathTruncated != 0
	dst.Exec.ArgvTruncated = e.ArgvTruncated != 0
	argv := e.Argv[:]
	if int(e.ArgvLen) <= len(argv) {
		argv = argv[:e.ArgvLen]
	} else {
		// argv_len beyond the buffer can only mean a producer/consumer mismatch; take the buffer, less the zero
		// fill after what the producer wrote.
		dst.Exec.ArgvTruncated = true
		argv = bytes.TrimRight(argv, "\x00")
	}
	dst.Exec.Argv = splitArgv(dst.Exec.Argv[:0], argv)
	dst.Exec.ArgvLastPartial = len(argv) > 0 && argv[len(argv)-1] != 0
	dst.Exec.Plane = e.Plane
	dst.Exec.Interpreted = e.Interpreted != 0
	dst.Exec.PinSeq = e.PinSeq
	return nil
}

// decodeExecKill reads struct tego_ev_exec_kill's tail: the kill names its exec as the exec record does (StartNS, the
// old thread id) and carries the area the new image maps.
func decodeExecKill(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.ExecKillEvent](raw)
	if err != nil {
		return err
	}
	dst.StartNS = e.ExecStartNS
	dst.Pin = PinBody{OldTID: e.OldTID, Seq: e.Seq, KillErr: e.KillErr, Form: e.Form, Interpreted: e.Interpreted != 0,
		ArgvTruncated: e.ArgvTruncated != 0}
	argv := e.Argv[:]
	if int(e.ArgvLen) <= len(argv) {
		argv = argv[:e.ArgvLen]
	} else {
		dst.Pin.ArgvTruncated = true
		argv = bytes.TrimRight(argv, "\x00")
	}
	dst.Pin.Argv = splitArgv(nil, argv)
	return nil
}

// decodeExecHeld reads struct tego_ev_exec_held's tail.
func decodeExecHeld(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.ExecHeldEvent](raw)
	if err != nil {
		return err
	}
	dst.StartNS = e.ExecStartNS
	dst.Pin = PinBody{OldTID: e.OldTID, Seq: e.Seq}
	return nil
}

// decodePlane reads struct tego_ev_plane's tail. path_ok is 0 when the name could not be read whole, and a
// buffer with no terminator is truncated whatever the flag says.
func decodePlane(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.PlaneEvent](raw)
	if err != nil {
		return err
	}
	dst.StartNS = e.StartNS
	path, noNUL := cstring(e.Path[:])
	dst.Plane = PlaneBody{RuleIdx: e.RuleIdx, Hook: e.Hook}
	switch dst.Kind {
	case KindPlaneAttr, KindPlaneMap, KindPlaneFS:
		// The object's final component and its directory, resolved as a file operation's are (handleFSOp), and
		// file_open's flags.
		dst.FS.Dev, dst.FS.Ino = userDev(e.Dev), e.DirIno
		dst.FS.Path, dst.FS.PathTruncated = path, noNUL || e.PathOK == 0
		dst.FS.Flags = e.Flags
	case KindPlaneSocket, KindPlaneControl:
		dst.Plane.Family, dst.Plane.Type, dst.Plane.Protocol = e.Family, e.Type, e.Protocol
		dst.Plane.Path, dst.Plane.PathTruncated = path, noNUL || e.PathOK == 0
		if dst.Kind == KindPlaneSocket && (e.Hook == bpf.PlaneHookNumber("socket_bind") || e.Hook == bpf.PlaneHookNumber("socket_listen")) {
			n := e.Flags >> 16
			if n > 107 {
				return fmt.Errorf("%w: Unix listener name length %d", ErrShortRecord, n)
			}
			if n > 0 {
				dst.Plane.Path = string(e.Path[:n])
				dst.Plane.PathTruncated = e.PathOK == 0
			}
			dst.FS.Dev, dst.FS.Ino = userDev(e.Dev), e.DirIno
			dst.FS.Flags = e.Flags
		}
	default:
		dst.Plane.Path, dst.Plane.PathTruncated = path, noNUL || e.PathOK == 0
	}
	return nil
}

// decodeSock reads struct tego_ev_sock's tail. The record carries no process start time (a CGROUP_SOCK program has
// no task to read it from), so StartNS stays 0 and the actor is named by the header's pid alone.
func decodeSock(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.SockEvent](raw)
	if err != nil {
		return err
	}
	dst.Sock = SockBody{Family: e.Family, Type: e.Type, Protocol: e.Protocol}
	return nil
}

// decodeSockopt reads struct tego_ev_sockopt's tail. Like cgroup/sock_create's, the record carries no process start
// time, so the actor is named by the header's pid alone.
func decodeSockopt(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.SockoptEvent](raw)
	if err != nil {
		return err
	}
	dst.Sockopt = SockoptBody{Level: e.Level, Optname: e.Optname, Optlen: e.Optlen, Name: e.Name}
	return nil
}

// decodeExit reads struct tego_ev_exit's tail.
func decodeExit(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.ExitEvent](raw)
	if err != nil {
		return err
	}
	dst.Exit = ExitBody{ExecStartNS: e.ExecStartNS, Code: e.Code, Signal: e.Signal}
	dst.StartNS = e.ExecStartNS
	return nil
}

func decodeExecResult(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.ExecResultEvent](raw)
	if err != nil {
		return err
	}
	dst.StartNS, dst.ExecResult.Ret = e.StartNS, e.Ret
	return nil
}

// decodeOpen reads struct tego_ev_fs: an open with the path bpf_d_path resolved. path_ok is 0 when that
// failed or truncated (§6 E4), and a buffer with no terminator is truncated whatever the flag says.
func decodeOpen(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.FSEvent](raw)
	if err != nil {
		return err
	}
	dst.StartNS = e.StartNS
	dst.FS.Flags = e.Flags
	dst.FS.Ino = uint64(e.Ino)
	dst.FS.Dev = userDev(e.Dev)
	var noNUL bool
	dst.FS.Path, noNUL = cstring(e.Path[:])
	dst.FS.PathTruncated = noNUL || e.PathOk == 0
	dst.FS.Ret, dst.FS.RetOK = e.Ret, e.RetOk != 0
	dst.FS.Created = e.Created != 0
	dst.FS.ExecOpen = e.ExecOpen != 0
	return nil
}

// decodeFSOp reads struct tego_ev_fsop: a file operation as raw identifiers. name_ok is 0 when the final
// component was truncated or unreadable; name2 means something only for a rename, a link and a symlink, and
// only a rename's and a link's has a directory of its own.
func decodeFSOp(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.FSOpEvent](raw)
	if err != nil {
		return err
	}
	dst.StartNS = e.StartNS
	dst.FS.Dev, dst.FS.Ino = userDev(e.Dev), e.DirIno
	var noNUL bool
	dst.FS.Path, noNUL = cstring(e.Name[:])
	dst.FS.PathTruncated = noNUL || e.NameOk == 0
	switch dst.Kind {
	case KindRename, KindLink:
		dst.FS.Dev2, dst.FS.Ino2 = userDev(e.Dev2), e.DirIno2
		fallthrough
	case KindSymlink:
		dst.FS.Path2, noNUL = cstring(e.Name2[:])
		dst.FS.Path2Truncated = noNUL || e.Name2Ok == 0
	}
	dst.FS.Ret, dst.FS.RetOK = e.Ret, e.RetOk != 0
	dst.FS.DirWalk = bpf.DirState(e.DirState)
	dst.FS.Dir, _ = bpf.DirPath(e.DirState, e.DirOff, e.Dir[:])
	if dst.Kind == KindRename || dst.Kind == KindLink {
		dst.FS.Dir2Walk = bpf.DirState(e.Dir2State)
		dst.FS.Dir2, _ = bpf.DirPath(e.Dir2State, e.Dir2Off, e.Dir2[:])
	}
	return nil
}

// userDev converts a super block's s_dev, the kernel's internal dev_t (major in the bits above MINORBITS=20,
// minor below), into the encoding stat(2) reports, which is what the directory index is keyed by. The two
// agree only for a small anonymous device such as a tmpfs; for a disk they never do, and comparing them raw
// made every unlink, rename and mkdir on one unresolvable.
func userDev(kdev uint64) uint64 {
	return unix.Mkdev(uint32(kdev>>20), uint32(kdev&(1<<20-1)))
}

// decodeNet reads struct tego_ev_net's tail.
func decodeNet(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.NetEvent](raw)
	if err != nil {
		return err
	}
	dst.StartNS = e.StartNS
	dst.Net = NetBody{Family: e.Family, Proto: e.Proto, Port: e.Port, Addr: e.Addr}
	return nil
}

// decodeCgroup reads struct tego_ev_cgroup's tail.
func decodeCgroup(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.CgroupEvent](raw)
	if err != nil {
		return err
	}
	dst.Cgroup = CgroupBody{ParentCgroupID: e.ParentCgroupID, ChildCgroupID: e.ChildCgroupID, Err: e.Err}
	return nil
}

// short builds the ErrShortRecord message for one kind.
func short(k Kind, got, want int) error {
	return fmt.Errorf("%w: %s sample is %d bytes, struct needs %d", ErrShortRecord, k, got, want)
}

// cstring reads a NUL-terminated string out of a fixed kernel buffer and reports whether the buffer
// held no terminator, which is how a fixed-width path or comm says it was truncated (E4, E19).
// The bytes are kept as the kernel wrote them: the recorder matches them against the contract's entries,
// which name a path by its bytes too, and a path with a byte that is not UTF-8 replaced before the match
// named no entry, so a read the kernel refused under a deny_read entry spelled with such a byte was recorded
// allow (E18). The ledger line is valid UTF-8 all the same: encoding/json
// replaces an invalid byte with U+FFFD when record.Event.SetPayload marshals the path.
func cstring(b []byte) (string, bool) {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i]), false
	}
	return string(b), true
}

// splitArgv splits the NUL-separated argv blob of an exec sample, appending into dst's capacity. The blob is the
// new mm's [arg_start, arg_end), each argument followed by its own NUL, so exactly one trailing NUL is the last
// argument's: `git commit -m ""` is "git\0commit\0-m\0\0", four arguments, and an exec of [""] is "\0", one. A
// blob cut off by truncation has no final NUL and keeps its last, partial argument. An empty blob is no argv.
func splitArgv(dst []string, b []byte) []string {
	if len(b) == 0 {
		return dst
	}
	b = bytes.TrimSuffix(b, []byte{0})
	for {
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return append(dst, strings.ToValidUTF8(string(b), "�"))
		}
		dst = append(dst, strings.ToValidUTF8(string(b[:i]), "�"))
		b = b[i+1:]
	}
}
