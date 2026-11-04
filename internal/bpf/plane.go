// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"structs"
)

// Tier 3's decision plane, bpf/decide.bpf.c (ADRs 0024, 0025; docs/p0/TIER3-PLAN.md §3). It is compiled twice,
// once per reader of its walk, and the two builds are registered apart from the tier-2 objects: Objects lists
// neither, so nothing that loads every tier-2 object loads a plane build, and PlaneObjects lists both. Hash covers
// both, since the plane pins its maps beside the tier-2 ones and shares tego_run_set with them.
const (
	// ObjectPlaneRdonly is decide.bpf.c built with TEGO_PLANE_RDONLY=1: its walk reads through bpf_rdonly_cast,
	// which a kernel's BTF must carry (6.2+, RHEL 9.8). It is the only build lockdown=confidentiality admits.
	ObjectPlaneRdonly Object = "decide_rd"
	// ObjectPlaneProbe is decide.bpf.c built with TEGO_PLANE_RDONLY=0: its walk reads through CO-RE
	// bpf_probe_read_kernel, for a kernel without bpf_rdonly_cast (AL2023 6.1).
	ObjectPlaneProbe Object = "decide_pr"
)

// PlaneMode is how the plane's programs attach (ADR 0024 (2)): one mode's programs are loaded, never both.
type PlaneMode string

const (
	// PlaneLSM attaches SEC("lsm/<hook>") programs (BPF_LSM_MAC); it needs bpf in the active LSM list.
	PlaneLSM PlaneMode = "lsm"
	// PlaneFmodRet attaches SEC("fmod_ret/security_<hook>") programs (BPF_MODIFY_RETURN) to the same bodies,
	// where bpf is not an active LSM.
	PlaneFmodRet PlaneMode = "fmod_ret"
)

// PlaneModes lists both modes.
var PlaneModes = []PlaneMode{PlaneLSM, PlaneFmodRet}

// PlaneHook is one hook the plane decides at, with its program in each mode.
type PlaneHook struct {
	// Name is the body's name in decide.bpf.c (tego_decide_<Name>).
	Name string
	// LSM is the LSM hook: SEC("lsm/<LSM>"), attached at bpf_lsm_<LSM>.
	LSM string
	// Security is the security_ function fmod_ret mode attaches to.
	Security string
	// Decides reports whether the hook's body in decide.bpf.c can refuse (has a `return -EACCES`), rather than
	// being T2's stub that looks its run up and returns 0. doctor's mode probe requires a deciding hook to refuse
	// its probe syscall in the scratch cgroup and a stub to pass it (docs/p0/enforce-plane.md R21); bpf/tests
	// TestPlaneDecidesMatchesTheBodies holds this field to the C, so the ticket that writes a body turns the
	// refusal check on by the same change.
	Decides bool
	// Unix marks step D's hooks (enforce-plane R14), which decide unix names where cgroup/connect_unix and
	// sendmsg_unix do not exist (below 6.7). A backend loads and attaches them only there, so no name is decided
	// twice; doctor's probe exercises them on every kernel.
	Unix bool
	// Optional marks a hook some supported kernel does not have, whose rule another hook decides there
	// (enforce-plane R3, §6 E14): file_truncate below 6.2 (ftruncate(2) and an O_TRUNC open reach path_truncate
	// instead) and the ACL hooks below 6.2 (setfacl is an xattr write there, inode_setxattr's). Where the kernel's
	// BTF lacks its target the hook is left out of the mode's load, probe and links, and doctor's row says so;
	// where the target exists it must pass like any other.
	Optional bool
}

// Program returns the hook's program name in one mode.
func (h PlaneHook) Program(m PlaneMode) string {
	if m == PlaneLSM {
		return "tego_lsm_" + h.Name
	}
	return "tego_fmr_" + h.Name
}

// Section returns the hook's ELF section in one mode.
func (h PlaneHook) Section(m PlaneMode) string {
	if m == PlaneLSM {
		return "lsm/" + h.LSM
	}
	return "fmod_ret/" + h.Security
}

// Target is the kernel function the hook's program attaches to in mode m: bpf_lsm_<hook> for LSM mode, the
// security_ function for fmod_ret mode.
func (h PlaneHook) Target(m PlaneMode) string {
	if m == PlaneLSM {
		return "bpf_lsm_" + h.LSM
	}
	return h.Security
}

// PlaneHooks are the plane's hooks, steps A, D, B and C (in landing order of their tickets) of TIER3-PLAN §2, in enum tego_plane_hook order;
// each is two programs, one per mode (bpf/tests TestPlaneHooksHaveBothSections pins the C side).
var PlaneHooks = []PlaneHook{
	{Name: "file_open", LSM: "file_open", Security: "security_file_open", Decides: true},
	{Name: "bprm_check", LSM: "bprm_check_security", Security: "security_bprm_check", Decides: true},
	{Name: "path_rename", LSM: "path_rename", Security: "security_path_rename", Decides: true},
	{Name: "path_link", LSM: "path_link", Security: "security_path_link", Decides: true},
	{Name: "path_unlink", LSM: "path_unlink", Security: "security_path_unlink", Decides: true},
	{Name: "path_rmdir", LSM: "path_rmdir", Security: "security_path_rmdir", Decides: true},
	{Name: "socket_connect", LSM: "socket_connect", Security: "security_socket_connect", Decides: true, Unix: true},
	{Name: "socket_sendmsg", LSM: "socket_sendmsg", Security: "security_socket_sendmsg", Decides: true, Unix: true},
	{Name: "path_mknod", LSM: "path_mknod", Security: "security_path_mknod", Decides: true},
	{Name: "path_mkdir", LSM: "path_mkdir", Security: "security_path_mkdir", Decides: true},
	{Name: "path_symlink", LSM: "path_symlink", Security: "security_path_symlink", Decides: true},
	{Name: "path_truncate", LSM: "path_truncate", Security: "security_path_truncate", Decides: true},
	{Name: "file_truncate", LSM: "file_truncate", Security: "security_file_truncate", Decides: true, Optional: true},
	{Name: "path_chmod", LSM: "path_chmod", Security: "security_path_chmod", Decides: true},
	{Name: "path_chown", LSM: "path_chown", Security: "security_path_chown", Decides: true},
	{Name: "inode_setxattr", LSM: "inode_setxattr", Security: "security_inode_setxattr", Decides: true},
	{Name: "inode_removexattr", LSM: "inode_removexattr", Security: "security_inode_removexattr", Decides: true},
	{Name: "inode_set_acl", LSM: "inode_set_acl", Security: "security_inode_set_acl", Decides: true, Optional: true},
	{Name: "inode_remove_acl", LSM: "inode_remove_acl", Security: "security_inode_remove_acl", Decides: true, Optional: true},
	{Name: "socket_create", LSM: "socket_create", Security: "security_socket_create", Decides: true},
	// Step C (enforce-plane R26, decide_stepc.h): PROT_EXEC mappings.
	{Name: "mmap_file", LSM: "mmap_file", Security: "security_mmap_file", Decides: true},
	{Name: "file_mprotect", LSM: "file_mprotect", Security: "security_file_mprotect", Decides: true},
	{Name: "socket_bind", LSM: "socket_bind", Security: "security_socket_bind", Decides: true},
	{Name: "ptrace_access_check", LSM: "ptrace_access_check", Security: "security_ptrace_access_check", Decides: true},
	{Name: "ptrace_traceme", LSM: "ptrace_traceme", Security: "security_ptrace_traceme", Decides: true},
	{Name: "bpf", LSM: "bpf", Security: "security_bpf", Decides: true},
	{Name: "key_permission", LSM: "key_permission", Security: "security_key_permission", Decides: true, Optional: true},
	{Name: "socket_listen", LSM: "socket_listen", Security: "security_socket_listen", Decides: true},
	// Mandatory on every plane: adopted tasks have no inherited topology floor.
	{Name: "capable", LSM: "capable", Security: "security_capable", Decides: true},

	{Name: "unix_may_send", LSM: "unix_may_send", Security: "security_unix_may_send", Decides: true},
}

// PlaneDecidesMappings reports whether the plane's hooks include step C's, whose bodies decide an executable mapping
// (ADR 0027): with bprm_check, they refuse an anonymous image's exec and its PROT_EXEC mapping race-free, so a run a
// plane mode decides needs no seccomp arm refusing every memfd_create where the kernel lacks MFD_NOEXEC_SEAL
// (enforce-plane R27). A mode is selected only once doctor's probe saw each of these refuse in its probe row
// (enforce-plane R21), so a run the plane decides has them loaded and probed.
func PlaneDecidesMappings() bool {
	var mmap, mprotect bool
	for _, h := range PlaneHooks {
		switch h.Name {
		case "mmap_file":
			mmap = h.Decides
		case "file_mprotect":
			mprotect = h.Decides
		}
	}
	return mmap && mprotect
}

// PlaneHooksFor is the hooks mode m loads on a kernel where has reports which functions its BTF declares: every
// hook but an Optional one whose target has does not report (enforce-plane R3, §6 E14). A nil has keeps every
// hook.
func PlaneHooksFor(m PlaneMode, has func(fn string) bool) []PlaneHook {
	out := make([]PlaneHook, 0, len(PlaneHooks))
	for _, h := range PlaneHooks {
		if h.Optional && has != nil && !has(h.Target(m)) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// The plane's own maps (bpf/include/maps.h, TEGO_PLANE_MAPS), pinned by name beside SharedMaps.
const (
	// MapPlaneRows is a HASH_OF_MAPS from run_idx to the slot's rows map (struct inode * -> PlaneRow). A slot keeps
	// its map across runs; a row of another gen counts as absent (ADR 0025 (1) as T0 amended it).
	MapPlaneRows = "tego_plane_rows"
	// MapPlaneExecRows is a HASH_OF_MAPS from run_idx to the slot's exec-rows map (struct inode * -> PlaneExecRow).
	MapPlaneExecRows   = "tego_plane_exec_rows"
	MapPlaneListenRows = "tego_plane_listen_rows"
	// MapPlaneScratch is the TASK_STORAGE map of each task's last decision (PlaneDecision), which the recorder's
	// fexit reads (ADR 0024 (11)).
	MapPlaneScratch = "tego_plane_scratch"
	// MapPlaneCounters is an ARRAY of PlaneCounts by run_idx, zeroed at Prepare like MapLost.
	MapPlaneCounters = "tego_plane_counters"
	// MapPlaneUnixPolicy is an ARRAY of PlaneUnix by run_idx: each slot's policy for step D's unix hooks, written
	// with the run's gen at Prepare.
	MapPlaneUnixPolicy = "tego_plane_unix_policy"
	// MapPlaneRecorded is a one-entry ARRAY (key 0) of the build's attached recorder fexit programs, as a mask of
	// 1 << the PlaneHooks index plus one (PlaneRecordedMask): a refusal on a hook whose bit is clear writes the
	// plane's own KindPlaneFS sample (enforce-plane §7, R23, TIER3-PLAN T9b). 0, the value nobody wrote, samples
	// every refusal.
	MapPlaneRecorded = "tego_plane_recorded"
	// MapPlaneSlots is an ARRAY of PlaneSlot by run_idx: each slot's header, written last by Prepare and zeroed first
	// by every clear; a decided hook refuses on a header of another gen (enforce-plane R6).
	MapPlaneSlots = "tego_plane_slots"
	// MapPlaneNameRows is a HASH_OF_MAPS from run_idx to the slot's name map (ADR 0043 D9): a name key
	// (agent.NameKey, a hash of a folded literal, never an address) -> PlaneNameRow, and key 0 -> the run's
	// PlaneNameConfig. Userspace writes and clears it; the hooks read it only under PlaneSlotNameDecides.
	MapPlaneNameRows = "tego_plane_name_rows"
	// MapPlaneExecPins is a HASH_OF_MAPS from run_idx to the slot's pins (ADR 0048 (3) P2): a PinKey -> the ExecPin
	// the supervisor wrote immediately before continuing the exec, which bprm_check moves into the task's storage.
	MapPlaneExecPins = "tego_plane_exec_pins"
	// MapPlanePinKeys is an ARRAY of PinKeyval by run_idx: the run's MAC key, written by Prepare with its gen.
	MapPlanePinKeys = "tego_plane_pin_keys"
	// MapPlaneExecArmed is the TASK_STORAGE map of each task's pin state (ExecArmed): the plane writes it, and the
	// recorder's sched_process_exec reads the pin seq from it, so both objects declare it, pinned by name.
	MapPlaneExecArmed = "tego_plane_exec_armed"
)

// PlaneExecPinProgram is the plane's tp_btf/sched_process_exec program of mode m (ADR 0048 (3) P2,
// bpf/decide_execpin.h): it checks each exec of a pinned run against its armed pin and kills it before its first
// instruction when the mapped argument area is not the covered one. It is no PlaneHook: it decides nothing a hook
// returns, and it attaches as a tracing program in both modes.
func PlaneExecPinProgram(m PlaneMode) string {
	if m == PlaneLSM {
		return "tego_exec_pin_lsm"
	}
	return "tego_exec_pin_fmr"
}

// PlaneExecPinSection is the ELF section of both modes' PlaneExecPinProgram.
const PlaneExecPinSection = "tp_btf/sched_process_exec"

// KernelOnlyMaps names the maps an object holds that are neither pinned by name nor a global-variable section and
// that no userspace code needs a handle to: the programs alone read them. A later run of the build adopts the pinned
// programs anyway, since the ones it would load carry maps of their own that nothing else uses; any other unpinned
// map makes every run load the object again (cgroup adoptObjectIn; the guard is TestEveryUnpinnedMapIsKernelOnly).
// None today: tego_plane_path_buf, the one there was, is pinned by name since master's 40351a82.
var KernelOnlyMaps = map[string]bool{}

// PlaneMaps lists the plane's own maps in pin order.
var PlaneMaps = []string{MapPlaneRows, MapPlaneExecRows, MapPlaneListenRows, MapPlaneScratch, MapPlaneCounters, MapPlaneUnixPolicy,
	MapPlaneRecorded, MapPlaneSlots, MapPlaneNameRows, MapPlaneExecPins, MapPlanePinKeys, MapPlaneExecArmed}

// PlaneFexitPrograms are the recorder's fexit programs of ObjectTraceProc on the security_ functions the plane
// decides at, by the plane hook each wraps (ADR 0024 (11)): where one is attached it takes the plane's decision and
// writes the action's one line, and where it is not the plane writes its own sample (enforce-plane R23, §7).
var PlaneFexitPrograms = map[string]string{
	"file_open": ProgFileOpen, "path_rename": ProgPathRename, "path_link": ProgPathLink, "path_unlink": ProgPathUnlink,
	"path_rmdir": ProgPathRmdir, "path_mknod": ProgPathMknod, "path_mkdir": ProgPathMkdir,
	"path_symlink": ProgPathSymlink, "path_truncate": ProgPathTruncate, "file_truncate": ProgFileTruncate,
}

// PlaneHookNumber is a hook's enum tego_plane_hook value, its PlaneHooks index plus one; 0 for a name no hook has.
func PlaneHookNumber(name string) uint16 {
	for i, h := range PlaneHooks {
		if h.Name == name {
			return uint16(i + 1)
		}
	}
	return 0
}

// PlaneRecordedMask is the MapPlaneRecorded value for a build whose recorder has the programs attached reports
// attached: bit PlaneHookNumber(hook) set for each hook of PlaneFexitPrograms whose fexit is attached. A nil
// attached is a build with no recorder, 0.
func PlaneRecordedMask(attached func(prog string) bool) uint32 {
	var mask uint32
	if attached == nil {
		return 0
	}
	for hook, prog := range PlaneFexitPrograms {
		if attached(prog) {
			mask |= 1 << PlaneHookNumber(hook)
		}
	}
	return mask
}

// Plane capacities mirrored from bpf/include/events.h.
const (
	// PlaneWalkMax bounds a walk's steps; a mount crossing counts none (ADR 0024 (1)).
	PlaneWalkMax = 64
	// PlaneRowsMax is the row count of one slot's rows map.
	PlaneRowsMax = 4096
	// PlaneExecRowsMax is the row count of one slot's exec-rows map.
	PlaneExecRowsMax   = 1024
	PlaneListenRowsMax = 256

	// ADR 0043 D9's name entries: name rows a slot holds (exact, prefix, exception and exemption-only), keys its map
	// holds (those and the config row at key 0), arms a row has, scope directories a run has (one bit each), leads and
	// distinct prefix lengths its header carries, entries a name rule's tag names (six bits), and dependency
	// directory names its config row carries, each at most PlaneNameDepLen bytes. TestPlaneCapsMatchRowCompiler holds
	// them to pkg/spec/agent's caps.
	PlaneNameRowsMax  = 64
	PlaneNameKeys     = PlaneNameRowsMax + 1
	PlaneNameArms     = 8
	PlaneScopesMax    = 8
	PlaneNameLeads    = 8
	PlaneNamePrefixes = 4
	PlaneNameEntries  = 64
	PlaneNameDeps     = 8
	PlaneNameDepLen   = 16
)

// PlaneListenKey is exact-name Unix listener lookup. A pathname parent pointer
// is written exclusively by the kernel iterator; userspace writes only abstract
// keys, whose Parent is zero.
type PlaneListenKey struct {
	_        structs.HostLayout
	Parent   uint64
	NameLen  uint32
	Abstract uint32
	Name     [108]byte
	Pad      uint32
}
type PlaneListenRow struct {
	_                structs.HostLayout
	ParentIno        uint64
	ParentGeneration uint32
	Dev              uint32
	Gen              uint32
	RuleIdx          uint16
	Pad              uint16
}

// PlaneRow is a slot's rows-map value: struct tego_plane_row. Its key, a struct inode *, never reaches
// userspace; rows are filled and cleared in the kernel (ADR 0025 (2)).
type PlaneRow struct {
	_ structs.HostLayout
	// Ino, Generation and Dev are the key inode's i_ino, i_generation and superblock s_dev, compared on every hit.
	Ino        uint64
	Generation uint32
	Dev        uint32
	// Gen is the run's Run.Gen; a row of another gen is a previous run's and counts as absent.
	Gen uint32
	// RuleIdx is the row's position in the row compiler's rows (decide.PlaneRows.FS), which the ledger resolves
	// by the hook's question (decide.PlaneRows.RuleAt).
	RuleIdx uint16
	// Kind is the row's answer, PlaneRow* bits (decide.PlaneKind).
	Kind uint8
	// Scope is the bit of the name entries' scope directory the row is keyed at (ADR 0043 D4, decide.PlaneRow's
	// Scopes), 0 elsewhere: only the name check's climb and D5 read it.
	Scope uint8
	// ExecRule is the lowest exec.allow directory entry covering this row, or PlaneRuleNone. RuleIdx names the
	// filesystem row; comparing it with an exec entry cannot determine which exec.allow entry comes first.
	ExecRule uint16
	Pad2     uint16
	Pad3     uint32
}

// PlaneExecRow is a slot's exec-rows value: struct tego_plane_exec_row. Keyed by a link (the kernel's
// tego_exec_link_key over an executable's inode, its directory's and its name), it is one name in one directory
// that file may be run under, one row per hard link an entry names (ADR 0025 (1) and its 2026-09-30 note,
// SEMANTICS §4); keyed by PlaneNameKey, a name matched wherever it lies. Whether exec is decided, and exec.anonymous,
// are the slot header's (PlaneSlot), never a row's.
type PlaneExecRow struct {
	_ structs.HostLayout
	// Parent and Inode are the directory's and the executable's struct inode *; only the kernel writes or compares
	// them.
	Parent           uint64
	Inode            uint64
	ParentIno        uint64
	Ino              uint64
	ParentGeneration uint32
	Generation       uint32
	Dev              uint32
	Gen              uint32
	// RuleIdx is the exec entry's position in RuleTable.Exec.
	RuleIdx uint16
	// NameLen is the bytes of Name used, at most 255.
	NameLen uint8
	// Flags is always zero (exec.anonymous is the slot header's PlaneSlotExecAnon).
	Flags uint8
	Pad   [4]uint8
	Name  [NameMax]byte
}

// PlaneRow.Kind bits (enum tego_plane_row_kind), the row compiler's decide.PlaneKind bit for bit
// (TestPlaneCapsMatchRowCompiler). A row with none refuses a modification and allows a read.
const (
	PlaneRowReadDeny      uint8 = 0x01
	PlaneRowModifyAllow   uint8 = 0x02
	PlaneRowRenameRefused uint8 = 0x04
	PlaneRowExecDir       uint8 = 0x08
	// PlaneRowProtected: a deny_write target is at or above the row; the attribute hooks refuse (R12).
	PlaneRowProtected uint8 = 0x10
	// PlaneRowMountOnly: a mounted root's row, for the walk inside a superblock only (R12); the walk that crosses
	// mounts passes it.
	PlaneRowMountOnly uint8 = 0x20
	// PlaneRowScopeOnly: a name entry's scope directory no entry keys (ADR 0043 D4, decide.PlaneScopeOnly); every
	// walk passes it, and only the name check's climb reads its Scope.
	PlaneRowScopeOnly uint8 = 0x40
)

// PlaneSlot is the MapPlaneSlots value: struct tego_plane_slot, a slot's header (enforce-plane R6). Every decided
// hook reads it after its run-set hit and refuses, counting NoRows, when its Gen is not the run's: a cleared slot
// (Gen 0, which no slot epoch is), a previous run's, or one whose Prepare did not finish. What a contract section's
// absence says (no exec:, no net:) its Flags say, so a slot whose rows are gone refuses rather than allows.
type PlaneSlot struct {
	_ structs.HostLayout
	// Gen is the run's Run.Gen.
	Gen uint32
	// Flags are PlaneSlot* bits.
	Flags uint32
	// FSRows and ExecRows are the rows the fill wrote, for a reader of the maps.
	FSRows   uint32
	ExecRows uint32
	// The name prefilter (ADR 0043 D2, D9), read only under PlaneSlotNameDecides (SetLeads writes it): NLeads leads,
	// each Lead[i] the first LeadLen[i] (at most eight) bytes of a literal, folded, in the host's byte order and zero
	// past its length; MinLen the shortest lead's length; NPrefixes distinct prefix literal lengths in PrefixLen,
	// ascending.
	NLeads    uint8
	NPrefixes uint8
	LeadLen   [PlaneNameLeads]uint8
	PrefixLen [PlaneNamePrefixes]uint8
	MinLen    uint8
	Pad       uint8
	Lead      [PlaneNameLeads]uint64
	// PidnsDev and PidnsIno name the launcher's pid namespace under PlaneSlotExecPin, in which a PinKey numbers its
	// tid: nsfs's s_dev in the kernel's encoding (major << 20 | minor, not stat's st_dev) and the namespace's inode.
	PidnsDev uint64
	PidnsIno uint64
	Pad2     [16]uint8
}

// SetLeads writes the header's name prefilter: leads (decide.PlaneRows.Leads, folded literals' first bytes, each 1
// to 8 bytes) and prefixLens (decide.PlaneRows.PrefixLens, ascending). false, with s unchanged, for a set the header
// cannot carry: more than PlaneNameLeads leads or PlaneNamePrefixes lengths, a lead of 0 or more than 8 bytes, or a
// length of 0.
func (s *PlaneSlot) SetLeads(leads []string, prefixLens []uint8) bool {
	if len(leads) > PlaneNameLeads || len(prefixLens) > PlaneNamePrefixes {
		return false
	}
	out := *s
	out.NLeads, out.NPrefixes, out.MinLen = uint8(len(leads)), uint8(len(prefixLens)), 0
	out.LeadLen, out.PrefixLen, out.Lead = [PlaneNameLeads]uint8{}, [PlaneNamePrefixes]uint8{}, [PlaneNameLeads]uint64{}
	for i, l := range leads {
		if l == "" || len(l) > 8 {
			return false
		}
		var w [8]byte
		copy(w[:], l)
		out.Lead[i], out.LeadLen[i] = binary.NativeEndian.Uint64(w[:]), uint8(len(l))
		if out.MinLen == 0 || uint8(len(l)) < out.MinLen {
			out.MinLen = uint8(len(l))
		}
	}
	for i, n := range prefixLens {
		if n == 0 {
			return false
		}
		out.PrefixLen[i] = n
	}
	*s = out
	return true
}

// PlaneSlot.Flags bits (enum tego_plane_slot_flag).
const (
	// PlaneSlotExecDecides: the contract has an exec: section; bprm_check and step C decide.
	PlaneSlotExecDecides uint32 = 0x01
	// PlaneSlotExecAnon: exec.anonymous, an image with no name may run.
	PlaneSlotExecAnon uint32 = 0x02
	// PlaneSlotUnixDecides: step D's hooks decide the run's unix names (below 6.7, with a net: section).
	PlaneSlotUnixDecides uint32 = 0x04
	// PlaneSlotNetDecides: the contract has a net: section; socket_create applies ADR 0018's allowlist.
	PlaneSlotNetDecides uint32 = 0x08
	// PlaneSlotNetICMP: the net section names an ICMP destination (a port-0 entry); ping sockets are admitted.
	PlaneSlotNetICMP        uint32 = 0x10
	PlaneSlotListenDecides  uint32 = 0x20
	PlaneSlotKeyringAllowed uint32 = 0x40
	// PlaneSlotNameDecides: the slot holds the run's name rows and config row (MapPlaneNameRows) and its header the
	// leads (ADR 0043 D9); file_open, the create, unlink and truncate hooks, path_link and path_rename ask names.
	PlaneSlotNameDecides uint32 = 0x80
	// PlaneSlotExecPin: every exec of the run carries an ExecPin, and the plane holds the exec to it (ADR 0048 (3)
	// P2): bprm_check refuses one whose pin is missing or differs, sched_process_exec kills one whose mapped argument
	// area is not the covered one, and the ptrace hooks refuse a peer of an argv-guarded task.
	PlaneSlotExecPin uint32 = 0x100
	// PlaneSlotBuiltinTTY delegates terminal opens to the inherited tty domain.
	PlaneSlotBuiltinTTY uint32 = 0x200
	// PlaneRuleBuiltinHost is a native peer refusal whose inode could not name a row.
	PlaneRuleBuiltinHost uint32 = 0x40000
	// PlaneRuleBuiltinSurface names the ledger control socket floor.
	PlaneRuleBuiltinSurface uint32 = 0x80000
)

// The exec pin's forms (ExecPin.Form, enum tego_pin_form) and flags (ExecPin.Flags, enum tego_pin_flag).
const (
	PinFormDirect  uint8 = 1
	PinFormScript  uint8 = 2
	PinFormUnknown uint8 = 3

	// PinGuard: the exec is guarded or its image dispatch-sensitive; a traced task's exec is refused and the task is
	// argv-guarded once the exec passes.
	PinGuard uint8 = 0x01
	// PinInterpOK: an unknown-form exec may run a later stage unpinned (no rule is reachable through an interpreter).
	PinInterpOK uint8 = 0x02
	// PinTraceGate is reserved for ADR 0044 (13)'s trace gate; no program reads it yet.
	PinTraceGate uint8 = 0x04
	// PinArgv0Filename: an unknown-form exec's decided argv[0] is the filename; without it a first binfmt_misc stage
	// with the P flag, which keeps argv[0] in front of the tail, is refused.
	PinArgv0Filename uint8 = 0x08
)

// PinRows is the pins one slot holds at once (TEGO_PIN_ROWS).
const PinRows = 4096

// PinChainMax is the interpreter stages a script pin names (TEGO_PIN_CHAIN_MAX): exec_binprm refuses depth > 5.
const PinChainMax = 5

// PinKey is struct tego_pin_key, an ExecPin's key in its slot's map: the exec's thread as the launcher's pid
// namespace numbers it and that thread's start time in clock ticks (/proc/<tid>/stat's field 22).
type PinKey struct {
	_     structs.HostLayout
	TID   uint32
	_     uint32
	Start uint64
}

// PinIdent is struct tego_pin_ident: a file's inode's super block s_dev, in the kernel's encoding, and i_ino.
type PinIdent struct {
	_   structs.HostLayout
	Dev uint64
	Ino uint64
}

// ExecPin is struct tego_exec_pin, one exec's pin (ADR 0048 (3) P2): the facts the supervisor's decision read, the
// MACs (internal/execpin) under the run's key.
type ExecPin struct {
	_      structs.HostLayout
	Gen    uint32
	Seq    uint32
	Form   uint8
	Flags  uint8
	NChain uint8
	_      uint8
	// K is the argv elements the decision read; Argc the vector's length as the supervisor read it.
	K       uint32
	Argc    uint32
	LenCov  uint32
	LenTail uint32
	// LenPath is bprm->filename's length before its NUL, which MACPath covers.
	LenPath uint32
	Image   PinIdent
	MACCov  uint64
	MACTail uint64
	MACName uint64
	MACPath uint64
	Chain   [PinChainMax]PinIdent
}

// PinKeyval is struct tego_pin_keyval, a slot's MapPlanePinKeys value: the run's key as two little-endian halves.
type PinKeyval struct {
	_   structs.HostLayout
	Gen uint32
	_   uint32
	K0  uint64
	K1  uint64
}

// PlaneRuleName is the tag of a rule index a name entry decided (TEGO_PLANE_RULE_NAME, ADR 0043 D8):
// PlaneRuleName | scope bit << 6 | the entry's position in RuleTable.NameDeny (decide.PlaneNameTag).
const PlaneRuleName uint16 = 0x8000

// PlaneNameRow is a slot's name-map value: struct tego_plane_name_row (ADR 0043 D9), keyed by agent.NameKey of
// its folded literal and form, holding its arms summed up (NewPlaneNameRow), so the kernel reads no arm.
type PlaneNameRow struct {
	_ structs.HostLayout
	// Gen is the run's Run.Gen; a row of another gen is a previous run's and absent.
	Gen uint32
	// Flags are PlaneNameRow* bits.
	Flags uint8
	// NameLen is the bytes of Name used, 1 to 255.
	NameLen uint8
	// Exempt is D3's scope bits: where the object's own directory carries one, every entry is cancelled for the name.
	Exempt uint8
	// ExceptFrom is the built-in exception's literal length: the name's bytes from there compare as spelled.
	ExceptFrom uint8
	// Deny is the entries whose deny arm is on the row, as bits by their position in RuleTable.NameDeny.
	Deny uint64
	// Except is the entries a built-in exception at this name cancels.
	Except uint64
	// Name is the literal, ASCII-folded, zero past NameLen.
	Name [NameMax]byte
	Pad  [8]uint8
}

// PlaneNameArm is one arm of a name row as compile gives it (decide.PlaneNameArm), which NewPlaneNameRow sums up into
// the row; no kernel structure has its layout.
type PlaneNameArm struct {
	// Scopes is the scope bits the arm applies beneath.
	Scopes uint8
	// Depth is 0 for any level of the climb, 1 for the object's own directory only (D3).
	Depth uint8
	// Flags are PlaneNameArm* bits.
	Flags uint8
	// RawFrom is an exception arm's literal length: the name's bytes from there compare exactly with Name's.
	RawFrom uint8
	// Rule is the entry's position in RuleTable.NameDeny, or PlaneNameArmAll.
	Rule uint16
}

// PlaneNameConfig is the name map's value at key 0: struct tego_plane_name_cfg, of PlaneNameRow's size. A candidate
// whose slot has none of the run's gen is refused, counted NoRows (ADR 0043 D9).
type PlaneNameConfig struct {
	_ structs.HostLayout
	// Gen is the run's Run.Gen.
	Gen uint32
	// Flags is PlaneNameRowConfig.
	Flags uint8
	// NDeps and NEntries are the Dep and EntryMask elements used.
	NDeps    uint8
	NEntries uint8
	// Scopes is every scope bit an entry's deny arm carries: D5's climb stops once it met them all.
	Scopes uint8
	// Entries is every entry with a scope, as bits by its position in RuleTable.NameDeny.
	Entries uint64
	// BitEntries[b] is the entries whose deny arm carries scope bit b.
	BitEntries [PlaneScopesMax]uint64
	// EntryMask is each entry's deny arm's scope bits, by its position in RuleTable.NameDeny.
	EntryMask [PlaneNameEntries]uint8
	// Dep is the dependency directories' names (agent.EnvSkipDirs), zero-padded, in the host's byte order.
	Dep [PlaneNameDeps][PlaneNameDepLen / 8]uint64
	// DepLens has bit n set for a dependency name n bytes long: the climb reads no other directory's name.
	DepLens uint32
	Pad     uint32
	// Zero is 0: the climb XORs it into every value it keeps from one level to the next, a word the verifier reads
	// from map memory and so knows nothing of (bpf/decide_names.h's tego_climb_state).
	Zero uint64
}

// PlaneNameRow.Flags and PlaneNameArm.Flags bits, and the rule of an arm that cancels every entry.
const (
	PlaneNameRowPrefix uint8  = 0x01
	PlaneNameRowConfig uint8  = 0x02
	PlaneNameArmExempt uint8  = 0x01
	PlaneNameArmAll    uint16 = 0xffff
)

// NewPlaneNameRow is the name row of literal (folded, as decide.PlaneNameRow.Name holds it) in its form, with gen,
// and its arms summed up: a deny arm's entry into Deny; a built-in exception's (exempt, one entry) into Except, its
// literal length into ExceptFrom; D3's exemption (exempt, every entry, depth 1) its scope bits into Exempt. false
// for a row the kernel cannot carry: an empty literal or one longer than 255 bytes, more than PlaneNameArms arms, an
// entry past PlaneNameEntries, exceptions of two literal lengths on one row, or an exemption of every entry at
// another depth than 1 (compile makes none of these; Prepare refuses rather than write a row that says less).
func NewPlaneNameRow(literal string, prefix bool, gen uint32, arms []PlaneNameArm) (PlaneNameRow, bool) {
	var r PlaneNameRow
	if literal == "" || len(literal) > NameMax-1 || len(arms) > PlaneNameArms {
		return r, false
	}
	r.Gen, r.NameLen = gen, uint8(len(literal))
	if prefix {
		r.Flags = PlaneNameRowPrefix
	}
	excepts := false
	for _, a := range arms {
		switch {
		case a.Flags&PlaneNameArmExempt == 0:
			if a.Rule >= PlaneNameEntries {
				return PlaneNameRow{}, false
			}
			r.Deny |= 1 << a.Rule
		case a.Rule == PlaneNameArmAll:
			if a.Depth != 1 {
				return PlaneNameRow{}, false
			}
			r.Exempt |= a.Scopes
		default:
			if a.Rule >= PlaneNameEntries || excepts && r.ExceptFrom != a.RawFrom {
				return PlaneNameRow{}, false
			}
			r.Except |= 1 << a.Rule
			r.ExceptFrom, excepts = a.RawFrom, true
		}
	}
	copy(r.Name[:], literal)
	return r, true
}

// NewPlaneNameConfig is the run's config row: entryMasks by entry position (at most PlaneNameEntries) and the
// dependency directories' names (at most PlaneNameDeps, each 1 to PlaneNameDepLen bytes); Scopes, Entries, BitEntries
// and DepLens are computed from them. false for a set the row cannot carry.
func NewPlaneNameConfig(gen uint32, entryMasks []uint8, deps []string) (PlaneNameConfig, bool) {
	var c PlaneNameConfig
	if len(entryMasks) > PlaneNameEntries || len(deps) > PlaneNameDeps {
		return c, false
	}
	c.Gen, c.Flags, c.NDeps, c.NEntries = gen, PlaneNameRowConfig, uint8(len(deps)), uint8(len(entryMasks))
	copy(c.EntryMask[:], entryMasks)
	for e, m := range entryMasks {
		c.Scopes |= m
		if m != 0 {
			c.Entries |= 1 << e
		}
		for b := 0; b < PlaneScopesMax; b++ {
			if m&(1<<b) != 0 {
				c.BitEntries[b] |= 1 << e
			}
		}
	}
	for i, d := range deps {
		if d == "" || len(d) > PlaneNameDepLen {
			return PlaneNameConfig{}, false
		}
		c.DepLens |= 1 << len(d)
		var w [PlaneNameDepLen]byte
		copy(w[:], d)
		for j := range c.Dep[i] {
			c.Dep[i][j] = binary.NativeEndian.Uint64(w[8*j:])
		}
	}
	return c, true
}

// PlaneRuleNone is the rule index of a decision no row made (TEGO_PLANE_RULE_NONE).
const PlaneRuleNone uint16 = 0xffff

// PlaneRuleMax is the largest rule index a row may carry: every index below PlaneRuleNone, which no row names.
const PlaneRuleMax = PlaneRuleNone - 1

// PlaneNameKey is the exec-rows key of an entry matched by its final component wherever it lies: decide.bpf.c's
// tego_name_read over the name's bytes, FNV-1a over the length and the name as eight-byte words in the host's
// byte order, zero-padded, with the top bit cleared and bit 0 set, so it is never 0, never a link key and never a
// kernel address. ok is false for a name the kernel cannot carry (empty, or longer than 255 bytes).
func PlaneNameKey(name string) (key uint64, ok bool) {
	if name == "" || len(name) > NameMax-1 {
		return 0, false
	}
	h := uint64(0xcbf29ce484222325) ^ uint64(len(name))
	var word [8]byte
	for i := 0; i < len(name); i += 8 {
		word = [8]byte{}
		copy(word[:], name[i:])
		h = (h ^ binary.NativeEndian.Uint64(word[:])) * 0x100000001b3
	}
	return h>>1 | 1, true
}

// PlaneExecName is a PlaneExecRow's Name and NameLen for name, false when the kernel cannot carry it.
func PlaneExecName(name string) (out [NameMax]byte, n uint8, ok bool) {
	if name == "" || len(name) > NameMax-1 {
		return out, 0, false
	}
	copy(out[:], name)
	return out, uint8(len(name)), true
}

// PlaneDecision is the MapPlaneScratch value: struct tego_plane_decision.
type PlaneDecision struct {
	_       structs.HostLayout
	RuleIdx uint32
	// Hook is the PlaneHooks index plus one (enum tego_plane_hook); zero before any decision, and zero again once
	// the recorder's fexit on the same hook has read it.
	Hook    uint16
	Verdict uint8
	Reason  uint8
	// Obj is the object the decision was on, which the recorder's fexit compares with its own argument;
	// kernel-only.
	Obj uint64
	// LaunderDentry and LaunderMnt carry the hook's trusted pointers to the plane's global walk as scalars: the
	// plane stores them here and loads them back (ADR 0024's T0 note, bpf/include/events.h); kernel-only, live.
	LaunderDentry uint64
	LaunderMnt    uint64
	// ExecObj, ExecRule and ExecVerdict are bprm_check's last decision, kept apart for sched_process_exec (the ELF
	// loader's open of PT_INTERP comes between and replaces the fields above); ExecObj is kernel-only.
	ExecObj      uint64
	ExecRule     uint32
	ExecVerdict  uint8
	ExecPad      [3]uint8
	ListenSock   uint64
	ListenRunIdx uint32
	ListenGen    uint32
	Bind         PlaneBind
}

type PlaneBind struct {
	_       structs.HostLayout
	StartNS uint64
	Dev     uint64
	DirIno  uint64
	RuleIdx uint32
	Flags   uint32
	NameLen uint32
	Reason  uint8
	Op      uint8
	Pad     [2]uint8
	Name    [108]byte
	Pad2    uint32
}

const (
	BindAbstract     uint32 = 1
	BindNameOK       uint32 = 2
	BindResolved     uint32 = 4
	BindMarked       uint32 = 8
	BindChainRefused uint32 = 16
	BindDecided      uint32 = 32
	// BindURing marks a record an io_uring op's producer wrote (TEGO_BIND_URING): no supervisor notification
	// precedes it, so no supervisor naming is expected (enforce-plane §2.20).
	BindURing uint32 = 64
)

// PlaneRuleFSRow is the bit bprm_check sets on a rule index that is an fs row's position, for an exec an exec.allow
// directory matched (TEGO_PLANE_RULE_FS_ROW): the ledger names the row's exec.allow entry
// (decide.PlaneRows.ExecRuleAt).
const PlaneRuleFSRow uint32 = 0x10000

const PlaneRuleListen uint32 = 0x20000

// ExecEvent.Plane values (enum tego_plane_named).
const (
	// PlaneNamedNone: the plane did not decide this exec.
	PlaneNamedNone uint8 = 0
	// PlaneNamedEntry: allowed by the exec entry at Hdr.RuleIdx (PlaneRuleNone for none).
	PlaneNamedEntry uint8 = 1
	// PlaneNamedFSRow: allowed by the exec.allow directory of the fs row at Hdr.RuleIdx.
	PlaneNamedFSRow uint8 = 2
)

// PlaneEvent is struct tego_ev_plane: the plane's own refusal sample on a hook no recorder fexit wraps
// (bprm_check, and step B's attribute hooks and socket_create), or on one whose fexit the build did not attach
// (KindPlaneFS), the ledger's one line of the refused action.
// Hdr.Verdict is VerdictRefused and Hdr.Reason the plane's; RuleIdx is the whole rule, PlaneRuleFSRow included, of
// which Hdr.RuleIdx keeps the low 16 bits. Hdr.Kind says which: KindPlaneExec, KindPlaneAttr, KindPlaneSocket or KindPlaneFS.
type PlaneEvent struct {
	_       structs.HostLayout
	Hdr     Header
	StartNS uint64
	RuleIdx uint32
	// Hook is the PlaneHooks index plus one.
	Hook uint16
	// PathOK is 0 when Path could not be read whole.
	PathOK uint8
	Pad    uint8
	// Dev and DirIno are KindPlaneAttr's and KindPlaneFS's directory: its super block's s_dev and its i_ino.
	Dev    uint64
	DirIno uint64
	// Family, Type and Protocol are KindPlaneSocket's socket_create arguments.
	Family   int32
	Type     int32
	Protocol int32
	// Flags is KindPlaneFS's file_open f_flags, else 0.
	Flags uint32
	// Path is bprm->filename, the spelling the task passed (KindPlaneExec), or the object's final component
	// (KindPlaneAttr, KindPlaneFS).
	Path [PathMax]byte
}

// PlaneCounts is the MapPlaneCounters value: struct tego_plane_counts, the plane's fail-closed outcomes at one
// slot, every one a refusal. Mismatch cannot happen by construction (ADR 0025 (4)). NoRows counts a slot with no
// header of the run's gen or no row map.
type PlaneCounts struct {
	_          structs.HostLayout
	Mismatch   uint64
	Unresolved uint64
	Bound      uint64
	NoRows     uint64
}

// PlaneUnix is the MapPlaneUnixPolicy value: struct tego_plane_unix, a slot's policy for step D's hooks
// (enforce-plane R14), written with the run's gen by Prepare's fill.
type PlaneUnix struct {
	_ structs.HostLayout
	// RelayCgroupID is the launcher's cgroup, the one caller whose /proc/self/fd/<n> connect is admitted; 0 admits
	// it from no one.
	RelayCgroupID uint64
	// Gen is the run's Run.Gen; a policy of another gen is a previous run's, and the hooks refuse.
	Gen uint32
	// Decides is 1 when the plane decides the run's unix names: its unix hooks are loaded (below 6.7) and the
	// contract has a net: section. It mirrors the slot header's PlaneSlotUnixDecides, which the hooks read.
	Decides uint8
	// Zero is always 0: the canonical check's starting state, read from the map so that no verifier takes it for a
	// constant (bpf/decide.bpf.c tego_unix_canon).
	Zero uint8
	Pad  [2]uint8
}

// PlaneObjects lists the plane builds this binary carries, sorted, or nothing when it carries none.
func PlaneObjects() []Object {
	out := make([]Object, 0, len(planeGenerated))
	for o := range planeGenerated {
		out = append(out, o)
	}
	sortObjects(out)
	return out
}
