// SPDX-License-Identifier: Apache-2.0

package bpf

import "structs"

// The plane's fill and clear, bpf/decide_fill.bpf.c (ADR 0025 (1), (2); docs/p0/TIER3-PLAN.md T4). The fill is an
// iter/task_file program that writes a slot's rows at the inodes of the launcher's held O_PATH descriptors, so
// userspace names a descriptor number and never an inode pointer; the clear is a syscall program that deletes a
// slot's rows of every gen but one, in the kernel. Like the plane it is built twice, once per reader of struct
// mount (the fill reports the descriptor's mount id), and it is registered apart from the tier-2 objects and the
// plane builds: nothing that loads those loads it. Its two maps are pinned beside the plane, per build and mode
// (enforce/cgroup plane.go pinPlaneFiller), and every launcher of the build fills through them at once: each has
// its own config and templates, keyed by its tgid.
const (
	// ObjectPlaneFillRdonly is decide_fill.bpf.c built with TEGO_PLANE_RDONLY=1 (bpf_rdonly_cast): the fill the
	// plane's decide_rd build goes with.
	ObjectPlaneFillRdonly Object = "decide_fill_rd"
	// ObjectPlaneFillProbe is decide_fill.bpf.c built with TEGO_PLANE_RDONLY=0 (CO-RE probe reads): the fill
	// decide_pr goes with.
	ObjectPlaneFillProbe Object = "decide_fill_pr"
)

// PlaneFillFor names the fill build that goes with a plane build: the one with the same reader.
func PlaneFillFor(plane Object) (Object, bool) {
	switch plane {
	case ObjectPlaneRdonly:
		return ObjectPlaneFillRdonly, true
	case ObjectPlaneProbe:
		return ObjectPlaneFillProbe, true
	}
	return "", false
}

// The fill object's programs and its own maps.
const (
	// ProgPlaneFill is the iter/task_file program.
	ProgPlaneFill = "tego_plane_fill"
	// ProgPlaneClear is the BPF_PROG_TYPE_SYSCALL program, run by BPF_PROG_TEST_RUN with a PlaneClearCtx.
	ProgPlaneClear = "tego_plane_clear"
	// MapPlaneFillConfig is a HASH from a filling launcher's tgid to its PlaneFillCfg.
	MapPlaneFillConfig = "tego_plane_fill_config"
	// MapPlaneFillWants is a HASH from PlaneFillKey(tgid, what, descriptor) to its PlaneFillRow.
	MapPlaneFillWants = "tego_plane_fill_wants"
)

// PlaneFillMax is how many descriptors one fill may name: a slot's fs rows plus its exec rows.
const PlaneFillMax = PlaneRowsMax + PlaneExecRowsMax + PlaneListenRowsMax

// PlaneFillLaunchers is how many whole fills the wants map holds at once (TEGO_PLANE_FILL_LAUNCHERS), and
// PlaneFillCfgs how many launchers' configs (TEGO_PLANE_FILL_CFGS).
const (
	PlaneFillLaunchers = 8
	PlaneFillCfgs      = 1024
)

// PlaneFillWhat says which of a slot's maps a wanted descriptor's row goes into (enum tego_plane_fill_what).
type PlaneFillWhat uint8

const (
	// PlaneFillFS writes a PlaneRow into tego_plane_rows' inner map.
	PlaneFillFS PlaneFillWhat = 1
	// PlaneFillExec writes a PlaneExecRow into tego_plane_exec_rows' inner map.
	PlaneFillExec   PlaneFillWhat = 2
	PlaneFillListen PlaneFillWhat = 3
)

// PlaneFillStatus is what the fill did with one wanted descriptor (enum tego_plane_fill_status).
type PlaneFillStatus uint32

// The statuses. Anything but PlaneFillOK fails Prepare.
const (
	PlaneFillUnseen  PlaneFillStatus = 0 // the launcher's table has no descriptor at this number
	PlaneFillOK      PlaneFillStatus = 1 // written with the run's gen
	PlaneFillNoMap   PlaneFillStatus = 2 // the slot has no inner map for the row
	PlaneFillDup     PlaneFillStatus = 3 // a row of the run's gen already has the key: one fs inode, one exec link (OtherRule names it)
	PlaneFillUpdate  PlaneFillStatus = 4 // the update failed (Err): the map is full or out of memory
	PlaneFillName    PlaneFillStatus = 5 // exec: the dentry's name is not the template's, byte for byte
	PlaneFillNoInode PlaneFillStatus = 6 // a negative dentry, or an exec file with no parent inode
	PlaneFillWhatBad PlaneFillStatus = 7 // the template's What is neither PlaneFillFS nor PlaneFillExec
)

func (s PlaneFillStatus) String() string {
	switch s {
	case PlaneFillUnseen:
		return "not open in the launcher"
	case PlaneFillOK:
		return "written"
	case PlaneFillNoMap:
		return "the slot has no rows map"
	case PlaneFillDup:
		return "another entry of this run already keys the same inode (fs) or link (exec)"
	case PlaneFillUpdate:
		return "the rows map refused the row"
	case PlaneFillName:
		return "the file's name is not the exec entry's"
	case PlaneFillNoInode:
		return "no inode (or no parent directory)"
	case PlaneFillWhatBad:
		return "a template of no known kind"
	}
	return "unknown status"
}

// PlaneFillCfg is the MapPlaneFillConfig value: struct tego_plane_fill_cfg.
type PlaneFillCfg struct {
	_ structs.HostLayout
	// Tgid is the launcher's: only its descriptors are read.
	Tgid uint32
	// RunIdx is the slot and Gen the run's tego_run.gen, written into every row.
	RunIdx uint32
	Gen    uint32
	Pad    uint32
	// Visited counts the descriptors the iterator showed the program, every task's; Matched the launcher's.
	Visited uint64
	Matched uint64
	// Launder and Row are the program's scratch; zero from userspace.
	Launder uint64
	Row     PlaneExecRow
}

// PlaneFillRow is the MapPlaneFillWants value: struct tego_plane_fill_row, one wanted descriptor's row template
// (What, Kind, RuleIdx, ExecRule, NameLen, Name) and what the kernel saw there (the rest).
type PlaneFillRow struct {
	_       structs.HostLayout
	What    PlaneFillWhat
	Kind    uint8
	RuleIdx uint16
	NameLen uint8
	// Scope is an fs row's scope bit (ADR 0043 D4, decide.PlaneRow's Scopes), which the fill writes into
	// PlaneRow.Scope.
	Scope uint8
	// ExecRule is an fs row's lowest covering exec.allow directory entry, or PlaneRuleNone.
	ExecRule  uint16
	Status    PlaneFillStatus
	OtherRule uint16
	Pad2      uint16
	Err       int32
	// Gen is the fill's gen, PlaneFillCfg.Gen: the program applies no template of another.
	Gen uint32
	// MntID and Ino are the descriptor's real_mount(f_path.mnt)->mnt_id and inode number, as fdinfo prints them.
	MntID uint64
	Ino   uint64
	// ParentIno is an exec file's parent directory's inode number.
	ParentIno uint64
	Name      [NameMax]byte
}

// PlaneClearCtx is the context of ProgPlaneClear: struct tego_plane_clear_ctx.
type PlaneClearCtx struct {
	_ structs.HostLayout
	// RunIdx is the slot; rows of KeepGen stay (0 keeps none).
	RunIdx  uint32
	KeepGen uint32
	// Deleted and ExecDeleted are the rows removed; Status is 1 when the slot has no rows map.
	Deleted       uint32
	ExecDeleted   uint32
	Status        int32
	ListenDeleted uint32
}

// PlaneFillObjects lists the fill builds this binary carries, sorted, or nothing when it carries none.
func PlaneFillObjects() []Object {
	out := make([]Object, 0, len(planeFillGenerated))
	for o := range planeFillGenerated {
		out = append(out, o)
	}
	sortObjects(out)
	return out
}

// PlaneFillKey is a MapPlaneFillWants key (TEGO_PLANE_FILL_KEY): the launcher's tgid in the high half, what in bits
// 30 and 31 and the descriptor number, below fs.nr_open's ceiling of 2^30, in the rest, so one descriptor can carry
// an fs row and an exec row and each launcher's templates are its own.
func PlaneFillKey(tgid uint32, what PlaneFillWhat, fd uint32) uint64 {
	return uint64(tgid)<<32 | uint64(what)<<30 | uint64(fd&(1<<30-1))
}

// PlaneFillKeyTgid is the tgid a MapPlaneFillWants key belongs to.
func PlaneFillKeyTgid(key uint64) uint32 { return uint32(key >> 32) }
