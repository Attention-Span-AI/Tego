// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The decision plane's lines (ADR 0024, docs/p0/enforce-plane.md R23, R24; TIER3-PLAN T9).
//
// The plane decides a governed run's opens, execs and fs mutations in the kernel and leaves each decision, with the
// kernel's rule_idx, in the task's tego_plane_scratch value. On the hooks a recorder fexit wraps (file_open,
// path_unlink, path_rmdir, path_rename, path_link) the fexit reads that value for its own call and stamps a plane
// refusal on the record's header, so the fs line this recorder writes for the action is the plane's refusal: one
// line, never a second. On bprm_check, which no fexit wraps, the plane writes its own sample (KindPlaneExec). An
// exec the plane allowed carries the plane's rule on its sched_process_exec record. Where the build did not attach a
// hook's fexit, the plane writes its own sample of that hook's refusals instead (KindPlaneFS, T9b), so the action
// still has its one line.
//
// The rule is named by resolving rule_idx through the plane's own rows (decide.CompilePlane over the run's table,
// which is what the backend filled the kernel from): an fs row's position by the hook's question
// (decide.PlaneRows.RowName, NamedAt), an exec entry's position, and an exec.allow directory's fs row
// (bpf.PlaneRuleFSRow set) by that row's exec.allow entry (ExecRuleAt). The reason stays in the closed set; the
// plane's own cause, where the set has no code for it, is plane_reason.

// planeRows is the run's plane rows, compiled on the first plane line (only the drain goroutine calls it). A table
// the plane cannot hold (ErrPlaneCap) has no rows, and nothing loaded the plane for it: every name is then unmatched.
func (r *Recorder) planeRows() *decide.PlaneRows {
	if !r.planeCompiled {
		r.planeCompiled = true
		if rt := r.rules.rt; rt != nil {
			if rows, err := decide.CompilePlane(rt); err == nil {
				r.plane = rows
			}
		}
	}
	return r.plane
}

// planeLine is the fs line of a refusal the plane made on hook's action (op, a record.FS* operation): its closed-set
// reason, the plane's own cause, and the rule its rule_idx names.
type planeLine struct {
	rule        string
	reason      record.Reason
	planeReason string
}

// planeFS names a plane refusal of an fs action from the record's header: its reason code and the fs row it
// stopped at (TEGO_PLANE_RULE_NONE for a walk that met none or failed). ok is false for a code no fs hook of the
// plane refuses with, which the caller records as a gap.
//
// A read or a modification a name entry refused (the rule_idx carries decide.PlaneRuleName) of a file with a
// deny_read entry at its canonical path, path, is named by that entry (ADR 0043 D8's first choice): an expansion
// entry compaction dropped from the rows, so the kernel's walk met the name entry instead.
func (r *Recorder) planeFS(rec *Record, op, path string) (planeLine, bool) {
	row := int(rec.RuleIdx)
	if rec.RuleIdx == bpf.PlaneRuleNone {
		row = -1
	}
	rows, rt := r.planeRows(), r.rules.rt
	name := func(q decide.PlaneQuestion, depth int) string {
		if rows == nil {
			return RuleUnmatched
		}
		if _, _, tagged := decide.PlaneNameUntag(rec.RuleIdx); tagged && path != "" {
			if e, ok := r.rules.denyReadAt(path); ok {
				return e.RuleName()
			}
		}
		return rows.RowName(rt, row, q, depth)
	}
	switch bpf.ReasonCode(rec.Reason) {
	case bpf.ReasonReadDenied:
		return planeLine{rule: name(decide.PlaneRead, 1), reason: record.ReasonReadDenied}, true
	case bpf.ReasonWriteOutsideContract, bpf.ReasonDeleteOutsideContract, bpf.ReasonRenameOutsideContract,
		bpf.ReasonMkdirOutsideContract:
		return planeLine{rule: name(decide.PlaneModify, 1), reason: decide.OpReason(op)}, true
	case bpf.ReasonDenyWriteAncestor:
		// A rename of a deny_write target or of a directory above one, at the object itself (depth 0).
		return planeLine{rule: name(decide.PlaneRename, 0), reason: record.ReasonRenameOutsideContract,
			planeReason: record.PlaneReasonDenyWriteAncestor}, true
	case bpf.ReasonRefer:
		// The stricter end's row, named by its nearest entry as compile --test names a REFER refusal.
		l := planeLine{rule: RuleUnmatched, reason: decide.OpReason(op), planeReason: record.PlaneReasonRefer}
		if rows != nil {
			l.rule = rows.NamedAt(rt, row)
		}
		return l, true
	case bpf.ReasonPathUnresolved:
		return planeLine{rule: RuleUnmatched, reason: record.ReasonPathUnresolved}, true
	case bpf.ReasonIdentityMismatch:
		return planeLine{rule: RuleUnmatched, reason: record.ReasonPathUnresolved,
			planeReason: record.PlaneReasonIdentityMismatch}, true
	case bpf.ReasonNone, bpf.ReasonExecNotAllowed, bpf.ReasonNetNotAllowed, bpf.ReasonNetHTTP,
		bpf.ReasonProcessScope, bpf.ReasonPinMissing, bpf.ReasonPinMismatch, bpf.ReasonPinUnverifiable,
		bpf.ReasonArgvChanged, bpf.ReasonArgvUnreadable, bpf.ReasonExecTraced:
		// No fs hook of the plane refuses with these.
	}
	return planeLine{rule: RuleUnmatched, reason: record.ReasonPathUnresolved}, false
}

// planeExecRule names an exec entry by bprm_check's rule (an entry's position, or an exec.allow directory's fs row
// with bpf.PlaneRuleFSRow set), unmatched for none.
func (r *Recorder) planeExecRule(idx uint32) string {
	rt := r.rules.rt
	if rt == nil || idx == uint32(bpf.PlaneRuleNone) {
		return RuleUnmatched
	}
	i := -1
	if rows := r.planeRows(); rows != nil {
		i = rows.ExecRuleAt(rt, idx)
	} else if idx&bpf.PlaneRuleFSRow == 0 && int(idx) < len(rt.Exec) {
		i = int(idx)
	}
	if i < 0 {
		return RuleUnmatched
	}
	return rt.Exec[i].RuleName()
}

// planeExecReason is a plane refusal of an exec's closed-set reason and the plane's own cause; ok is false for a
// code bprm_check never refuses with.
func planeExecReason(code uint8) (reason record.Reason, planeReason string, ok bool) {
	switch bpf.ReasonCode(code) {
	case bpf.ReasonExecNotAllowed:
		return record.ReasonExecNotAllowed, "", true
	case bpf.ReasonPathUnresolved:
		return record.ReasonPathUnresolved, "", true
	case bpf.ReasonIdentityMismatch:
		return record.ReasonPathUnresolved, record.PlaneReasonIdentityMismatch, true
	case bpf.ReasonPinMissing, bpf.ReasonPinMismatch, bpf.ReasonPinUnverifiable, bpf.ReasonExecTraced:
		// ADR 0048 (8): a bprm_check pin step's refusal is exec-not-allowed, rule exec.pin, its cause the plane's.
		return record.ReasonExecNotAllowed, pinPlaneReason(bpf.ReasonCode(code)), true
	case bpf.ReasonNone, bpf.ReasonWriteOutsideContract, bpf.ReasonDeleteOutsideContract,
		bpf.ReasonRenameOutsideContract, bpf.ReasonMkdirOutsideContract, bpf.ReasonReadDenied, bpf.ReasonNetNotAllowed,
		bpf.ReasonNetHTTP, bpf.ReasonRefer, bpf.ReasonDenyWriteAncestor, bpf.ReasonProcessScope,
		bpf.ReasonArgvChanged, bpf.ReasonArgvUnreadable:
		// bprm_check never refuses with these (the last two are sched_process_exec's kills).
	}
	return record.ReasonPathUnresolved, "", false
}

// RuleExecPin is the rule of an exec the kernel held to its pin and refused or killed (ADR 0048 (8)).
const RuleExecPin = "exec.pin"

// pinPlaneReason is an exec pin's plane reason code's plane_reason value, "" for any other code.
func pinPlaneReason(code bpf.ReasonCode) string {
	switch code {
	case bpf.ReasonPinMissing:
		return record.PlaneReasonPinMissing
	case bpf.ReasonPinMismatch:
		return record.PlaneReasonPinMismatch
	case bpf.ReasonPinUnverifiable:
		return record.PlaneReasonPinUnverifiable
	case bpf.ReasonArgvChanged:
		return record.PlaneReasonArgvChanged
	case bpf.ReasonArgvUnreadable:
		return record.PlaneReasonArgvUnreadable
	case bpf.ReasonExecTraced:
		return record.PlaneReasonExecTraced
	case bpf.ReasonNone, bpf.ReasonWriteOutsideContract, bpf.ReasonDeleteOutsideContract, bpf.ReasonRenameOutsideContract,
		bpf.ReasonMkdirOutsideContract, bpf.ReasonReadDenied, bpf.ReasonPathUnresolved, bpf.ReasonExecNotAllowed,
		bpf.ReasonNetNotAllowed, bpf.ReasonNetHTTP, bpf.ReasonRefer, bpf.ReasonDenyWriteAncestor,
		bpf.ReasonIdentityMismatch, bpf.ReasonProcessScope:
	}
	return ""
}

// handlePlaneExec records the plane's own refusal of an exec (KindPlaneExec): the exec's one line, since the
// kernel refused it in bprm_check after every other producer let it through (the supervisor continues such an exec
// and writes no line for it when the plane decides execs, supervisor.md R7a). It names the spelling the task passed
// and the process as it stands, whose image the refusal left unchanged; argv never reached a mapped stack.
func (r *Recorder) handlePlaneExec(rec *Record) {
	entry, _ := r.procs.lookup(int(rec.PID), rec.StartNS)
	path := rec.Plane.Path
	if rec.Plane.PathTruncated || path == "" {
		r.gap(GapPathTruncated, 1)
		path = TruncatedPath
	}
	reason, planeReason, ok := planeExecReason(rec.Reason)
	if !ok {
		r.gap(GapMalformedRecord, 1)
	}
	rule := r.planeExecRule(rec.Plane.RuleIdx)
	if pinPlaneReason(bpf.ReasonCode(rec.Reason)) != "" {
		rule = RuleExecPin
		r.pins.pinRefused.Add(1)
	}
	ev := r.event(rec, record.KindExec, rule, record.VerdictRefused, reason)
	r.setPayload(ev, record.ExecPayload{
		Path:          path,
		Argv:          []string{},
		ExecID:        entry.ExecID,
		ParentExecID:  r.procs.parentExecID(int(rec.PPID), 0),
		Mechanism:     record.MechanismPlane,
		DecisionPlane: r.opts.DecisionPlane,
		PlaneReason:   planeReason,
	})
	r.emit(ev)
}

// The plane's hooks by enum tego_plane_hook value (bpf.PlaneHooks' index plus one) that write a KindPlaneAttr
// sample, and the fs operation each line names: chmod and an ACL (which rewrites the permissions) are chmod, chown
// is chown, and an xattr set or removal is xattr.
var planeAttrOps = map[string]string{
	"path_chmod": record.FSChmod, "inode_set_acl": record.FSChmod, "inode_remove_acl": record.FSChmod,
	"path_chown": record.FSChown, "inode_setxattr": record.FSXattr, "inode_removexattr": record.FSXattr,
}

// planeAttrOp is the operation a KindPlaneAttr record's hook names, false for a hook that writes none.
func planeAttrOp(hook uint16) (string, bool) {
	if hook == 0 || int(hook) > len(bpf.PlaneHooks) {
		return "", false
	}
	op, ok := planeAttrOps[bpf.PlaneHooks[hook-1].Name]
	return op, ok
}

// handlePlaneAttr records the plane's own refusal of an attribute change (KindPlaneAttr: path_chmod, path_chown, the
// xattr and ACL hooks; enforce-plane R12, R23): the action's one line, since no recorder fexit wraps these hooks. The
// file is named as a file operation's is, by its directory's (dev, ino) and final component through the rule table's
// directory index, and the rule by the kernel's row (PlaneRows.RowName for PlaneProtect: the deny_write target).
func (r *Recorder) handlePlaneAttr(rec *Record) {
	op, ok := planeAttrOp(rec.Plane.Hook)
	if !ok {
		r.gap(GapMalformedRecord, 1)
		op = record.FSChmod
	}
	path, _, resolved := r.resolveFSOpPath(rec.FS.Dev, rec.FS.Ino, rec.FS.Path, rec.FS.PathTruncated, true, "",
		bpf.DirNone)
	r.dirUnresolvedGap(resolved, rec.FS.PathTruncated)
	rule, reason, planeReason := RuleUnmatched, record.ReasonPathUnresolved, ""
	switch bpf.ReasonCode(rec.Reason) {
	case bpf.ReasonWriteOutsideContract:
		reason = record.ReasonWriteOutsideContract
		if rows, rt := r.planeRows(), r.rules.rt; rows != nil && rec.RuleIdx != bpf.PlaneRuleNone {
			rule = rows.RowName(rt, int(rec.RuleIdx), decide.PlaneProtect, 1)
		}
	case bpf.ReasonPathUnresolved:
	case bpf.ReasonIdentityMismatch:
		planeReason = record.PlaneReasonIdentityMismatch
	case bpf.ReasonNone, bpf.ReasonDeleteOutsideContract, bpf.ReasonRenameOutsideContract, bpf.ReasonMkdirOutsideContract,
		bpf.ReasonReadDenied, bpf.ReasonExecNotAllowed, bpf.ReasonNetNotAllowed, bpf.ReasonNetHTTP, bpf.ReasonRefer,
		bpf.ReasonDenyWriteAncestor, bpf.ReasonProcessScope, bpf.ReasonPinMissing, bpf.ReasonPinMismatch,
		bpf.ReasonPinUnverifiable, bpf.ReasonArgvChanged, bpf.ReasonArgvUnreadable, bpf.ReasonExecTraced:
		r.gap(GapMalformedRecord, 1) // no attribute hook refuses with these
	default:
		r.gap(GapMalformedRecord, 1)
	}
	ev := r.event(rec, record.KindFS, rule, record.VerdictRefused, reason)
	r.setPayload(ev, record.FSPayload{Op: op, Path: path, Mechanism: record.MechanismPlane,
		DecisionPlane: r.opts.DecisionPlane, PlaneReason: planeReason})
	r.emit(ev)
}

// planeFSKinds is the record kind whose line each hook a recorder fexit wraps writes (enum tego_plane_hook's
// names): a KindPlaneFS sample is named as that fexit's record would have been (fsOp, handleFSOp).
var planeFSKinds = map[string]Kind{
	"file_open": KindOpen, "path_unlink": KindUnlink, "path_rmdir": KindRmdir, "path_rename": KindRename,
	"path_link": KindLink, "path_mknod": KindMknod, "path_mkdir": KindMkdir, "path_symlink": KindSymlink,
	"path_truncate": KindTruncate, "file_truncate": KindTruncate,
}

// planeFSKind is the record kind a KindPlaneFS sample's hook stands for, false for a hook no recorder fexit wraps.
func planeFSKind(hook uint16) (Kind, bool) {
	if hook == 0 || int(hook) > len(bpf.PlaneHooks) {
		return 0, false
	}
	k, ok := planeFSKinds[bpf.PlaneHooks[hook-1].Name]
	return k, ok
}

// handlePlaneFS records the plane's own refusal on a hook whose recorder fexit the build did not attach
// (KindPlaneFS; enforce-plane §7, R23, TIER3-PLAN T9b): the action's one line, which that fexit would have written
// with the plane's refusal stamped on it. It is named as the fexit's line is, by the operation the hook stands for
// (an rmdir the unlink, a mknod the open with O_CREAT, as handleFSOp names them) and the plane's rule and reason
// (planeFS); the object as a file operation's, by its directory's (dev, ino) and final component through the rule
// table's directory index, since the plane has no bpf_d_path. A rename or a link names its source alone.
func (r *Recorder) handlePlaneFS(rec *Record) {
	kind, ok := planeFSKind(rec.Plane.Hook)
	if !ok {
		r.gap(GapMalformedRecord, 1)
		kind = KindOpen
	}
	op := fsOp(kind)
	path, _, resolved := r.resolveFSOpPath(rec.FS.Dev, rec.FS.Ino, rec.FS.Path, rec.FS.PathTruncated, true, "",
		bpf.DirNone)
	r.dirUnresolvedGap(resolved, rec.FS.PathTruncated)
	pl, ok := r.planeFS(rec, op, path)
	if !ok {
		r.gap(GapMalformedRecord, 1)
	}
	payload := record.FSPayload{Op: op, Path: path, Mechanism: record.MechanismPlane, DecisionPlane: r.opts.DecisionPlane,
		PlaneReason: pl.planeReason}
	switch kind {
	case KindOpen:
		payload.Flags = int(rec.FS.Flags)
	case KindMknod:
		payload.Flags = unix.O_CREAT
	}
	ev := r.event(rec, record.KindFS, pl.rule, record.VerdictRefused, pl.reason)
	r.setPayload(ev, payload)
	r.emit(ev)
}

// handlePlaneSocket records the plane's own refusal of a socket (KindPlaneSocket: socket_create, ADR 0018 (5)): a
// refused line naming the family, type and protocol, reason net-not-allowed and rule unmatched, as the supervisor's
// own socket refusal is (supervisor socket.go), since no entry of the contract can name a socket family. It is the
// one line of a socket the filter never saw: io_uring's IORING_OP_SOCKET, or any other path to __sock_create.
func (r *Recorder) handlePlaneSocket(rec *Record) {
	if rec.Plane.Hook == bpf.PlaneHookNumber("socket_bind") || rec.Plane.Hook == bpf.PlaneHookNumber("socket_listen") {
		r.handlePlaneListener(rec)
		return
	}
	reason := record.ReasonNetNotAllowed
	switch bpf.ReasonCode(rec.Reason) {
	case bpf.ReasonNetNotAllowed:
	case bpf.ReasonPathUnresolved:
		reason = record.ReasonPathUnresolved // a slot with no rows map: the plane failed closed
	case bpf.ReasonNone, bpf.ReasonWriteOutsideContract, bpf.ReasonDeleteOutsideContract, bpf.ReasonRenameOutsideContract,
		bpf.ReasonMkdirOutsideContract, bpf.ReasonReadDenied, bpf.ReasonExecNotAllowed, bpf.ReasonNetHTTP, bpf.ReasonRefer,
		bpf.ReasonDenyWriteAncestor, bpf.ReasonIdentityMismatch, bpf.ReasonProcessScope, bpf.ReasonPinMissing,
		bpf.ReasonPinMismatch, bpf.ReasonPinUnverifiable, bpf.ReasonArgvChanged, bpf.ReasonArgvUnreadable,
		bpf.ReasonExecTraced:
		r.gap(GapMalformedRecord, 1) // socket_create refuses with none of these
	default:
		r.gap(GapMalformedRecord, 1)
	}
	target := record.SocketTriple(rec.Plane.Family, rec.Plane.Type, rec.Plane.Protocol)
	ev := r.event(rec, record.KindRefused, RuleUnmatched, record.VerdictRefused, reason)
	// A refused line is no action: it carries rule and reason, never a verdict or an authority (spec/record/v1).
	ev.Verdict, ev.Authority, ev.Attr = "", "", nil
	r.setPayload(ev, record.RefusedPayload{Op: "socket", Target: target, Reason: reason, Rule: RuleUnmatched,
		Mechanism: record.MechanismPlane, DecisionPlane: r.opts.DecisionPlane})
	r.emit(ev)
}

// PlaneMapRule is the rule a refused executable mapping names (enforce-plane R26: rule exec-map): ADR 0027's
// policy, which no single contract entry states.
const PlaneMapRule = "exec-map"

// handlePlaneMap records the plane's own refusal of an executable mapping (KindPlaneMap: mmap_file, file_mprotect;
// enforce-plane R23, R26): the action's one line, since no recorder fexit wraps these hooks. A mapping is no action
// the record's kinds name, so it is a refused line, as a refused socket is: op mmap or mprotect by the hook, the target
// the file named as a file operation's is, through the directory index, or "anonymous" for a file no path names (a
// memfd, an unlinked file, an overlay's backing file), rule exec-map; a fail-closed refusal reads path-unresolved.
func (r *Recorder) handlePlaneMap(rec *Record) {
	op := "mmap"
	if h := rec.Plane.Hook; h > 0 && int(h) <= len(bpf.PlaneHooks) && bpf.PlaneHooks[h-1].Name == "file_mprotect" {
		op = "mprotect"
	} else if h == 0 || int(h) > len(bpf.PlaneHooks) || bpf.PlaneHooks[h-1].Name != "mmap_file" {
		r.gap(GapMalformedRecord, 1)
	}
	target := "anonymous"
	// The kernel sets path_ok for a file it deliberately sent nameless, so an empty name with PathTruncated is a name
	// it failed to read: the file is named, and the line says so (TruncatedPath and a gap), never "anonymous".
	if rec.FS.Path != "" || rec.FS.PathTruncated {
		path, _, resolved := r.resolveFSOpPath(rec.FS.Dev, rec.FS.Ino, rec.FS.Path, rec.FS.PathTruncated, true, "",
			bpf.DirNone)
		r.dirUnresolvedGap(resolved, rec.FS.PathTruncated)
		target = path
	}
	rule, reason := PlaneMapRule, record.ReasonExecNotAllowed
	switch bpf.ReasonCode(rec.Reason) {
	case bpf.ReasonExecNotAllowed:
	case bpf.ReasonPathUnresolved, bpf.ReasonIdentityMismatch:
		rule, reason = RuleUnmatched, record.ReasonPathUnresolved // the plane failed closed
	case bpf.ReasonNone, bpf.ReasonWriteOutsideContract, bpf.ReasonDeleteOutsideContract, bpf.ReasonRenameOutsideContract,
		bpf.ReasonMkdirOutsideContract, bpf.ReasonReadDenied, bpf.ReasonNetNotAllowed, bpf.ReasonNetHTTP, bpf.ReasonRefer,
		bpf.ReasonDenyWriteAncestor, bpf.ReasonProcessScope, bpf.ReasonPinMissing, bpf.ReasonPinMismatch,
		bpf.ReasonPinUnverifiable, bpf.ReasonArgvChanged, bpf.ReasonArgvUnreadable, bpf.ReasonExecTraced:
		r.gap(GapMalformedRecord, 1) // no mapping hook refuses with these
	default:
		r.gap(GapMalformedRecord, 1)
	}
	ev := r.event(rec, record.KindRefused, rule, record.VerdictRefused, reason)
	// A refused line is no action: it carries rule and reason, never a verdict or an authority (spec/record/v1).
	ev.Verdict, ev.Authority, ev.Attr = "", "", nil
	r.setPayload(ev, record.RefusedPayload{Op: op, Target: target, Reason: reason, Rule: rule,
		Mechanism: record.MechanismPlane, DecisionPlane: r.opts.DecisionPlane})
	r.emit(ev)
}
