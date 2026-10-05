// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func (r *Recorder) handlePlaneListener(rec *Record) {
	if rec.Verdict != KernelRefused {
		r.gap(GapMalformedRecord, 1)
		return
	}
	op := "bind"
	if rec.Plane.Hook == bpf.PlaneHookNumber("socket_listen") {
		op = "listen"
	}
	rule := RuleUnmatched
	if rt := r.rules.rt; rt != nil && rec.Plane.RuleIdx&bpf.PlaneRuleListen != 0 {
		i := int(rec.Plane.RuleIdx & 0xffff)
		if i < len(rt.Listen) {
			rule = rt.Listen[i].RuleName()
		}
	}
	reason, planeReason := record.ReasonNetNotAllowed, ""
	switch bpf.ReasonCode(rec.Reason) {
	case bpf.ReasonNetNotAllowed:
	case bpf.ReasonPathUnresolved:
		reason = record.ReasonPathUnresolved
	case bpf.ReasonIdentityMismatch:
		reason, planeReason = record.ReasonPathUnresolved, record.PlaneReasonIdentityMismatch
	case bpf.ReasonNone, bpf.ReasonWriteOutsideContract, bpf.ReasonDeleteOutsideContract,
		bpf.ReasonRenameOutsideContract, bpf.ReasonMkdirOutsideContract, bpf.ReasonReadDenied,
		bpf.ReasonExecNotAllowed, bpf.ReasonNetHTTP, bpf.ReasonRefer, bpf.ReasonDenyWriteAncestor,
		bpf.ReasonProcessScope, bpf.ReasonPinMissing, bpf.ReasonPinMismatch, bpf.ReasonPinUnverifiable,
		bpf.ReasonArgvChanged, bpf.ReasonArgvUnreadable, bpf.ReasonExecTraced:
		r.gap(GapMalformedRecord, 1)
		return
	default:
		r.gap(GapMalformedRecord, 1)
		return
	}
	proto, target := "", record.SocketTriple(rec.Plane.Family, rec.Plane.Type, rec.Plane.Protocol)
	if rec.Plane.Family == unix.AF_UNIX {
		proto = "unix"
		target = rec.Plane.Path
		if rec.FS.Flags&1 != 0 {
			target = "unix:@" + target
			if rec.Plane.PathTruncated {
				r.gap(GapPathTruncated, 1)
			}
		} else if target != "" {
			p, _, resolved := r.resolveFSOpPath(rec.FS.Dev, rec.FS.Ino, target, rec.Plane.PathTruncated, true, "", bpf.DirNone)
			r.dirUnresolvedGap(resolved, rec.Plane.PathTruncated)
			target = "unix:" + p
		}
	}
	ev := r.event(rec, record.KindNet, rule, record.VerdictRefused, reason)
	r.setPayload(ev, record.NetPayload{Op: op, Proto: proto, Dst: target, Mechanism: record.MechanismPlane,
		DecisionPlane: r.opts.DecisionPlane, PlaneReason: planeReason})
	r.emit(ev)
}
