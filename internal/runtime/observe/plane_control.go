// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"strconv"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func (r *Recorder) handlePlaneControl(rec *Record) {
	if rec.Verdict != KernelRefused {
		r.gap(GapMalformedRecord, 1)
		return
	}
	var op, rule, target string
	var expected bpf.ReasonCode
	var reason record.Reason
	switch rec.Plane.Hook {
	case bpf.PlaneHookNumber("ptrace_access_check"):
		op, rule = "ptrace", "process-scope"
		target = strconv.Itoa(int(rec.Plane.Family))
		expected, reason = bpf.ReasonProcessScope, record.ReasonLandlockTopology
	case bpf.PlaneHookNumber("ptrace_traceme"):
		op, rule = "ptrace_traceme", "process-scope"
		target = strconv.Itoa(int(rec.Plane.Family))
		expected, reason = bpf.ReasonProcessScope, record.ReasonLandlockTopology
	case bpf.PlaneHookNumber("bpf"):
		op, rule = "bpf", "bpf"
		target = "command " + strconv.Itoa(int(rec.Plane.Type))
		expected, reason = bpf.ReasonProcessScope, record.ReasonLandlockTopology
	case bpf.PlaneHookNumber("key_permission"):
		op, rule = "key_permission", "keyring"
		target = "permission " + strconv.Itoa(int(rec.Plane.Type))
		expected, reason = bpf.ReasonReadDenied, record.ReasonReadDenied
	default:
		r.gap(GapMalformedRecord, 1)
		return
	}
	if bpf.ReasonCode(rec.Reason) == bpf.ReasonPathUnresolved {
		reason = record.ReasonPathUnresolved
	} else if bpf.ReasonCode(rec.Reason) != expected {
		r.gap(GapMalformedRecord, 1)
		return
	}
	ev := r.event(rec, record.KindRefused, rule, record.VerdictRefused, reason)
	ev.Verdict, ev.Authority, ev.Attr = "", "", nil
	r.setPayload(ev, record.RefusedPayload{Op: op, Target: target, Rule: rule, Reason: reason,
		Mechanism: record.MechanismPlane, DecisionPlane: r.opts.DecisionPlane})
	r.emit(ev)
}
