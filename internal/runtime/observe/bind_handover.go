// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

type BindResultBody struct {
	Ret            int64
	Dev, DirIno    uint64
	RuleIdx, Flags uint32
	Name           string
}

func decodeBindResult(dst *Record, raw []byte) error {
	e, err := decodeRecord[bpf.BindResultEvent](raw)
	if err != nil {
		return err
	}
	if e.NameLen > 107 || e.Flags & ^(bpf.BindAbstract|bpf.BindNameOK|bpf.BindResolved|bpf.BindMarked|bpf.BindChainRefused|bpf.BindDecided|bpf.BindURing) != 0 {
		return fmt.Errorf("%w: invalid bind result flags/name length", ErrShortRecord)
	}
	dst.StartNS = e.StartNS
	dst.BindResult = BindResultBody{Ret: e.Ret, Dev: userDev(e.Dev), DirIno: e.DirIno, RuleIdx: e.RuleIdx, Flags: e.Flags, Name: string(e.Name[:e.NameLen])}
	return nil
}

type bindOutcomeIdentity struct {
	kind                Kind
	pid, tid, slot, gen uint32
	start, at           uint64
	ret                 int64
}
type bindOutcomesSeen struct {
	ring [8]bindOutcomeIdentity
	next int
}

func (s *bindOutcomesSeen) first(rec *Record) bool {
	key := bindOutcomeIdentity{rec.Kind, rec.PID, rec.TID, rec.RunIdx, rec.Gen, rec.StartNS, rec.MonoNS, rec.BindResult.Ret}
	for _, old := range s.ring {
		if old == key {
			return false
		}
	}
	s.ring[s.next] = key
	s.next = (s.next + 1) % len(s.ring)
	return true
}

func (r *Recorder) handleBindResult(rec *Record) {
	b := rec.BindResult
	if (ExecResultBody{Ret: b.Ret}).restarting() {
		return
	}
	if b.Ret > 0 || !r.bindOutcomes.first(rec) {
		if b.Ret > 0 {
			r.gap(GapMalformedRecord, 1)
		}
		return
	}
	var joined, owned bool
	fn, op := r.opts.ContinuedBind, "bind"
	if rec.Kind == KindListenResult {
		fn, op = r.opts.ContinuedListen, "listen"
	}
	// An io_uring op passes no seccomp notification: there is no supervisor naming to join, and none is missing.
	uring := b.Flags&bpf.BindURing != 0
	if fn != nil && !uring {
		n, ok := fn(int(rec.TID), int(rec.PID), rec.StartNS, rec.MonoNS)
		joined, owned = ok, n.SupervisorOwned
	}
	if joined && owned {
		return
	}
	if !joined && !uring {
		r.gap(GapBindMetadataMissing, 1)
	}
	rule, reason, planeReason := RuleUnmatched, record.Reason(""), ""
	v, from, mechanism := record.VerdictObserved, "unknown", ""
	marked := b.Flags&bpf.BindMarked != 0
	decided := marked && b.Flags&bpf.BindDecided != 0
	if decided {
		if rec.Verdict != KernelAllow && rec.Verdict != KernelRefused {
			r.gap(GapMalformedRecord, 1)
			return
		}
		v, from, mechanism = record.VerdictAllow, "plane", record.MechanismPlane
		if b.RuleIdx&bpf.PlaneRuleListen != 0 {
			i := int(b.RuleIdx & 0xffff)
			if rt := r.rules.rt; rt != nil && i < len(rt.Listen) {
				rule = rt.Listen[i].RuleName()
			}
		} else if b.RuleIdx&bpf.PlaneRuleFSRow != 0 {
			if rows := r.planeRows(); rows != nil {
				rule = rows.RowName(r.rules.rt, int(b.RuleIdx&0xffff), decide.PlaneModify, 1)
			}
		}
		if rec.Verdict == KernelRefused {
			if b.Ret >= 0 {
				r.gap(GapMalformedRecord, 1)
				return
			}
			v = record.VerdictRefused
			switch bpf.ReasonCode(rec.Reason) {
			case bpf.ReasonNetNotAllowed:
				reason = record.ReasonNetNotAllowed
			case bpf.ReasonWriteOutsideContract:
				reason = record.ReasonWriteOutsideContract
			case bpf.ReasonReadDenied:
				reason = record.ReasonReadDenied
			case bpf.ReasonPathUnresolved:
				reason = record.ReasonPathUnresolved
			case bpf.ReasonIdentityMismatch:
				reason, planeReason = record.ReasonPathUnresolved, record.PlaneReasonIdentityMismatch
			case bpf.ReasonNone, bpf.ReasonDeleteOutsideContract, bpf.ReasonRenameOutsideContract,
				bpf.ReasonMkdirOutsideContract, bpf.ReasonExecNotAllowed, bpf.ReasonNetHTTP, bpf.ReasonRefer,
				bpf.ReasonDenyWriteAncestor, bpf.ReasonProcessScope, bpf.ReasonPinMissing, bpf.ReasonPinMismatch,
				bpf.ReasonPinUnverifiable, bpf.ReasonArgvChanged, bpf.ReasonArgvUnreadable, bpf.ReasonExecTraced:
				r.gap(GapMalformedRecord, 1)
				return
			default:
				r.gap(GapMalformedRecord, 1)
				return
			}
		} else if rec.Reason != uint8(bpf.ReasonNone) {
			r.gap(GapMalformedRecord, 1)
			return
		}
		if v != record.VerdictRefused && (b.Flags&bpf.BindChainRefused != 0 || b.Ret == -int64(unix.EACCES) || b.Ret == -int64(unix.EPERM)) {
			v, reason, rule, from, mechanism = record.VerdictRefused, record.ReasonPathUnresolved, RuleUnmatched, record.FSVerdictChain, ""
		}
	}
	if !decided && (b.Flags&bpf.BindChainRefused != 0 || b.Ret == -int64(unix.EACCES) || b.Ret == -int64(unix.EPERM)) {
		v, reason, from = record.VerdictRefused, record.ReasonPathUnresolved, record.FSVerdictChain
	}
	target := "<unavailable>"
	if marked && b.Flags&bpf.BindNameOK != 0 && b.Name != "" {
		switch {
		case b.Flags&bpf.BindAbstract != 0:
			target = "unix:@" + b.Name
		case b.Flags&bpf.BindResolved != 0:
			p, _, resolved := r.resolveFSOpPath(b.Dev, b.DirIno, b.Name, false, true, "", bpf.DirNone)
			r.dirUnresolvedGap(resolved, false)
			target = "unix:" + p
		default:
			// This is the kernel-copied attempted spelling, not a resolved inode.
			target = "unix:" + strings.TrimRight(b.Name, "\x00")
		}
	} else if marked {
		r.gap(GapPathTruncated, 1)
	}
	if r.silent && v != record.VerdictRefused {
		return
	}
	ev := r.event(rec, record.KindNet, rule, v, reason)
	proto := ""
	if marked {
		proto = "unix"
	}
	p := record.NetPayload{Op: op, Proto: proto, Dst: target, Mechanism: mechanism, PlaneReason: planeReason, SyscallRet: b.Ret, VerdictFrom: from}
	if mechanism != "" {
		p.DecisionPlane = r.opts.DecisionPlane
	}
	if b.Ret < 0 {
		p.SyscallErrno = int(-b.Ret)
	}
	r.setPayload(ev, p)
	r.emit(ev)
}
