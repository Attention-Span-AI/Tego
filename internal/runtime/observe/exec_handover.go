// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An attempt can open a script, its interpreter and an ELF loader. These are fragments of the exec, not
// terminal actions: only sched_process_exec or a negative syscall result emits its exec line. A fixed ring
// bounds retention when results are lost; AttemptMonoNS prevents an older fragment naming a newer attempt.
const execFragmentLimit = 512

type execFragment struct {
	header    Header
	start     uint64
	path      string
	truncated bool
	open      bool
	ret       int32
	rule      uint32
}

type execFragments struct {
	ring [execFragmentLimit]execFragment
	next int
}

// A duplicate terminal sample must not consume naming again and become a second unmatched exec line.
// Only exact recent sample identities match; distinct attempts of one long-lived process stay separate.
type execOutcomeIdentity struct {
	kind      Kind
	pid, tid  uint32
	start, at uint64
	ret       int64
}

type execOutcomesSeen struct {
	ring [8]execOutcomeIdentity
	next int
}

func (s *execOutcomesSeen) first(rec *Record) bool {
	key := execOutcomeIdentity{kind: rec.Kind, pid: rec.PID, tid: rec.TID, start: rec.StartNS,
		at: rec.MonoNS, ret: rec.ExecResult.Ret}
	for _, old := range s.ring {
		if old == key {
			return false
		}
	}
	s.ring[s.next] = key
	s.next = (s.next + 1) % len(s.ring)
	return true
}

func (r *Recorder) rememberExecFragment(rec *Record) {
	f := execFragment{header: rec.Header, start: rec.StartNS, path: rec.Plane.Path,
		truncated: rec.Plane.PathTruncated, rule: rec.Plane.RuleIdx}
	if rec.Kind == KindOpen {
		if !rec.FS.RetOK {
			r.gap(GapMalformedRecord, 1)
			return
		}
		f.open, f.path, f.truncated, f.ret = true, rec.FS.Path, rec.FS.PathTruncated, rec.FS.Ret
	}
	if r.execFragments.ring[r.execFragments.next].header.MonoNS != 0 {
		r.gap(GapExecFragmentOverflow, 1)
	}
	r.execFragments.ring[r.execFragments.next] = f
	r.execFragments.next = (r.execFragments.next + 1) % len(r.execFragments.ring)
}

func execTID(rec *Record, original int) int {
	if original > 0 {
		return original
	}
	return int(rec.TID)
}

func (f *execFragment) task(rec *Record, tid int) bool {
	return f.header.TID == uint32(execTID(rec, tid)) && f.header.PID == rec.PID && f.start == rec.StartNS
}

// find returns only evidence inside the joined attempt's interval. The first open proves the initial image
// (for a declared MCP start); the latest open names the image whose bprm check could refuse.
func (h *execFragments) find(rec *Record, tid int, after uint64) (firstOpen, lastOpen, refusal *execFragment) {
	for i := range h.ring {
		f := &h.ring[i]
		at := f.header.MonoNS
		if !f.task(rec, tid) || at <= after || at >= rec.MonoNS {
			continue
		}
		if f.open {
			if firstOpen == nil || at < firstOpen.header.MonoNS {
				firstOpen = f
			}
			if lastOpen == nil || at > lastOpen.header.MonoNS {
				lastOpen = f
			}
		}
		if (!f.open || f.ret < 0) && (refusal == nil || at > refusal.header.MonoNS) {
			refusal = f
		}
	}
	return
}

func (h *execFragments) discard(rec *Record, tid int) {
	for i := range h.ring {
		f := &h.ring[i]
		if f.task(rec, tid) && f.header.MonoNS <= rec.MonoNS {
			*f = execFragment{}
		}
	}
}

// joinExec takes the supervisor's naming of the attempt a kernel exec record ends. With the outcome links attached
// (ExecResults) every attempt ends in a record. Without them the plane may still decide the run's execs, and the
// recorder's sched_process_exec record is the line of each one it allowed (supervisor.md R7a): that line joins the
// naming too, so an anonymous image reads fileless and a dropped one dropped (supervisor R16b). Either way the attempt a
// record joins is that exec's own (the hand-over gives the tid's latest attempt, and every trapped exec puts one
// before it is answered), so a supervisor-owned naming means the supervisor wrote the exec's line and the caller
// drops the kernel's (without the links a final drain after a recorder failure wrote it twice).
func (r *Recorder) joinExec(rec *Record, original int) (supervisor.ExecNaming, bool) {
	if r.opts.ContinuedExec != nil {
		n, ok := r.opts.ContinuedExec(execTID(rec, original), int(rec.PID), rec.StartNS, rec.MonoNS)
		if ok && n.AttemptMonoNS != 0 && n.AttemptMonoNS < rec.MonoNS {
			return n, true
		}
	}
	if r.opts.ExecResults || r.opts.ContinuedExec != nil {
		r.gap(GapExecMetadataMissing, 1)
	}
	return supervisor.ExecNaming{}, false
}

// Outcome fields are additive within ledger v1. syscall_ret records an actual failure, including failures
// outside a policy hook (ENOEXEC, ETXTBSY, ENOENT); attempted metadata never supplies a kernel verdict.
type execOutcomePayload struct {
	supervisor.GateFields
	record.ExecPayload
	ArgvTruncated bool `json:"argv_truncated,omitempty"`
	Fileless      bool `json:"fileless,omitempty"`
	Dropped       bool `json:"dropped,omitempty"`
}

func (p *execOutcomePayload) applyNaming(n supervisor.ExecNaming) {
	p.GateFields = n.GateFields
	p.Argv, p.ArgvTruncated, p.Fileless, p.Dropped = n.Argv, n.ArgvTruncated, n.Fileless, n.Dropped
	// ADR 0048 (8): an exec a command rule admitted names that rule on the kernel's line too.
	p.CommandRule, p.CommandList, p.CommandMatch, p.CommandVia = n.CommandRule, n.CommandList, n.CommandMatch, n.CommandVia
	p.ClosureOf, p.ArgvFacts, p.ArgvRead = n.ClosureOf, n.ArgvFacts, n.ArgvRead
	if p.Argv == nil {
		p.Argv = []string{}
	}
	if n.ParentExecID != "" && p.ParentExecID == "" {
		p.ParentExecID = n.ParentExecID
	}
}

// successArgv keeps the mapped stack's arguments authoritative. A matching truncated prefix can retain
// additional attempt metadata, but those unseen tail bytes remain explicitly truncated evidence.
func (r *Recorder) successArgv(p *execOutcomePayload, rec *Record, n supervisor.ExecNaming, joined bool) {
	p.Argv, p.ArgvTruncated = rec.Exec.Argv, rec.Exec.ArgvTruncated
	if !joined {
		return
	}
	p.ArgvFrom = "kernel"
	match := slices.Equal(rec.Exec.Argv, n.Argv)
	if rec.Exec.ArgvTruncated {
		match = len(rec.Exec.Argv) != 0 && len(n.Argv) >= len(rec.Exec.Argv)
		for i, arg := range rec.Exec.Argv {
			if !match {
				break
			}
			if i == len(rec.Exec.Argv)-1 && rec.Exec.ArgvLastPartial {
				match = strings.HasPrefix(n.Argv[i], arg)
			} else {
				match = n.Argv[i] == arg
			}
		}
		if match {
			p.Argv, p.ArgvFrom = n.Argv, "kernel-prefix+attempt"
		}
	}
	if !match {
		if !interpretedArgv(rec, n) {
			r.gap(GapExecArgvMismatch, 1)
		}
	}
}

// A binfmt rewrite inserts the interpreter's arguments and the original kernel filename ahead of the
// invocation's remaining arguments. Only the kernel marker permits this comparison; a native binary whose
// caller changes argv to look like an interpreter must not be accepted. The mapped vector remains the payload.
func interpretedArgv(rec *Record, n supervisor.ExecNaming) bool {
	if !rec.Exec.Interpreted || rec.Exec.ArgvTruncated || n.ArgvTruncated || len(n.Argv) == 0 ||
		rec.Exec.PathTruncated || rec.Exec.RawPath == "" {
		return false
	}
	for i := 1; i < len(rec.Exec.Argv); i++ {
		if rec.Exec.Argv[i] == rec.Exec.RawPath && slices.Equal(rec.Exec.Argv[i+1:], n.Argv[1:]) {
			return true
		}
	}
	return false
}

func (r *Recorder) handleExecResult(rec *Record) {
	if rec.ExecResult.restarting() {
		return
	}
	ret := rec.ExecResult.Ret
	if ret >= 0 || ret < -4095 {
		r.gap(GapMalformedRecord, 1)
		return
	}
	naming, joined := r.joinExec(rec, int(rec.TID))
	if joined && naming.SupervisorOwned {
		r.execFragments.discard(rec, int(rec.TID))
		return
	}
	entry, _ := r.procs.lookup(int(rec.PID), rec.StartNS)
	p := execOutcomePayload{ExecPayload: record.ExecPayload{Path: TruncatedPath, Argv: []string{},
		ExecID: entry.ExecID, ParentExecID: r.procs.parentExecID(int(rec.PPID), 0), SyscallRet: ret}}
	rule, verdict, reason := RuleUnmatched, record.VerdictObserved, record.Reason("")
	if joined {
		p.applyNaming(naming)
		p.ArgvFrom = "attempt"
		p.Path = naming.Path // only attempted spelling until a kernel fragment names an opened image
		_, opened, refused := r.execFragments.find(rec, int(rec.TID), naming.AttemptMonoNS)
		if opened != nil {
			p.Path = opened.path
			if opened.truncated || p.Path == "" {
				p.Path = TruncatedPath
				r.gap(GapPathTruncated, 1)
			}
		}
		if refused != nil {
			if !refused.open {
				var joinedReason bool
				reason, p.PlaneReason, joinedReason = planeExecReason(refused.header.Reason)
				if !joinedReason {
					r.gap(GapMalformedRecord, 1)
				}
				verdict, rule = record.VerdictRefused, r.planeExecRule(refused.rule)
				if p.PlaneReason != "" && pinPlaneReason(bpf.ReasonCode(refused.header.Reason)) != "" {
					// ADR 0048 (8): a bprm_check pin step's refusal names the pin, not an exec entry.
					rule = RuleExecPin
					r.pins.pinRefused.Add(1)
				}
				p.Mechanism, p.DecisionPlane = record.MechanismPlane, r.opts.DecisionPlane
				if opened == nil {
					p.Path = refused.path
					if refused.truncated || p.Path == "" {
						p.Path = TruncatedPath
						r.gap(GapPathTruncated, 1)
					}
					if !filepath.IsAbs(p.Path) && p.Path != TruncatedPath {
						r.gap(GapExecUnresolved, 1)
					}
				}
			} else {
				rule, verdict, reason = r.execOpenRefusal(refused, &p)
			}
		}
		if naming.Path != "" && naming.Path != p.Path {
			p.AttemptPath = naming.Path
		}
		if naming.ArgvTruncated {
			r.gap(GapArgvTruncated, 1)
		}
	}
	r.execFragments.discard(rec, int(rec.TID))
	ev := r.event(rec, record.KindExec, rule, verdict, reason)
	r.setPayload(ev, p)
	r.emitAction(ev)
}

func (r *Recorder) execOpenRefusal(f *execFragment, p *execOutcomePayload) (string, record.Verdict, record.Reason) {
	if f.header.Verdict == KernelRefused {
		rec := Record{Header: f.header}
		line, ok := r.planeFS(&rec, record.FSOpen, p.Path)
		if !ok {
			r.gap(GapMalformedRecord, 1)
		}
		p.Mechanism, p.DecisionPlane, p.PlaneReason = record.MechanismPlane, r.opts.DecisionPlane, line.planeReason
		return line.rule, record.VerdictRefused, line.reason
	}
	rule := RuleUnmatched
	model := func() (record.Verdict, record.Reason) {
		if f.truncated || !filepath.IsAbs(f.path) || hasDotDot(f.path) || r.rules.rt == nil {
			return record.VerdictObserved, ""
		}
		fs := r.rules.matchFS(f.path)
		if fs.DenyRead {
			rule = fs.Rule
			return decide.InferFS(r.rules.rt, record.FSOpen, false, fs)
		}
		res := r.rules.fx.EvaluateExec(agent.Action{Kind: agent.ActionExec, Path: f.path}, r.rules.rt.Tier)
		if res.Rule != "" && res.Rule != agent.InvalidActionRule {
			rule = res.Rule
		}
		if res.Verdict == agent.VerdictRefused {
			return record.VerdictRefused, res.Reason
		}
		if r.rules.execUngranted(rule, f.path) {
			// The entry's EXECUTE is on the inode the ruleset held, which its name no longer holds: the ruleset
			// refused an exec nothing grants (for a directory entry; for a file).
			rule = RuleUnmatched
			return record.VerdictRefused, record.ReasonExecNotAllowed
		}
		return record.VerdictObserved, ""
	}
	v, reason, other := decide.ChainFS(f.ret, model)
	if other {
		p.Errno, p.By = int64(-f.ret), record.FSByOther
	} else if v == record.VerdictRefused {
		p.By = "lsm-chain"
	}
	return rule, v, reason
}

// execMCP is the MCP start line of a declared server's exec, nil for any other: the caller emits it after the exec's
// own line, and not at all when the plane killed the exec (exec_pin.go).
func (r *Recorder) execMCP(rec *Record, n supervisor.ExecNaming, joined bool) *record.Event {
	if !joined || n.MCPName == "" || n.MCPPath == "" || n.ArgvTruncated || rec.Exec.ArgvTruncated ||
		(!slices.Equal(rec.Exec.Argv, n.Argv) && !interpretedArgv(rec, n)) || r.silent {
		return nil
	}
	first, _, _ := r.execFragments.find(rec, int(rec.Exec.OldTID), n.AttemptMonoNS)
	if first == nil || first.truncated || first.path != n.MCPPath || first.ret != 0 {
		return nil
	}
	ev := r.event(rec, record.KindMCP, "mcp["+n.MCPName+"]", record.VerdictAllow, "")
	r.setPayload(ev, record.MCPPayload{Name: n.MCPName, Command: n.Argv, Transport: "stdio"})
	return ev
}
