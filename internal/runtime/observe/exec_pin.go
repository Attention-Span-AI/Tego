// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"sync/atomic"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The fold of a pinned run's execs (ADR 0048 (8), P2; docs/p0/enforce-plane.md §2.22 "The line"). At a decision plane
// whose run is pinned, the plane's sched_process_exec program checks every exec the plane let through bprm_check
// against its pin and reports the outcome in one sample: a held sample when the mapped argument area is the one the
// pin covers, a kill sample (SIGKILL already pending) when it is not, cannot be read, or no pin was armed. The
// recorder's own exec record of the same exec comes from another program on the same tracepoint, before or after the
// plane's (the order is the order the two links were attached in), so the exec's one line waits here until both are
// read:
//
//   - a kill makes the line refused, rule exec.pin, whatever else arrives: no line says allow for an exec the plane
//     killed (ADR 0016: the verdict is what the mechanism answered);
//   - a held sample of the pin the decision wrote makes the line's argv_facts kernel_pinned: the claim rests on the
//     kernel's positive sample, never on a kill that did not arrive;
//   - an exec record whose sample did not arrive (a ring loss), or whose pin is not the one the decision wrote, is
//     argv_facts unproven, with the gap exec-pin-unproven;
//   - a kill whose exec record did not arrive is its own refused line.
//
// The two samples are reserved in one tracepoint invocation of the exec's own task, with preemption off, so nothing
// else of that process can be in the ring between them: the fold pairs them by the process (pid, start), and a later
// record of the same process (its next exec, a file it opens, its exit) settles whatever of an earlier exec is still
// waiting, as the final drain does. A waiting half pairs only with the other half of the same exec (samePin): the
// sample whose seq is the record's pin_seq. Both programs read that seq from the exec's task (the cur_seq its first
// bprm_check stage wrote, 0 when the task holds no state of the run), so a kill names it as the record does, armed pin
// or not. A half of another seq, 0 included, is an earlier exec's whose other half the ring lost: it is settled
// alone, and the new half waits for its own pair, so an earlier exec's held sample never makes a later killed exec's
// line, and a later exec's kill never refuses an earlier exec that ran. The seq is also what the held proof is checked
// by: the exec record's pin_seq, the held sample's seq (the pin the check read) and the seq the supervisor's decision
// wrote must be one pin.

// GapExecPinUnproven is a pinned exec whose line could not say the kernel held it to its decided facts: neither the
// plane's held sample nor its kill arrived, or the pin the kernel held it to is not the one the decision wrote.
const GapExecPinUnproven = "exec-pin-unproven"

// GapExecPinKillFailed is a pinned exec the plane found differing from its pin and could not kill (bpf_send_signal
// failed): the launcher killed it through its pidfd, late, and its line says detected_bypass.
const GapExecPinKillFailed = "exec-pin-kill-failed"

// maxPinWaiting bounds the processes whose exec half the fold holds; past it every one is settled as it stands. Both
// halves of an exec arrive within one tracepoint invocation, so in a healthy run the fold holds one or two.
const maxPinWaiting = 4096

type procKey struct {
	pid   uint32
	start uint64
}

// pinWait is one process's half of an exec: its exec line (built as handleExec builds it, emitted when settled) or the
// plane's sample, whichever was read first.
type pinWait struct {
	exec   *pinExec
	sample *Record
}

type pinExec struct {
	ev     *record.Event
	p      execOutcomePayload
	naming supervisor.ExecNaming
	joined bool
	seq    uint32 // the exec record's pin_seq
	mcp    *record.Event
}

// execPinFold is the fold's state. The drain goroutine owns the map, as it owns execFragments; the counters are read
// by run_end.
type execPinFold struct {
	waiting                        map[procKey]pinWait
	killed, killFailed, pinRefused atomic.Int64
}

// SetExecPins says the run's execs are pinned (ADR 0048 (3) P2): its handle pinned its slot, so every exec the plane
// lets through bprm_check is checked at sched_process_exec, and its line waits for the plane's held or kill sample.
// kill is the late backstop for a kill the kernel could not send (the process's pidfd); nil kills nothing. Called
// before Start.
func (r *Recorder) SetExecPins(on bool, kill func(pid int, startBootNS uint64) error) {
	r.opts.ExecPins, r.opts.ExecPinKill = on, kill
}

// ExecPinCounts is run_end's exec_rules counters of a pinned run (ADR 0048 (8)): the execs the plane killed, those
// whose kill the kernel could not send, and those bprm_check refused for their pin.
func (r *Recorder) ExecPinCounts() (killed, killFailed, pinRefused int64) {
	return r.pins.killed.Load(), r.pins.killFailed.Load(), r.pins.pinRefused.Load()
}

// pinKillErrTestHook, when not zero, is the error a binary built with -tags tegotesthooks says the plane's
// bpf_send_signal returned for every kill sample of a pinned run (exec_pin_testhook.go; ADR 0048 P2's K6 kill-failed
// cell). The kernel did send the kill; the line, the counters and the pidfd backstop take the failure path.
var pinKillErrTestHook int32

// handleExecPin takes a plane held or kill sample of a pinned run.
func (r *Recorder) handleExecPin(rec *Record) {
	if rec.Kind == KindPlaneExecKill && rec.Pin.KillErr == 0 {
		rec.Pin.KillErr = pinKillErrTestHook
	}
	if rec.Kind == KindPlaneExecKill {
		r.pins.killed.Add(1)
		if rec.Pin.KillErr != 0 {
			r.pins.killFailed.Add(1)
		}
	}
	key := procKey{rec.PID, rec.StartNS}
	if w, ok := r.pins.waiting[key]; ok {
		delete(r.pins.waiting, key)
		switch {
		case w.exec != nil && samePin(w.exec.seq, rec):
			r.settleExec(w.exec, rec)
			return
		case w.exec != nil:
			r.settleExec(w.exec, nil) // its sample was lost: this sample is a later exec's, whose record may follow
		default:
			r.settleSample(w.sample) // its exec record was lost: this sample is a later exec's
		}
	}
	c := copyPinRecord(rec)
	r.wait(key, pinWait{sample: &c})
}

// holdExec keeps a pinned exec's line until its plane sample is read, or settles it at once when the sample came first.
func (r *Recorder) holdExec(rec *Record, x *pinExec) {
	key := procKey{rec.PID, rec.StartNS}
	if w, ok := r.pins.waiting[key]; ok {
		delete(r.pins.waiting, key)
		switch {
		case w.sample != nil && samePin(x.seq, w.sample):
			r.settleExec(x, w.sample)
			return
		case w.sample != nil:
			r.settleSample(w.sample) // its exec record was lost: this record is a later exec's
		default:
			r.settleExec(w.exec, nil) // its sample was lost: this record is a later exec's
		}
	}
	r.wait(key, pinWait{exec: x})
}

// samePin says whether plane sample s is the sample of the exec whose record read pin seq: its seq is that seq, 0
// included. Both programs read the seq from the exec's task, the cur_seq its first bprm_check stage wrote, in one
// tracepoint invocation: a kill names it whether or not a pin was armed.
func samePin(seq uint32, s *Record) bool {
	return s.Pin.Seq == seq
}

// settlePinsOf settles what still waits of process (pid, start) when another of its records is read: an exec's two
// halves are adjacent among the process's records, so the missing one will not come. A record that names no start
// (0) settles every process of the pid; a process's records come in order, and a pid is not reused before its exit.
func (r *Recorder) settlePinsOf(pid uint32, start uint64) {
	for k, w := range r.pins.waiting {
		if k.pid == pid && (start == 0 || k.start == start) {
			delete(r.pins.waiting, k)
			r.settle(w)
		}
	}
}

// settleAllPins settles everything still waiting: the final drain has read what the ring held.
func (r *Recorder) settleAllPins() {
	for k, w := range r.pins.waiting {
		delete(r.pins.waiting, k)
		r.settle(w)
	}
}

func (r *Recorder) wait(key procKey, w pinWait) {
	if r.pins.waiting == nil {
		r.pins.waiting = map[procKey]pinWait{}
	}
	r.pins.waiting[key] = w
	if len(r.pins.waiting) > maxPinWaiting {
		// Each is then said as it stands (unproven, or a kill's own line), never dropped.
		r.settleAllPins()
	}
}

func (r *Recorder) settle(w pinWait) {
	if w.exec != nil {
		r.settleExec(w.exec, nil)
	} else {
		r.settleSample(w.sample)
	}
}

// settleSample says a plane sample whose exec record never arrived: a kill is its own refused line; a held sample
// says nothing, since the exec record it would have proved is already a lost sample.
func (r *Recorder) settleSample(s *Record) {
	if s.Kind == KindPlaneExecKill {
		r.emitKill(nil, s)
	}
}

// settleExec emits a waiting exec line with its plane sample s: a kill, a held sample, or none (nil).
func (r *Recorder) settleExec(x *pinExec, s *Record) {
	if s != nil && s.Kind == KindPlaneExecKill {
		r.emitKill(x, s)
		return
	}
	if s == nil || !x.joined || s.Pin.Seq == 0 || s.Pin.Seq != x.seq || x.naming.PinSeq != x.seq {
		x.p.ArgvFacts = record.ArgvFactsUnproven
		r.gap(GapExecPinUnproven, 1)
		r.setPayload(x.ev, x.p)
		r.emitAction(x.ev)
		return // no MCP start: the exec may have been killed, and that line would say a server ran
	}
	x.p.ArgvFacts = record.ArgvFactsKernelPinned
	r.setPayload(x.ev, x.p)
	r.emitAction(x.ev)
	if x.mcp != nil {
		r.emit(x.mcp)
	}
}

// emitKill writes the line of an exec the plane killed (ADR 0048 (8)): refused, rule exec.pin, its plane_reason, argv
// the kernel's mapped vector and argv_decided the decision's. w is the exec's waiting line, or nil when the kill is
// its own line; a kill the kernel could not send is the launcher's to make through the process's pidfd.
func (r *Recorder) emitKill(w *pinExec, k *Record) {
	// sched_process_exec kills with argv-changed, argv-unreadable, pin-missing or pin-unverifiable; any other code is a
	// malformed sample, still a refused line (the process is dead or dying either way).
	reason, planeReason := record.ReasonExecNotAllowed, pinPlaneReason(bpf.ReasonCode(k.Reason))
	if planeReason == "" {
		r.gap(GapMalformedRecord, 1)
	}
	var (
		ev  *record.Event
		p   execOutcomePayload
		n   supervisor.ExecNaming
		ok2 bool
	)
	if w != nil {
		ev, p, n, ok2 = w.ev, w.p, w.naming, w.joined
		ev.Rule, ev.Verdict, ev.Reason = RuleExecPin, record.VerdictRefused, reason
	} else {
		entry, _ := r.procs.lookup(int(k.PID), k.StartNS)
		ev = r.event(k, record.KindExec, RuleExecPin, record.VerdictRefused, reason)
		p = execOutcomePayload{ExecPayload: record.ExecPayload{Path: TruncatedPath, ExecID: entry.ExecID,
			ParentExecID: r.procs.parentExecID(int(k.PPID), 0)}}
		if n, ok2 = r.joinExec(k, int(k.Pin.OldTID)); ok2 {
			p.applyNaming(n)
			p.Path = n.Path
		}
		if p.Path == "" || p.Path == TruncatedPath {
			p.Path = TruncatedPath
			r.gap(GapPathTruncated, 1)
		}
	}
	p.Argv, p.ArgvTruncated, p.ArgvFrom = k.Pin.Argv, k.Pin.ArgvTruncated, "kernel"
	if p.Argv == nil {
		p.Argv = []string{}
	}
	if k.Pin.ArgvTruncated {
		r.gap(GapArgvTruncated, 1)
	}
	if ok2 {
		p.ArgvDecided = n.Argv
	}
	p.Mechanism, p.DecisionPlane, p.PlaneReason = record.MechanismPlane, r.opts.DecisionPlane, planeReason
	p.Signal = record.SignalKill
	if k.Pin.KillErr != 0 {
		// The kernel could not send the kill: the program may run until the pidfd's lands (R6d).
		p.KillFailed, p.DetectedBypass = int64(k.Pin.KillErr), true
		r.gap(GapExecPinKillFailed, 1)
		if r.opts.ExecPinKill != nil {
			if err := r.opts.ExecPinKill(int(k.PID), k.StartNS); err != nil {
				r.logWarn("pidfd kill of an exec the plane could not kill failed", "pid", k.PID,
					"err", fmt.Errorf("observe: %w", err))
			} else {
				r.logWarn("pidfd kill sent to an exec the plane could not kill", "pid", k.PID)
			}
		}
	}
	r.setPayload(ev, p)
	r.emitAction(ev)
}

// copyPinRecord keeps what the fold reads of a plane sample past the drain's reuse of rec.
func copyPinRecord(rec *Record) Record {
	c := Record{Header: rec.Header, StartNS: rec.StartNS, Pin: rec.Pin}
	c.Pin.Argv = append([]string(nil), rec.Pin.Argv...)
	return c
}
