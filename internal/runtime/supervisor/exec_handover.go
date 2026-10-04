// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type continuedExec struct {
	tid, pid        int
	startNS         uint64
	named, consumed bool
	naming          ExecNaming
}

type execHandover struct {
	mu   sync.Mutex
	ring [handoverSize]continuedExec
	next int
}

func (h *execHandover) put(e continuedExec) {
	e.naming.Argv = append([]string(nil), e.naming.Argv...)
	h.mu.Lock()
	h.ring[h.next] = e
	h.next = (h.next + 1) % len(h.ring)
	h.mu.Unlock()
}

// find consumes the latest attempt before the terminal kernel event. Consumed
// and unreadable entries remain as tombstones, so a duplicate or a naming gap
// never falls back to the previous attempt's argv.
func (h *execHandover) find(tid, pid int, startNS, at uint64) (ExecNaming, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var last *continuedExec
	for i := range h.ring {
		e := &h.ring[i]
		if e.tid == tid && e.naming.AttemptMonoNS != 0 && e.naming.AttemptMonoNS < at &&
			(last == nil || e.naming.AttemptMonoNS > last.naming.AttemptMonoNS) {
			last = e
		}
	}
	if last == nil || last.consumed || !last.named || last.pid != pid || startNS == 0 ||
		proc.ExecStartNS(last.startNS) != proc.ExecStartNS(startNS) {
		return ExecNaming{}, false
	}
	last.consumed = true
	n := last.naming
	n.Argv = append([]string(nil), n.Argv...)
	return n, true
}

// ContinuedExec supplies metadata once for the success or failure of the exec
// originally notified by tid. A non-leader exec changes its TID on success, so
// the kernel success record supplies the original TID separately from pid.
func (l *Loop) ContinuedExec(tid, pid int, startNS, at uint64) (ExecNaming, bool) {
	return l.execHanded.find(tid, pid, startNS, at)
}

// handOverExec continues an exec a kernel recorder decides and records (no command rules, no exec gate), handing it
// the naming its line takes: fileless and dropped are the exec's own facts, judged once by recordExec (supervisor R16b).
func (l *Loop) handOverExec(n *notif, r *reader, c *compiled, p, raw string, argvAddr uint64, img execImage, resolved, readable, fileless, dropped bool) {
	if c.pol.Rules.Gate.Has(gate.Exec) {
		// Embedded callers cannot bypass the score through a direct fast handover.
		l.respond(n, respErrno(refusalErrno))
		ev := action(l.event(n, record.KindExec, record.SourceSeccomp), "gate.unreadable", record.VerdictRefused, record.ReasonExecGate)
		ev.Authority = record.AuthorityGate
		g := gate.Decision{Verdict: gate.Refused, Score: gate.MaxScore, Rule: "gate.unreadable"}
		l.emitFor(n, ev, execPayload{ExecPayload: record.ExecPayload{Path: p}, GateFields: gatePayload(&g, false)})
		return
	}

	argv, truncated := r.argv(argvAddr, c.argvMax)
	if n.gone {
		return
	}
	pid, execID, parentID := l.execIdentity(c, n)
	_, ticks, err := l.k.ProcStat(pid)
	cwd, _ := l.k.StatID(fmt.Sprintf("/proc/%d/cwd", n.pid))
	if !l.valid(n) {
		return
	}
	e := continuedExec{tid: n.pid, pid: pid, startNS: ticks * proc.NanosPerTick,
		named: readable && err == nil && execID != "",
		naming: ExecNaming{Path: p, RawPath: raw, Argv: argv, ExecID: execID, ParentExecID: parentID,
			ArgvTruncated: truncated, Fileless: fileless, Dropped: dropped, CwdDev: cwd.dev, CwdIno: cwd.ino,
			AttemptMonoNS: l.mono()},
	}
	if !truncated && resolved {
		e.naming.MCPName = c.mcpServerOf(p, img, argv)
		e.naming.MCPPath = strings.TrimSuffix(img.link, deletedSuffix)
	}
	l.execHanded.put(e)
	l.respond(n, respContinue())
}
