// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"sync"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

type continuedBind struct {
	tid, pid        int
	startNS         uint64
	named, consumed bool
	naming          BindNaming
}

type bindHandover struct {
	mu   sync.Mutex
	ring [handoverSize]continuedBind
	next int
}

func (h *bindHandover) put(e continuedBind) {
	h.mu.Lock()
	for i := range h.ring {
		if h.ring[i].tid == e.tid && h.ring[i].naming.AttemptMonoNS == e.naming.AttemptMonoNS && e.naming.AttemptMonoNS != 0 {
			h.ring[i] = e
			h.mu.Unlock()
			return
		}
	}
	h.ring[h.next] = e
	h.next = (h.next + 1) % len(h.ring)
	h.mu.Unlock()
}

func (h *bindHandover) find(tid, pid int, startNS, at uint64) (BindNaming, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var last *continuedBind
	for i := range h.ring {
		e := &h.ring[i]
		if e.tid == tid && e.naming.AttemptMonoNS != 0 && e.naming.AttemptMonoNS < at && (last == nil || e.naming.AttemptMonoNS > last.naming.AttemptMonoNS) {
			last = e
		}
	}
	if last == nil || last.consumed || !last.named || last.pid != pid || startNS == 0 || proc.ExecStartNS(last.startNS) != proc.ExecStartNS(startNS) {
		return BindNaming{}, false
	}
	last.consumed = true
	return last.naming, true
}

func (l *Loop) ContinuedBind(tid, pid int, startBootNS, eventMonoNS uint64) (BindNaming, bool) {
	return l.bindHanded.find(tid, pid, startBootNS, eventMonoNS)
}

func (l *Loop) saveBindNaming(n *notif, d dest, rule string, supervisorOwned bool) {
	if n.bindAttemptNS == 0 {
		n.bindAttemptNS = l.mono()
	}
	pid := l.tgidOf(n.pid)
	_, ticks, err := l.k.ProcStat(pid)
	name := d.unixPath
	if len(d.abstract) > 0 {
		name = string(d.abstract)
	}
	if d.unixPath != "" {
		r := l.newReader(n)
		name = r.resolve(atFDCWD, d.unixPath)
		if !r.ok() {
			name = ""
		}
	}
	l.bindHanded.put(continuedBind{tid: n.pid, pid: pid, startNS: ticks * proc.NanosPerTick, named: err == nil && (supervisorOwned || d.ok),
		naming: BindNaming{Path: name, Abstract: len(d.abstract) > 0, Rule: rule, AttemptMonoNS: n.bindAttemptNS, SupervisorOwned: supervisorOwned}})
}

func (l *Loop) beginBindHandover(n *notif) {
	n.bindAttemptNS = l.mono()
	l.bindHanded.put(continuedBind{tid: n.pid, naming: BindNaming{AttemptMonoNS: n.bindAttemptNS}})
}

func (l *Loop) bindHandoffReady() bool { return l.kernelBindHandoff != nil && l.kernelBindHandoff() }
