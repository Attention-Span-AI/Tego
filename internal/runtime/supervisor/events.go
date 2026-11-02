// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"sync"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// execPayload is record.ExecPayload plus the truncation flag this tier needs: record v1 permits optional
// additions within v: 1 (VERSIONING §2), and argv read under a byte budget has to say when it hit it
// (R3, R16). The embedded struct is anonymous, so the flag encodes as one more top-level key.
type execPayload struct {
	record.ExecPayload
	GateFields
	// ArgvTruncated reports that the argv byte budget or the entry cap cut the vector short (E10, E11).
	ArgvTruncated bool `json:"argv_truncated,omitempty"`
	// PathSearch marks a candidate of the run's own PATH search rather than a binary the agent named:
	// execvp had to try this path to reach the entry in the line's rule, and nothing ran here (R28).
	// A reader that does not know the key ignores it; the verdict alone already reads honestly.
	PathSearch bool `json:"path_search,omitempty"`
	// Fileless marks an exec whose image is an anonymous inode — a memfd, another anonymous inode, or a
	// file unlinked since it was opened — rather than a binary on disk (Falco's proc.is_exe_from_memfd,
	// SEMANTICS §4). Such an image has no path Landlock's exec check governs, so this loop refuses it
	// (rule=exec-anon) unless the contract has no exec: section (R16b); the flag lets a reader tell a
	// fileless exec apart from an ordinary one either way, and tego drift lists the images it and Dropped
	// flag (limits-check-doctor-cli.md R17a). Record v1 optional addition (VERSIONING §2).
	Fileless bool `json:"fileless,omitempty"`
	// Dropped marks an exec whose image lies under a write entry and changed after the run started: a
	// binary the run itself wrote and then executed (drop-and-execute, Falco's proc.is_exe_upper_layer
	// analogue, R16b). It is decided on the inode's ctime, so a file another process changed there during
	// the run reads the same. In a run with command rules a #! interpreter or a directly-invoked loader's program
	// the exec loads is judged too (execCommand.dropped), whatever the image floor answers; without them only the
	// exec's own image is (R16b). recordExec judges it once, and the naming a kernel recorder's line takes carries
	// that same value (ExecNaming.Dropped).
	// Record v1 optional addition (VERSIONING §2).
	Dropped bool `json:"dropped,omitempty"`
}

// netPayload is record.NetPayload plus the marker this tier owes a reader of a syscall it continued: the
// address was read and admitted (or, with no net: section, only recorded), and the kernel then acted on its own
// copy of it, which a sibling thread can have rewritten (R13b). record v1 permits optional additions within
// v: 1 (VERSIONING §2), the same way argv_truncated is added above.
type netPayload struct {
	record.NetPayload
	GateFields
	// BestEffort marks a line for a syscall this loop answered CONTINUE: what the line names is this loop's
	// copy, and the kernel's may differ. A refused line never carries it (R13b as amended 2026-10-16): every
	// refusal this loop records is one it enforced, and until then an unconnected datagram's refusal was
	// recorded with this mark while the datagram left.
	BestEffort bool `json:"best_effort,omitempty"`
	// ResultUnknown marks a connect or Fast-Open send this loop performed on the target's own socket and
	// then stopped waiting for, because the target abandoned the syscall while it was still running
	// (E35). The side effect is real — the connection may be established, the bytes may be on the wire —
	// but no result ever reached the agent. Below 5.19, or without WAIT_KILLABLE_RECV, the kernel restarts
	// an abandoned syscall, so a second notification for the same logical call is on its way, and without
	// the marker that pair reads as two connects the agent made, which is what `drift` and `measure` would
	// then count; with the flag the target was killed, and the marker says the agent never saw it. A
	// 5.19+ kernel without cce436aa can still restart a call whose answer NOTIF_SEND delivered, when a
	// non-fatal signal lands as it is sent; nothing marks that pair, because nothing here can see it
	// (relayOrphaned).
	ResultUnknown bool `json:"result_unknown,omitempty"`
	// What is, on a unix destination the unix-only state refused (rule host-sockets, ADR 0070), what the well-known
	// daemon socket it names gives an agent that reaches it (agent.HostSocketWhat: "the Docker daemon,
	// root-equivalent"); absent for a socket R19's list does not name. Added at record minor 16.
	What string `json:"what,omitempty"`
}

// event starts an event for one notification with the identity fields every line carries. The ledger
// writer stamps run, agent, ts, mono_ns, seq, prev and id again on append; they are filled here so an
// event validates on its own, which is what the unit tests and any non-ledger sink see.
//
// seccomp reports the tid of the thread that trapped; pid is its thread group, the process, which tgidOf
// resolves once per thread and caches. Both carried the tid, so every thread of a multi-threaded agent read as
// a process of its own.
func (l *Loop) event(n *notif, kind record.Kind, src record.Source) *record.Event {
	pol := l.table.Load().pol
	return &record.Event{
		V: record.Version, TS: time.Now(), MonoNS: n.recvMono, Run: pol.RunID, Agent: pol.Agent,
		PID: l.tgidOfNotif(n), TID: n.pid, Kind: kind, Source: src,
	}
}

// tgidCacheSize bounds tgidCache. It bounds memory only: a cached answer can outlive its thread's id — pids
// are host-wide, eviction counts only the threads that notify here, and pid_max is 32768 on many hosts — so
// every hit is revalidated (tgidOf).
const tgidCacheSize = 4096

// tgidCache maps a thread id to its thread group, first in, first out.
type tgidCache struct {
	mu    sync.Mutex
	m     map[int]int
	order []int
}

// tgidOfNotif is tgidOf of the notifying thread, asked once per notification.
func (l *Loop) tgidOfNotif(n *notif) int {
	if n.tgid == 0 {
		n.tgid = l.tgidOf(n.pid)
	}
	return n.tgid
}

// tgidOf is tid's thread group: cached, or read from /proc/<tid>/status. A cached answer is used only while
// tid is still a thread of that group (InGroup, one lookup and no read): a tid the kernel handed to a new
// task in another group after the old one exited is read again, where the unchecked cache gave every line of
// the new task the dead one's process. A task gone before the read is its own group, the value the line
// carried before.
func (l *Loop) tgidOf(tid int) int {
	c := &l.tgids
	c.mu.Lock()
	g, ok := c.m[tid]
	c.mu.Unlock()
	if ok && l.k.InGroup(g, tid) {
		return g
	}
	g, err := l.k.Tgid(tid)
	if err != nil || g <= 0 {
		return tid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[int]int, tgidCacheSize)
	}
	if _, ok := c.m[tid]; !ok {
		if len(c.order) >= tgidCacheSize {
			delete(c.m, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, tid)
	}
	c.m[tid] = g
	return g
}

// action finishes an action event (exec, fs, net): those four fields are what record v1 requires on every
// one of them (record §2.1 R8), and rule is never free text — the specifics live there, the closed reason
// set in reason.
func action(ev *record.Event, rule string, v record.Verdict, reason record.Reason) *record.Event {
	ev.Rule = rule
	ev.Verdict = v
	ev.Authority = record.AuthorityRule
	ev.Reason = reason
	ev.Attr = record.Unattributed()
	return ev
}

// emitFor records an event for one notification, but only once that notification has been answered: a
// decision this loop never reached is not a decision the run made (R19, E1). Data read before the target
// died still backs the event of a decision that was made (E2).
func (l *Loop) emitFor(n *notif, ev *record.Event, payload any) {
	if !n.answered {
		return
	}
	l.awaitPrev(n)
	l.emit(ev, payload)
}

// emit sends one event to the sink after the notification has already been answered (R23, I5). The sink is
// the supervisor's own queue lane, which waits for room up to its bound rather than let a flooding agent
// choose what the ledger loses: the notification that caused the event is never held
// back, but this worker's next ones wait behind it, so the backpressure is per worker. Every event of this
// package passes through here, which is why an observe run's verdicts are stamped here and nowhere else
// (R30).
func (l *Loop) emit(ev *record.Event, payload any) {
	if ev == nil {
		return
	}
	if l.observing() {
		if ev.Kind == record.KindRefused {
			// respond continued the call this line would call refused (R30): a handler that writes a refused line
			// without asking observing() is a bug, and the line would put a refusal that never happened in
			// last-refusal.json and the agent's reason channel, so it is dropped here.
			l.log.Warn("supervisor: refused line in an observe run dropped; the call was continued", "rule", ev.Rule)
			return
		}
		stampObserved(ev)
	}
	if err := ev.SetPayload(payload); err != nil {
		l.log.Warn("supervisor: event payload", "kind", ev.Kind, "err", err)
		return
	}
	l.sink.Emit(ev)
}

// emitGap records that this package could not produce a record it should have (a recovered handler panic).
// It is best-effort and carries no agent data.
func (l *Loop) emitGap(n *notif, what, why string) {
	ev := l.event(n, record.KindGap, record.SourceSupervisor)
	l.awaitPrev(n)
	l.emit(ev, record.GapPayload{What: what, Why: why, Count: 1})
}

// recording reports whether the advisory record-only events are wanted: record: off keeps the ledger to
// refusals and decisions, and this package's fs events are advisory by construction (P0-DESIGN §4.3).
// A refusal is never suppressed by it.
func (c *compiled) recording() bool { return c.record != agent.RecordOff }
