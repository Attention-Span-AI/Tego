// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"path"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// handoverSize bounds the naming kept for the kernel recorder: the recorder reads the kernel's record of a
// continued syscall within milliseconds, and a refused create's record waits only for the task's next one, so
// a few hundred actions of all the run's threads are far more than it ever asks behind.
const handoverSize = 512

// FSNaming is how this loop would have named a filesystem action it left to the kernel recorder's line
// (Options.KernelFS, R7a): the spellings the task passed, the rule and the advisory verdict and reason, taken
// where the path lands (R15b) and at both ends of a rename (R17).
type FSNaming struct {
	GateFields
	Path, Path2 string
	Rule        string
	Verdict     record.Verdict
	Reason      record.Reason
}

// handed is one fs action continued while the kernel recorder reads the run, keyed as the kernel's record can
// key it: the thread, and the moment it was handed over (CLOCK_MONOTONIC, the clock of the record's
// bpf_ktime_get_ns), with the operation and the final component of each end where it lands (a dentry's own name)
// to check the match. A thread makes one syscall at a time, and a continued syscall reaches its hook only after
// this loop answers it, so the record of an action is stamped after the action was handed over and before the
// thread's next notification was: the action a record is of is its thread's last one handed over before the
// record's own stamp, whatever the recorder has fallen behind by. An action continued without a naming (its path
// unread) is kept too, with none, so a record of it is named by nothing rather than by the thread's previous
// action.
type handed struct {
	tid         int
	at          uint64
	op          string
	name, name2 string
	named       bool
	naming      FSNaming
}

// handover is a ring of the most recent handed-over actions.
type handover struct {
	mu   sync.Mutex
	ring [handoverSize]handed
	next int
}

func (h *handover) put(e handed) {
	h.mu.Lock()
	h.ring[h.next] = e
	h.next = (h.next + 1) % len(h.ring)
	h.mu.Unlock()
}

// find is the action of tid a record stamped at is of — tid's last one handed over before at — when it is op on
// ends named name and name2 ("" matches any second end). A thread's entries leave the ring oldest first, so when
// that action has left it no older one of the thread is there to be taken for it.
func (h *handover) find(tid int, op, name, name2 string, at uint64) (FSNaming, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var last *handed
	for i := range h.ring {
		e := &h.ring[i]
		if e.tid == tid && e.at < at && (last == nil || e.at > last.at) {
			last = e
		}
	}
	if last == nil || !last.named || last.op != op || last.name != name || (name2 != "" && last.name2 != name2) {
		return FSNaming{}, false
	}
	return last.naming, true
}

// handOver keeps this loop's naming of a continued fs action whose line the kernel recorder writes, stamped
// before the answer lets the kernel run it. name and name2 are the line's names of end and end2 (lineName).
func (l *Loop) handOver(n *notif, r *reader, op string, end, end2 fsEnd, name, name2 string, d fsDecided) {
	p, p2 := end.p, end2.p
	e := handed{tid: n.pid, op: op, at: l.mono()}
	if !unnamedFS(r, op, p, p2) {
		at := l.landed(n, end)
		e.name, e.named = path.Base(at), true
		e.naming = FSNaming{Path: name, Path2: name2, Rule: d.rule, Verdict: d.verdict, Reason: d.reason, GateFields: gatePayload(d.gate, d.unsupported)}
		if op == record.FSRename || op == record.FSLink {
			e.name2 = path.Base(l.landed(n, end2))
		}
	}
	l.handed.put(e)
}

// ContinuedFS names a filesystem action this loop continued and left to the kernel recorder's line (R7a), for
// a record the recorder cannot name by its own index: the thread that made it, the operation (a record.FS*
// constant; an O_CREAT create is an open), the final component of each end, name2 "" for a one-ended
// operation, and the record's own stamp (bpf_ktime_get_ns, CLOCK_MONOTONIC). ok is false when this loop handed
// no such action over as that thread's last before the stamp. It is the lookup the recorder asks
// (observe.Options.ContinuedFS), as ContinuedNet is for a continued connect.
func (l *Loop) ContinuedFS(tid int, op, name, name2 string, at uint64) (FSNaming, bool) {
	return l.handed.find(tid, op, name, name2, at)
}

// monotonicNS is CLOCK_MONOTONIC in nanoseconds, the clock bpf_ktime_get_ns reads.
func monotonicNS() uint64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
