// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"runtime/debug"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sysNotif and sysResp are the kernel's notification structs; the layout check lives in platform/sys.
type (
	sysNotif = sys.SeccompNotif
	sysResp  = sys.SeccompNotifResp
)

// notif is one notification's working state: allocated per notification, owned by one worker, never
// shared. pid is the notifying task's id, advisory until an ID_VALID bracket confirms the notification is
// still live (E3).
type notif struct {
	id     uint64
	pid    int
	arch   uint32
	nr     int32
	args   [6]uint64
	recvAt time.Time
	// recvMono is recvAt as a CLOCK_MONOTONIC reading, the mono_ns of every line this notification writes (R23a);
	// 0 for a notification receive did not admit (a test driving a handler directly), whose lines the pipeline
	// stamps.
	recvMono        uint64
	bindAttemptNS   uint64
	listenAttemptNS uint64

	// answered is set once a response has been attempted: exactly one is ever sent (I11), and an event is
	// only recorded for a notification that got as far as an answer.
	answered bool
	// gone is set when the kernel reported the id stale: the target died, so there is nothing to answer
	// and nothing more to read (R19).
	gone bool
	// detached is set when the run was cancelled while an allowed connect or Fast-Open send was still in
	// flight on the duplicate (R9, R12). Its real result will never be known, and I3 forbids answering
	// with an invented one, so the notification is left for the listener close to fail closed.
	detached bool
	// replaced is set when a standby worker took this notification's worker's place in the pool while it
	// waited on a relayed syscall (R21, backfill). The worker that carried it retires when the handler
	// returns, so receive capacity stays at Workers rather than growing for the rest of the run.
	replaced bool
	// starved is set once backfill found maxStandby standbys already running for this notification, so the
	// relay is counted in metrics.starved once however many poll ticks retry it.
	starved bool
	// done is the run's cancellation channel, carried per notification because a relayed syscall is the
	// one thing a handler does that the wake fd cannot reach. Nil outside Run: a nil channel is never
	// ready, so a handler driven directly by a test waits for the relay exactly as it did before.
	done <-chan struct{}
	// entry is the dispatch entry handling it; empty for an unknown (arch, nr).
	entry entry
	// r is the read session this notification opened, returned to the pool by finish.
	r *reader
	// unixPass is what this notification's R11a questions have learnt from sock_diag and stat (boundByRun), made
	// on the first one: a sendmmsg batch asks one per addressed message, and the pass bounds their work together.
	unixPass *unixPass
	// tgid is pid's thread group once tgidOfNotif has asked (0 until then): one lookup per notification, which its
	// line and a held open's pin both need.
	tgid int
	// execRoot is the task's root an exec's decision holds in a run with command rules (taskRoot), closed by
	// recordExec before it returns.
	execRoot taskRoot

	// prev is the previous notification of the same thread, set by admit when it was answered and still writing
	// its lines at receipt; awaitPrev waits for it before this one's first line (R23a). sent is answered as other
	// workers read it, set before NOTIF_SEND releases the thread; finished is set once every line of this
	// notification is written. Both are read with sync/atomic: notif is copied by value in the benchmarks, so it
	// holds no atomic type.
	prev     *notif
	sent     uint32
	finished uint32
	// waiter is the parked wait of the thread's next notification on this one, woken by retire once finished is set
	// (awaitPrev sets it, under the order book's lock, which retire takes to wake it). waited is how long awaitPrev
	// waited: the previous notification's hold rather than this one's, which finish leaves out of R22's held time
	// and slow count.
	waiter *orderWaiter
	waited time.Duration
}

// pass is n's unixPass, made the first time one of its R11 or R11a questions needs it.
func (n *notif) pass() *unixPass {
	if n.unixPass == nil {
		n.unixPass = newUnixPass()
	}
	return n.unixPass
}

// newNotif copies one received notification into worker-owned state and stamps the monotonic receive time
// held_ms is derived from (E14).
func newNotif(raw *sysNotif) *notif {
	return &notif{
		id: raw.ID, pid: int(raw.Pid), arch: raw.Data.Arch, nr: raw.Data.Nr,
		args: raw.Data.Args, recvAt: time.Now(),
	}
}

// resp is the three response shapes NOTIF_SEND can take (R18): CONTINUE, an errno, or a relayed result.
type resp struct {
	cont  bool
	errno int32
	val   int64
	// refusal marks an errno this loop chose, as opposed to one a relayed syscall returned. Only a refusal
	// is a decision, so it is the one answer an observe run turns into CONTINUE (R30); a relayed errno is a
	// real result the syscall already produced, and I3 forbids answering anything else for it.
	refusal bool
}

// respContinue lets the syscall run unchanged: the answer for every record-only kind and for a datagram
// send (R13b). It is never a grant — Landlock decides the continued syscall on its own (R15).
func respContinue() resp { return resp{cont: true} }

// respErrno refuses the syscall with a negative errno and val -1 (R18b).
func respErrno(e unix.Errno) resp { return resp{errno: -int32(e), val: -1, refusal: true} }

// respMiss answers an exec whose pathname names nothing with the errno the task's own lookup meets (R16b (0)). It is
// no refusal: the kernel would answer the same errno, so the loop decides nothing by it, and an observe run answers it
// as an enforcing run does rather than continuing it (R30): a continued miss is a second lookup, which a file renamed
// into place after the walk wins, an exec that would then run with no line at all.
func respMiss(e unix.Errno) resp { return resp{errno: -int32(e), val: -1} }

// respResult relays the real result of a syscall this loop performed on a duplicate: a value on success,
// the real negative errno otherwise (R9, R12, I3).
func respResult(n int, err error) resp {
	if err != nil {
		e, ok := err.(unix.Errno) //nolint:errorlint // a raw syscall errno, never wrapped here
		if !ok {
			e = unix.EACCES
		}
		return resp{errno: -int32(e), val: -1}
	}
	return resp{val: int64(n)}
}

// handle dispatches one notification under the per-notification recover() the whole package relies on
// (R25): a handler bug refuses or continues one syscall and never takes down a worker, a sibling
// notification, or the run (I12, E34).
func (l *Loop) handle(n *notif) {
	e, ok := l.dispatch[dispatchKey{arch: n.arch, nr: n.nr}]
	n.entry = e
	defer l.finish(n)
	if !ok {
		// Unreachable through this tier's filter, whose every notify arm has an entry here (the
		// completeness test in enforce/landlock walks them, R1, E21). Should one ever be missing, the
		// syscall is refused as the kernel refuses it once the listener is gone: ENOSYS. CONTINUE handed a
		// syscall the filter chose to ask about to the kernel unexamined, so a refusal by notification alone
		// failed open on a missing or misnumbered entry (ADR 0018).
		l.log.Warn("supervisor: notification for an undispatched syscall, refused", "arch", n.arch, "nr", n.nr)
		l.respond(n, respErrno(unix.ENOSYS))
		return
	}
	defer func() {
		if r := recover(); r != nil {
			l.recovered(n, r)
		}
	}()
	// Before the handler answers: a mutation invalidates the walk cache before the kernel runs it, and this
	// thread's previous one has run by now (walkcache.go).
	l.walks.saw(n.pid, n.nr, mutating(e.name))
	e.fn(l, n)
}

// finish accounts one notification and guarantees it was answered: a handler that returned without
// responding (a bug, not a spec path) still leaves the target unblocked, refused (failClosed, I11). It runs
// after handle's recover has returned, so its answer runs
// under a recover of its own (R25 e): after a panicking handler whose fail-closed answer panicked too, this is
// the same answer path again, and a second panic here escaped handle and the worker and ended the process.
func (l *Loop) finish(n *notif) {
	l.contained(n, "finish answer", func() {
		if !n.answered && !n.gone && !n.detached {
			l.log.Warn("supervisor: handler returned without answering", "nr", n.nr, "id", n.id)
			l.respond(n, failClosed())
		}
	})
	if n.r != nil {
		l.release(n.r)
		n.r = nil
	}
	// The time spent waiting for the thread's previous notification to write its lines (awaitPrev) is that one's
	// hold, already in its own heldUS: counted here too, order keeping looked like a slow decision (R22, R23a).
	total := time.Since(n.recvAt)
	held := total - n.waited
	l.metrics.heldUS.Add(held.Microseconds())
	if held > l.budget {
		l.metrics.anomalies.Add(1)
		l.log.Debug("supervisor: slow notification", "nr", n.nr, "held_us", held.Microseconds(),
			"budget_us", l.budget.Microseconds())
		// Its lines carry its receipt (R23a); its completion, which a long relay ends, is activity too (Options.Late).
		if l.late != nil && n.recvMono != 0 {
			l.late(n.recvMono + uint64(total.Nanoseconds()))
		}
	}
	l.retire(n)
}

// failClosed is the answer to a notification this loop cannot finish: a handler that panicked or returned without
// answering, or an ID_VALID that failed (R5, R25, I11). Every kind refuses, whatever it would have answered, because
// the handler that failed is the only thing that knew: a read-open it continued was a read the deputy would have held
// (ADR 0069 D6), a write or a mode change one a live block names, and each rule added here had to be taught to a list
// of what failed closed. An observe run continues it, as every refusal (respond, R30).
func failClosed() resp { return respErrno(refusalErrno) }

// recovered handles a panicking handler (R25): the stack goes to the own log and never to the ledger, the
// notification is answered fail-closed if its id is still valid, and a gap event records that a record was
// lost. The worker loops on.
//
// The answer and the gap line each run under a recover of their own (R25 e): the gap re-runs the emit path
// (event, tgidOf, Sink.Emit) every handler shares, so a panic whose cause is on it panics again here, inside
// handle's deferred recover, where nothing else would catch it and the process would die. The answer comes
// first so the task is released even when the line cannot be written; finish answers fail-closed should the
// answer panic before it was marked sent, under its own recover, since that retry is the same code path.
func (l *Loop) recovered(n *notif, r any) {
	stack := debug.Stack()
	if rp, ok := r.(relayPanic); ok {
		r, stack = rp.value, rp.stack // the relay goroutine's frames, not the worker's that re-raised it
	}
	l.log.Error("supervisor: handler panic", "nr", n.nr, "id", n.id, "panic", r, "stack", string(stack))
	l.contained(n, "answer", func() {
		if !n.answered && !n.gone && !n.detached {
			if ok, err := l.idValid(n); err == nil && !ok {
				n.gone = true // R19: nothing to answer
			} else {
				// Live, or unknown: an answer to a notification already gone fails ENOENT harmlessly, while
				// none to one still pending leaves its task trapped.
				l.respond(n, failClosed())
			}
		}
	})
	l.contained(n, "gap line", func() { l.emitGap(n, record.GapRecord, "handler-panic") })
}

// contained runs one step of the recovery path, logging and swallowing a panic in it (R25 e).
func (l *Loop) contained(n *notif, step string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			l.log.Error("supervisor: panic while recovering from a handler panic", "step", step, "nr", n.nr,
				"id", n.id, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn()
}

// respond answers the notification exactly once and accounts the hold. A stale id (the target died
// between the decision and the response) is not an error: the notification is abandoned (R19, E2).
//
// It is also the one place an observe run's refusals become CONTINUE (R30). Every refusal of this package,
// decided or fail-closed, reaches the kernel through here, so no handler needs to know the run is
// record-only, and none can refuse by forgetting to.
func (l *Loop) respond(n *notif, r resp) {
	if n.answered || n.gone {
		return
	}
	if r.refusal && l.observing() {
		r = respContinue()
	}
	n.answered = true
	atomic.StoreUint32(&n.sent, 1)
	if l.activity != nil {
		l.activity()
	}
	out := sysResp{ID: n.id}
	if r.cont {
		out.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	} else {
		out.Error = r.errno
		out.Val = r.val
	}
	err := l.k.Send(&out)
	if err != nil && !isGone(err) {
		// Not the target's death: the kernel did not take the answer (sys retries EINTR already), and an
		// answer never taken leaves the task trapped until the listener closes. One more attempt.
		l.log.Error("supervisor: NOTIF_SEND failed, retrying once", "nr", n.nr, "id", n.id, "err", err)
		err = l.k.Send(&out)
	}
	if err != nil {
		// The target died between the decision and the response (R19, E2). The decision still stands and
		// what was read before the death may still back an event; there is simply no one to answer.
		n.gone = true
		if !isGone(err) {
			l.log.Error("supervisor: NOTIF_SEND failed", "nr", n.nr, "id", n.id, "err", err)
		}
	}
}

// valid brackets a read of the target: it reports whether the notification is still live. A false answer
// from the kernel marks the notif gone, so no later read is trusted and no response is attempted (R2, R19).
// An ID_VALID that fails (sys retries EINTR already; idValid retries anything else once) proves nothing
// about the target, whose notification may still be pending: valid answers it fail-closed (failClosed, R5)
// before marking it gone, so no read is trusted and nothing else is answered. Marked gone unanswered, its
// task stayed trapped until the listener closed.
func (l *Loop) valid(n *notif) bool {
	if n.gone {
		return false
	}
	ok, err := l.idValid(n)
	if err != nil {
		l.respond(n, failClosed())
		n.gone = true
		return false
	}
	if !ok {
		n.gone = true
	}
	return ok
}

// idValid is ID_VALID with a failure retried once. A dead target is (false, nil); an error says nothing
// about the target, and the caller decides what an unknown answer means.
func (l *Loop) idValid(n *notif) (bool, error) {
	ok, err := l.k.IDValid(n.id)
	if err != nil {
		l.log.Error("supervisor: ID_VALID failed, retrying once", "nr", n.nr, "id", n.id, "err", err)
		if ok, err = l.k.IDValid(n.id); err != nil {
			l.log.Error("supervisor: ID_VALID failed", "nr", n.nr, "id", n.id, "err", err)
		}
	}
	return ok, err
}

// isGone reports whether err says the notification id no longer exists: the target died between the
// decision and the response (R19, E2).
func isGone(err error) bool { return errors.Is(err, unix.ENOENT) }
