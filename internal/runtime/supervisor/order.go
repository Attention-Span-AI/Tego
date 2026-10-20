// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Per-thread record order (R23a). The pool answers a thread's notifications on whichever worker is free, and
// each worker emits after it answers (R23): the answer releases the thread, whose next syscall can be received,
// decided, answered and emitted by another worker before the first worker's emit has reached the sink. A PATH
// search (execvp trying /usr/local/sbin/bash, /usr/local/bin/bash, /usr/sbin/bash, /usr/bin/bash) was recorded
// with a later attempt before an earlier one, so the record's last attempt was not the program that ran, and
// mono_ns, which the pipeline stamped when the event reached it, was out of order with it.
//
// Two things restore the thread's order without touching the answer path:
//
//   - mono_ns is taken at receipt (stamp), under recvMu, where one thread's notifications arrive in the order it
//     made the syscalls: a thread is blocked in one notified syscall at a time.
//   - the emits of a notification wait for the previous notification of the same thread to finish (awaitPrev)
//     when that one was already answered at receipt, which is the race above. The wait happens after this
//     notification's own answer, so it never delays the agent, and only on the overlap: on an idle box the previous
//     notification has nearly always finished before this one was received and nothing is linked, while under load
//     a sequential thread overlaps regularly (about a third of a flood's notifications park, which is why a park
// allocates nothing in the steady state, orderWaiter). A linked wait yields a
//     few times (the previous emit is usually a few microseconds from done), then parks on a waiter the previous
//     notification's retire wakes, so it costs no CPU and ends when that one finishes; and it is that
//     notification's hold, not this one's, so finish leaves it out of R22's held time (a single-thread flood under
// load linked a few percent of its notifications, and a 20 µs sleep poll, which a loaded box stretches, counted in
// each one's hold doubled the flood's average).
//
// A previous notification that was not answered at receipt is never waited for: its thread can only have made
// another syscall because a signal withdrew the first (E35), and that one may be parked on a relay or a person's
// answer for minutes. The wait is bounded by orderWait all the same, so a handler that stalls after its answer
// costs order, never a worker.

// orderWait bounds how long an emit waits for the previous notification of its thread: above the sink lane's
// own bound (250 ms, R23) for each of the at most two lines one notification writes (exec and mcp).
const orderWait = time.Second

// orderBook is the last notification received for each thread that has one in flight.
type orderBook struct {
	mu   sync.Mutex
	last map[int]*notif
	// monoBase and wallBase anchor mono_ns to the monotonic reading time.Now carries: a receipt's mono_ns is
	// monoBase plus the time since wallBase, so stamp reads no clock of its own beyond the time.Now newNotif
	// already takes (CLOCK_MONOTONIC through the vDSO, which is what the Go runtime's monotonic reading is on
	// Linux). The anchor's error is half the interval it was taken in (anchorMono), far below one syscall.
	monoBase uint64
	wallBase time.Time
	// lost counts the emits that gave up waiting (orderWait): their line may precede the previous one's.
	lost atomic.Int64
	// idle holds the waiters no park is using, under mu. A park takes one and gives it back, so the book holds at
	// most as many as parks ever ran at once (about one per worker), and a park allocates only while that grows.
	idle []*orderWaiter
}

// orderWaiter is what a parked awaitPrev waits on: a one-slot channel the previous notification's retire sends on,
// and the timer that bounds the wait, both kept for the next park (orderBook.idle). Made fresh on every park, a
// channel and a timer cost four allocations each time a sequential thread's next syscall overlapped the previous
// emit past the yields, which under load is about a third of a flood's notifications.
type orderWaiter struct {
	wake chan struct{}
	t    *time.Timer
}

// takeWaiter is an idle waiter, or a new one with its timer stopped. Called with o.mu held.
func (o *orderBook) takeWaiter() *orderWaiter {
	if k := len(o.idle); k > 0 {
		w := o.idle[k-1]
		o.idle[k-1] = nil
		o.idle = o.idle[:k-1]
		return w
	}
	w := &orderWaiter{wake: make(chan struct{}, 1), t: time.NewTimer(orderWait)}
	w.t.Stop()
	return w
}

// anchorMono takes the CLOCK_MONOTONIC reading and the time.Time it corresponds to: the reading bracketed by two
// time.Now calls, its time the midpoint. The tightest of three brackets is kept.
func anchorMono(mono func() uint64) (uint64, time.Time) {
	var (
		bestM uint64
		bestT time.Time
		bestW = time.Duration(1<<63 - 1)
	)
	for range 3 {
		t0 := time.Now()
		m := mono()
		t1 := time.Now()
		if w := t1.Sub(t0); w < bestW {
			bestW, bestM, bestT = w, m, t0.Add(w/2)
		}
	}
	return bestM, bestT
}

// admit is receive's bookkeeping for one notification, under recvMu: its receipt mono_ns, and the link to the
// thread's previous notification when that one is answered and not yet finished.
func (l *Loop) admit(n *notif) {
	o := &l.order
	if !o.wallBase.IsZero() && !n.recvAt.Before(o.wallBase) {
		n.recvMono = o.monoBase + uint64(n.recvAt.Sub(o.wallBase))
	}
	o.mu.Lock()
	if prev := o.last[n.pid]; prev != nil && atomic.LoadUint32(&prev.sent) == 1 {
		n.prev = prev
	}
	if o.last == nil {
		o.last = make(map[int]*notif)
	}
	o.last[n.pid] = n
	o.mu.Unlock()
}

// retire marks n finished, every line it writes written, wakes a notification waiting on it, and forgets it as its
// thread's last notification. It runs once per notification (finish); a second call changes nothing.
func (l *Loop) retire(n *notif) {
	n.prev = nil
	o := &l.order
	o.mu.Lock()
	o.retireLocked(n)
	o.mu.Unlock()
}

// retireLocked is retire's body, called with o.mu held.
func (o *orderBook) retireLocked(n *notif) {
	if atomic.SwapUint32(&n.finished, 1) == 0 && n.waiter != nil {
		select {
		case n.waiter.wake <- struct{}{}:
		default: // never full: one waiter per notification, and one that timed out is emptied (awaitPrev)
		}
		n.waiter = nil
	}
	if o.last[n.pid] == n {
		delete(o.last, n.pid)
	}
}

// orderSpins is how many times awaitPrev yields before it parks: a previous notification already answered is
// usually writing its line, microseconds from done, and a wait that ends while yielding allocates nothing.
const orderSpins = 64

// awaitPrev waits, before n's first line, until the previous notification of n's thread has finished writing
// its own (R23a); a no-op for a notification nothing was linked to, which is nearly all of them. It yields
// orderSpins times, then parks on one of the book's waiters, set as prev.waiter under the lock retire takes to wake
// it, bounded by orderWait. A wait that times out takes its waiter back under that lock, so no later retire sends on
// it, and empties a wake sent before it did; either way the waiter goes back to the book with its channel empty and
// its timer stopped. Only n's thread links to prev, and only once (admit), so prev has at most one waiter. The time
// waited is n.waited, which finish leaves out of n's hold.
func (l *Loop) awaitPrev(n *notif) {
	prev := n.prev
	if prev == nil {
		return
	}
	n.prev = nil
	if atomic.LoadUint32(&prev.finished) == 1 {
		return
	}
	start := time.Now()
	defer func() { n.waited += time.Since(start) }()
	for range orderSpins {
		runtime.Gosched()
		if atomic.LoadUint32(&prev.finished) == 1 {
			return
		}
	}
	o := &l.order
	o.mu.Lock()
	if atomic.LoadUint32(&prev.finished) == 1 { // retired after the last yield (TestAnOrderWaitThatParksAfterThePreviousFinishedDoesNotWait)
		o.mu.Unlock()
		return
	}
	w := o.takeWaiter()
	prev.waiter = w
	o.mu.Unlock()
	w.t.Reset(orderWait)
	woke := false
	select {
	case <-w.wake:
		woke = true
	case <-w.t.C:
		o.mu.Lock()
		if prev.waiter == w {
			prev.waiter = nil
		}
		o.mu.Unlock()
		select {
		case <-w.wake: // retire woke it as the timer fired (TestAnOrderWaitWokenAsItsTimerFiresKeepsTheWake)
			woke = true
		default:
		}
	}
	w.t.Stop()
	o.mu.Lock()
	o.idle = append(o.idle, w)
	o.mu.Unlock()
	if !woke {
		// Counted into run_end.supervisor.order_lost (Metrics), and said once per run at Warn: a reader of the
		// record is told the order it relies on was not kept, not only a debug log.
		if l.order.lost.Add(1) == 1 {
			l.log.Warn("supervisor: a line of this thread's previous notification is still unwritten; order not kept (counted in run_end.supervisor.order_lost)",
				"tid", n.pid, "wait", orderWait)
		}
	}
}
