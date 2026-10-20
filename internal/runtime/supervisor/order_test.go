// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gateSink holds the first line it is given until release closes, the way a sink lane at its bound holds a
// worker (R23), and records the lines in the order they reach it.
type gateSink struct {
	entered, release chan struct{}
	once             sync.Once
	mu               sync.Mutex
	events           []*record.Event
}

func (s *gateSink) Emit(ev *record.Event) {
	first := false
	s.once.Do(func() { first = true })
	if first {
		close(s.entered)
		<-s.release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *gateSink) all() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

// TestOneThreadsLinesKeepTheOrderOfItsSyscalls is R23a, the custom-agent POC's finding: a thread's second exec,
// received on another worker while the first one's line was still on its way to the sink, was recorded before the
// first, with a mono_ns after the line it preceded. The second notification's line now waits for the first's, and
// both carry the mono_ns of their receipt.
func TestOneThreadsLinesKeepTheOrderOfItsSyscalls(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	f.put(0x10000, cstr("/usr/sbin/bash"))
	execFixture(f, 0x20000, []string{"bash", "-c", "first"})
	f.put(0x90000, cstr("/usr/bin/bash"))
	execFixture(f, 0xA0000, []string{"bash", "-c", "second"})
	f.stats[4242] = procStat{ppid: 1, start: 10}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{
		{Path: "/usr/sbin/bash", Source: agent.ExecSourceAllow},
		{Path: "/usr/bin/bash", Source: agent.ExecSourceAllow},
	}
	sink := &gateSink{entered: make(chan struct{}), release: make(chan struct{})}
	l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}

	first := notifFor(nr, 4242, 0x10000, 0x20000, 0)
	l.admit(first)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); l.handle(first) }()
	<-sink.entered // answered, and its line is held at the sink

	second := notifFor(nr, 4242, 0x90000, 0xA0000, 0)
	second.id = 8
	l.admit(second)
	if second.prev != first {
		t.Fatal("the second notification of the thread is not linked to the first, which was answered and still writing")
	}
	var secondDone atomic.Bool
	go func() { defer wg.Done(); l.handle(second); secondDone.Store(true) }()
	time.Sleep(100 * time.Millisecond)
	if n := len(sink.all()); n != 0 || secondDone.Load() {
		t.Fatalf("the second exec's line reached the sink (%d lines, done=%v) while the first's was still held", n, secondDone.Load())
	}
	close(sink.release)
	wg.Wait()

	evs := sink.all()
	if len(evs) != 2 {
		t.Fatalf("want 2 lines, got %d", len(evs))
	}
	var paths []string
	for _, ev := range evs {
		var p execPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p.Path)
	}
	if !slices.Equal(paths, []string{"/usr/sbin/bash", "/usr/bin/bash"}) {
		t.Errorf("lines in the order %v, want the thread's syscall order [/usr/sbin/bash /usr/bin/bash]", paths)
	}
	if evs[0].MonoNS == 0 || evs[1].MonoNS <= evs[0].MonoNS {
		t.Errorf("mono_ns %d then %d: want the receipts' readings, increasing", evs[0].MonoNS, evs[1].MonoNS)
	}
	if got := l.order.lost.Load(); got != 0 {
		t.Errorf("order.lost = %d, want 0", got)
	}
	if len(l.order.last) != 0 {
		t.Errorf("the order book still holds %d threads after both notifications finished", len(l.order.last))
	}
}

// TestAdmitStampsTheReceipt is R23a's clock: mono_ns is the CLOCK_MONOTONIC reading of the receipt, on the same
// clock the pipeline and the kernel recorder use, not of the moment the line reached the pipeline.
func TestAdmitStampsTheReceipt(t *testing.T) {
	f := newFake()
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	before := monotonicNS()
	n := notifFor(nrFor(t, "mkdirat"), 42, argCWD, 0x1000, 0o755)
	l.admit(n)
	after := monotonicNS()
	// The anchor's error is half the interval it was taken in; a microsecond either way is far more than that.
	if n.recvMono+1000 < before || n.recvMono > after+1000 {
		t.Fatalf("recvMono = %d, want within [%d, %d]", n.recvMono, before, after)
	}
	f.put(0x1000, cstr("/work/d"))
	time.Sleep(2 * time.Millisecond)
	l.handle(n)
	if evs := sink.all(); len(evs) != 1 || evs[0].MonoNS != n.recvMono {
		t.Fatalf("lines %+v: want one, with mono_ns %d (the receipt)", evs, n.recvMono)
	}
}

// TestAnUnansweredPreviousNotificationIsNotWaitedFor: a thread with a notification still unanswered made another
// syscall only because a signal withdrew the first (E35), which may be parked on a relay or a person's answer, so
// nothing is linked to it.
func TestAnUnansweredPreviousNotificationIsNotWaitedFor(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	nr := nrFor(t, "mkdirat")
	first := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	l.admit(first)
	second := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	l.admit(second)
	if second.prev != nil {
		t.Fatal("linked to a notification that was never answered")
	}
}

// TestTheOrderWaitIsBounded: a previous notification that never finishes costs order, never the worker.
func TestTheOrderWaitIsBounded(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	prev := &notif{pid: 42, sent: 1}
	n := &notif{pid: 42, prev: prev}
	start := time.Now()
	l.awaitPrev(n)
	if took := time.Since(start); took < orderWait || took > orderWait+2*time.Second {
		t.Fatalf("awaitPrev took %v, want about %v", took, orderWait)
	}
	if l.order.lost.Load() != 1 {
		t.Fatalf("order.lost = %d, want 1", l.order.lost.Load())
	}
	// The count reaches run_end.supervisor.order_lost through Metrics: it was read by nothing.
	if got := l.Metrics().OrderLost; got != 1 {
		t.Fatalf("Metrics().OrderLost = %d, want 1", got)
	}
}

// TestAnOpenAnsweredByADDFDOrdersTheNextNotification is R23a for the answers that are not respond's Send: an
// approved held open completed by ADDFD+SEND, and an alternate delivered by it, release the thread in that ioctl,
// so its next syscall can be received while the open's line is still to be written. That notification must be
// linked to the open, as one after a Send is; the open set no sent flag, and the next line could precede its own.
func TestAnOpenAnsweredByADDFDOrdersTheNextNotification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(x *askReadFixture) ask.Decision
	}{
		{"approved", func(*askReadFixture) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} }},
		{"alternate", func(x *askReadFixture) ask.Decision { return alternateDecision(t, x.standIn) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newAskReadFixture(t)
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return tc.answer(x) })
			x.f.put(0x10000, cstr(x.secret))
			n := notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000, uint64(unix.O_RDONLY|unix.O_CLOEXEC))
			next := notifFor(nrFor(t, "mkdirat"), 42, argCWD, 0x1000, 0o755)
			next.id = n.id + 1
			sends := 0
			x.k.onSend = func() {
				// The kernel has released the thread: its next syscall is received now, before the open's line.
				sends++
				l.admit(next)
			}
			l.admit(n)
			l.handle(n)
			if sends != 1 || !n.answered || len(sink.all()) != 1 {
				t.Fatalf("sends=%d answered=%v lines=%d: want one ADDFD+SEND answer and its line", sends, n.answered, len(sink.all()))
			}
			if next.prev != n {
				t.Fatal("the thread's next notification, received after the ADDFD+SEND, is not ordered after the open")
			}
		})
	}
}

// TestAHeldOpenDeliveredByADDFDOrdersTheNextNotification is R23a for the open deputy's delivery (ADR 0041 Stage B,
// gate.completion: held), which reached the integration branch beside R23a: a held open is answered by ADDFD+SEND
// (DeliverHeld), not by respond's Send, so the thread's next syscall can be received while the open's line is still
// to be written. That notification must be linked to the open, as one after a Send or an ask's ADDFD+SEND is; the
// held delivery set no sent flag, and the next line could precede the open's (found when WA-L6b was merged).
func TestAHeldOpenDeliveredByADDFDOrdersTheNextNotification(t *testing.T) {
	for _, tc := range []struct {
		name string
		// pattern and score are the read gate's: the target matches "token" and is asked (answered approved), and
		// "*.env", which it does not match, leaves it allowed, a held open still (the gate may escalate).
		pattern string
		score   int
		asked   bool
	}{
		{"approved ask", "token", 60, true},
		{"gate allow", "*.env", 90, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.pol.Rules.Gate = testGate(t, gate.ReadMatches, tc.pattern, tc.score).WithHeldCompletion()
			l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
			x.addr += 0x2000
			x.f.put(0x10000+x.addr, cstr(x.target))
			n := notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000+x.addr, uint64(unix.O_RDONLY|unix.O_CLOEXEC))
			next := notifFor(nrFor(t, "mkdirat"), 42, argCWD, 0x1000, 0o755)
			next.id = n.id + 1
			sends := 0
			x.k.onSend = func() {
				// The kernel has released the thread: its next syscall is received now, before the open's line.
				sends++
				l.admit(next)
			}
			l.admit(n)
			l.handle(n)
			if (len(*asked) == 1) != tc.asked || len(x.k.heldDelivered) != 1 || sends != 1 || !n.answered || len(sink.all()) != 1 {
				t.Fatalf("asked %d, delivered %q, sends=%d answered=%v lines=%d: want one held delivery by ADDFD+SEND and its line",
					len(*asked), x.k.heldDelivered, sends, n.answered, len(sink.all()))
			}
			if next.prev != n {
				t.Fatal("the thread's next notification, received after the held open's ADDFD+SEND, is not ordered after the open")
			}
		})
	}
}

// TestASlowNotificationIsActivityAtItsFinish: every line carries its notification's receipt as
// mono_ns (R23a), so a syscall the loop relayed for long wrote a line stamped at its start, and the budget watcher's
// stall check, which counts mono_ns, saw no activity at its completion. A notification finished past the soft ceiling
// calls Options.Late with the monotonic reading of its finish; its line keeps the receipt, and a fast one calls nothing.
func TestASlowNotificationIsActivityAtItsFinish(t *testing.T) {
	nr := nrFor(t, "mkdirat")
	f := newFake()
	f.put(0x1000, cstr("/work/proj/d"))
	var late []uint64
	sink := &testSink{}
	l, err := New(testListener(), testPolicy(nil, []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite}}, nil), sink,
		Options{kernel: f, Workers: 1, Budget: time.Second, Late: func(mono uint64) { late = append(late, mono) }})
	if err != nil {
		t.Fatal(err)
	}
	fast := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	l.admit(fast)
	l.handle(fast)
	if len(late) != 0 {
		t.Fatalf("a fast notification called Late: %v", late)
	}
	slow := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	slow.id = 8
	l.admit(slow)
	// Received three seconds ago, as a relay that blocked that long was: recvMono keeps the admitted receipt.
	const blocked = 3 * time.Second
	slow.recvAt = slow.recvAt.Add(-blocked)
	l.handle(slow)
	if len(late) != 1 || late[0] < slow.recvMono+uint64(blocked.Nanoseconds()) {
		t.Fatalf("Late = %v, want one call at or after the receipt %d plus %v", late, slow.recvMono, blocked)
	}
	evs := sink.all()
	if len(evs) != 2 || evs[1].MonoNS != slow.recvMono {
		t.Fatalf("lines %d, the slow one's mono_ns %d: want its receipt %d", len(evs), evs[len(evs)-1].MonoNS, slow.recvMono)
	}
}

// TestTheOrderWaitIsNotTheNotificationsHold: a notification whose lines waited for the previous
// one of its thread (R23a) counted that wait in its own hold, the previous notification's emit counted twice, so a
// single-thread flood under load (TestIntegrationUDPFlood) reported R22's soft budget missed for order keeping, not
// for any decision. The wait is the previous notification's hold, not this one's: it is left out of heldUS and of
// the slow-notification count.
func TestTheOrderWaitIsNotTheNotificationsHold(t *testing.T) {
	nr := nrFor(t, "mkdirat")
	l, err := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: newFake(), Workers: 1, Budget: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	prev := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	l.admit(prev)
	atomic.StoreUint32(&prev.sent, 1) // answered, its line still on its way to the sink
	n := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	n.id = prev.id + 1
	l.admit(n)
	if n.prev != prev {
		t.Fatal("the thread's next notification is not linked to the answered one")
	}
	const wait = 60 * time.Millisecond
	go func() {
		time.Sleep(wait)
		l.retire(prev)
	}()
	l.awaitPrev(n)
	n.answered = true
	l.finish(n)
	if held := time.Duration(l.metrics.heldUS.Load()) * time.Microsecond; held >= wait {
		t.Errorf("held %v: the %v spent waiting for the previous notification is counted as this one's hold", held, wait)
	}
	if a := l.metrics.anomalies.Load(); a != 0 {
		t.Errorf("anomalies = %d: the order wait made the notification slow by R22's soft budget", a)
	}
	if l.order.lost.Load() != 0 {
		t.Errorf("order.lost = %d, want 0", l.order.lost.Load())
	}
}

// TestTheOrderWaitEndsWhenThePreviousFinishes: past a few yields the wait parks until the previous notification's
// retire wakes it, not found by a poll, so a worker spends no CPU in it and leaves it as soon as the line it waits
// for is written.
func TestTheOrderWaitEndsWhenThePreviousFinishes(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	nr := nrFor(t, "mkdirat")
	prev := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	l.admit(prev)
	atomic.StoreUint32(&prev.sent, 1)
	n := notifFor(nr, 42, argCWD, 0x1000, 0o755)
	n.id = prev.id + 1
	l.admit(n)
	if n.prev != prev {
		t.Fatal("the thread's next notification is not linked to the answered one")
	}
	done := make(chan struct{})
	go func() {
		l.awaitPrev(n)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("awaitPrev returned before the previous notification finished")
	case <-time.After(20 * time.Millisecond):
	}
	l.retire(prev)
	select {
	case <-done:
	case <-time.After(orderWait / 2):
		t.Fatal("awaitPrev did not return after the previous notification finished")
	}
	if l.order.lost.Load() != 0 {
		t.Errorf("order.lost = %d, want 0", l.order.lost.Load())
	}
}

// parkedOn reports whether a notification's order wait is parked on prev: awaitPrev has yielded orderSpins times and
// registered itself for prev's retire.
func parkedOn(l *Loop, prev *notif) bool {
	l.order.mu.Lock()
	defer l.order.mu.Unlock()
	return prev.waiter != nil
}

// TestAParkedOrderWaitAllocatesNothing: a wait that outlasted the yields made the previous
// notification's channel and a timer on every park. Under load a sequential thread's next syscall regularly overlaps
// the previous emit, and BenchmarkSeccompNotifyRoundTrip went from 14 to 15 allocs/op and 6% more B/op. A park
// reuses the loop's own waiters, so in the steady state it costs no allocation.
func TestAParkedOrderWaitAllocatesNothing(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	prev := &notif{pid: 42}
	n := &notif{pid: 42}
	start, stop := make(chan struct{}), make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-start:
			}
			for !parkedOn(l, prev) {
				runtime.Gosched()
			}
			l.retire(prev)
		}
	}()
	defer close(stop)
	allocs := testing.AllocsPerRun(200, func() {
		atomic.StoreUint32(&prev.finished, 0)
		atomic.StoreUint32(&prev.sent, 1)
		n.prev, n.waited = prev, 0
		start <- struct{}{}
		l.awaitPrev(n)
	})
	if allocs != 0 {
		t.Errorf("a parked order wait allocates %v times, want none", allocs)
	}
	if l.order.lost.Load() != 0 {
		t.Errorf("order.lost = %d, want 0: every wait ended on the previous notification's retire", l.order.lost.Load())
	}
}

// TestATimedOutOrderWaitLeavesItsWaiterClean: a wait that gave up (orderWait) puts its waiter back for the next park,
// and the previous notification it gave up on may still retire later. That retire must not wake the waiter's next
// user, whose own previous notification has not finished: the waiter is taken off the notification it timed out on
// under the book's lock, so the late retire sends nothing, and the next park ends on its own previous one's retire.
func TestATimedOutOrderWaitLeavesItsWaiterClean(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	stalled := &notif{pid: 42, sent: 1}
	l.awaitPrev(&notif{pid: 42, prev: stalled})
	if l.order.lost.Load() != 1 {
		t.Fatalf("order.lost = %d, want 1 for the wait that gave up", l.order.lost.Load())
	}
	l.retire(stalled) // finishes after the wait gave up on it
	if len(l.order.idle) != 1 || len(l.order.idle[0].wake) != 0 {
		t.Fatalf("idle waiters %d, the first holding %d wakes: want one, empty", len(l.order.idle), len(l.order.idle[0].wake))
	}
	prev := &notif{pid: 43, sent: 1}
	n := &notif{pid: 43, prev: prev}
	done := make(chan struct{})
	go func() {
		l.awaitPrev(n)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("the next park returned before its previous notification finished: a stale wake reached it")
	case <-time.After(50 * time.Millisecond):
	}
	l.retire(prev)
	select {
	case <-done:
	case <-time.After(orderWait / 2):
		t.Fatal("awaitPrev did not return after the previous notification finished")
	}
	if l.order.lost.Load() != 1 {
		t.Errorf("order.lost = %d, want still 1", l.order.lost.Load())
	}
}

// TestAnOrderWaitThatParksAfterThePreviousFinishedDoesNotWait at the park's other
// edge: the previous notification retires after the wait's last yield and before the wait takes the book's lock to
// park. That retire found no waiter to wake, so a park registered then would wait out orderWait for a wake that never
// comes and count an order lost that was kept; the wait reads finished again under the lock and returns.
func TestAnOrderWaitThatParksAfterThePreviousFinishedDoesNotWait(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	prev := &notif{pid: 46, sent: 1}
	done := make(chan struct{})
	l.order.mu.Lock()
	go func() {
		l.awaitPrev(&notif{pid: 46, prev: prev})
		close(done)
	}()
	time.Sleep(50 * time.Millisecond) // the wait's yields end, and it blocks on the lock to park
	l.order.retireLocked(prev)
	l.order.mu.Unlock()
	select {
	case <-done:
	case <-time.After(orderWait / 2):
		t.Fatal("awaitPrev parked on a previous notification that had already finished")
	}
	if got := l.order.lost.Load(); got != 0 {
		t.Errorf("order.lost = %d, want 0", got)
	}
}

// TestAnOrderWaitWokenAsItsTimerFiresKeepsTheWake: a retire that runs between the order
// wait's timer firing and the wait taking the book's lock wakes the waiter all the same, and the wait must take that
// wake. Left in the channel, the waiter went back to the book holding it, and the next park that took the waiter
// returned at once, before its own previous notification finished: its lines could precede that one's, and the wait
// counted as woken, so nothing reached run_end.supervisor.order_lost. The previous notification did finish, so this
// wait kept its order and counts no loss.
func TestAnOrderWaitWokenAsItsTimerFiresKeepsTheWake(t *testing.T) {
	l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	late := &notif{pid: 44, sent: 1}
	done := make(chan struct{})
	go func() {
		l.awaitPrev(&notif{pid: 44, prev: late})
		close(done)
	}()
	for !parkedOn(l, late) {
		runtime.Gosched()
	}
	// Held past orderWait, the lock keeps the timed-out wait from taking its waiter back, and the retire it waits for
	// runs under the same hold: the wake lands after the timer has fired.
	l.order.mu.Lock()
	w := late.waiter
	time.Sleep(orderWait + 300*time.Millisecond)
	l.order.retireLocked(late)
	l.order.mu.Unlock()
	select {
	case <-done:
	case <-time.After(orderWait):
		t.Fatal("awaitPrev did not return after its timer fired and the previous notification finished")
	}
	if got := l.order.lost.Load(); got != 0 {
		t.Errorf("order.lost = %d, want 0: the previous notification finished, and its retire woke the wait", got)
	}
	if len(l.order.idle) != 1 || l.order.idle[0] != w || len(w.wake) != 0 {
		t.Fatalf("idle waiters %d, the wait's own holding %d wakes: want it back alone, empty", len(l.order.idle), len(w.wake))
	}
	prev := &notif{pid: 45, sent: 1}
	next := make(chan struct{})
	go func() {
		l.awaitPrev(&notif{pid: 45, prev: prev})
		close(next)
	}()
	select {
	case <-next:
		t.Fatal("the next park returned before its previous notification finished: a stale wake reached it")
	case <-time.After(50 * time.Millisecond):
	}
	l.retire(prev)
	select {
	case <-next:
	case <-time.After(orderWait / 2):
		t.Fatal("awaitPrev did not return after the previous notification finished")
	}
}
