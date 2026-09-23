// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type fakeSignaler struct {
	mu   sync.Mutex
	got  []syscall.Signal
	fail error
}

func (f *fakeSignaler) Signal(sig syscall.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, sig)
	return f.fail
}

func (f *fakeSignaler) received() []syscall.Signal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]syscall.Signal(nil), f.got...)
}

type fakeKiller struct {
	mu    sync.Mutex
	calls int
	done  chan struct{}
	once  sync.Once
}

func newFakeKiller() *fakeKiller { return &fakeKiller{done: make(chan struct{})} }

func (k *fakeKiller) Kill() error {
	k.mu.Lock()
	k.calls++
	k.mu.Unlock()
	k.once.Do(func() { close(k.done) })
	return nil
}

func (k *fakeKiller) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.calls
}

func newHandler(t *testing.T, tty bool, grace time.Duration, stop func() bool) (*SignalHandler, *fakeSignaler, *fakeKiller) {
	t.Helper()
	s, k := &fakeSignaler{}, newFakeKiller()
	h, err := NewSignalHandler(s, k, SignalPolicy{StopGrace: grace, StdinIsTTY: tty, StopRequested: stop})
	if err != nil {
		t.Fatal(err)
	}
	return h, s, k
}

func TestNewSignalHandlerRejects(t *testing.T) {
	if _, err := NewSignalHandler(&fakeSignaler{}, newFakeKiller(), SignalPolicy{}); err == nil {
		t.Fatal("zero StopGrace accepted")
	}
	if _, err := NewSignalHandler(nil, newFakeKiller(), SignalPolicy{StopGrace: time.Second}); err == nil {
		t.Fatal("nil Signaler accepted")
	}
}

func TestSignalForwardingRules(t *testing.T) {
	tests := []struct {
		name      string
		tty       bool
		sig       syscall.Signal
		forwarded bool
		grace     bool
	}{
		{"SIGTERM tty", true, syscall.SIGTERM, true, true},
		{"SIGTERM no tty", false, syscall.SIGTERM, true, true},
		{"SIGHUP tty", true, syscall.SIGHUP, true, true},
		{"SIGUSR1 tty", true, syscall.SIGUSR1, true, false},
		{"SIGUSR2 no tty", false, syscall.SIGUSR2, true, false},
		{"SIGINT tty: terminal already delivered it", true, syscall.SIGINT, false, true},
		{"SIGINT no tty", false, syscall.SIGINT, true, true},
		{"SIGQUIT tty", true, syscall.SIGQUIT, false, false},
		{"SIGQUIT no tty", false, syscall.SIGQUIT, true, false},
		{"SIGWINCH never", false, syscall.SIGWINCH, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, s, k := newHandler(t, tc.tty, time.Hour, nil)
			defer h.stopTimer()
			h.Handle(tc.sig)
			got := s.received()
			if (len(got) == 1 && got[0] == tc.sig) != tc.forwarded {
				t.Fatalf("forwarded %v, want forwarded=%v", got, tc.forwarded)
			}
			if h.Forwarded(tc.sig) != len(got) {
				t.Fatalf("Forwarded(%v) = %d, want %d", tc.sig, h.Forwarded(tc.sig), len(got))
			}
			o := h.Outcome()
			if (o.Signal == tc.sig) != tc.grace || (h.timer != nil) != tc.grace {
				t.Fatalf("outcome %+v timer=%v, want grace=%v", o, h.timer != nil, tc.grace)
			}
			if o.Escalated || k.count() != 0 {
				t.Fatalf("escalated without cause: %+v kills=%d", o, k.count())
			}
		})
	}
}

// Also pins runtime-launch.md R9: stop_grace is launcher-owned; its expiry escalates once with Manager.Kill.
func TestStopGraceExpiryEscalates(t *testing.T) {
	h, _, k := newHandler(t, false, 30*time.Millisecond, nil)
	h.Handle(syscall.SIGTERM)
	select {
	case <-k.done:
	case <-time.After(5 * time.Second):
		t.Fatal("cgroup.kill never written after stop_grace")
	}
	o := h.Outcome()
	if !o.Escalated || o.Signal != syscall.SIGTERM || o.Stopped {
		t.Fatalf("outcome %+v", o)
	}
	// A second trigger after escalation neither restarts nor kills again.
	h.Handle(syscall.SIGHUP)
	h.Escalate()
	if k.count() != 1 {
		t.Fatalf("kill count %d, want 1", k.count())
	}
	if h.KillError() != nil {
		t.Fatal(h.KillError())
	}
}

// TestSecondStopGraceTriggerDoesNotExtend pins Handle's own documented contract -- "starts the timer if
// none runs (the remaining time is never shortened, R9)" -- for the case nothing else in this suite
// exercises: a *second, distinct* stop_grace trigger (SIGHUP) arriving while the timer from a first trigger
// (SIGTERM) is already counting down. TestStopGraceExpiryEscalates only sends its second signal *after*
// escalation already happened, which proves no double-kill but says nothing about whether a mid-window
// trigger pushes the deadline out. If Handle restarted the timer on every trigger instead of only when none
// is running, an agent could indefinitely postpone cgroup.kill by re-sending any forwarded signal.
//
// It runs in a synctest bubble, whose clock moves only when every goroutine in it is blocked: the timer is
// checked not to have fired one nanosecond before stop_grace ends and to have fired exactly when it does,
// however loaded the machine is. On the real clock the test had 75 ms between the right deadline and a
// restarted one, and a loaded runner could spend that before the check ran.
//
// Also pins runtime-launch.md R9: the grace timer starts once and is never restarted or extended.
func TestSecondStopGraceTriggerDoesNotExtend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const grace = 300 * time.Millisecond
		h, _, k := newHandler(t, false, grace, nil)
		defer h.stopTimer()
		h.Handle(syscall.SIGTERM)
		time.Sleep(grace / 2)
		h.Handle(syscall.SIGHUP) // a second, distinct stop_grace trigger arriving mid-window
		time.Sleep(grace/2 - time.Nanosecond)
		synctest.Wait()
		if k.count() != 0 {
			t.Fatalf("escalated before stop_grace (%v) ran out: the second trigger shortened it", grace)
		}
		// Correct: fires exactly grace after the first trigger. A restart-on-every-trigger bug would fire
		// grace/2 + grace after it instead.
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if k.count() != 1 {
			t.Fatalf("not escalated %v after the first trigger: the second trigger restarted stop_grace", grace)
		}
		if o := h.Outcome(); o.Signal != syscall.SIGTERM || !o.Escalated {
			t.Fatalf("outcome %+v, want the first trigger (SIGTERM) recorded, not the second (SIGHUP), and escalated", o)
		}
	})
}

// Also pins runtime-launch.md R9: a second SIGINT escalates at once.
func TestDoubleInterruptEscalates(t *testing.T) {
	h, s, k := newHandler(t, true, time.Hour, nil)
	defer h.stopTimer()
	now := time.Unix(1000, 0)
	h.policy.Now = func() time.Time { return now }
	h.Handle(syscall.SIGINT)
	if k.count() != 0 {
		t.Fatal("first SIGINT escalated")
	}
	now = now.Add(2500 * time.Millisecond)
	h.Handle(syscall.SIGINT) // outside the window: just another trigger
	if k.count() != 0 {
		t.Fatal("SIGINT after the window escalated")
	}
	now = now.Add(time.Second)
	h.Handle(syscall.SIGINT) // within 2s of the previous one
	if k.count() != 1 || !h.Outcome().Escalated {
		t.Fatalf("double SIGINT did not escalate: kills=%d outcome=%+v", k.count(), h.Outcome())
	}
	if len(s.received()) != 0 {
		t.Fatalf("SIGINT re-sent on a tty: %v", s.received())
	}
}

func TestStopRequestedMarksStopped(t *testing.T) {
	h, _, _ := newHandler(t, false, time.Hour, func() bool { return true })
	defer h.stopTimer()
	h.Handle(syscall.SIGTERM)
	if o := h.Outcome(); !o.Stopped || o.Signal != syscall.SIGTERM {
		t.Fatalf("outcome %+v", o)
	}
}

func TestSignalerESRCHStillCounts(t *testing.T) {
	s, k := &fakeSignaler{fail: syscall.ESRCH}, newFakeKiller()
	h, err := NewSignalHandler(s, k, SignalPolicy{StopGrace: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer h.stopTimer()
	h.Handle(syscall.SIGUSR1)
	if h.Forwarded(syscall.SIGUSR1) != 1 {
		t.Fatal("ESRCH (already exited) not counted as forwarded")
	}
	s.fail = errors.New("other")
	h.Handle(syscall.SIGUSR2)
	if h.Forwarded(syscall.SIGUSR2) != 0 {
		t.Fatal("a failed forward counted")
	}
}

func TestRunConsumesUntilCancel(t *testing.T) {
	h, s, _ := newHandler(t, false, time.Hour, nil)
	ch := make(chan os.Signal, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx, ch) }()
	ch <- syscall.SIGUSR1
	ch <- os.Interrupt // an os.Signal that is a syscall.Signal (SIGINT); forwarded without a tty
	ch <- fakeSignal{}
	deadline := time.After(5 * time.Second)
	for len(s.received()) < 2 {
		select {
		case <-deadline:
			t.Fatalf("received %v", s.received())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if h.timer != nil {
		t.Fatal("timer left running after Run returned")
	}
	if got := s.received(); len(got) != 2 || got[0] != syscall.SIGUSR1 || got[1] != syscall.SIGINT {
		t.Fatalf("received %v", got)
	}
	ch2 := make(chan os.Signal)
	close(ch2)
	if err := h.Run(context.Background(), ch2); err != nil {
		t.Fatal(err)
	}
}

type fakeSignal struct{}

func (fakeSignal) String() string { return "fake" }
func (fakeSignal) Signal()        {}

func TestHandledSignals(t *testing.T) {
	want := map[syscall.Signal]bool{syscall.SIGTERM: true, syscall.SIGHUP: true, syscall.SIGUSR1: true,
		syscall.SIGUSR2: true, syscall.SIGINT: true, syscall.SIGQUIT: true}
	got := HandledSignals()
	if len(got) != len(want) {
		t.Fatalf("HandledSignals = %v", got)
	}
	for _, s := range got {
		if !want[s.(syscall.Signal)] {
			t.Fatalf("unexpected %v", s)
		}
	}
	ch, stop := Notify()
	stop()
	if ch == nil {
		t.Fatal("nil channel")
	}
}

// failingKiller is a Killer whose cgroup.kill write fails, the case §7 has no row for today: the run tree
// survives the escalation.
type failingKiller struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (k *failingKiller) Kill() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	return k.err
}

func (k *failingKiller) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.calls
}

// TestFailedEscalationIsNotSwallowed is the fail-open case: cgroup.kill returned an error, so the agent's
// process tree is still running. Two things must follow. run_end must not claim an escalation that did not
// happen -- Outcome.Escalated is what that field publishes -- and the error must leave the handler, the way
// limits.Watcher never swallows its own kill error (§7). Before this, the error went into an unread field
// and run_end reported escalated=true for a tree nothing had killed.
//
// Also pins runtime-launch.md R9: a failed kill is not an escalation and its error leaves the handler.
func TestFailedEscalationIsNotSwallowed(t *testing.T) {
	boom := errors.New("cgroup.kill: permission denied")
	k := &failingKiller{err: boom}
	h, err := NewSignalHandler(&fakeSignaler{}, k, SignalPolicy{StopGrace: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx, make(chan os.Signal)) }()
	h.Handle(syscall.SIGTERM)

	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Fatalf("Run = %v, want it to report the failed cgroup.kill (%v)", err, boom)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run never reported the failed escalation: the run would wait in Child.Wait for a tree nothing killed")
	}
	if o := h.Outcome(); o.Escalated {
		t.Fatalf("outcome %+v: escalated asserted for a cgroup.kill that failed", o)
	}
	if !errors.Is(h.KillError(), boom) {
		t.Fatalf("KillError = %v, want %v", h.KillError(), boom)
	}
}

// TestFailedEscalationIsRetriedByTheNextTrigger is the other half of leaving Escalated false: the tree is
// still alive, so a later Escalate call must try cgroup.kill again rather than treat the run as already
// escalated. A successful write is still written once (TestStopGraceExpiryEscalates). Under Run no later
// signal gets here: the failure ends Run and the group's error path retries the kill.
//
// Also pins runtime-launch.md R9: a later Escalate retries a failed kill.
func TestFailedEscalationIsRetriedByTheNextTrigger(t *testing.T) {
	k := &failingKiller{err: errors.New("boom")}
	h, err := NewSignalHandler(&fakeSignaler{}, k, SignalPolicy{StopGrace: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer h.stopTimer()
	h.Escalate()
	h.Escalate()
	if k.count() != 2 {
		t.Fatalf("kill count %d, want 2: a failed escalation must be retried", k.count())
	}
	k.mu.Lock()
	k.err = nil
	k.mu.Unlock()
	h.Escalate()
	if !h.Outcome().Escalated || h.KillError() != nil {
		t.Fatalf("outcome %+v killErr %v, want the successful retry recorded", h.Outcome(), h.KillError())
	}
	h.Escalate()
	if k.count() != 3 {
		t.Fatalf("kill count %d, want 3: a successful escalation is written once (R9)", k.count())
	}
}

// slowKiller is a Killer whose cgroup.kill write takes a while, and which records the call only once that
// write has finished -- so "the escalation completed" is observable, not merely "the escalation started".
type slowKiller struct {
	delay time.Duration

	mu   sync.Mutex
	done int
}

func (k *slowKiller) Kill() error {
	time.Sleep(k.delay)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.done++
	return nil
}

func (k *slowKiller) completed() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.done
}

// TestRunJoinsTheStopGraceEscalation pins §9's "every goroutine Run starts is started inside the errgroup it
// later Wait()s on; none fire-and-forget" for R9's escalation. stop_grace fires on a goroutine of time's own
// and Timer.Stop only reports whether the timer had already fired -- it never waits for the body. runtime.Run
// reads Outcome() for run_end and closes the run cgroup's directory fd as soon as the worker set is joined,
// so a cgroup.kill that lands after Run returned is both missing from the record and aimed at a descriptor
// that may already be closed and reused.
//
// The interleaving is staged through the handler's own lock rather than left to chance, because the window
// -- the timer has fired, its goroutine has not yet reached escalateLocked -- is otherwise microseconds
// wide: the test holds h.mu, cancels so Run queues on it inside stopTimer, then lets the timer fire so its
// goroutine queues behind Run. The unlock hands the lock to the longest waiter, Run, which therefore reaches
// a fired-but-unrun timer -- exactly the state the fix has to survive.
//
// Also pins runtime-launch.md R9: the timer goroutine is joined before Run returns.
func TestRunJoinsTheStopGraceEscalation(t *testing.T) {
	const grace = 50 * time.Millisecond
	k := &slowKiller{delay: 200 * time.Millisecond}
	h, err := NewSignalHandler(&fakeSignaler{}, k, SignalPolicy{StopGrace: grace})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx, make(chan os.Signal)) }()
	h.Handle(syscall.SIGTERM) // arms stop_grace

	h.mu.Lock()
	cancel()                                // Run wakes and queues on h.mu inside stopTimer
	time.Sleep(grace + 50*time.Millisecond) // the timer fires; its goroutine queues behind Run
	h.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run never returned")
	}
	if n := k.completed(); n != 1 {
		t.Fatalf("Run returned with %d completed cgroup.kill writes, want 1: the stop_grace escalation "+
			"is still to come, after the run's worker set was joined", n)
	}
}
