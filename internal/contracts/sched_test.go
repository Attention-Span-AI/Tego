// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tests of this package never read the real scheduler: a busy machine would decide what they find. readScheduler
// is a fake whose counters follow the wall clock by a share the test names. By default the helper is blocked (asleep,
// no run-queue wait), as a stuck mount's is, which is what every other test of this package assumes.
func init() { readScheduler = (&fakeScheduler{state: 'S'}).read }

// fakeScheduler counts one task whose cumulative run and wait time follow the wall clock since the first read: wait
// and run are the given shares of the elapsed time (0 to 1); a task with neither is asleep.
type fakeScheduler struct {
	mu       sync.Mutex
	state    byte
	wait     float64        // share of the elapsed time spent waiting for a CPU
	run      float64        // share of the elapsed time spent on a CPU
	wchan    string         // what a task in state D sleeps in
	more     map[int]Thread // other tasks of the process, as they are
	err      error
	t0       time.Time
	readings int
}

func (f *fakeScheduler) read(pid int, start uint64) (map[int]Thread, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readings++
	if f.err != nil {
		return nil, f.err
	}
	if f.t0.IsZero() {
		f.t0 = time.Now()
	}
	elapsed := time.Since(f.t0)
	out := map[int]Thread{7: {State: f.state, Run: time.Duration(float64(elapsed) * f.run), Wait: time.Duration(float64(elapsed) * f.wait), WChan: f.wchan}}
	for tid, t := range f.more {
		out[tid] = t
	}
	return out, nil
}

// useScheduler makes f what the exchange reads, for one test.
func useScheduler(t *testing.T, f *fakeScheduler) {
	t.Helper()
	before := readScheduler
	readScheduler = f.read
	t.Cleanup(func() { readScheduler = before })
}

// useLocationTimeout shrinks the location budget (and so its step and cap) for one test.
func useLocationTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	before := locationTimeout
	locationTimeout = d
	t.Cleanup(func() { locationTimeout = before })
}

// scopeOf is a scope as newBudget makes it, with the test's short budgets.
func scopeOf(startup time.Duration) *budget {
	return &budget{startup: startup, location: locationTimeout, extra: locationCap() - locationTimeout}
}

// holdsSlot says the scripted worker of ctx holds a kernel slot of this name, as a real one does, and is this process
// as far as /proc can tell; stuckAt then says whether the exchange recorded it as stuck.
func holdsSlot(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	w := ctx.Value(helperSessionKey{}).(*helperSession).worker
	w.slot, w.pid, w.start = name, os.Getpid(), processStart(os.Getpid())
	t.Cleanup(func() { forgetStuck(name) })
}

// blockedWorker is a worker that says it is ready and then never answers.
func blockedWorker(t *testing.T, release chan struct{}) func(*scriptedWorker) {
	return func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		<-release
	}
}

// A helper that was blocked when its budget ran out (asleep, or in uninterruptible sleep), whatever its wait for a CPU
// was, is a location that does not answer: the mount words, after the one budget, with no extension.
func TestBlockedHelperIsAStuckMountAtTheFirstBudget(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	for _, c := range []struct {
		name string
		f    *fakeScheduler
	}{
		{"asleep", &fakeScheduler{state: 'S'}},
		{"uninterruptible sleep", &fakeScheduler{state: 'D'}},
		{"in uninterruptible sleep after waiting for a CPU", &fakeScheduler{state: 'D', wait: 0.9}},
		{"asleep with a little of each", &fakeScheduler{state: 'S', wait: 0.1, run: 0.1}},
		{"in uninterruptible sleep after running", &fakeScheduler{state: 'D', run: 0.9}},
		{"in uninterruptible sleep in a name that is not in the table", &fakeScheduler{state: 'D', wchan: "some_unknown_wait"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			useScheduler(t, c.f)
			release := make(chan struct{})
			defer close(release)
			ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
			holdsSlot(t, ctx, "@test-blocked-"+strings.ReplaceAll(c.name, " ", "-"))
			begin := time.Now()
			_, err := exchange(ctx, []byte("request"))
			waited := time.Since(begin)
			if !stuckAt("@test-blocked-" + strings.ReplaceAll(c.name, " ", "-")) {
				t.Fatal("a blocked helper was not recorded as stuck on its slot")
			}
			gone(t, err, UnavailableLocation, "busy")
			if !IsLocationUnavailable(err) || IsCheckTooSlow(err) || IsCheckUnclear(err) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("typed answer: %v", err)
			}
			if waited < 250*time.Millisecond || waited > 600*time.Millisecond {
				t.Fatalf("a blocked helper was refused after %v, want about one budget (300ms)", waited)
			}
		})
	}
}

// A helper that waited for a CPU for most of the window is starved, not stuck: its budget is extended, and it
// finishes inside the cap and succeeds.
func TestStarvedHelperIsGivenMoreTimeAndFinishes(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	f := &fakeScheduler{state: 'R', wait: 0.9}
	useScheduler(t, f)
	ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		time.Sleep(800 * time.Millisecond) // more than two budgets, less than the cap of four
		w.sendReply(t, "answer")
	})
	begin := time.Now()
	body, err := exchange(ctx, []byte("request"))
	if err != nil || string(body) != "answer" {
		t.Fatalf("a starved helper that finished inside the cap was refused after %v: %q %v", time.Since(begin), body, err)
	}
	b := budgetOf(ctx)
	if b.extra != 300*time.Millisecond || b.location > 150*time.Millisecond || b.location < 50*time.Millisecond {
		t.Fatalf("scope after two steps and 800ms: extra %v (want 300ms), location left %v (want about 100ms)", b.extra, b.location)
	}
}

// A helper that was on a CPU for most of the window is working, not stuck: its budget is extended as a starved
// helper's is, and it finishes inside the cap and succeeds.
func TestRunningHelperIsGivenMoreTimeAndFinishes(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useScheduler(t, &fakeScheduler{state: 'R', run: 0.9})
	ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		time.Sleep(800 * time.Millisecond)
		w.sendReply(t, "answer")
	})
	begin := time.Now()
	body, err := exchange(ctx, []byte("request"))
	if err != nil || string(body) != "answer" {
		t.Fatalf("a helper that was working was refused after %v: %q %v", time.Since(begin), body, err)
	}
}

// A helper that is still working at the cap is refused in its own words, typed, at about the cap: not the mount's,
// not the busy machine's, and not recorded as stuck.
func TestRunningHelperPastTheCapIsStillWorking(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useScheduler(t, &fakeScheduler{state: 'R', run: 0.9})
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
	holdsSlot(t, ctx, "@test-working")
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, CheckWorking, UnavailableLocation)
	if !IsCheckWorking(err) || IsLocationUnavailable(err) || IsCheckTooSlow(err) || IsCheckUnclear(err) || IsStartupUnavailable(err) ||
		strings.Contains(err.Error(), "very busy") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("typed answer: %v", err)
	}
	if waited < 1100*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("a working helper was refused after %v, want about the cap (1.2s)", waited)
	}
	if stuckAt("@test-working") {
		t.Fatal("a helper that was working was recorded as stuck")
	}
}

// Working for a window and then blocked in D is a stuck mount at the end of that window.
func TestRunningThenBlockedIsAStuckMount(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	f := &fakeScheduler{state: 'R', run: 0.9}
	useScheduler(t, f)
	time.AfterFunc(450*time.Millisecond, func() { f.mu.Lock(); f.state, f.run = 'D', 0; f.mu.Unlock() })
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, UnavailableLocation, CheckWorking)
	if !IsLocationUnavailable(err) || waited < 550*time.Millisecond || waited > 1100*time.Millisecond {
		t.Fatalf("working, then blocked: %v after %v, want the mount words after two budgets (600ms)", err, waited)
	}
}

// A helper that stays starved to the cap is refused in the busy words, typed, at about the cap and not before.
func TestStarvedHelperPastTheCapIsTooSlow(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	f := &fakeScheduler{state: 'R', wait: 0.9}
	useScheduler(t, f)
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
	holdsSlot(t, ctx, "@test-starved")
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, CheckTooSlow, UnavailableLocation)
	if !IsCheckTooSlow(err) || IsLocationUnavailable(err) || IsCheckUnclear(err) || IsStartupUnavailable(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("typed answer: %v", err)
	}
	if waited < 1100*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("a starved helper was refused after %v, want about the cap (1.2s)", waited)
	}
	// It is not a helper stuck on its slot: nothing is recorded as stuck.
	if got := stuckAt("@test-starved"); got {
		t.Fatal("a starved helper was recorded as stuck")
	}
}

// A helper that is starved for a window and then blocked is a stuck mount at the end of that window: the evidence
// is the latest window's, not the first.
func TestStarvedThenBlockedIsAStuckMount(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	f := &fakeScheduler{state: 'R', wait: 0.9}
	useScheduler(t, f)
	time.AfterFunc(450*time.Millisecond, func() { f.mu.Lock(); f.state, f.wait = 'D', 0; f.mu.Unlock() })
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, UnavailableLocation, CheckTooSlow)
	if !IsLocationUnavailable(err) || waited < 550*time.Millisecond || waited > 1100*time.Millisecond {
		t.Fatalf("starved, then blocked: %v after %v, want the mount words after two budgets (600ms)", err, waited)
	}
}

// When the counters cannot be read (no schedstat in the kernel, or the helper has gone), the words claim neither
// cause, after the one budget.
func TestUnreadableCountersClaimNeitherCause(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	for name, readErr := range map[string]error{
		"a kernel without schedstat": ErrNoSchedstat,
		"a helper that has gone":     errors.New("the process has ended"),
	} {
		t.Run(name, func(t *testing.T) {
			useScheduler(t, &fakeScheduler{err: readErr})
			release := make(chan struct{})
			defer close(release)
			ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
			holdsSlot(t, ctx, "@test-unclear")
			begin := time.Now()
			_, err := exchange(ctx, []byte("request"))
			waited := time.Since(begin)
			if stuckAt("@test-unclear") {
				t.Fatal("a helper whose state could not be read was recorded as stuck")
			}
			gone(t, err, CheckUnclear, UnavailableLocation)
			if !IsCheckUnclear(err) || IsLocationUnavailable(err) || IsCheckTooSlow(err) || strings.Contains(err.Error(), "does not answer") ||
				!errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("typed answer: %v", err)
			}
			if waited < 250*time.Millisecond || waited > 600*time.Millisecond {
				t.Fatalf("an unreadable helper was refused after %v, want one budget (300ms)", waited)
			}
		})
	}
}

// A page's location time is bounded by the cap in all, not by the cap times its checks: starved checks that each
// finish after more than a budget run the scope out of its cap, and the check that crosses it is refused too slow,
// the next at once, with the same words and no helper started.
func TestScopeLocationTimeNeverExceedsTheCap(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useScheduler(t, &fakeScheduler{state: 'R', wait: 0.9})
	ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), func(w *scriptedWorker) {
		// A worker that answers every check after 500 ms; the caller abandons it when the scope's cap ends, and its
		// writes then fail, which is not a finding.
		for {
			if writeFrame(w.reply, w.header) != nil {
				return
			}
			if _, err := readFrame(w.request, maxExchangeBytes); err != nil {
				return
			}
			if writeFrame(w.reply, []byte{frameReady}) != nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
			if writeFrame(w.reply, append([]byte{0}, "answer"...)) != nil {
				return
			}
		}
	})
	begin := time.Now()
	var refusedAt time.Duration
	var refused error
	for i := range 6 {
		_, err := exchange(ctx, []byte("request"))
		if err != nil {
			refusedAt, refused = time.Since(begin), err
			if i < 2 {
				t.Fatalf("check %d refused too early: %v", i+1, err)
			}
			break
		}
	}
	if refused == nil || !IsCheckTooSlow(refused) {
		t.Fatalf("no check of the scope was refused too slow: %v", refused)
	}
	if refusedAt > 1200*time.Millisecond+300*time.Millisecond {
		t.Fatalf("the scope spent %v on the location, over the cap of 1.2s", refusedAt)
	}
	again := time.Now()
	_, err := exchange(ctx, []byte("request"))
	if !IsCheckTooSlow(err) || time.Since(again) > 200*time.Millisecond {
		t.Fatalf("a check of a scope past its cap: %v after %v", err, time.Since(again))
	}
}

// Without a scope, one check is bounded by the same cap.
func TestWorkerClockOutlivesTheCallersCap(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	if got, want := workerWithin(context.Background()), locationCap()+workerBackstop(); got != want {
		t.Fatalf("a check outside any scope: the worker's clock is %v, want %v", got, want)
	}
	b := scopeOf(time.Second)
	if got := b.within(); got != locationCap()+workerBackstop() {
		t.Fatalf("a fresh scope: %v", got)
	}
	b.chargeLocation(200 * time.Millisecond)
	if got := b.within(); got != locationCap()-200*time.Millisecond+workerBackstop() {
		t.Fatalf("after 200ms: %v", got)
	}
	if got := b.within(); got <= locationCap()-locationTimeout {
		t.Fatalf("the worker's clock %v would end before the caller's last step", got)
	}
}

// A compile pause is not counted in the window: a helper starved while it works at the location, then paused (the
// compile), is judged by the counters of the part that was not paused.
func TestPausedTimeIsNotInTheWindow(t *testing.T) {
	at := time.Unix(0, 0)
	now := func() time.Time { return at }
	var run, wait time.Duration
	read := func(int, uint64) (map[int]Thread, error) {
		return map[int]Thread{1: {State: 'S', Run: run, Wait: wait}}, nil
	}
	w := NewWatchWith(read, 1, 0, now)
	at = at.Add(100 * time.Millisecond) // 100 ms at the location, all of it waiting for a CPU
	wait += 100 * time.Millisecond
	w.Pause()
	at = at.Add(900 * time.Millisecond) // the compile: the helper is asleep, nothing is counted
	w.Resume()
	at = at.Add(100 * time.Millisecond) // 100 ms more, running
	run += 100 * time.Millisecond
	if got := w.Judge(); got != Starved {
		t.Fatalf("100 ms waiting of 200 ms of location time: %v, want starved (a half)", got)
	}
	// The window after a judgement is a new one.
	at = at.Add(100 * time.Millisecond)
	run += 100 * time.Millisecond
	if got := w.Judge(); got != Running {
		t.Fatalf("a window of running only: %v, want running", got)
	}
}

// The thresholds are exactly half of the window, for waiting (starved, checked first) and for running, and state D
// beats any wait and any run.
func TestWatchThresholds(t *testing.T) {
	for _, c := range []struct {
		name  string
		state byte
		wait  time.Duration // out of 1000 ms
		run   time.Duration
		want  Verdict
	}{
		{"just under half of waiting", 'R', 499 * time.Millisecond, 0, Blocked},
		{"half waiting", 'R', 500 * time.Millisecond, 0, Starved},
		{"all waiting", 'S', 1000 * time.Millisecond, 0, Starved},
		{"uninterruptible sleep with all waiting", 'D', 1000 * time.Millisecond, 0, Blocked},
		{"nothing: asleep", 'S', 0, 0, Blocked},
		{"just under half running", 'R', 0, 499 * time.Millisecond, Blocked},
		{"half running", 'R', 0, 500 * time.Millisecond, Running},
		{"all running", 'S', 0, 1000 * time.Millisecond, Running},
		{"uninterruptible sleep with all running", 'D', 0, 1000 * time.Millisecond, Blocked},
		{"under half of each", 'S', 400 * time.Millisecond, 400 * time.Millisecond, Blocked},
		{"half waiting and half running", 'R', 500 * time.Millisecond, 500 * time.Millisecond, Starved},
		{"a little waiting, mostly running", 'R', 100 * time.Millisecond, 800 * time.Millisecond, Running},
	} {
		t.Run(c.name, func(t *testing.T) {
			at := time.Unix(0, 0)
			var wait, run time.Duration
			read := func(int, uint64) (map[int]Thread, error) {
				return map[int]Thread{1: {State: c.state, Wait: wait, Run: run}}, nil
			}
			w := NewWatchWith(read, 1, 0, func() time.Time { return at })
			at, wait, run = at.Add(time.Second), c.wait, c.run
			if got := w.Judge(); got != c.want {
				t.Fatalf("%v", got)
			}
		})
	}
}

// The wait of the task that waited longest counts, not the sum of the tasks: several idle runtime threads do not
// make a blocked helper look starved, and a thread born in the window counts from zero.
func TestWatchCountsTheLongestTaskAndNewTasks(t *testing.T) {
	at := time.Unix(0, 0)
	threads := map[int]Thread{1: {State: 'S'}, 2: {State: 'S'}}
	read := func(int, uint64) (map[int]Thread, error) {
		out := map[int]Thread{}
		for k, v := range threads {
			out[k] = v
		}
		return out, nil
	}
	w := NewWatchWith(read, 1, 0, func() time.Time { return at })
	at = at.Add(time.Second)
	threads[1] = Thread{State: 'S', Wait: 300 * time.Millisecond}
	threads[2] = Thread{State: 'S', Wait: 300 * time.Millisecond}
	if got := w.Judge(); got != Blocked {
		t.Fatalf("two tasks that waited 300 ms each in a second: %v, want blocked (not a sum of 600 ms)", got)
	}
	at = at.Add(time.Second)
	threads[3] = Thread{State: 'R', Wait: 700 * time.Millisecond} // born in the window
	if got := w.Judge(); got != Starved {
		t.Fatalf("a task born in the window that waited 700 ms of it: %v, want starved", got)
	}
}

// A counter that cannot be read at the baseline or at the end is Unreadable, never a guess.
func TestWatchUnreadable(t *testing.T) {
	at := time.Unix(0, 0)
	fail := true
	read := func(int, uint64) (map[int]Thread, error) {
		if fail {
			return nil, ErrNoSchedstat
		}
		return map[int]Thread{1: {State: 'S'}}, nil
	}
	w := NewWatchWith(read, 1, 0, func() time.Time { return at })
	fail = false
	at = at.Add(time.Second)
	if got := w.Judge(); got != Unreadable {
		t.Fatalf("no baseline: %v, want unreadable", got)
	}
	at = at.Add(time.Second)
	if got := w.Judge(); got != Blocked {
		t.Fatalf("the next window has a baseline: %v, want blocked", got)
	}
	fail = true
	at = at.Add(time.Second)
	if got := w.Judge(); got != Unreadable {
		t.Fatalf("a failing read at the end: %v, want unreadable", got)
	}
}

// The real reader, on this process and on its child: the thread count and the state are the kernel's, a recycled pid
// and a gone process are refused, and the run-queue wait never goes backwards. (Only the process Tego started is read.)
func TestProcSchedulerReadsOwnTasks(t *testing.T) {
	self := os.Getpid()
	first, err := procScheduler(self, 0)
	if err != nil {
		if errors.Is(err, ErrNoSchedstat) {
			t.Skip("this kernel has no schedstat: the exchange refuses in the neutral words")
		}
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("no tasks of this process")
	}
	second, err := procScheduler(self, processStart(self))
	if err != nil {
		t.Fatal(err)
	}
	for tid, a := range first {
		if b, ok := second[tid]; ok && (b.Wait < a.Wait || b.Run < a.Run) {
			t.Fatalf("task %d counters went backwards: %+v then %+v", tid, a, b)
		}
	}
	if _, err := procScheduler(self, processStart(self)+1000); err == nil {
		t.Fatal("a pid with another start time was read")
	}
	if _, err := procScheduler(0, 0); err == nil {
		t.Fatal("pid 0 was read")
	}
	if _, err := procScheduler(1<<22+7, 0); err == nil {
		t.Fatal("a process that does not exist was read")
	}
}

func TestParseSchedstat(t *testing.T) {
	run, wait, err := parseSchedstat([]byte("123456789 42000 17\n"))
	if err != nil || run != 123456789 || wait != 42000 {
		t.Fatalf("%v %v %v", run, wait, err)
	}
	for _, bad := range []string{"", "1", "a b c", "-1 2 3"} {
		if _, _, err := parseSchedstat([]byte(bad)); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

// The words of a refusal after the ready frame are never re-worded by a later wrapper: CheckUnavailable and
// refusal keep the too-slow and unclear words, as they keep the mount's.
func TestTooSlowAndUnclearKeepTheirWordsThroughWrappers(t *testing.T) {
	for name, err := range map[string]error{
		"too slow": &unavailableError{err: context.DeadlineExceeded, fault: faultStarved},
		"working":  &unavailableError{err: context.DeadlineExceeded, fault: faultWorking},
		"unclear":  &unavailableError{err: context.DeadlineExceeded, fault: faultUnread},
	} {
		if got := CheckUnavailable(err); got != err {
			t.Errorf("%s: CheckUnavailable re-worded %v as %v", name, err, got)
		}
		if got := refusal(err, true); got != err {
			t.Errorf("%s: refusal re-worded %v as %v", name, err, got)
		}
		if got := refusal(err, false); got != err {
			t.Errorf("%s: refusal before the ready frame re-worded %v as %v", name, err, got)
		}
		if IsLocationUnavailable(err) || IsStartupUnavailable(err) {
			t.Errorf("%s counted as the mount's or the start-up's", name)
		}
	}
}

var diskWaits = []string{"jbd2_log_wait_commit", "ext4_sync_file", "btrfs_commit_transaction.part.0", "xfs_log_force_lsn", "io_schedule",
	"folio_wait_bit_common", "wait_on_page_bit_killable", "blk_mq_get_tag"}

// A helper blocked in this computer's own disk or journal is slow, not stuck: it is given the steps a starved helper is,
// and finishes inside the cap and succeeds.
func TestHelperBlockedInTheDiskIsGivenMoreTimeAndFinishes(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	for _, wchan := range diskWaits {
		t.Run(wchan, func(t *testing.T) {
			useScheduler(t, &fakeScheduler{state: 'D', wchan: wchan})
			ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), func(w *scriptedWorker) {
				w.sendHeader(t)
				w.readRequest(t)
				w.sendReady(t)
				time.Sleep(800 * time.Millisecond) // more than two budgets, less than the cap of four
				w.sendReply(t, "answer")
			})
			begin := time.Now()
			body, err := exchange(ctx, []byte("request"))
			if err != nil || string(body) != "answer" {
				t.Fatalf("a helper waiting for the disk that finished inside the cap was refused after %v: %q %v", time.Since(begin), body, err)
			}
		})
	}
}

// A helper still blocked in the disk at the cap gets the disk words, typed, at about the cap: not the mount's, not
// the busy machine's, and recorded as holding its slot until the disk answers.
func TestHelperBlockedInTheDiskToTheCapGetsTheDiskWords(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	for _, wchan := range diskWaits {
		t.Run(wchan, func(t *testing.T) {
			// Waiting for a CPU as well does not matter: state D comes first.
			useScheduler(t, &fakeScheduler{state: 'D', wait: 0.9, wchan: wchan})
			release := make(chan struct{})
			defer close(release)
			ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
			holdsSlot(t, ctx, "@test-disk-"+wchan)
			begin := time.Now()
			_, err := exchange(ctx, []byte("request"))
			waited := time.Since(begin)
			gone(t, err, CheckDisk, UnavailableLocation)
			if !IsCheckDisk(err) || IsLocationUnavailable(err) || IsCheckTooSlow(err) || IsCheckWorking(err) || IsCheckUnclear(err) || IsStartupUnavailable(err) ||
				strings.Contains(err.Error(), "stuck mount") || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("typed answer: %v", err)
			}
			if waited < 1100*time.Millisecond || waited > 2*time.Second {
				t.Fatalf("a helper blocked in the disk was refused after %v, want about the cap (1.2s)", waited)
			}
			if !stuckAt("@test-disk-" + wchan) {
				t.Fatal("a helper blocked in the disk was not recorded as holding its slot")
			}
			if budgetOf(ctx).extra != 0 {
				t.Fatal("the budget was not used up to its cap")
			}
		})
	}
}

// A disk wait that turns into a wait in a mount ends with the mount words at the end of that window; a disk wait in a
// page that has less than a step left is refused with the disk words at once, like a starved one.
func TestDiskWaitThenMountAndTheRequestBound(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	t.Run("disk then fuse", func(t *testing.T) {
		f := &fakeScheduler{state: 'D', wchan: "jbd2_log_wait_commit"}
		useScheduler(t, f)
		time.AfterFunc(450*time.Millisecond, func() { f.mu.Lock(); f.wchan = "fuse_simple_request"; f.mu.Unlock() })
		release := make(chan struct{})
		defer close(release)
		ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
		begin := time.Now()
		_, err := exchange(ctx, []byte("request"))
		waited := time.Since(begin)
		gone(t, err, UnavailableLocation, CheckDisk)
		if !IsLocationUnavailable(err) || waited < 550*time.Millisecond || waited > 1100*time.Millisecond {
			t.Fatalf("disk, then a mount: %v after %v, want the mount words after two budgets (600ms)", err, waited)
		}
	})
	t.Run("the page's bound", func(t *testing.T) {
		useScheduler(t, &fakeScheduler{state: 'D', wchan: "jbd2_log_wait_commit"})
		release := make(chan struct{})
		defer close(release)
		ctx := withScriptedBudget(t, context.Background(), requestScopeOf(800*time.Millisecond), blockedWorker(t, release))
		begin := time.Now()
		_, err := exchange(ctx, []byte("request"))
		waited := time.Since(begin)
		if !IsCheckDisk(err) || waited < 550*time.Millisecond || waited > 790*time.Millisecond {
			t.Fatalf("a disk wait in a page bounded at 800ms: %v after %v (its own cap is 1.2s)", err, waited)
		}
	})
}

// A helper blocked anywhere else keeps the mount words at the first budget: a network or user-space filesystem, a name
// the table does not have, a hidden or empty one, a thread that is not in state D whatever it sleeps in, and a helper
// that has a thread in the disk and another in something else.
func TestHelperBlockedElsewhereKeepsTheMountWords(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	for name, f := range map[string]*fakeScheduler{
		"fuse":                    {state: 'D', wchan: "fuse_simple_request"},
		"fuse waiting":            {state: 'D', wchan: "request_wait_answer"},
		"nfs":                     {state: 'D', wchan: "nfs_wait_bit_killable"},
		"rpc":                     {state: 'D', wchan: "rpc_wait_bit_killable"},
		"cifs":                    {state: 'D', wchan: "cifs_call_async"},
		"smb":                     {state: 'D', wchan: "smb2_compound_op"},
		"ceph":                    {state: 'D', wchan: "ceph_mdsc_do_request"},
		"9p":                      {state: 'D', wchan: "p9_client_rpc"},
		"unknown":                 {state: 'D', wchan: "some_unknown_wait"},
		"empty":                   {state: 'D', wchan: ""},
		"hidden by the kernel":    {state: 'D', wchan: "0"},
		"a disk name, but asleep": {state: 'S', wchan: "jbd2_log_wait_commit"},
	} {
		t.Run(name, func(t *testing.T) {
			useScheduler(t, f)
			release := make(chan struct{})
			defer close(release)
			ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
			_, err := exchange(ctx, []byte("request"))
			gone(t, err, UnavailableLocation, "disk")
			if !IsLocationUnavailable(err) || IsCheckDisk(err) {
				t.Fatalf("typed answer: %v", err)
			}
		})
	}
	t.Run("one thread in the disk and one in a mount: no extension", func(t *testing.T) {
		useScheduler(t, &fakeScheduler{state: 'D', wchan: "jbd2_log_wait_commit", more: map[int]Thread{8: {State: 'D', WChan: "fuse_simple_request"}}})
		release := make(chan struct{})
		defer close(release)
		ctx := withScriptedBudget(t, context.Background(), scopeOf(10*time.Second), blockedWorker(t, release))
		begin := time.Now()
		_, err := exchange(ctx, []byte("request"))
		gone(t, err, UnavailableLocation, "disk")
		if time.Since(begin) > 600*time.Millisecond || budgetOf(ctx).extra != locationCap()-locationTimeout {
			t.Fatalf("a helper with a thread in a mount was extended: %v after %v", err, time.Since(begin))
		}
	})
	t.Run("one thread in the disk and one in a mount", func(t *testing.T) {
		if onlyDiskWaits(map[int]Thread{1: {State: 'D', WChan: "jbd2_log_wait_commit"}, 2: {State: 'D', WChan: "fuse_simple_request"}}) ||
			onlyDiskWaits(map[int]Thread{1: {State: 'D', WChan: "jbd2_log_wait_commit"}, 2: {State: 'D'}}) ||
			onlyDiskWaits(map[int]Thread{1: {State: 'S', WChan: "jbd2_log_wait_commit"}}) {
			t.Fatal("a helper with a thread blocked outside the disk was called a disk wait")
		}
		if !onlyDiskWaits(map[int]Thread{1: {State: 'D', WChan: "jbd2_log_wait_commit"}, 2: {State: 'S', WChan: "futex_do_wait"}, 3: {State: 'D', WChan: "ext4_sync_file"}}) {
			t.Fatal("two threads blocked in the disk, one asleep elsewhere, was not a disk wait")
		}
	})
}

// The table's names and families, exact names with the compiler's "." suffixes and prefixes, and the near misses.
func TestWchanTable(t *testing.T) {
	for name, want := range map[string]wchanFamily{
		"jbd2_log_wait_commit": wchanDisk, "jbd2_journal_commit_transaction": wchanDisk, "xfs_log_force_lsn": wchanDisk,
		"btrfs_commit_transaction": wchanDisk, "io_schedule": wchanDisk, "io_schedule_timeout": wchanDisk, "folio_wait_bit_common": wchanDisk,
		"wait_on_page_bit": wchanDisk, "blk_mq_get_tag": wchanDisk, "ext4_sync_file": wchanDisk, "ext4_wait_block_bitmap": wchanDisk,
		"fuse_simple_request": wchanNetwork, "request_wait_answer": wchanNetwork, "request_wait_answer.part.0": wchanNetwork,
		"nfs_wait_bit_killable": wchanNetwork, "rpc_wait_bit_killable": wchanNetwork, "cifs_call_async": wchanNetwork,
		"smb2_compound_op": wchanNetwork, "smbd_post_send": wchanNetwork, "ceph_mdsc_do_request": wchanNetwork, "p9_client_rpc": wchanNetwork,
		// Not in the table.
		"": wchanUnknown, "0": wchanUnknown, "futex_do_wait": wchanUnknown, "ep_poll": wchanUnknown, "jbd2": wchanUnknown, "ext4": wchanUnknown,
		"request_wait_answerx": wchanUnknown, "my_ext4_sync_file": wchanUnknown, "schedule": wchanUnknown, "pipe_read": wchanUnknown,
	} {
		if got := classifyWchan(name); got != want {
			t.Errorf("classifyWchan(%q) = %v, want %v", name, got, want)
		}
	}
}

// ADR 0144 holds the table the code has, row for row: a row added to the code and not to the ADR fails here.
func TestWchanTableIsInADR0144(t *testing.T) {
	adr, err := os.ReadFile("../../docs/adr/0144-machine-baseline.md")
	if err != nil {
		t.Skip("the ADR is not in this tree (the public export)")
	}
	text := string(adr)
	for _, r := range wchanTable {
		cell := "`" + r.name + "`"
		if r.prefix {
			cell = "`" + r.name + "*`"
		}
		if !strings.Contains(text, cell) {
			t.Errorf("ADR 0144 lacks the wchan table row %s", cell)
		}
	}
}
