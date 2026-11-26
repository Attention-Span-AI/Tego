// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// scriptedWorker is a helper worker played by the test over real pipes: the exchange talks to it exactly as it talks
// to a re-executed worker, and nothing depends on how fast this machine starts a process. It sits in the session
// the exchange will use. script gets the worker's two ends and writes whatever the case needs, as late as it needs.
type scriptedWorker struct {
	request *os.File // what the exchange sent
	reply   *os.File // where the worker answers
	header  []byte
}

func (w *scriptedWorker) sendHeader(t *testing.T) {
	t.Helper()
	if err := writeFrame(w.reply, w.header); err != nil {
		t.Errorf("header: %v", err)
	}
}

func (w *scriptedWorker) readRequest(t *testing.T) {
	t.Helper()
	if _, err := readFrame(w.request, maxExchangeBytes); err != nil {
		t.Errorf("request: %v", err)
	}
}

func (w *scriptedWorker) sendReady(t *testing.T) {
	t.Helper()
	if err := writeFrame(w.reply, []byte{frameReady}); err != nil {
		t.Errorf("ready: %v", err)
	}
}

func (w *scriptedWorker) sendPause(t *testing.T, max time.Duration) {
	t.Helper()
	frame := make([]byte, 9)
	frame[0] = framePause
	binary.BigEndian.PutUint64(frame[1:], uint64(max))
	if err := writeFrame(w.reply, frame); err != nil {
		t.Errorf("pause: %v", err)
	}
}

func (w *scriptedWorker) sendResume(t *testing.T) {
	t.Helper()
	if err := writeFrame(w.reply, []byte{frameResume}); err != nil {
		t.Errorf("resume: %v", err)
	}
}

func (w *scriptedWorker) sendReply(t *testing.T, body string) {
	t.Helper()
	if err := writeFrame(w.reply, append([]byte{0}, body...)); err != nil {
		t.Errorf("reply: %v", err)
	}
}

// withScriptedWorker puts a scripted worker into a session of a scope whose budgets are the given ones and runs
// script in the background. The returned context is the exchange's.
func withScriptedWorker(t *testing.T, startup, location time.Duration, script func(*scriptedWorker)) context.Context {
	t.Helper()
	return withScriptedWorkerIn(t, context.Background(), startup, location, script)
}

// withScriptedWorkerIn is withScriptedWorker in a session of parent, so a test can cancel its caller.
func withScriptedWorkerIn(t *testing.T, parent context.Context, startup, location time.Duration, script func(*scriptedWorker)) context.Context {
	t.Helper()
	return withScriptedBudget(t, parent, &budget{startup: startup, location: location}, script)
}

// withScriptedBudget is withScriptedWorkerIn for a scope with the given budget, extra and all.
func withScriptedBudget(t *testing.T, parent context.Context, b *budget, script func(*scriptedWorker)) context.Context {
	t.Helper()
	as, err := readHelperCredentials()
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(as)
	if err != nil {
		t.Fatal(err)
	}
	input, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	receive, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, closeSession := WithHelperSession(parent)
	ctx = context.WithValue(ctx, budgetKey{}, b)
	session := ctx.Value(helperSessionKey{}).(*helperSession)
	session.worker = &helperWorker{send: send, receive: receive, started: true, release: heldSlot()}
	var played sync.WaitGroup
	played.Add(1)
	go func() {
		defer played.Done()
		script(&scriptedWorker{request: input, reply: output, header: header})
	}()
	t.Cleanup(func() {
		closeSession()
		_ = input.Close()
		_ = output.Close()
		played.Wait()
	})
	return ctx
}

func gone(t *testing.T, err error, words string, notWords string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no refusal, want %q", words)
	}
	if !strings.Contains(err.Error(), words) || strings.Contains(err.Error(), notWords) {
		t.Fatalf("refusal %q: want %q and not %q", err, words, notWords)
	}
}

// A helper that starts slowly succeeds: the time it takes to become ready, longer than the whole location budget,
// is the start-up budget's, and the location budget starts only when the helper says it is ready.
func TestSlowHelperStartIsNotTheLocationsTime(t *testing.T) {
	ctx := withScriptedWorker(t, 10*time.Second, 300*time.Millisecond, func(w *scriptedWorker) {
		time.Sleep(450 * time.Millisecond) // the machine is busy: the worker is slow to say it is alive
		w.sendHeader(t)
		w.readRequest(t)
		time.Sleep(450 * time.Millisecond) // and slow to decode the request
		w.sendReady(t)
		w.sendReply(t, "answer")
	})
	body, err := exchange(ctx, []byte("request"))
	if err != nil || string(body) != "answer" {
		t.Fatalf("a slow start was refused: %q %v", body, err)
	}
}

// A helper that never becomes ready ends with the busy words, not the mount words, after the start-up budget; the
// refusal still wraps the deadline, so every caller that refuses on a deadline refuses the same way.
func TestHelperThatNeverBecomesReadyIsBusyNotAStuckMount(t *testing.T) {
	release := make(chan struct{})
	ctx := withScriptedWorker(t, 300*time.Millisecond, 10*time.Second, func(w *scriptedWorker) {
		time.Sleep(100 * time.Millisecond)
		w.sendHeader(t)
		w.readRequest(t)
		<-release // never says it is ready
	})
	defer close(release)
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, StartupUnavailable, UnavailableLocation)
	if !IsStartupUnavailable(err) || IsLocationUnavailable(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("typed answer: startup=%v location=%v deadline=%v", IsStartupUnavailable(err), IsLocationUnavailable(err), errors.Is(err, context.DeadlineExceeded))
	}
	if waited < 250*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("the start-up budget ended after %v, want about 300ms", waited)
	}
}

// A helper that is ready but blocks on the location ends with the mount words after the location budget, counted
// from its ready frame and not from the exchange's start.
func TestReadyHelperThatBlocksOnTheLocationIsAStuckMount(t *testing.T) {
	release := make(chan struct{})
	ctx := withScriptedWorker(t, 10*time.Second, 300*time.Millisecond, func(w *scriptedWorker) {
		time.Sleep(400 * time.Millisecond)
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		<-release // blocks on the location
	})
	defer close(release)
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, UnavailableLocation, StartupUnavailable)
	if !IsLocationUnavailable(err) || IsStartupUnavailable(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("typed answer: startup=%v location=%v deadline=%v", IsStartupUnavailable(err), IsLocationUnavailable(err), errors.Is(err, context.DeadlineExceeded))
	}
	if waited < 650*time.Millisecond {
		t.Fatalf("the location budget ended after %v, before 400ms of start plus 300ms: it was counted from the exchange's start", waited)
	}
}

// The wait for a free helper slot is the start-up budget's: a full pool refuses with the busy words and says how
// many helpers are alive.
func TestWaitForAFreeHelperSlotIsTheStartupBudgets(t *testing.T) {
	allWorkers, governed := processWorkers, governedWorkers
	processWorkers, governedWorkers = helperPools(2)
	t.Cleanup(func() { processWorkers, governedWorkers = allWorkers, governed })
	for range cap(processWorkers) {
		processWorkers <- struct{}{}
	}
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	ctx = context.WithValue(ctx, budgetKey{}, &budget{startup: 300 * time.Millisecond, location: 10 * time.Second})
	begin := time.Now()
	_, err := exchange(ctx, nil)
	waited := time.Since(begin)
	gone(t, err, StartupUnavailable, UnavailableLocation)
	if !strings.Contains(err.Error(), "2 filesystem helpers are still alive") || !IsStartupUnavailable(err) {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	if waited < 250*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("the slot wait ended after %v, want about 300ms", waited)
	}
}

// One scope has one location budget: after a location did not answer, a further check of the same page refuses at
// once, without starting a helper, as the page's single five-second deadline did.
func TestLocationBudgetIsSharedByAScope(t *testing.T) {
	release := make(chan struct{})
	ctx := withScriptedWorker(t, 10*time.Second, 300*time.Millisecond, func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		<-release
	})
	defer close(release)
	if _, err := exchange(ctx, []byte("one")); !IsLocationUnavailable(err) {
		t.Fatalf("first check: %v", err)
	}
	begin := time.Now()
	_, err := exchange(ctx, []byte("two"))
	gone(t, err, UnavailableLocation, StartupUnavailable)
	if waited := time.Since(begin); waited > 200*time.Millisecond {
		t.Fatalf("the second check of a spent scope took %v", waited)
	}
}

// The words never repeat and never hide each other.
func TestCheckUnavailableKeepsWhichWordsItHas(t *testing.T) {
	busy := &startupError{err: context.DeadlineExceeded}
	if got := CheckUnavailable(busy); got != error(busy) {
		t.Fatalf("a start-up refusal was re-worded as a stuck location: %v", got)
	}
	stuck := CheckUnavailable(context.DeadlineExceeded)
	if got := CheckUnavailable(stuck); got != stuck || strings.Count(got.Error(), UnavailableLocation) != 1 {
		t.Fatalf("the location words were repeated: %v", got)
	}
}

// A compile is not the location (ruling 1): the helper pauses its location clock for work that does not touch the
// location, so ready plus compile time longer than the whole location budget still succeeds.
func TestSlowCompileIsNotTheLocationsTime(t *testing.T) {
	ctx := withScriptedWorker(t, 10*time.Second, 300*time.Millisecond, func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		time.Sleep(100 * time.Millisecond) // the location: 100 ms of its 300
		w.sendPause(t, 10*time.Second)
		time.Sleep(700 * time.Millisecond) // the compile: more than the location budget on its own
		w.sendResume(t)
		time.Sleep(100 * time.Millisecond) // the location again: 200 ms in all
		w.sendReply(t, "answer")
	})
	body, err := exchange(ctx, []byte("request"))
	if err != nil || string(body) != "answer" {
		t.Fatalf("a slow compile used the location's budget: %q %v", body, err)
	}
	if _, left := budgetOf(ctx).left(); left < 50*time.Millisecond || left > 150*time.Millisecond {
		t.Fatalf("the scope's location budget after 200 ms of location time is %v, want about 100ms", left)
	}
}

// A compile that never finishes ends, at what the helper said it needed, in the words of a check that did not finish:
// not the mount's, not a contract that does not compile.
func TestPausedHelperThatNeverResumesIsACompileThatDidNotFinish(t *testing.T) {
	release := make(chan struct{})
	ctx := withScriptedWorker(t, 10*time.Second, 5*time.Second, func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		w.sendPause(t, 300*time.Millisecond)
		<-release
	})
	defer close(release)
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, CompileUnfinished, UnavailableLocation)
	if !IsCompileUnfinished(err) || IsLocationUnavailable(err) || IsStartupUnavailable(err) || !errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "does not compile") || strings.Contains(err.Error(), StartupUnavailable) {
		t.Fatalf("typed answer: %v", err)
	}
	if waited < 250*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("the pause ended after %v, want about 300ms", waited)
	}
}

// A helper that resumes and then blocks on the location is still a stuck mount, with only what was left of the budget.
func TestHelperThatBlocksAfterACompileIsAStuckMount(t *testing.T) {
	release := make(chan struct{})
	ctx := withScriptedWorker(t, 10*time.Second, 400*time.Millisecond, func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		time.Sleep(200 * time.Millisecond)
		w.sendPause(t, 10*time.Second)
		time.Sleep(500 * time.Millisecond)
		w.sendResume(t)
		<-release
	})
	defer close(release)
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, UnavailableLocation, CompileUnfinished)
	if !IsLocationUnavailable(err) || waited < 850*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("stuck after a compile: %v after %v, want the mount words after about 200+500+200ms", err, waited)
	}
}

// Failures that are not deadlines say the checker could not start, with the reason; they refuse like any start-up
// refusal and fail closed, and never claim the location did not answer or the machine is busy.
func TestStartFailuresAreNotAMountThatDoesNotAnswer(t *testing.T) {
	wrongAuthority := func(w *scriptedWorker) {
		var h helperCredentials
		if err := json.Unmarshal(w.header, &h); err != nil {
			t.Error(err)
		}
		h.Full.UIDs[0]++ // a helper that came up with other authority than its caller's
		changed, _ := json.Marshal(h)
		_ = writeFrame(w.reply, changed)
	}
	cases := []struct {
		name   string
		script func(*scriptedWorker)
		reason string
	}{
		{"refused credential check", wrongAuthority, "credentials differ after exec"},
		{"worker that dies before it is ready", func(w *scriptedWorker) { w.sendHeader(t); w.readRequest(t); _ = w.reply.Close() }, "filesystem helper reply"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := withScriptedWorker(t, 10*time.Second, 10*time.Second, c.script)
			_, err := exchange(ctx, []byte("request"))
			gone(t, err, StartFailure+": ", UnavailableLocation)
			if !IsStartFailure(err) || !IsStartupUnavailable(err) || IsLocationUnavailable(err) || strings.Contains(err.Error(), StartupUnavailable) ||
				strings.Contains(err.Error(), "very busy") || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("start failure: %v", err)
			}
		})
	}
	// A failed fork, and a launcher that exits non-zero, are the same refusal.
	for name, err := range map[string]error{
		"fork":     fmt.Errorf("start filesystem helper: %w", syscall.EAGAIN),
		"launcher": fmt.Errorf("filesystem helper launcher: %w", errors.New("exit status 1")),
	} {
		got := refusal(err, false)
		if !IsStartFailure(got) || IsLocationUnavailable(got) || !strings.Contains(got.Error(), StartFailure+": ") || !errors.Is(got, err) {
			t.Fatalf("%s: %v", name, got)
		}
	}
	// A deadline stays the busy words, after the ready frame the mount's.
	if got := refusal(context.DeadlineExceeded, false); IsStartFailure(got) || !IsStartupUnavailable(got) || !strings.Contains(got.Error(), StartupUnavailable) {
		t.Fatalf("a start-up deadline: %v", got)
	}
	if got := refusal(syscall.EIO, true); !IsLocationUnavailable(got) {
		t.Fatalf("a failure after the ready frame: %v", got)
	}
}

// A caller that gives up (context.Canceled) is neither a location that did not answer nor a machine that is busy, at
// any point of the exchange.
func TestCancelledCallerIsNeitherMountNorBusy(t *testing.T) {
	check := func(t *testing.T, err error) {
		t.Helper()
		if !IsCancelledCheck(err) || IsLocationUnavailable(err) || IsStartupUnavailable(err) || !errors.Is(err, context.Canceled) ||
			!strings.Contains(err.Error(), CancelledCheck) || strings.Contains(err.Error(), UnavailableLocation) ||
			strings.Contains(err.Error(), "very busy") {
			t.Fatalf("cancelled caller: %v", err)
		}
	}
	t.Run("before the helper is ready", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		release := make(chan struct{})
		ctx := withScriptedWorkerIn(t, parent, 10*time.Second, 10*time.Second, func(w *scriptedWorker) {
			w.sendHeader(t)
			w.readRequest(t)
			<-release
		})
		defer close(release)
		time.AfterFunc(150*time.Millisecond, cancel)
		_, err := exchange(ctx, []byte("request"))
		check(t, err)
	})
	t.Run("while the helper touches the location", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		release := make(chan struct{})
		ctx := withScriptedWorkerIn(t, parent, 10*time.Second, 10*time.Second, func(w *scriptedWorker) {
			w.sendHeader(t)
			w.readRequest(t)
			w.sendReady(t)
			<-release
		})
		defer close(release)
		time.AfterFunc(150*time.Millisecond, cancel)
		_, err := exchange(ctx, []byte("request"))
		check(t, err)
	})
	t.Run("already cancelled", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := exchange(parent, []byte("request"))
		check(t, err)
	})
	t.Run("CheckUnavailable", func(t *testing.T) { check(t, CheckUnavailable(context.Canceled)) })
	// A deadline that is a cancellation's cause keeps the deadline's words.
	if got := CheckUnavailable(fmt.Errorf("%w: %w", context.Canceled, context.DeadlineExceeded)); IsCancelledCheck(got) {
		t.Fatalf("a deadline was worded as a cancellation: %v", got)
	}
}

// stuckPool is a pool of the given size whose every kernel slot is taken, and whose local workers are given back
// as a stuck check's are (abandoned: the worker keeps its kernel slot).
func stuckPool(t *testing.T, size int) []string {
	t.Helper()
	allWorkers, governed, pool := processWorkers, governedWorkers, helperReservationPool
	processWorkers, governedWorkers = helperPools(size)
	helperReservationPool = fmt.Sprintf("tego.contracts-test.stuck.%d.%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { processWorkers, governedWorkers, helperReservationPool = allWorkers, governed, pool })
	var names []string
	for _, slot := range helperSlots(false) {
		name := fmt.Sprintf("@%s.%d.%d", helperReservationPool, os.Geteuid(), slot)
		holder, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = holder.Close(); forgetStuck(name) })
		names = append(names, name)
	}
	return names
}

// A pool whose every slot is held by a check of this process that is stuck on a location refuses at once, in the
// mount's words, and says how many earlier checks are stuck: waiting for the start-up budget could not free one.
func TestFullPoolOfStuckChecksRefusesAtOnce(t *testing.T) {
	names := stuckPool(t, 2)
	release := make(chan struct{})
	defer close(release)
	for _, name := range names {
		ctx := withScriptedWorker(t, 10*time.Second, 150*time.Millisecond, func(w *scriptedWorker) {
			w.sendHeader(t)
			w.readRequest(t)
			w.sendReady(t)
			<-release
		})
		// The scripted worker stands for a real one: it holds the kernel slot a test bound, and its process is this
		// one, alive as long as the test runs.
		w := ctx.Value(helperSessionKey{}).(*helperSession).worker
		w.slot, w.pid, w.start = name, os.Getpid(), processStart(os.Getpid())
		if _, err := exchange(ctx, []byte("request")); !IsLocationUnavailable(err) {
			t.Fatalf("the stuck check: %v", err)
		}
	}
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	ctx = context.WithValue(ctx, budgetKey{}, &budget{startup: 20 * time.Second, location: 5 * time.Second})
	begin := time.Now()
	_, err := exchange(ctx, nil)
	gone(t, err, UnavailableLocation, StartupUnavailable)
	if !IsLocationUnavailable(err) || !strings.Contains(err.Error(), "2 earlier checks are still stuck") || strings.Contains(err.Error(), "very busy") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	if waited := time.Since(begin); waited > 3*time.Second {
		t.Fatalf("a pool full of stuck checks waited %v before it refused", waited)
	}
}

// What a slot's state cannot be known as, the wait stays the start-up budget's, and says exactly what is known: how many
// helpers are alive. It is a start failure's words, not the mount's and not a busy machine's.
func TestFullPoolOfUnknownHelpersKeepsTheWaitAndSaysWhatIsKnown(t *testing.T) {
	names := stuckPool(t, 2)
	// One slot is held by a stuck check of this process, the other by a helper nothing is known about (another
	// command's): nothing the wait knows would free either.
	markStuck(&helperWorker{slot: names[0], pid: os.Getpid(), start: processStart(os.Getpid())}, false)
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	ctx = context.WithValue(ctx, budgetKey{}, &budget{startup: 400 * time.Millisecond, location: 5 * time.Second})
	begin := time.Now()
	_, err := exchange(ctx, nil)
	waited := time.Since(begin)
	if waited < 350*time.Millisecond {
		t.Fatalf("the wait ended after %v, before the start-up budget", waited)
	}
	if !IsStartFailure(err) || IsLocationUnavailable(err) || !errors.Is(err, context.DeadlineExceeded) ||
		!strings.Contains(err.Error(), "2 filesystem helpers are still alive") || !strings.Contains(err.Error(), "cannot tell whether they are busy or stuck") ||
		strings.Contains(err.Error(), "very busy") || strings.Contains(err.Error(), UnavailableLocation) {
		t.Fatalf("the refusal claims more than is known: %v", err)
	}
}

// A record of a stuck check whose helper has ended is no knowledge: a slot taken again is another helper's.
func TestStuckRecordEndsWithItsHelper(t *testing.T) {
	names := stuckPool(t, 2)
	markStuck(&helperWorker{slot: names[0], pid: os.Getpid(), start: processStart(os.Getpid())}, false)
	if !stuckAt(names[0]) {
		t.Fatal("a live helper's record was not kept")
	}
	markStuck(&helperWorker{slot: names[1], pid: os.Getpid(), start: processStart(os.Getpid()) + 1}, false) // not this process's start time
	if stuckAt(names[1]) {
		t.Fatal("a slot taken again by another process was counted as stuck")
	}
}

// A page that makes several checks waits the start-up budget once, not once per check: after a helper of the scope
// did not become ready in it, the scope's further checks refuse at once, without starting another helper.
func TestScopeSpendsTheStartupBudgetOnce(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedWorker(t, 400*time.Millisecond, 10*time.Second, func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		<-release // never says it is ready
	})
	begin := time.Now()
	var refused []string
	for range 5 { // five checks of one page
		_, err := exchange(ctx, []byte("request"))
		if !IsStartupUnavailable(err) {
			t.Fatalf("check %d: %v", len(refused)+1, err)
		}
		refused = append(refused, err.Error())
	}
	if waited := time.Since(begin); waited < 350*time.Millisecond || waited > 1500*time.Millisecond {
		t.Fatalf("five checks of a scope with a 400ms start-up budget took %v: the budget was spent more than once", waited)
	}
	if startLeft, _ := budgetOf(ctx).left(); startLeft > 0 {
		t.Fatalf("the scope still has %v of start-up budget after the checker never started", startLeft)
	}
}

// WithScope is idempotent and SameScope says which exchanges share budgets.
func TestWithScopeIsOneScopePerContext(t *testing.T) {
	a := WithScope(context.Background())
	b := WithScope(a)
	c := WithScope(context.Background())
	if !SameScope(a, b) || SameScope(a, c) || SameScope(context.Background(), context.Background()) {
		t.Fatal("scopes are not what WithScope says")
	}
}

// heldSlot takes a slot of the current worker pool for a hand-made worker, given back to that same pool by its close.
func heldSlot() func() {
	pool := processWorkers
	pool <- struct{}{}
	return func() { <-pool }
}
