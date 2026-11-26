// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// The tests here run a REAL helper process (this test binary, re-executed by TestMain as HelperMain: undumpable, as in
// production) and read its REAL scheduler counters, not a scripted worker and a fake reader. The slow answer is an
// operation of the helper that waits for a time the test names. It is what a check of a busy local disk looks like to the
// caller: a helper that was asked and has not answered. ADR 0144, "A local location is a busy disk, not a stuck mount".

// opArgs reads the payload of the two operations below: the time to hold, and where to write this helper's pid.
func opArgs(payload []byte) (time.Duration, error) {
	fields := strings.Fields(string(payload))
	if len(fields) == 0 {
		return 0, errors.New("no time to hold")
	}
	d, err := time.ParseDuration(fields[0])
	if err != nil {
		return 0, err
	}
	if len(fields) > 1 {
		if err := os.WriteFile(fields[1], []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			return 0, err
		}
	}
	return d, nil
}

func init() {
	RegisterHelperOperation("test-slow-answer", func(ctx context.Context, payload []byte) ([]byte, error) {
		d, err := opArgs(payload)
		if err != nil {
			return nil, err
		}
		select {
		case <-time.After(d):
			return []byte("answered"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	RegisterHelperOperation("test-disk-wait", func(ctx context.Context, payload []byte) ([]byte, error) {
		d, err := opArgs(payload)
		if err != nil {
			return nil, err
		}
		return nil, stayInUninterruptibleSleep(ctx, d)
	})
}

// helperOp runs a test operation of the real helper, held for hold, and registers the check that the helper process is
// gone when the test ends (an exact pid, from the file the operation writes it to).
func helperOp(t *testing.T, ctx context.Context, op, hold string) ([]byte, error) {
	t.Helper()
	pidfile := filepath.Join(t.TempDir(), "helper.pid")
	t.Cleanup(func() { reapHelper(t, pidfile) })
	return HelperExchange(ctx, op, []byte(hold+" "+pidfile))
}

// helperPidOf is the pid the operation wrote, 0 before it has.
func helperPidOf(pidfile string) int {
	b, err := os.ReadFile(pidfile)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

// reapHelper waits, bounded, for the helper process of the pidfile to be gone and ends it, and any child of it, by exact
// pid if it is not, failing the test that left it.
func reapHelper(t *testing.T, pidfile string) {
	t.Helper()
	pid := helperPidOf(pidfile)
	if pid == 0 {
		return
	}
	gone := func() bool { _, err := readParsedStat(pid); return err != nil }
	deadline := time.Now().Add(10 * time.Second)
	for !gone() && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if gone() {
		return
	}
	for _, child := range childrenOf(pid) {
		_ = syscall.Kill(child, syscall.SIGKILL)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Errorf("helper process %d was still alive 10 s after its test; it and its children were ended by pid", pid)
}

// childrenOf are the processes whose parent is pid.
func childrenOf(pid int) []int {
	entries, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range entries {
		if c, err := strconv.Atoi(e.Name()); err == nil {
			if pp, err := readParsedStat(c); err == nil && pp == pid {
				out = append(out, c)
			}
		}
	}
	return out
}

// useRealScheduler makes the exchange read the kernel's counters of the helper, for one test.
func useRealScheduler(t *testing.T) {
	t.Helper()
	before := readScheduler
	readScheduler = procScheduler
	t.Cleanup(func() { readScheduler = before })
}

// useClass decides the class of every location of one test, in place of the mount table (which has its own tests).
func useClass(t *testing.T, local bool) {
	t.Helper()
	before := readLocal
	readLocal = func([]string) bool { return local }
	t.Cleanup(func() { readLocal = before })
}

func slowCheck(t *testing.T, op string, answerAfter time.Duration) (string, time.Duration, *budget, error) {
	t.Helper()
	ctx, cancel := WithBudget(context.Background())
	defer cancel()
	ctx, closeSession := WithHelperSession(ctx)
	defer closeSession()
	ctx = WithLocations(ctx, "/data/contracts")
	begin := time.Now()
	body, err := helperOp(t, ctx, op, answerAfter.String())
	return string(body), time.Since(begin), budgetOf(ctx), err
}

// A helper in uninterruptible sleep (state D, which is what a wait for the disk is) that answers after the location
// budget, on a local filesystem, is waited for and its answer is used.
func TestRealHelperInDiskWaitOnALocalFilesystemIsWaitedFor(t *testing.T) {
	requireDiskWait(t)
	useLocationTimeout(t, 300*time.Millisecond)
	useRealScheduler(t)
	useClass(t, true)
	body, took, b, err := slowCheck(t, "test-disk-wait", 700*time.Millisecond) // more than two budgets, less than the local cap of six
	if err != nil || body != "" {
		t.Fatalf("a wait for a local disk was refused after %v: %q %v", took, body, err)
	}
	if !granted(b) {
		t.Fatalf("the helper was not given a step past its first budget (extra %v, local extra %v)", b.extra, b.localExtra)
	}
}

// granted says the scope gave the check a step past its first budget; spent says it gave every step there is.
func granted(b *budget) bool {
	return b.extra < locationCap()-locationTimeout || b.localExtra < localCap()-locationCap()
}
func spent(b *budget) bool { return b.extra == 0 && b.localExtra == 0 }

// A helper still in that wait at the local cap is refused in the disk's words, never the mount's, after every step of the
// local cap (6 budgets) was given and not only the ordinary 4. The proof is the scope's own account, not a stopwatch.
func TestRealHelperInDiskWaitPastTheLocalCapIsTheBusyDisk(t *testing.T) {
	requireDiskWait(t)
	useLocationTimeout(t, 300*time.Millisecond)
	useRealScheduler(t)
	useClass(t, true)
	_, took, b, err := slowCheck(t, "test-disk-wait", 6*time.Second)
	gone(t, err, CheckDisk, UnavailableLocation)
	if !IsCheckDisk(err) || IsLocationUnavailable(err) || strings.Contains(err.Error(), "stuck mount") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("typed answer: %v", err)
	}
	if !spent(b) || took < 1700*time.Millisecond {
		t.Fatalf("refused after %v with extra %v and local extra %v left: not every step of the local cap was given", took, b.extra, b.localExtra)
	}
}

// A location that may stop answering is exactly as it was, whatever the helper is in: the first budget, the mount's
// words, no extension (nothing was granted).
func TestRealHelperInDiskWaitOnAMountThatMayStopKeepsTheMountWords(t *testing.T) {
	requireDiskWait(t)
	useLocationTimeout(t, 300*time.Millisecond)
	useRealScheduler(t)
	useClass(t, false)
	_, _, b, err := slowCheck(t, "test-disk-wait", 700*time.Millisecond)
	gone(t, err, UnavailableLocation, "disk")
	if !IsLocationUnavailable(err) || IsCheckDisk(err) || !errors.Is(err, context.DeadlineExceeded) || granted(b) {
		t.Fatalf("typed answer %v, granted %v", err, granted(b))
	}
}

// A helper that is only asleep (state S: Tego's own code waiting on something that is not the disk) on a LOCAL location
// is not called a busy disk: it has today's words at today's budget, like every class (nothing was granted).
func TestRealHelperAsleepOnALocalFilesystemKeepsTodaysVerdict(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useRealScheduler(t)
	useClass(t, true)
	_, _, b, err := slowCheck(t, "test-slow-answer", 700*time.Millisecond)
	gone(t, err, UnavailableLocation, "disk")
	if !IsLocationUnavailable(err) || IsCheckDisk(err) || !errors.Is(err, context.DeadlineExceeded) || granted(b) {
		t.Fatalf("typed answer %v, granted %v", err, granted(b))
	}
}

// With no location declared at all the check is as it always was.
func TestRealHelperWithNoLocationDeclaredKeepsTheMountWords(t *testing.T) {
	requireDiskWait(t)
	useLocationTimeout(t, 300*time.Millisecond)
	useRealScheduler(t)
	before := readLocal
	readLocal = func([]string) bool {
		t.Fatal("the mount table was read for a check that declared no location")
		return true
	}
	t.Cleanup(func() { readLocal = before })
	ctx, cancel := WithBudget(context.Background())
	defer cancel()
	ctx, closeSession := WithHelperSession(ctx)
	defer closeSession()
	_, err := helperOp(t, ctx, "test-disk-wait", "700ms")
	gone(t, err, UnavailableLocation, "disk")
}

// The wait function of a helper cannot be read (the kernel hides it for an undumpable process): for a local location in
// state D that does not matter, the helper is waiting for the disk.
func TestLocalDiskWaitIsGivenMoreTimeWhateverTheWaitFunctionSays(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useClass(t, true)
	for name, f := range map[string]*fakeScheduler{
		"in uninterruptible sleep, wait function hidden":    {state: 'D', wchan: ""},
		"in uninterruptible sleep, wait function '0'":       {state: 'D', wchan: "0"},
		"in uninterruptible sleep, a name not in the table": {state: 'D', wchan: "some_unknown_wait"},
		"a thread in the disk":                              {state: 'D', wchan: "jbd2_log_wait_commit"},
	} {
		t.Run(name, func(t *testing.T) {
			useScheduler(t, f)
			ctx := withScriptedBudget(t, WithLocations(context.Background(), "/data"), scopeOf(10*time.Second), func(w *scriptedWorker) {
				w.sendHeader(t)
				w.readRequest(t)
				w.sendReady(t)
				time.Sleep(800 * time.Millisecond) // more than two budgets, less than the local cap of six
				w.sendReply(t, "answer")
			})
			ctx = withClass(ctx)
			begin := time.Now()
			body, err := exchange(ctx, []byte("request"))
			if err != nil || string(body) != "answer" {
				t.Fatalf("a slow answer of a local location was refused after %v: %q %v", time.Since(begin), body, err)
			}
		})
	}
}

// A thread that does wait in a network or user-space filesystem keeps the mount words even for a location that was
// classed local: the wait function can make a verdict more exact, never less.
func TestLocalLocationWaitingInAMountKeepsTheMountWords(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useClass(t, true)
	useScheduler(t, &fakeScheduler{state: 'D', wchan: "nfs_wait_bit_killable"})
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, WithLocations(context.Background(), "/data"), scopeOf(10*time.Second), blockedWorker(t, release))
	ctx = withClass(ctx)
	holdsSlot(t, ctx, "@test-local-in-a-mount")
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	gone(t, err, UnavailableLocation, "disk")
	if !IsLocationUnavailable(err) || granted(budgetOf(ctx)) {
		t.Fatalf("typed answer %v after %v, granted %v", err, time.Since(begin), granted(budgetOf(ctx)))
	}
	if !stuckAt("@test-local-in-a-mount") {
		t.Fatal("a helper blocked in a mount was not recorded as holding its slot")
	}
}

// A local helper still silent at the local cap is refused in the disk's words, and still holds its slot: the stuck
// helper accounting is the same for both classes.
func TestLocalLocationPastTheLocalCapIsTheBusyDiskAndHoldsItsSlot(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useClass(t, true)
	useScheduler(t, &fakeScheduler{state: 'D'}) // hidden wait function, as for every undumpable helper
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, WithLocations(context.Background(), "/data"), scopeOf(10*time.Second), blockedWorker(t, release))
	ctx = withClass(ctx)
	holdsSlot(t, ctx, "@test-local-cap")
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	gone(t, err, CheckDisk, UnavailableLocation)
	if !IsCheckDisk(err) || waited < 1700*time.Millisecond {
		t.Fatalf("typed answer %v after %v, want the disk words at the local cap (1.8s)", err, waited)
	}
	if !stuckAt("@test-local-cap") {
		t.Fatal("a local helper that did not answer was not recorded as holding its slot")
	}
	b := budgetOf(ctx)
	if b.extra != 0 || b.localExtra != 0 {
		t.Fatalf("the budget was not used up to the local cap: %v %v", b.extra, b.localExtra)
	}
	// The scope's later checks refuse at once, in the same words.
	begin = time.Now()
	_, err = exchange(ctx, []byte("again"))
	if !IsCheckDisk(err) || time.Since(begin) > 100*time.Millisecond {
		t.Fatalf("a later check of the scope: %v after %v", err, time.Since(begin))
	}
}

// A local check in a request scope is refused in the disk's words at the request's bound, with the part of a step
// that is left to it, not a step short.
func TestLocalLocationIsBoundedByTheRequestScope(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useClass(t, true)
	useScheduler(t, &fakeScheduler{state: 'D'})
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, WithLocations(context.Background(), "/data"), requestScopeOf(1000*time.Millisecond), blockedWorker(t, release))
	ctx = withClass(ctx)
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	if !IsCheckDisk(err) || waited < 900*time.Millisecond || waited > 10*time.Second {
		t.Fatalf("a local check in a request bounded at 1s: %v after %v", err, waited)
	}
}

// What is given to which class: the ordinary cap to every check, the local cap only to a local one, and never past it.
func TestBudgetGrantsTheLocalCapOnlyToLocalChecks(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	for _, c := range []struct {
		local bool
		want  time.Duration
	}{{false, locationCap() - locationTimeout}, {true, localCap() - locationTimeout}} {
		b := scopeOf(time.Second)
		var total time.Duration
		for i := 0; i < 20; i++ {
			total += b.grant(c.local)
		}
		if total != c.want {
			t.Fatalf("local=%v: granted %v, want %v", c.local, total, c.want)
		}
	}
	// A scope that spent the ordinary cap on a mount's check still gives a later local check the rest.
	b := scopeOf(time.Second)
	for b.grant(false) > 0 {
	}
	if got := b.grant(true); got != locationTimeout {
		t.Fatalf("a local check after the ordinary cap was spent: %v, want a step", got)
	}
	if localCap() != 6*locationTimeout || StartTimeout != 6*CheckTimeout {
		t.Fatalf("the local cap %v is not six budgets and the start-up budget", localCap())
	}
}

// The helper's own bound for one contract's source is the local one for a local location, and an interrupted source
// says the disk's words, not the mount's.
func TestInterruptedSourceOfALocalLocationSaysTheDisksWords(t *testing.T) {
	useLocationTimeout(t, 100*time.Millisecond)
	_, o := fixture(t)
	ctx := context.WithValue(context.Background(), localKey{}, true)
	c := Catalog{machine: o.Machine}
	e := Entry{Path: "/data/contract.yaml"}
	begin := time.Now()
	c.checkSource(ctx, &e, o, func(ctx context.Context, _ string, _ rulefile.Guard) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	waited := time.Since(begin)
	if waited < 550*time.Millisecond || waited > 10*time.Second {
		t.Fatalf("a local source was interrupted after %v, want the local bound (600ms)", waited)
	}
	if e.State != "incomplete" || !c.Incomplete || len(e.Diagnostics) == 0 {
		t.Fatalf("not reported: %+v", e)
	}
	msg := e.Diagnostics[len(e.Diagnostics)-1].Message
	if !strings.Contains(msg, CheckDisk) || strings.Contains(msg, "stuck mount") {
		t.Fatalf("the words of a local source that was interrupted: %q", msg)
	}
}

// The locations a check is classed by are the ones its caller declared and the ones its request names; a relative one
// cannot be placed in the mount table, which is then not even read.
func TestClassOfACheckIsDecidedFromItsDeclaredAndOwnLocations(t *testing.T) {
	var asked [][]string
	before := readLocal
	readLocal = func(p []string) bool { asked = append(asked, append([]string(nil), p...)); return true }
	t.Cleanup(func() { readLocal = before })
	ctx := WithLocations(WithLocations(context.Background(), "/home/u/.tego", ""), "/home/u/.tego", "/srv/ledger")
	req := checkRequest{Operation: "source", Entry: Entry{Path: "/work/agent.yaml"}}
	req.Places.Dir = "/work"
	if !localCheck(withClass(ctx, requestLocations(&req)...)) {
		t.Fatal("not local")
	}
	if len(asked) != 1 || strings.Join(asked[0], " ") != "/home/u/.tego /srv/ledger /work/agent.yaml /work" {
		t.Fatalf("the table was asked about %q", asked)
	}
	if localCheck(withClass(context.Background())) || len(asked) != 1 {
		t.Fatal("a check with no location is local, or asked the table about none")
	}
	if localCheck(withClass(WithLocations(context.Background(), "/a", "relative/b"))) || len(asked) != 1 {
		t.Fatal("a relative location was placed, or the table was read for it")
	}
	if localCheck(context.Background()) {
		t.Fatal("a context nobody classified is local")
	}
}

// A helper that is only asleep on a local location, or whose counters cannot be read, has today's verdict at today's
// budget: the mount words, and the words that claim neither cause. Not the disk's.
func TestLocalLocationAsleepOrUnreadableKeepsTodaysVerdict(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useClass(t, true)
	for name, c := range map[string]struct {
		f     *fakeScheduler
		words string
		is    func(error) bool
	}{
		"asleep":              {&fakeScheduler{state: 'S'}, UnavailableLocation, IsLocationUnavailable},
		"counters unreadable": {&fakeScheduler{err: ErrNoSchedstat}, CheckUnclear, IsCheckUnclear},
	} {
		t.Run(name, func(t *testing.T) {
			useScheduler(t, c.f)
			release := make(chan struct{})
			defer close(release)
			ctx := withScriptedBudget(t, WithLocations(context.Background(), "/data"), scopeOf(10*time.Second), blockedWorker(t, release))
			ctx = withClass(ctx)
			begin := time.Now()
			_, err := exchange(ctx, []byte("request"))
			waited := time.Since(begin)
			gone(t, err, c.words, "disk")
			if !c.is(err) || IsCheckDisk(err) || granted(budgetOf(ctx)) {
				t.Fatalf("typed answer %v after %v, want today's verdict at the first budget (nothing granted)", err, waited)
			}
		})
	}
}

// Slow local checks at once take the pool's slots like any other, and give them back when their helper is abandoned.
// The check that finds the slots held ends in the disk's words whichever way it ends (served by a slot a refused check
// returned and refused at its own local cap, or refused at once for the stuck holders): never the mount's, which no
// holder is stuck on. The assertions are on words and on the pool, not on timing.
func TestSeveralSlowLocalChecksDoNotStarveThePool(t *testing.T) {
	requireDiskWait(t)
	useLocationTimeout(t, 300*time.Millisecond)
	useRealScheduler(t)
	useClass(t, true)
	allWorkers, governed := processWorkers, governedWorkers
	processWorkers, governedWorkers = helperPools(2)
	t.Cleanup(func() { processWorkers, governedWorkers = allWorkers, governed })
	type result struct {
		took time.Duration
		err  error
	}
	results := make(chan result, 3)
	for range 3 {
		go func() {
			_, took, _, err := slowCheck(t, "test-disk-wait", 4*time.Second)
			results <- result{took, err}
		}()
	}
	var tooks []time.Duration
	for range 3 {
		r := <-results
		if !IsCheckDisk(r.err) {
			t.Fatalf("a slow local check ended with %v after %v, want the disk words", r.err, r.took)
		}
		tooks = append(tooks, r.took)
	}
	if longest := slices.Max(tooks); longest > 20*time.Second {
		t.Fatalf("a check ended after %v: %v", longest, tooks)
	}
	// Every slot is back in the pool, so the next check is served at once.
	if len(processWorkers) != 0 {
		t.Fatalf("%d slots of the pool are still taken after every check ended", len(processWorkers))
	}
}

// A dashboard request that waits the full local bound still answers inside its own limit: the refusal comes at the
// request's bound, with the disk's words and time left to write the page.
func TestRealHelperInDiskWaitEndsAtTheRequestsBound(t *testing.T) {
	requireDiskWait(t)
	useLocationTimeout(t, 300*time.Millisecond)
	useRealScheduler(t)
	useClass(t, true)
	ctx := WithRequestScope(context.Background(), 1500*time.Millisecond)
	ctx, closeSession := WithHelperSession(ctx)
	defer closeSession()
	ctx = WithLocations(ctx, "/data/contracts")
	begin := time.Now()
	_, err := helperOp(t, ctx, "test-disk-wait", "6s")
	took := time.Since(begin)
	if !IsCheckDisk(err) || took < 1400*time.Millisecond || took > 10*time.Second {
		t.Fatalf("a local check in a request bounded at 1.5s: %v after %v", err, took)
	}
	if left, ok := ScopeLeft(ctx); !ok || left < -200*time.Millisecond {
		t.Fatalf("the request's bound was overrun: %v left", left)
	}
}

// A caller that asked to be told (the command line) hears once, when a local disk's wait goes past its first budget;
// a check that answers inside the first budget, or one of a location that may stop answering, says nothing.
func TestLocalDiskWaitIsToldToTheCallerOnce(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useScheduler(t, &fakeScheduler{state: 'D'})
	for name, c := range map[string]struct {
		local bool
		after time.Duration
		want  int
	}{"slow local": {true, 800 * time.Millisecond, 1}, "quick local": {true, 50 * time.Millisecond, 0}, "slow mount": {false, 800 * time.Millisecond, 0}} {
		t.Run(name, func(t *testing.T) {
			useClass(t, c.local)
			var notes []string
			base := WithWaitNote(WithLocations(context.Background(), "/data"), func(m string) { notes = append(notes, m) })
			release := make(chan struct{})
			defer close(release)
			script := func(w *scriptedWorker) {
				w.sendHeader(t)
				w.readRequest(t)
				w.sendReady(t)
				time.Sleep(c.after)
				w.sendReply(t, "answer")
			}
			if !c.local {
				script = blockedWorker(t, release) // refused at the first budget, never answered
			}
			ctx := withScriptedBudget(t, base, scopeOf(10*time.Second), script)
			ctx = withClass(ctx)
			_, err := exchange(ctx, []byte("request"))
			if c.local && err != nil || len(notes) != c.want || c.want == 1 && notes[0] != DiskWaitNote {
				t.Fatalf("err %v, notes %q, want %d", err, notes, c.want)
			}
		})
	}
}

// A request that finds every slot held by helpers this process abandoned says what holds them: the disk's words when every
// holder is stuck on this computer's disk, the mount's when any one is stuck on a mount (the stricter reading wins:
// nobody is told the disk is busy while a slot is held by a mount that does not answer). The refusal is at once, as
// it always was. No helper, no timing: the holders are records of this process's own stuck checks.
func TestRefusalForStuckHoldersSaysWhatHoldsTheSlots(t *testing.T) {
	for name, c := range map[string]struct {
		disk     [2]bool
		wantDisk bool
	}{
		"all on the disk":                 {[2]bool{true, true}, true},
		"one on a mount, one on the disk": {[2]bool{true, false}, false},
		"all on a mount":                  {[2]bool{false, false}, false},
	} {
		t.Run(name, func(t *testing.T) {
			names := stuckPool(t, 2)
			for i, n := range names {
				markStuck(&helperWorker{slot: n, pid: os.Getpid(), start: processStart(os.Getpid())}, c.disk[i])
			}
			ctx, closeSession := WithHelperSession(context.Background())
			defer closeSession()
			ctx = context.WithValue(ctx, budgetKey{}, &budget{startup: 20 * time.Second, location: 5 * time.Second})
			begin := time.Now()
			_, err := exchange(ctx, nil)
			if took := time.Since(begin); took > 3*time.Second {
				t.Fatalf("a pool full of stuck checks waited %v before it refused", took)
			}
			if !IsHelpersStuck(err) || !errors.Is(err, context.DeadlineExceeded) || IsStartupUnavailable(err) {
				t.Fatalf("not the refusal for stuck holders: %v", err)
			}
			if c.wantDisk {
				gone(t, err, CheckDisk, UnavailableLocation)
				if !IsCheckDisk(err) || IsLocationUnavailable(err) || !strings.Contains(err.Error(), "2 earlier checks are still waiting for this computer's disk") {
					t.Fatalf("every holder is stuck on the disk, and the refusal says: %v", err)
				}
			} else {
				gone(t, err, UnavailableLocation, CheckDisk)
				if IsCheckDisk(err) || !IsLocationUnavailable(err) || !strings.Contains(err.Error(), "2 earlier checks are still stuck on a location") {
					t.Fatalf("a holder is stuck on a mount, and the refusal says: %v", err)
				}
			}
		})
	}
}

// A command makes a scope for each of its checks (tego contracts sets none), and says it waits for the disk once: two slow
// local checks under one note are one note.
func TestDiskWaitNoteIsOncePerCommandNotPerCheck(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useScheduler(t, &fakeScheduler{state: 'D'})
	useClass(t, true)
	var notes []string
	base := WithWaitNote(WithLocations(context.Background(), "/data"), func(m string) { notes = append(notes, m) })
	for range 2 {
		ctx := withScriptedBudget(t, base, scopeOf(10*time.Second), func(w *scriptedWorker) { // a scope of its own each
			w.sendHeader(t)
			w.readRequest(t)
			w.sendReady(t)
			time.Sleep(800 * time.Millisecond)
			w.sendReply(t, "answer")
		})
		if _, err := exchange(withClass(ctx), []byte("request")); err != nil {
			t.Fatal(err)
		}
	}
	if len(notes) != 1 {
		t.Fatalf("two slow local checks of one command said %q", notes)
	}
}
