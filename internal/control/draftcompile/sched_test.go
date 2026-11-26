// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// The tests of this package never read the real scheduler: a busy machine would decide what they find. The compiler
// child is watched through a fake whose counters follow the wall clock by a share the test names. By default the
// child is asleep with no run-queue wait, as a child that is blocked is.
func init() { watchChild = (&fakeChild{state: 'S'}).watch }

type fakeChild struct {
	mu    sync.Mutex
	state byte
	wait  float64 // share of the elapsed time spent waiting for a CPU
	run   float64 // share of the elapsed time spent on a CPU
	err   error
	t0    time.Time
}

func (f *fakeChild) read(int, uint64) (map[int]contracts.Thread, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.t0.IsZero() {
		f.t0 = time.Now()
	}
	elapsed := time.Since(f.t0)
	return map[int]contracts.Thread{3: {State: f.state, Run: time.Duration(float64(elapsed) * f.run), Wait: time.Duration(float64(elapsed) * f.wait)}}, nil
}

func (f *fakeChild) watch(pid int, start uint64) *contracts.Watch {
	return contracts.NewWatchWith(f.read, pid, start, time.Now)
}

func useChild(t *testing.T, f *fakeChild) {
	t.Helper()
	before := watchChild
	watchChild = f.watch
	t.Cleanup(func() { watchChild = before })
}

// A compile that is still running when its budget ends, and was starved of a CPU for most of it, is given more time
// and finishes: the machine's slowness is not a compile that did not finish.
func TestStarvedCompileIsGivenMoreTimeAndFinishes(t *testing.T) {
	useChild(t, &fakeChild{state: 'R', wait: 0.9})
	ctx := within(t, 20*time.Second*raceScale, 400*time.Millisecond) // the child's 900 ms is not scaled
	b := ctx.Value(budgetKey{}).(*compileBudget)
	_, err := Check(ctx, Request{Text: []byte("slow-finish")}) // answers after 900 ms of a 400 ms budget
	if err != nil {
		t.Fatalf("a starved compile that finished inside the cap was refused: %v", err)
	}
	if b.extra != Cap-Budget-Budget {
		t.Fatalf("one step was granted: the request's extra is %v, want %v", b.extra, Cap-2*Budget)
	}
	waitSlots(t, 0)
}

// A compile that stays starved to the cap is refused as a check that did not finish because the machine is very busy,
// typed, wrapping the deadline, never as a contract that does not compile.
func TestStarvedCompilePastTheCapIsTooSlow(t *testing.T) {
	useChild(t, &fakeChild{state: 'R', wait: 0.9})
	ctx := within(t, 20*time.Second, 300*time.Millisecond)
	ctx.Value(budgetKey{}).(*compileBudget).extra = 500 * time.Millisecond // the cap, after this request's first budget
	begin := time.Now()
	_, err := Check(ctx, Request{Text: []byte("stall")})
	waited := time.Since(begin)
	if !contracts.IsCompileUnfinished(err) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), contracts.CompileUnfinished) ||
		strings.Contains(err.Error(), "does not compile") {
		t.Fatalf("a compile starved to the cap: %v", err)
	}
	if waited < 750*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("the cap ended after %v, want about 300ms + 500ms", waited)
	}
	waitSlots(t, 0)
}

// A compile whose child was asleep, or blocked in D, or whose counters cannot be read, is refused at the end of
// the budget, with no extension and in words that claim no cause: not "the machine is very busy".
func TestCompileThatWasNotStarvedClaimsNoCause(t *testing.T) {
	for name, f := range map[string]*fakeChild{
		"asleep":                  {state: 'S'},
		"uninterruptible sleep":   {state: 'D', wait: 0.9},
		"a little of each":        {state: 'S', wait: 0.1, run: 0.1},
		"uninterruptible running": {state: 'D', run: 0.9},
		"a kernel with no counts": {err: contracts.ErrNoSchedstat},
	} {
		t.Run(name, func(t *testing.T) {
			useChild(t, f)
			ctx := within(t, 20*time.Second, 300*time.Millisecond)
			begin := time.Now()
			_, err := Check(ctx, Request{Text: []byte("stall")})
			waited := time.Since(begin)
			if !contracts.IsCompileUnfinished(err) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), contracts.CompileNoAnswer) ||
				strings.Contains(err.Error(), "very busy") || strings.Contains(err.Error(), "does not compile") {
				t.Fatalf("a compile that was not starved: %v", err)
			}
			if waited < 250*time.Millisecond || waited > 1500*time.Millisecond {
				t.Fatalf("a compile that was not starved was refused after %v, want one budget (300ms)", waited)
			}
			waitSlots(t, 0)
		})
	}
}

// A compile that could not run is not a contract that does not compile: the words say the compiler was busy, or could
// not run, typed, with the reason kept; a real compile error still is one.
func TestCompileInfrastructureFailuresHaveTheirOwnWords(t *testing.T) {
	// Both compiler slots taken for the whole admission wait.
	done := make(chan error, cap(slots))
	ctx, cancel := context.WithCancel(t.Context())
	for range cap(slots) {
		go func() { _, err := Check(ctx, Request{Text: []byte("stall")}); done <- err }()
	}
	waitSlots(t, cap(slots))
	_, err := Check(WithGoverned(context.Background()), Request{Text: []byte("stall")})
	if !contracts.IsCompileUnfinished(err) || !strings.Contains(err.Error(), contracts.CompileBusy) || !strings.Contains(err.Error(), "busy, try again") ||
		strings.Contains(err.Error(), "does not compile") || strings.Contains(err.Error(), "very busy") {
		t.Fatalf("a full compiler slot: %v", err)
	}
	cancel()
	for range cap(slots) {
		<-done
	}
	waitSlots(t, 0)
	for name, text := range map[string]string{"a child that dies": "dies", "a child whose answer is no result": "garbage"} {
		_, err := Check(t.Context(), Request{Text: []byte(text)})
		if !contracts.IsCompileUnfinished(err) || !strings.Contains(err.Error(), contracts.CompileCouldNotRun) || strings.Contains(err.Error(), "does not compile") {
			t.Fatalf("%s: %v", name, err)
		}
		waitSlots(t, 0)
	}
}

// A compile child that was on a CPU for most of its budget is working, not stuck: it is given more time like a
// starved one, and finishes inside the cap.
func TestRunningCompileIsGivenMoreTimeAndFinishes(t *testing.T) {
	useChild(t, &fakeChild{state: 'R', run: 0.9})
	ctx := within(t, 20*time.Second*raceScale, 400*time.Millisecond)
	if _, err := Check(ctx, Request{Text: []byte("slow-finish")}); err != nil {
		t.Fatalf("a compile that was working and finished inside the cap was refused: %v", err)
	}
	waitSlots(t, 0)
}

// At the cap a compile that was working says so, in words that claim neither the machine nor a stuck compile.
func TestRunningCompilePastTheCapIsStillWorking(t *testing.T) {
	useChild(t, &fakeChild{state: 'R', run: 0.9})
	ctx := within(t, 20*time.Second, 300*time.Millisecond)
	ctx.Value(budgetKey{}).(*compileBudget).extra = 500 * time.Millisecond
	begin := time.Now()
	_, err := Check(ctx, Request{Text: []byte("stall")})
	waited := time.Since(begin)
	if !contracts.IsCompileUnfinished(err) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), contracts.CompileStillWorking) ||
		strings.Contains(err.Error(), "very busy") || strings.Contains(err.Error(), "does not compile") {
		t.Fatalf("a compile that was still working at the cap: %v", err)
	}
	if waited < 750*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("the cap ended after %v, want about 300ms + 500ms", waited)
	}
	waitSlots(t, 0)
}
