// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
)

func TestCompilationBudgetCountsChecksOnly(t *testing.T) {
	ctx := WithBudget(t.Context())
	b := ctx.Value(budgetKey{}).(*compileBudget)
	b.remaining = 80 * time.Millisecond
	c, err := beginCompilation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, cancel := c.startContext(); cancel == nil {
		t.Fatal("no start context")
	} else {
		time.Sleep(20 * time.Millisecond) // the child starting: the allowance's time
		cancel()
	}
	if left := c.startRun(); left <= 0 || left > 80*time.Millisecond {
		t.Fatalf("the compile budget of the first check is %v", left)
	}
	c.end()
	remaining := b.remaining
	if b.start > StartAllowance-15*time.Millisecond || remaining < 40*time.Millisecond {
		t.Fatalf("start-up time was charged to the wrong budget: start %v, remaining %v", b.start, remaining)
	}
	time.Sleep(100 * time.Millisecond) // Writer time, outside compilation.
	second, err := beginCompilation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.end()
	second.startContext()
	if left := second.startRun(); left <= 0 || left > remaining {
		t.Fatalf("writer consumed compile budget: %v left of %v", left, remaining)
	}
}

func TestCompilationBudgetIsSharedAndCancellationRetained(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	ctx := WithBudget(parent)
	if WithBudget(ctx) != ctx {
		t.Fatal("nested planning reset the total budget")
	}
	b := ctx.Value(budgetKey{}).(*compileBudget)
	b.remaining = -time.Millisecond
	c, err := beginCompilation(ctx)
	if err != nil || !errors.Is(c.exhausted(), context.DeadlineExceeded) {
		t.Fatalf("exhausted budget was reset: %v %v", err, c.exhausted())
	}
	c.end()
	cancel()
	if _, err = beginCompilation(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("request cancellation lost: %v", err)
	}
}

func TestCompilerSharesExhaustedRequestBudget(t *testing.T) {
	ctx := WithBudget(t.Context())
	ctx.Value(budgetKey{}).(*compileBudget).remaining = -time.Millisecond
	_, err := Check(ctx, Request{})
	if !errors.Is(err, context.DeadlineExceeded) || !contracts.IsCompileUnfinished(err) {
		t.Fatalf("Check reset an exhausted request budget: %v", err)
	}
}

// within bounds a request's budgets to a test's own, as a request's WithBudget would at its start.
func within(t *testing.T, start, compile time.Duration) context.Context {
	t.Helper()
	ctx := WithBudget(t.Context())
	b := ctx.Value(budgetKey{}).(*compileBudget)
	b.start, b.remaining = start, compile
	return ctx
}

// A child that takes longer to start than the whole compile budget still compiles: the time a busy machine takes to
// run a new process is the start-up allowance's, and the compile budget starts when the child says it is running.
func TestSlowChildStartIsNotTheCompilesTime(t *testing.T) {
	ctx := within(t, 20*time.Second*raceScale, 400*time.Millisecond*raceScale)
	_, err := Check(ctx, Request{Text: []byte("slow-start")}) // the test child waits 900 ms before it reads its request
	if err == nil || contracts.IsCompileUnfinished(err) || !strings.Contains(err.Error(), "no machine config") {
		t.Fatalf("a slow child start was refused as a compile that did not finish: %v", err)
	}
	waitSlots(t, 0)
}

// A compile that never finishes is not a contract that does not compile: it is a refusal in the words of a check
// that did not finish, typed, and it still wraps the deadline. A child that only sleeps was not starved, so the words
// claim no cause (TestCompileThatWasNotStarvedClaimsNoCause has the others).
func TestCompileThatNeverFinishesIsNotAnError(t *testing.T) {
	ctx := within(t, 20*time.Second, 300*time.Millisecond)
	begin := time.Now()
	_, err := Check(ctx, Request{Text: []byte("stall")})
	if !contracts.IsCompileUnfinished(err) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), contracts.CompileNoAnswer) {
		t.Fatalf("a compile that did not finish: %v", err)
	}
	if strings.Contains(err.Error(), "does not compile") || time.Since(begin) < 250*time.Millisecond {
		t.Fatalf("wrong words or time (%v): %v", time.Since(begin), err)
	}
	waitSlots(t, 0)
}

// A child that never says it is running, within the start-up allowance, is refused in the same words.
func TestChildThatNeverStartsIsNotFinished(t *testing.T) {
	ctx := within(t, 300*time.Millisecond, 20*time.Second)
	_, err := Check(ctx, Request{Text: []byte("stall-before-ready")})
	if !contracts.IsCompileUnfinished(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a child that never started: %v", err)
	}
	waitSlots(t, 0)
}

// A caller that gives up gets the cancelled words, neither the deadline's nor a compile error's.
func TestCancelledCompileSaysItWasCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(200*time.Millisecond, cancel)
	_, err := Check(ctx, Request{Text: []byte("stall")})
	if !contracts.IsCompileUnfinished(err) || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), contracts.CompileCancelled) ||
		strings.Contains(err.Error(), contracts.CompileUnfinished) {
		t.Fatalf("cancelled compile: %v", err)
	}
	waitSlots(t, 0)
}

// A real compile error is still a contract that does not compile: Result.Error is no refusal of the typed words.
func TestRealCompileErrorIsNotUnfinished(t *testing.T) {
	_, err := Check(t.Context(), Request{})
	if err == nil || contracts.IsCompileUnfinished(err) {
		t.Fatalf("a compile error read as an unfinished one: %v", err)
	}
}
