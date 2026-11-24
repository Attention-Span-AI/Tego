// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// StartAllowance bounds everything before the compiler child is running, for all the checks of one request: waiting
// for a compiler slot, computing the built-in grammar's fingerprint, starting the child and its report that it has
// read the draft and is about to compile it. A busy machine uses this time and none of Budget, and it is the same
// as the helper's start-up budget (contracts.StartTimeout): 30 s, times raceScale in a race build.
const StartAllowance = contracts.StartTimeout

// Cap is the most compile time one request may be given in all, however starved its compiler children are: 20 s, times
// raceScale in a race build. A child that is still running when its Budget ends is given another Budget while the
// kernel's counters for it say it was starved of a CPU (contracts.Watch), until the cap.
const Cap = 20 * time.Second * raceScale

type budgetKey struct{}
type compileBudget struct {
	gate chan struct{}
	// start is what is left of StartAllowance, remaining what is left of Budget, extra what may still be granted on
	// top of remaining while a child is starved.
	start     time.Duration
	remaining time.Duration
	extra     time.Duration
}

// WithBudget shares one total compilation/admission budget across a request's
// checks. Time spent publishing a file does not consume compilation time. The
// original request still controls cancellation of both compilation and writing.
func WithBudget(ctx context.Context) context.Context {
	if ctx.Value(budgetKey{}) != nil {
		return ctx
	}
	b := &compileBudget{gate: make(chan struct{}, 1), start: StartAllowance, remaining: Budget, extra: Cap - Budget}
	b.gate <- struct{}{}
	return context.WithValue(ctx, budgetKey{}, b)
}

// compilation is one check's use of the two budgets: the start-up allowance until its child is running, and the
// compile budget from then on. A request's checks (WithBudget) take turns and share what is left; a check outside
// one has both whole.
type compilation struct {
	parent             context.Context
	b                  *compileBudget
	startLeft, runLeft time.Duration
	extra, granted     time.Duration
	began, running     time.Time
}

// beginCompilation takes the request's turn: it waits for the check before it, within parent.
func beginCompilation(parent context.Context) (*compilation, error) {
	b, ok := parent.Value(budgetKey{}).(*compileBudget)
	if !ok {
		return &compilation{parent: parent, startLeft: StartAllowance, runLeft: Budget, extra: Cap - Budget}, nil
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	select {
	case <-parent.Done():
		return nil, parent.Err()
	case <-b.gate:
	}
	return &compilation{parent: parent, b: b, startLeft: b.start, runLeft: b.remaining, extra: b.extra}, nil
}

// exhausted is the error of a request whose start-up allowance or compile budget is already spent, nil otherwise.
func (c *compilation) exhausted() error {
	if c.startLeft <= 0 || c.runLeft <= 0 {
		return context.DeadlineExceeded
	}
	return nil
}

// startContext is the context of the start-up: it ends with what is left of the allowance.
func (c *compilation) startContext() (context.Context, context.CancelFunc) {
	c.began = time.Now()
	return context.WithTimeout(c.parent, c.startLeft)
}

// startRun starts the compile budget, at the moment the child is running, and says how long it is.
func (c *compilation) startRun() time.Duration {
	c.running = time.Now()
	return c.runLeft
}

// grant gives a child that ran out of its budget while it was starved another step of Budget, as much as the cap
// still allows, and says how much (0 at the cap).
func (c *compilation) grant() time.Duration {
	step := min(Budget, c.extra)
	if step <= 0 {
		return 0
	}
	c.extra -= step
	c.granted += step
	return step
}

// end charges what the check used and gives the request's turn to the next.
func (c *compilation) end() {
	if c.b == nil {
		return
	}
	if c.running.IsZero() {
		c.b.start -= time.Since(c.began)
	} else {
		c.b.start -= c.running.Sub(c.began)
		c.b.remaining += c.granted - time.Since(c.running)
		c.b.extra = c.extra
	}
	c.b.gate <- struct{}{}
}
