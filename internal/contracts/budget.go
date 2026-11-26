// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"errors"
	"sync"
	"time"
)

// budget is what one scope (a command, a dashboard page request) may spend on helper exchanges: the start-up budget
// (StartTimeout) and the location budget (CheckTimeout) are each spent once for the whole scope, as the single
// five-second deadline of a page was, so a stuck mount cannot cost a page one full interval per check.
type budget struct {
	mu       sync.Mutex
	startup  time.Duration
	location time.Duration
	// extra is what the scope may still be granted on top of its location budget, one step at a time, while a
	// helper that ran out of its budget was starved of a CPU (see Watch): the scope's total is capped at
	// locationCap(), however many checks it makes.
	extra time.Duration
	// localExtra is what a check of a local location (ADR 0144, "A local location is a busy disk, not a stuck mount")
	// may be granted on top of extra, up to localCap(): a local disk does answer, so its wait is bounded
	// longer than a mount's. It is drawn on only after extra, and only by a check whose location is local.
	localExtra time.Duration
	// noted says the scope's caller has been told it waits for a local disk (noteDiskWait).
	noted bool
	// asked says a helper of this scope has reported it was about to touch a location.
	asked bool
	// until is when a request scope (WithRequestScope) must be done with its helper exchanges, the zero time for a
	// scope with no such bound: the start-up wait, the location time (extensions included) and a compile's pause of
	// every exchange of the scope end by it, whatever their own budgets would still allow.
	until time.Time
	// startRefused is the first refusal of a check of this scope before its helper was ready (the pool at capacity, a
	// checker that did not start): once the scope's time or start-up budget is spent, its later checks refuse in the
	// same words, which say why, and not in words about the time being spent.
	startRefused error
	// refused is the refusal a check of this scope ended in after its helper had said it was ready: the scope's later
	// checks refuse at once in the same words, without starting a helper.
	refused error
}

// locationTimeout is CheckTimeout, a variable so a test whose worker is traced system call by system call (the
// lifecycle test's ptrace tracer, which a busy machine starves) can give the location the time such a worker needs.
var locationTimeout = CheckTimeout

type budgetKey struct{}

// locationCapSteps is how many location budgets the cap is, and so how many a helper may be given in all.
const locationCapSteps = 4

// locationCap is the most location time one scope (or a check outside any) may be given in all, however starved its
// helpers are: four of the location budgets, 20 s. A starved helper is given another locationTimeout at the end of
// each budget while the kernel's counters still say starved, until the cap.
func locationCap() time.Duration { return locationCapSteps * locationTimeout }

// workerBackstop is how long past the cap a worker's own clock lives. The caller's clock decides when a check ends
// (it is the one that reads the kernel's counters); the worker's is only the backstop that ends an operation whose
// caller has gone, so it must never end first.
func workerBackstop() time.Duration { return locationTimeout / 5 }

// localCapSteps is how many location budgets the cap of a local location is: six, which is StartTimeout (30 s) with
// the budgets at their production size. A local location is a filesystem of this computer's own storage: its disk
// answers in the end however busy it is, so it is waited for as long as a request may wait for a checker to start.
const localCapSteps = 6

// localCap is the most location time one scope may be given for checks of local locations. It is never less than
// locationCap(). A request scope's own bound (WithRequestScope) still ends a check before it where it is shorter.
func localCap() time.Duration { return max(localCapSteps*locationTimeout, locationCap()) }

func newBudget() *budget {
	return &budget{startup: startTimeout, location: locationTimeout, extra: locationCap() - locationTimeout,
		localExtra: localCap() - locationCap()}
}

func budgetOf(ctx context.Context) *budget {
	b, _ := ctx.Value(budgetKey{}).(*budget)
	return b
}

// WithBudget makes ctx a scope whose helper exchanges share one start-up budget and one location budget; the outer
// deadline (their sum, and the longest a paused helper is waited for, PauseLimit) is only a backstop. A ctx that is already a scope is returned bounded again, not reset.
func WithBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(WithScope(ctx), startTimeout+locationTimeout+PauseLimit)
}

// WithScope makes ctx a scope (see WithBudget) with no deadline of its own: the two budgets bound what the scope's
// helper exchanges can spend, so the outer deadline is not needed, and a caller with no place to cancel one (a
// request's context at its entry point) uses this. A ctx that is already a scope is returned as it is.
func WithScope(ctx context.Context) context.Context {
	if budgetOf(ctx) == nil {
		ctx = context.WithValue(ctx, budgetKey{}, newBudget())
	}
	return ctx
}

// WithRequestScope is WithScope for a request that must be answered within a time of its own: a dashboard page, whose
// server stops writing when its write deadline passes and then closes the connection with no response at all. The
// scope's helper exchanges together end by now+within, however much start-up and location budget they would otherwise
// have (a pool at capacity waits 30 s for a slot, a starved helper 20 s more), so the page can still say what
// happened. The caller derives within from the server's own write deadline. A ctx that is already a scope is returned
// as it is.
func WithRequestScope(ctx context.Context, within time.Duration) context.Context {
	if budgetOf(ctx) == nil {
		b := newBudget()
		b.until = time.Now().Add(within)
		ctx = context.WithValue(ctx, budgetKey{}, b)
	}
	return ctx
}

// ScopeLeft is how long the request scope of ctx has left, and whether it has a bound at all (WithRequestScope).
func ScopeLeft(ctx context.Context) (time.Duration, bool) {
	if b := budgetOf(ctx); b != nil {
		return b.untilLeft()
	}
	return 0, false
}

// untilLeft is the time to the scope's bound, and whether it has one.
func (b *budget) untilLeft() (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.until.IsZero() {
		return 0, false
	}
	return time.Until(b.until), true
}

// SameScope reports whether a and b are in the same scope: their helper exchanges spend the same budgets.
func SameScope(a, b context.Context) bool {
	x := budgetOf(a)
	return x != nil && x == budgetOf(b)
}

// LocationLeft is how long a helper exchange of ctx may still spend on the location once its helper is ready, before
// the kernel's counters are asked whether it was starved.
func LocationLeft(ctx context.Context) time.Duration {
	if b := budgetOf(ctx); b != nil {
		_, left := b.left()
		return left
	}
	return locationTimeout
}

// workerWithin is how long the worker's own clock runs for a request of ctx: the budget and what a helper may be
// granted (the local steps only for a check of a local location, so a check of any other class has the worker clock it
// always had), and the backstop. The worker never ends before its caller.
func workerWithin(ctx context.Context) time.Duration {
	local := localCheck(ctx)
	if b := budgetOf(ctx); b != nil {
		return b.within(local)
	}
	if local {
		return localCap() + workerBackstop()
	}
	return locationCap() + workerBackstop()
}

func (b *budget) left() (startup, location time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.startup, min(b.location, locationTimeout)
}

func (b *budget) chargeStart(spent time.Duration) {
	b.mu.Lock()
	b.startup -= spent
	b.mu.Unlock()
}

// minLocalStep is the least window a local location's last extension may be: a shorter one, before the request's own
// bound, says nothing.
const minLocalStep = 100 * time.Millisecond

// grant adds one more step to the location budget while the cap allows it, and says how much it added (0 at the
// cap). local says the check's location is a local one, which may be given the steps up to localCap() and not only
// to locationCap().
func (b *budget) grant(local bool) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	avail := b.extra
	if local {
		avail += b.localExtra
	}
	step := min(locationTimeout, avail)
	// Extensions are whole steps, and never past the request's own bound: a helper that is starved or working when the
	// scope has less than a step left is refused as one starved or working to the cap, at once, instead of being given
	// a window too short to say anything about. A local location's last step may be the part of a step that is left to
	// the bound: its disk is not judged by a window, it is waited for.
	if !b.until.IsZero() {
		if left := time.Until(b.until); left < step {
			if !local || left < minLocalStep {
				return 0
			}
			step = left
		}
	}
	if step <= 0 {
		return 0
	}
	fromExtra := min(step, b.extra)
	b.extra -= fromExtra
	b.localExtra -= step - fromExtra
	b.location += step
	return step
}

// within is the most a worker's clock may run for this scope: what is left of the budget and everything that may
// still be granted to a check of this class (local: with the local steps), and the backstop.
func (b *budget) within(local bool) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if local {
		return max(b.location, 0) + b.extra + b.localExtra + workerBackstop()
	}
	return max(b.location, 0) + b.extra + workerBackstop()
}

// refuse records the refusal the scope's checks end in from now on.
func (b *budget) refuse(err error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refused == nil {
		b.refused = err
	}
	return err
}

// refuseStart records the first refusal before a helper was ready.
func (b *budget) refuseStart(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.startRefused == nil {
		b.startRefused = err
	}
}

func (b *budget) startRefusal() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.startRefused
}

func (b *budget) refusal() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.refused
}

func (b *budget) chargeLocation(spent time.Duration) {
	b.mu.Lock()
	b.location -= spent
	b.mu.Unlock()
}

// firstNote is true once for the scope.
func (b *budget) firstNote() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	was := b.noted
	b.noted = true
	return !was
}

func (b *budget) markAsked() {
	b.mu.Lock()
	b.asked = true
	b.mu.Unlock()
}

// refuseExpired is the refusal for a ctx that is done before a helper exchange begins, nil while it is not. Its
// deadline passed before the location was asked (this scope has asked none), or after an earlier check of the scope
// had: the first is the checker not starting in time, the second a location that did not answer.
func refuseExpired(ctx context.Context) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	if b := budgetOf(ctx); errors.Is(err, context.DeadlineExceeded) && (b == nil || !b.wasAsked()) {
		return &startupError{err: err}
	}
	return CheckUnavailable(err)
}

// LocationAsked reports whether a helper of the scope ctx belongs to (WithBudget) has said it is about to touch a
// location. A caller that must end a request only after that point, not before (a test that stands in for a location
// that does not answer), waits for it: before it, a deadline is the checker not starting in time.
func LocationAsked(ctx context.Context) bool {
	b := budgetOf(ctx)
	return b != nil && b.wasAsked()
}

func (b *budget) wasAsked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.asked
}
