// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"sync"
	"time"
)

// A compile is not the location (ADR 0144, "Compile time is not the location's time"). The helper's location budget
// is a clock that runs only while the helper touches the location. Work that does not touch it, the draft compiler
// that the rules service starts, pauses the clock with PauseLocation: the worker tells its caller (a pause frame
// naming the longest it may take), the caller stops its own clock, and both start it again, with the time that was
// left, when the work ends.

// PauseLimit is the most a caller waits for a paused worker, whatever the worker says it needs: the start-up allowance
// of a compile and its budget extended to its cap of 20 s (draftcompile), with room. A paused helper that does not resume within it is abandoned
// and refused in the words of a check that did not finish, never the mount's: nobody asked the location.
const PauseLimit = StartTimeout + 25*time.Second*raceScale

// locationClock is the worker's context for one operation: the helper's lifetime (its pipe) and a deadline that
// runs only while the clock is not paused. Its Err also looks at the pipe, as helperDeadlineContext's does, so a
// resumed read cannot miss a closed pipe because a watcher has not yet run.
type locationClock struct {
	context.Context // the helper's lifetime and the request's values
	mu              sync.Mutex
	timer           *time.Timer
	left            time.Duration
	since           time.Time
	paused          bool
	done            chan struct{}
	err             error
}

type helperClockKey struct{}

// newLocationClock starts a location clock of within on parent. cancel ends it as the context.CancelFunc of a
// deadline context does.
func newLocationClock(parent context.Context, within time.Duration) (*locationClock, context.CancelFunc) {
	c := &locationClock{Context: parent, left: within, since: time.Now(), done: make(chan struct{})}
	c.timer = time.AfterFunc(within, func() { c.finish(context.DeadlineExceeded) })
	go func() {
		select {
		case <-parent.Done():
			c.finish(parent.Err())
		case <-c.done:
		}
	}()
	return c, func() { c.finish(context.Canceled) }
}

func (c *locationClock) finish(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	c.err = err
	c.timer.Stop()
	close(c.done)
}

func (c *locationClock) Done() <-chan struct{} { return c.done }

func (c *locationClock) Err() error {
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return err
	}
	// The parent's Err looks at the helper's pipe itself, before any watcher has run.
	if perr := c.Context.Err(); perr != nil {
		c.finish(perr)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Deadline is when the clock ends if it is not paused again; none while it is paused.
func (c *locationClock) Deadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused || c.err != nil {
		return time.Time{}, false
	}
	return c.since.Add(c.left), true
}

func (c *locationClock) Value(key any) any {
	if key == (helperClockKey{}) {
		return c
	}
	return c.Context.Value(key)
}

func (c *locationClock) pause() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused || c.err != nil {
		return
	}
	c.timer.Stop()
	c.left -= time.Since(c.since)
	c.paused = true
}

func (c *locationClock) resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused || c.err != nil {
		return
	}
	c.paused = false
	c.since = time.Now()
	c.timer.Reset(max(c.left, 0))
}

// helperPauseKey carries the worker's way of telling its caller that the location clock stops and starts.
type helperPauseKey struct{}

type helperPauser struct {
	pause  func(max time.Duration) error
	resume func() error
}

// PauseLocation stops the location clock of the helper that runs ctx for as long as the returned function has not
// been called, and only while the caller says it can wait: max is the longest the paused work may take. Work that
// does not touch the location (a compile) runs under the returned context, which carries ctx's values and the
// helper's lifetime but no location deadline, so the work's own budgets are the only ones that apply. The returned
// function restarts the clock with the time that was left; it is safe to call more than once.
//
// Outside a helper (a test's direct call, a service run in its caller) there is no clock: ctx is returned and
// nothing changes. A pause that cannot be announced (the caller has gone) is not made.
func PauseLocation(ctx context.Context, max time.Duration) (context.Context, func()) {
	clock, ok := ctx.Value(helperClockKey{}).(*locationClock)
	pauser, hasPauser := ctx.Value(helperPauseKey{}).(*helperPauser)
	if !ok || !hasPauser || ctx.Err() != nil {
		return ctx, func() {}
	}
	if err := pauser.pause(min(max, PauseLimit)); err != nil {
		return ctx, func() {}
	}
	clock.pause()
	var once sync.Once
	return pausedContext{Context: clock.Context, values: ctx}, func() {
		once.Do(func() {
			_ = pauser.resume()
			clock.resume()
		})
	}
}

// pausedContext cancels as the helper's lifetime does and answers values as the operation's context does.
type pausedContext struct {
	context.Context
	values context.Context
}

func (c pausedContext) Value(key any) any { return c.values.Value(key) }

// WithHelperContext is WithHelperDeadline for a parent whose deadline is its own location clock, or none: the
// derived context ends with the parent and checks the helper's pipe as the parent does.
func WithHelperContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	lifetime, ok := parent.Value(helperLifetimeKey{}).(*helperLifetime)
	if !ok {
		return ctx, cancel
	}
	return helperDeadlineContext{Context: ctx, lifetime: lifetime, cancel: cancel}, cancel
}

// HasLocationClock reports whether ctx is, or derives from, a helper operation's location clock.
func HasLocationClock(ctx context.Context) bool {
	_, ok := ctx.Value(helperClockKey{}).(*locationClock)
	return ok
}
