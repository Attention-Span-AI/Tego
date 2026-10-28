// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Clock is one reading of the two clocks a time limit is judged on (ADR 0125 decision 4): the wall clock, and
// CLOCK_BOOTTIME, which no clock step moves and which counts a suspend.
type Clock struct {
	Wall time.Time
	Boot time.Duration
}

// ReadClock reads both clocks now. A BOOTTIME that cannot be read (never on Linux) reads as 0, which no pin has
// passed: a limit then ends by the wall clock's side alone, as the rules of Ended and Begun say.
func ReadClock() Clock {
	var ts unix.Timespec
	c := Clock{Wall: time.Now()}
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) == nil {
		c.Boot = time.Duration(ts.Nano())
	}
	return c
}

// readClock is ReadClock, replaced in tests.
var readClock = ReadClock

// Pin is the BOOTTIME instant t falls at, read from c: the launcher pins each limit the first time it sees it and
// never derives it again, so a later wall-clock step does not move it.
func (c Clock) Pin(t time.Time) time.Duration { return c.Boot + t.Sub(c.Wall) }

// Ended reports whether a narrowing whose limit is t (pinned at pin when pinned) has ended at c: only when both clocks
// have passed it, so a wall clock stepped forward never ends a block early. A wall clock stepped back keeps it longer:
// a narrowing ends on the later side, and a step never shortens it.
func Ended(t time.Time, pin time.Duration, pinned bool, c Clock) bool {
	return !c.Wall.Before(t) && (!pinned || c.Boot >= pin)
}

// Begun reports whether the instant t (pinned at pin when pinned) has come at c on either clock: how a loosening's
// limit ends, and how a refusal comes back, so a clock step never lengthens a loosening.
func Begun(t time.Time, pin time.Duration, pinned bool, c Clock) bool {
	return !c.Wall.Before(t) || (pinned && c.Boot >= pin)
}

// The bounds of a time limit: a change made at at may end at until only when until-at is MinSpan to MaxSpan.
const (
	MinSpan = time.Minute
	MaxSpan = 400 * 24 * time.Hour
)

// CheckUntil refuses a limit until, set on a change made at at, that ends sooner than MinSpan or later than MaxSpan
// after it. The error wraps ErrInvalid and names the bounds.
func CheckUntil(at, until time.Time) error {
	d := until.Sub(at)
	if d < MinSpan || d > MaxSpan {
		return fmt.Errorf("%w: a time limit ends 1 minute to 400 days from now; %s is %s away", ErrInvalid,
			until.UTC().Format(time.RFC3339), d.Round(time.Second))
	}
	return nil
}

// checkSlack is how much sooner than MinSpan a limit may end when it is checked inside Update. A caller checks the
// limit it was asked for against its own now (runact, the CLI, the dashboard); the overlay's methods check it again
// against an at taken later, after a lock wait of up to 3 s and rounded to the millisecond, so a limit asked for at
// exactly MinSpan ("--for 1m") must not pass the first check and fail the second.
const checkSlack = 5 * time.Second

// checkUntilSlack is CheckUntil with checkSlack off its lower bound; its upper bound is unchanged, since a later at
// only brings until closer.
func checkUntilSlack(at, until time.Time) error {
	if d := until.Sub(at); d >= MinSpan-checkSlack && d < MinSpan {
		return nil
	}
	return CheckUntil(at, until)
}

// ErrNoTimeLimits is a time limit asked of a run whose launcher does not read one (its run_start's record_minor is below
// record.MinorLiveModes, or not known): that launcher would refuse the whole overlay once it held one and ignore every
// later change. Every writer (runact, `tego block`) refuses such a limit with these words.
var ErrNoTimeLimits = errors.New("this run was started by an older tego that has no time limits; place it without one, or restart the run")

// DeadlineKey names one limit of one entry: its key and the instant, "exec:/bin/ls@2026-11-14T17:00:00Z". The
// launcher keys its pins and the expiry lines it wrote by it, so a re-added block with a new limit gets its own.
func DeadlineKey(key string, t time.Time) string { return key + "@" + t.UTC().Format(time.RFC3339Nano) }
