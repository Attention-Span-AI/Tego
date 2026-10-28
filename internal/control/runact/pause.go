// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// The words a pause or a resume returns (Paused.Word).
const (
	WordPaused        = "paused"
	WordAlreadyPaused = "already paused"
	WordResumed       = "resumed"
	WordNotPaused     = "was not paused"
)

// ErrPauseNotRunning is a pause or a resume asked of a run no launcher holds.
var ErrPauseNotRunning = errors.New("the run is not running, so there is nothing to pause or resume")

// ErrPauseUnsupported is a pause or a resume asked of a run whose launcher did not mark that it reads one
// (liveblock.TakesControl): a run an older Tego started, an adopted run, or one with no cgroup of its own. An older
// launcher refuses the whole live-block file once it lists a pause, so the pause would never take and every later
// live block of the run would stay waiting; nothing is written.
var ErrPauseUnsupported = errors.New("this run's launcher cannot pause it")

// Paused is what a pause or a resume asked.
type Paused struct {
	Run string
	// Word is what was asked, in the words the page shows (WordPaused, WordAlreadyPaused, WordResumed,
	// WordNotPaused). The launcher applies it within about half a second and writes the gap line that confirms it
	// (ledgerview.LiveFacts.Paused).
	Word string
	// Serial is the overlay's serial after the change: the launcher's gap line carrying it says it is in force.
	Serial uint64
}

// Pause asks run's launcher to freeze the run (on) or thaw it, as `tego pause` and `tego resume` do: it writes the
// pause or the resume into the run's overlay (internal/liveblock) under its lock, and the launcher, which owns the
// run's cgroup, applies it and records it; this package freezes nothing itself. It is refused for a run that is not
// running, and to a caller inside a run (SelfGoverned, failing closed): a governed agent may neither stop the work of
// a run nor start it again.
func Pause(ctx context.Context, root, run string, on bool) (Paused, error) {
	dir, err := runDir(root, run)
	if err != nil {
		return Paused{}, err
	}
	if in, _ := SelfGoverned(); in { // fails closed: a cgroup it cannot judge refuses too
		return Paused{}, fmt.Errorf("%w (run %s)", ErrGoverned, run)
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		return Paused{}, err
	}
	if !held {
		return Paused{}, ErrPauseNotRunning
	}
	if !liveblock.TakesControl(dir) {
		return Paused{}, fmt.Errorf("%w (run %s)", ErrPauseUnsupported, run)
	}
	out, by := Paused{Run: run}, liveblock.By("dashboard")
	o, err := liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		var ok bool
		if on {
			_, ok = o.Pause(by, time.Now())
			out.Word = map[bool]string{true: WordPaused, false: WordAlreadyPaused}[ok]
		} else {
			_, ok = o.Resume(by, time.Now())
			out.Word = map[bool]string{true: WordResumed, false: WordNotPaused}[ok]
		}
		return ok, nil
	})
	if o != nil {
		out.Serial = o.Serial
	}
	return out, err
}

// PauseAsk is what a run's overlay asks of its pause now: Paused, and the serial and time of the pause or resume that
// asked it (0 and zero when the overlay no longer lists it, or never had one). Takes is whether the run's launcher
// reads a pause at all (liveblock.TakesControl): a view offers Pause only then.
type PauseAsk struct {
	Takes  bool
	Paused bool
	Serial uint64
	At     time.Time
}

// PauseRequest is run's pause as its overlay asks it now, the request the launcher answers with a gap line, and
// whether its launcher reads one; only Takes when the run has no overlay or it cannot be read.
func PauseRequest(root, run string) PauseAsk {
	dir, err := runDir(root, run)
	if err != nil {
		return PauseAsk{}
	}
	a := PauseAsk{Takes: liveblock.TakesControl(dir)}
	o, err := liveblock.Read(dir, run)
	if err != nil {
		return a
	}
	a.Paused = o.Paused
	for _, c := range o.Changes {
		if c.Control() {
			a.Serial, a.At = c.Serial, c.At
		}
	}
	return a
}
