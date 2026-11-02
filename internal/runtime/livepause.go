// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A person's pause and resume of a running run (record.MinorLiveControl). They ride the run's live-block overlay
// (liveblock.OpPause, OpResume): `tego pause`, `tego resume` and the dashboard's Pause write it, and the launcher,
// which polls it (watchLiveBlocks), applies each change in serial order by freezing or thawing the run's own cgroup
// (cgroup.freeze of run-<id>.scope, never anything above it) and writes one gap what=enforce line per change:
// run-paused or run-resumed once cgroup.events confirms it, pause-failed or resume-failed when it cannot. Every
// change the launcher applies has its line, a pause put in force from the overlay's own paused flag included (its
// change no longer listed). A failed change is tried again until the overlay asks otherwise, and its failure line is
// written once.
//
// A freeze can miss. The kernel's freezer cannot enter the killable wait of a task whose seccomp notification the
// supervisor has received (the listener uses SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV), so a freeze that lands while a
// notification is in flight never completes. Two cases matter:
//   - an ask held for a person: its thread waits until the person answers. No freeze is tried while one waits
//     (errAskWaiting); a pause asked then is recorded pause-failed, and put in force once the ask is answered. The
//     dashboard offers no Pause while a request waits.
//   - a held read: the open deputy is a process of the run's cgroup (ADR 0041 D2), so it can be frozen before it
//     answers, and the agent's thread waits on it. Each freeze is therefore a few short attempts (freezeAttempt),
//     thawed between them: each is a fresh chance to land between two reads.
//
// A freeze not confirmed is always thawed, so a pause-failed run is running, never half frozen; and a failed pause is
// tried again with a growing back-off (pauseRetryFirst to pauseRetryMax), so the agent runs nearly all the time
// rather than being frozen and thawed at the poll's pace.
//
// While a freeze is in force the budget watcher counts the run as held (limits.WithHeld), so stall_after does not end
// a paused run; wall time keeps counting. A stop thaws the run first (thawOnStop): a frozen agent cannot handle the
// SIGTERM that starts stop_grace, so it would sit out the whole grace and end killed. A run that ends while paused
// is thawed as its workers stop, so no frozen scope outlives it; the processes a kill ends die frozen or not, since a
// fatal signal ends a frozen task.

// The freezer this file drives; tests replace them, since a fake scope's cgroup.events never changes on its own.
var (
	freezeCgroup = cgroup.Freeze
	waitFrozen   = cgroup.WaitFrozenWithin
	// pauseAskWaiting is whether an ask holds a thread of the run for a person (runner.askWaiting); pauseNow the
	// clock of the retry back-off.
	pauseAskWaiting = (*runner).askWaiting
	pauseNow        = time.Now
)

// The shape of one freeze and of its retries.
const (
	// freezeAttempt is how long one attempt waits for cgroup.events to say frozen: a freeze takes milliseconds
	// (8.6 ms measured on a looping agent, under 100 ms on a busy one), so one that has not completed by then is
	// held by an in-flight notification, and a thaw and a fresh attempt does better than waiting.
	freezeAttempt = 100 * time.Millisecond
	// freezeGap is the thaw between two attempts: long enough for the deputy to answer the read it was holding.
	freezeGap = 20 * time.Millisecond
	// freezeBudget bounds all the attempts of one freeze: `tego pause` waits two seconds for the line, and the poll
	// is half a second.
	freezeBudget = time.Second
	// pauseRetryFirst and pauseRetryMax bound the back-off between two tries of a pause that failed.
	pauseRetryFirst = 2 * time.Second
	pauseRetryMax   = 30 * time.Second
)

// markPauseReader tells writers that this launcher reads a pause: it makes the run directory's
// liveblock.ControlName once the live-block poll runs, and only for a run with a cgroup of its own to freeze. `tego
// pause` and the dashboard ask a pause only of a run that has the mark (liveblock.TakesControl), so none is written to
// an older launcher, which would refuse the whole overlay once it listed one and leave every later live block waiting.
// A mark that cannot be made is logged: the run then offers no Pause, and nothing else changes.
func (r *runner) markPauseReader() {
	if r.dir == "" || r.cg.Path == "" {
		return
	}
	if err := liveblock.MarkControl(r.dir); err != nil {
		r.log.Warn("live controls: the run's pause mark could not be made, so it cannot be paused", "err", err)
	}
}

// errNoCgroup is a pause asked of a run that has no cgroup of its own to freeze.
var errNoCgroup = errors.New("the run has no cgroup of its own to freeze")

// errAskWaiting is a pause asked while an ask holds one of the run's threads for a person: that thread cannot be
// frozen until the ask is answered, so no freeze is tried until then.
var errAskWaiting = errors.New("a request of the agent waits for a person's answer, and its thread cannot be frozen until it is answered")

// pauseState is the run's pause as the launcher put it in force.
type pauseState struct {
	// held is set while the run may be frozen: from a freeze write until a thaw is written (or confirmed, for a
	// resume). The budget watcher's held hook reads it (runner.held), so no stall is counted while the agent cannot
	// run. A freeze write that fails changed nothing, so it clears it.
	held atomic.Bool

	mu sync.Mutex
	// applied is the state last put in force (true: frozen); want is the overlay's Paused as last read, and last the
	// pause or resume that asked it.
	applied, want bool
	last          liveblock.Change
	// recorded is set once the failure line of last was written, so a change tried again is recorded once.
	recorded bool
	// retryAt is when a failed pause is tried again, and backoff the wait that set it (0 before the first failure).
	retryAt time.Time
	backoff time.Duration
	// stopping is set once a stop thawed the run: no freeze is applied after it.
	stopping bool
}

// held is the budget watcher's held hook (limits.WithHeld): an ask awaiting its person, or a pause.
func (r *runner) held() bool { return r.askWaiting() || r.pause.held.Load() }

// applyControl applies one pause or resume from the overlay and records it.
func (r *runner) applyControl(ctx context.Context, c liveblock.Change) {
	p := &r.pause
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setWant(c.Op == liveblock.OpPause, c)
	r.applyLocked(ctx)
}

// wantPaused puts the overlay's own Paused in force once its changes were applied. When the change that set it is no
// longer listed (lost), it is still applied, and recorded under the overlay's serial with no one named.
func (r *runner) wantPaused(ctx context.Context, paused bool, serial uint64) {
	p := &r.pause
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.want == paused {
		return // applied, or failed and tried again later (retryPause)
	}
	op := map[bool]string{true: liveblock.OpPause, false: liveblock.OpResume}[paused]
	p.setWant(paused, liveblock.Change{Serial: serial, Op: op})
	r.applyLocked(ctx)
}

// setWant records a new pause or resume to apply: its failure is recorded afresh and tried at once. Called with mu.
func (p *pauseState) setWant(on bool, c liveblock.Change) {
	p.want, p.last = on, c
	p.recorded, p.retryAt, p.backoff = false, time.Time{}, 0
}

// retryPause tries again a pause or a resume the launcher has not managed to put in force: a pause once no ask waits
// and its back-off has passed, a resume (or a thaw left undone) on every poll.
func (r *runner) retryPause(ctx context.Context) {
	p := &r.pause
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.want == p.applied && (p.want || !p.held.Load()):
		return // in force, and no thaw left undone
	case p.want && (pauseAskWaiting(r) || pauseNow().Before(p.retryAt)):
		return
	}
	r.applyLocked(ctx)
}

// applyLocked brings the cgroup to p.want and writes the line of p.last. Called with p.mu held.
func (r *runner) applyLocked(ctx context.Context) {
	p := &r.pause
	on := p.want
	if on && p.stopping {
		return // the run is being stopped: it stays thawed so it can end
	}
	var err error
	if on || p.applied || p.held.Load() {
		err = r.setFrozen(ctx, on)
	} // else a resume of a run never frozen: there is nothing to thaw, and run-resumed says it was not frozen
	if err == nil {
		p.applied, p.recorded, p.retryAt, p.backoff = on, false, time.Time{}, 0
		if p.last.Serial != 0 {
			why := map[bool]string{true: record.GapRunPaused, false: record.GapRunResumed}[on]
			r.emitControlGap(why, p.last)
		}
		return
	}
	if on && !errors.Is(err, errAskWaiting) {
		p.backoff = min(max(2*p.backoff, pauseRetryFirst), pauseRetryMax)
		p.retryAt = pauseNow().Add(p.backoff)
	}
	r.log.Warn("live controls: the run's pause could not be changed; tried again later", "pause", on, "err", err)
	if p.last.Serial != 0 && !p.recorded {
		p.recorded = true
		why := map[bool]string{true: record.GapPauseFailed, false: record.GapResumeFailed}[on]
		r.emitControlGap(why, p.last)
	}
}

// setFrozen freezes (on) or thaws the run's cgroup and waits for cgroup.events to confirm it. A freeze is a few short
// attempts within freezeBudget, each thawed again when it is not confirmed, so a failed pause leaves the run running
// and never half frozen; none is tried while an ask waits. A thaw that fails leaves the run held.
func (r *runner) setFrozen(ctx context.Context, on bool) error {
	if r.cg.Path == "" {
		return errNoCgroup
	}
	if !on {
		err := freezeCgroup(r.cg, false)
		if err == nil {
			err = waitFrozen(ctx, r.cg, false, cgroup.FreezeWait)
		}
		if err == nil {
			r.pause.held.Store(false)
		}
		return err
	}
	deadline := pauseNow().Add(freezeBudget)
	for {
		if pauseAskWaiting(r) {
			return errAskWaiting
		}
		r.pause.held.Store(true)
		if err := freezeCgroup(r.cg, true); err != nil {
			r.pause.held.Store(false) // the write failed, so nothing was frozen
			return err
		}
		err := waitFrozen(ctx, r.cg, true, freezeAttempt)
		if err == nil {
			return nil
		}
		if terr := freezeCgroup(r.cg, false); terr != nil {
			return fmt.Errorf("%w; the thaw after it failed too: %w", err, terr) // held stays: it may be frozen
		}
		r.pause.held.Store(false)
		if !errors.Is(err, cgroup.ErrNotFrozen) || pauseNow().Add(freezeGap+freezeAttempt).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(freezeGap):
		}
	}
}

// thawForStop thaws a paused run before a stop signal reaches it, and keeps it thawed from then on. It writes no
// line: the run_end that follows ends the pause in the record.
func (r *runner) thawForStop(ctx context.Context) {
	p := &r.pause
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopping = true
	if !p.held.Load() {
		return
	}
	if err := r.setFrozen(context.WithoutCancel(ctx), false); err != nil {
		r.log.Warn("live controls: thaw before the stop failed; stop_grace's kill still ends the run", "err", err)
		return
	}
	p.applied = false
}

// thawOnStop passes the run's signals on to the signal handler, thawing a paused run before each signal that starts
// stop_grace (identity.StartsStopGrace): the agent must be running to handle it. It runs in the run's group and ends
// with ctx or when in closes.
func (r *runner) thawOnStop(ctx context.Context, in <-chan os.Signal) <-chan os.Signal {
	out := make(chan os.Signal, cap(in))
	r.group.Go("pause-stop", func() error {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return nil
			case s, ok := <-in:
				if !ok {
					return nil
				}
				if sig, isSig := s.(syscall.Signal); isSig && identity.StartsStopGrace(sig) {
					r.thawForStop(ctx)
				}
				select {
				case out <- s:
				case <-ctx.Done():
					return nil
				}
			}
		}
	})
	return out
}

// emitControlGap queues one gap what=enforce line about a pause or a resume (record.MinorLiveControl).
func (r *runner) emitControlGap(why string, c liveblock.Change) {
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	lc := &record.LiveControlChange{Op: c.Op, By: c.By, Serial: c.Serial, At: c.At}
	if err := ev.SetPayload(record.GapPayload{What: record.GapEnforce, Why: why, LiveControl: lc}); err != nil {
		return
	}
	if r.queue != nil {
		r.queue.Emit(ev)
	}
}
