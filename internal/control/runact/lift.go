// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"fmt"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The words a lift, a grant and a restore return (Lifted.Word). Each is asked, not done: the run's launcher checks
// the request and writes the line of what took effect (live-rule-lifted, live-rule-restored or live-lift-refused).
const (
	WordLiftAsked    = "lift asked"
	WordGrantAsked   = "grant asked"
	WordRestoreAsked = "restore asked"
)

// The refusals of a lift, a grant and a restore are liveblock's (liveblock.CheckFence, LiftKey), as `tego lift`,
// `tego grant` and `tego restore` give them, beside ErrNotRunning and ErrNoTimeLimits.
var (
	// ErrLocked is a lift or a restore asked of a Locked run, which has no fence.
	ErrLocked = liveblock.ErrLocked
	// ErrOutsideFence is a lift or a restore of an entry the run's fence does not list.
	ErrOutsideFence = liveblock.ErrOutsideFence
	// ErrNoKey is a lift of a run whose lift key cannot be read (liveblock.ReadKey).
	ErrNoKey = liveblock.ErrNoKey
)

// Lifted is what a lift, a grant or a restore asked.
type Lifted struct {
	Run string
	// Rule is the fence entry's rule, live.fence[<kind>:<value>].
	Rule string
	// Word is what was asked: WordLiftAsked (the entry is one of the contract's refusals), WordGrantAsked (it is new
	// access), or WordRestoreAsked.
	Word string
	// Source is the fence entry's source, deny or new (record.LiveFenceSourceDeny, record.LiveFenceSourceNew).
	Source string
	// Until is the lift's time limit; zero is the rest of the run.
	Until time.Time
	// Serial is the overlay's serial after the change: the launcher's line carrying it says what took effect.
	Serial uint64
}

// Lift asks the launcher of an Adjustable run to allow the fence entry of kind on value until until (zero: the rest
// of the run), as `tego lift` and `tego grant` do (ADR 0125 decision 3): it writes a lift, MAC'ed under the run's key,
// into the run's overlay, and the launcher decides what takes effect and records it. It loosens, so it is refused,
// in this order: to a caller inside a run (SelfGoverned; an error from the check counts as inside); for a run, kind
// or value that do not parse; by liveblock.CheckFence, as the CLI refuses it, for a run that is not running
// (ErrNotRunning), a limit its launcher does not read (ErrNoTimeLimits), a Locked run (ErrLocked) and an entry its
// fence does not list (ErrOutsideFence); for a limit outside liveblock.CheckUntil's bounds; and when the run's key
// cannot be read (ErrNoKey). via is "cli" or "dashboard" (liveblock.By).
func Lift(ctx context.Context, root, run, kind, value string, until time.Time, via string) (Lifted, error) {
	if in, _ := SelfGoverned(); in { // fails closed: a cgroup it cannot judge refuses too
		return Lifted{}, fmt.Errorf("%w (run %s)", ErrGoverned, run)
	}
	dir, k, v, f, err := fenceTarget(root, run, kind, value, until)
	if err != nil {
		return Lifted{}, err
	}
	e, _ := f.InFence(string(k), v)
	out := Lifted{Run: run, Rule: liveblock.FenceRule(k, v), Source: e.Source, Until: until.UTC(), Word: WordLiftAsked}
	if e.Source == record.LiveFenceSourceNew {
		out.Word = WordGrantAsked
	}
	if !until.IsZero() {
		if err := liveblock.CheckUntil(time.Now(), until); err != nil {
			return Lifted{}, err
		}
	}
	key, err := liveblock.LiftKey(dir, run)
	if err != nil {
		return Lifted{}, err
	}
	o, err := liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		_, err := o.Lift(k, v, liveblock.By(via), time.Now(), until, key)
		return err == nil, err
	})
	if err != nil {
		return Lifted{}, err
	}
	out.Serial = o.Serial
	return out, nil
}

// Restore asks the launcher of an Adjustable run to refuse the fence entry of kind on value again, as `tego restore`
// does. It narrows, so it is allowed from inside a run; it is refused for a run that is not running, a Locked run and
// an entry outside the fence, as Lift is.
func Restore(ctx context.Context, root, run, kind, value, via string) (Lifted, error) {
	dir, k, v, f, err := fenceTarget(root, run, kind, value, time.Time{})
	if err != nil {
		return Lifted{}, err
	}
	e, _ := f.InFence(string(k), v)
	out := Lifted{Run: run, Rule: liveblock.FenceRule(k, v), Source: e.Source, Word: WordRestoreAsked}
	o, err := liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		_, err := o.Restore(k, v, liveblock.By(via), time.Now())
		return err == nil, err
	})
	if err != nil {
		return Lifted{}, err
	}
	out.Serial = o.Serial
	return out, nil
}

// fenceTarget is the run directory, kind, normalized value and start facts of a lift (until: its limit, zero for none)
// or a restore (until zero) of kind on value on run, after the checks both make: they parse, and liveblock.CheckFence
// passes (the run is running, its launcher reads the limit, it is Adjustable, and its fence lists the entry).
func fenceTarget(root, run, kind, value string, until time.Time) (dir string, k liveblock.Kind, v string, f livestatus.Facts, err error) {
	if dir, err = runDir(root, run); err != nil {
		return
	}
	if k, err = liveblock.ParseKind(kind); err != nil {
		return
	}
	if v, err = liveblock.Normalize(k, value); err != nil {
		return
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		return
	}
	f = StartFacts(dir)
	t := liveTarget(run, held, f)
	_, t.Fenced = f.InFence(string(k), v)
	err = liveblock.CheckFence(t, k, v, until)
	return
}
