// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"time"
)

// Target is what a writer knows of the run a live change is for, the facts CheckBlock and CheckFence decide on: its
// id, whether a launcher holds it (internal/runlock), and what its run_start says that launcher reads
// (internal/check/livestatus.Facts). This package reads neither, so each writer hands them in: runact for the
// dashboard, and `tego block`, `tego unblock`, `tego lift`, `tego grant` and `tego restore` for the terminal. The
// writers share these checks and their words, so the dashboard and the terminal never answer one change two ways.
type Target struct {
	// Run is the run's id, which RunWords names.
	Run string
	// Running: a launcher holds the run's lock, so it reads the overlay within about a second.
	Running bool
	// Timed: the launcher reads a time limit (livestatus.Facts.Timed).
	Timed bool
	// NarrowKinds: the launcher knows read and write blocks (livestatus.Facts.NarrowKinds).
	NarrowKinds bool
	// ReadsSeen: the run's supervisor sees its reads, held or recorded (livestatus.Facts.ReadsSeen).
	ReadsSeen bool
	// Adjustable: the run's fence may be lifted and restored while it runs (ADR 0125); false is a Locked run.
	Adjustable bool
	// Fenced: the run's fence lists the entry a lift, a grant or a restore names (livestatus.Facts.InFence).
	Fenced bool
	// Starting: the run's run_start cannot be read yet (livestatus.Facts.Started is false), so none of the facts above is
	// known: its launcher holds the run's lock a few seconds before it writes that line. A check that decides on a fact
	// refuses it as not known yet (ErrStarting), never as Locked or as an older launcher.
	Starting bool
	// StartUnreadable: the run's first record line is there and cannot be read as its run_start
	// (livestatus.Facts.StartUnreadable), so no fact is known and waiting will not make one known. Starting is true with
	// it; a check refuses it as ErrStartUnreadable, never with "try again" (the review's S1).
	StartUnreadable bool
}

// The refusals of a live change the run cannot take (CheckBlock, CheckFence, LiftKey). Each check returns one inside
// the sentence that says why: its Error says "the run", for a page that names the run beside it (runact hands it to
// the dashboard), and RunWords names the run by its id, for the terminal. errors.Is tells them apart.
var (
	// ErrNotRunning is a change asked of a run no launcher holds: nothing would read it. A run that has ended is
	// refused every change, a block's removal too: its blocks ended with it, and its overlay is left as it was when
	// it ended (`tego block --list` still reads it).
	ErrNotRunning = errors.New("the run is not running")
	// ErrOldLauncher is a read or write block asked of a run whose launcher predates those kinds: that launcher fails
	// to read an overlay holding one, keeps the blocks it last read and ignores every later change until the block is
	// removed.
	ErrOldLauncher = errors.New("the run was started by an older tego that has no read or write blocks")
	// ErrReadsUnseen is a read block asked of a run whose supervisor does not see its reads: placed, it would refuse
	// nothing.
	ErrReadsUnseen = errors.New("the run's reads are not seen, so a read block would refuse nothing")
	// ErrLocked is a lift, a grant or a restore asked of a Locked run, which has no fence (ADR 0125), or an MCP tool
	// switch or a model route that would leave a Locked run looser than its contract (CheckLoosening).
	ErrLocked = errors.New("the run is Locked: nothing loosens until its next run")
	// ErrOutsideFence is a lift, a grant or a restore of an entry the run's fence does not list: it changes from the
	// next run only.
	ErrOutsideFence = errors.New("the entry is outside the run's fence")
	// ErrNoKey is a lift asked of a run whose live key cannot be read (ReadKey), so no lift can be MAC'ed.
	ErrNoKey = errors.New("the run's live key cannot be read, so no lift can be asked")
	// ErrStarting is a change that depends on the run's mode or its launcher's facts, asked of a running run whose
	// run_start cannot be read yet (Target.Starting): the change fails closed, in words that say the run is still
	// starting, and is taken once that line is written. A Locked refusal there named a mode nobody knew: the same
	// change worked seconds later on an Adjustable run (acceptance 2B, 2026-11-11).
	ErrStarting = errors.New("the run is still starting: its mode is not known yet")
	// ErrStartUnreadable is such a change asked of a running run whose first record line is complete and is not a
	// run_start this tego can read (Target.StartUnreadable): it fails closed as ErrStarting does, in words that say the
	// line cannot be read, since waiting does not change that (the review's S1: "try again in a few seconds" never came
	// true for a damaged first line).
	ErrStartUnreadable = errors.New("the run's first record line is not a run_start this tego can read")
)

// refusal is a check's error: the sentinel errors.Is tells it by (and the error that caused it, if any), with its
// sentence twice, once saying "the run" (Error) and once naming the run by its id (RunWords).
type refusal struct {
	err, cause error
	page, term string
}

func (r *refusal) Error() string { return r.page }

func (r *refusal) Unwrap() []error {
	if r.cause == nil {
		return []error{r.err}
	}
	return []error{r.err, r.cause}
}

// refuse is a refusal of err whose sentence say writes for a subject: "the run" for Error, run's id for RunWords.
func refuse(err error, run string, say func(run string) string) *refusal {
	return &refusal{err: err, page: say("the run"), term: say(run)}
}

// noTimeLimits is ErrNoTimeLimits as a refusal: its own words, after the run's id in RunWords.
func noTimeLimits(run string) error {
	return &refusal{err: ErrNoTimeLimits, page: ErrNoTimeLimits.Error(), term: run + ": " + ErrNoTimeLimits.Error()}
}

// RunWords is err's sentence naming its run by id, for the terminal, where nothing else on the line names the run:
// the refusals of CheckBlock, CheckFence and LiftKey. Any other error is its Error.
func RunWords(err error) string {
	var r *refusal
	if errors.As(err, &r) {
		return r.term
	}
	return err.Error()
}

// CheckBlock refuses a block's add (add true) or removal of kind, with the time limit until (zero: none), that the run
// t describes cannot take; nil lets the writer go on to write it. The first rule that matches decides:
//   - a run that is not running (ErrNotRunning): nothing would enforce an add, and a removal finds nothing to remove,
//     since the run's blocks ended with it;
//   - a time limit, or a read or write block, on a run whose run_start cannot be read yet (ErrStarting), or whose first
//     line is not one this tego reads (ErrStartUnreadable): the facts the next two rules decide on are not known; a
//     plain block needs none and is taken;
//   - a time limit its launcher does not read (ErrNoTimeLimits): that launcher would refuse the whole overlay and
//     ignore every later change;
//   - a read or write block its launcher does not know (ErrOldLauncher), for the same reason;
//   - a read block on a run whose reads are not seen (ErrReadsUnseen): it would refuse nothing.
//
// The bounds of the limit itself (CheckUntil) are checked where it is read: livetime.Parse for `--for` and `--until`,
// runact for the dashboard's.
func CheckBlock(t Target, kind Kind, add bool, until time.Time) error {
	switch {
	case !t.Running && add:
		return refuse(ErrNotRunning, t.Run, func(run string) string {
			return run + " is not running, so a live block would enforce nothing"
		})
	case !t.Running:
		return refuse(ErrNotRunning, t.Run, func(run string) string {
			return run + " is not running: its live blocks ended with it, so there is nothing to remove"
		})
	case t.Starting && (!until.IsZero() || (add && (kind == KindRead || kind == KindWrite))):
		return notKnown(t)
	case !until.IsZero() && !t.Timed:
		return noTimeLimits(t.Run)
	case add && (kind == KindRead || kind == KindWrite) && !t.NarrowKinds:
		return refuse(ErrOldLauncher, t.Run, func(run string) string {
			return run + " was started by an older tego that has no " + string(kind) + " blocks, so it would not put this one in force"
		})
	case add && kind == KindRead && !t.ReadsSeen:
		return refuse(ErrReadsUnseen, t.Run, func(run string) string {
			return run + " does not see its reads (they are neither held nor recorded), so a read block would refuse nothing"
		})
	}
	return nil
}

// CheckFence refuses a lift or a grant (until: its time limit, zero for none) or a restore (until zero) of the fence
// entry of kind on value that the run t describes cannot take; nil lets the writer go on. The first rule that matches
// decides: a run that is not running (ErrNotRunning: nothing would apply it), a run whose run_start cannot be read yet
// (ErrStarting, or ErrStartUnreadable for a first line this tego does not read), a time limit its launcher does not
// read (ErrNoTimeLimits), a Locked run (ErrLocked: it has no fence), and an entry its fence does not list
// (ErrOutsideFence). A lift's key (LiftKey) and its limit's bounds (CheckUntil) are the writer's to check.
func CheckFence(t Target, kind Kind, value string, until time.Time) error {
	switch {
	case !t.Running:
		return refuse(ErrNotRunning, t.Run, func(run string) string {
			return run + " is not running, so nothing would apply it; a run's fence starts refused again in its next run"
		})
	case t.Starting:
		return notKnown(t)
	case !until.IsZero() && !t.Timed:
		return noTimeLimits(t.Run)
	case !t.Adjustable:
		return locked(t.Run)
	case !t.Fenced:
		return refuse(ErrOutsideFence, t.Run, func(run string) string {
			return Key(kind, value) + " is outside " + run + "'s fence, so it cannot change while the run runs"
		})
	}
	return nil
}

// CheckLoosening refuses a live change that would leave the run t describes looser than its contract, in CheckFence's
// order: a run that is not running (ErrNotRunning: nothing would apply it, so a free lock is never a go-ahead), a run
// whose run_start cannot be read yet (ErrStarting: its mode is not known, so the change is refused as not known, not as
// Locked; ErrStartUnreadable for a first line this tego does not read), then a Locked run (ErrLocked, in the words
// CheckFence refuses a lift with); nil lets the writer go on. Its writers are the live switches outside this overlay:
// an MCP tool switch to a decision looser than the contract's (`tego mcp`, internal/control/mcpact, ADR 0126 §4) and a
// model route other than direct (`tego route`, internal/control/routeact, ADR 0127 §6). A change that tightens, or one back to the contract, is not theirs to bring here: a Locked run takes it
// as it takes a live block or an unblock. A run whose run_start could not be read has no facts, so the change is
// refused (fail closed), as ErrStarting or ErrStartUnreadable.
func CheckLoosening(t Target) error {
	switch {
	case !t.Running:
		return refuse(ErrNotRunning, t.Run, func(run string) string { return run + " is not running, so nothing would apply it" })
	case t.Starting:
		return notKnown(t)
	case !t.Adjustable:
		return locked(t.Run)
	}
	return nil
}

// notKnown is the refusal of a change that decides on a fact of the run t describes while its run_start cannot be
// read: ErrStartUnreadable when its first line is there and is not one this tego reads, else ErrStarting.
func notKnown(t Target) error {
	if t.StartUnreadable {
		say := func(run string) string {
			return run + "'s first record line is not a run_start this tego can read (a damaged line, another kind of line, " +
				"or one a newer tego wrote), so what it takes while it runs is not known; nothing was changed"
		}
		return &refusal{err: ErrStartUnreadable, page: say("the run"),
			term: say(t.Run) + "; tego events " + t.Run + " --verify checks its record"}
	}
	return starting(t.Run)
}

// starting is ErrStarting's refusal of a change to run, the one sentence every writer says while a run's run_start
// cannot be read yet: nothing was changed, and the same change can be asked again once the line is written.
func starting(run string) error {
	return refuse(ErrStarting, run, func(run string) string {
		return run + " is still starting: its first record line (run_start) cannot be read yet, so what it takes while " +
			"it runs is not known; nothing was changed; try again in a few seconds"
	})
}

// locked is ErrLocked's refusal of a change to run, the one sentence every writer says for a Locked run. It names no
// mechanism, since what holds the run differs by writer: the kernel and the supervisor for a lift, Tego's MCP relay
// for a tool switch, its model forwarder for a route.
func locked(run string) error {
	return refuse(ErrLocked, run, func(run string) string {
		return run + " is Locked: it keeps to its contract while it runs, so nothing loosens until its next run"
	})
}

// LiftKey is the lift key of the run in dir (ReadKey), or ErrNoKey with why, in a refusal that names run.
func LiftKey(dir, run string) ([]byte, error) {
	key, err := ReadKey(dir)
	if err != nil {
		r := refuse(ErrNoKey, run, func(run string) string {
			return run + "'s live key cannot be read, so no lift can be asked: " + err.Error()
		})
		r.cause = err
		return nil, r
	}
	return key, nil
}

// The words a block's add or removal says it did (BlockWord): the second field of `tego block`'s first line
// ("<run>: <word> <rule>") and runact.Blocked.Word, which the dashboard's flash reads.
const (
	WordBlocked        = "blocked"
	WordAlreadyBlocked = "already blocked"
	WordRemoved        = "block removed"
	WordNotBlocked     = "was not blocked"
)

// BlockWord is what a block's add (add true) or removal says it did; changed is whether it changed the overlay
// (AddUntil's and RemoveUntil's ok).
func BlockWord(add, changed bool) string {
	switch {
	case add && changed:
		return WordBlocked
	case add:
		return WordAlreadyBlocked
	case changed:
		return WordRemoved
	}
	return WordNotBlocked
}
