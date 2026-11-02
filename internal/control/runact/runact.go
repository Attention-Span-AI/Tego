// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrBadRun is a run id that is not one, or names no run directory under the ledger root.
var ErrBadRun = errors.New("no such run in this ledger root")

// ErrBadAsk is an ask id that is not a broker's ("q-" and 32 hex digits).
var ErrBadAsk = errors.New("invalid ask id")

// The reasons a broker's decision carries (internal/runtime/ask's ReasonDenied and ReasonTimeout are these).
const (
	reasonDenied  = string(record.ReasonAskDenied)
	reasonTimeout = string(record.ReasonAskTimeout)
)

// runDir is <root>/<run> for a valid run id whose directory exists.
func runDir(root, run string) (string, error) {
	if !ledger.IsRunID(run) {
		return "", fmt.Errorf("%q: %w", run, ErrBadRun)
	}
	dir := filepath.Join(root, run)
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%s: %w", run, ErrBadRun)
		}
		return "", err
	}
	return dir, nil
}

// Answered is what became of one answer.
type Answered struct {
	Run      string
	Decision askproto.Decision
	// Word is what `tego approve` or `tego deny` prints after "<ask_id>: ".
	Word string
}

// Answer answers the held request askID of run under the ledger root root, approving or refusing it once, as
// `tego approve <run> <ask_id>` and `tego deny <run> <ask_id>` do.
// With always the answer stands for the rest of the run for the same operation, rule and exact target, as
// --always does; an always the broker cannot keep (askproto.ErrNotRememberable, ErrStandingFull, ErrStandingBusy)
// leaves the request pending.
func Answer(ctx context.Context, root, run, askID string, approve, always bool) (Answered, error) {
	dir, err := runDir(root, run)
	if err != nil {
		return Answered{}, err
	}
	if !askproto.ValidID(askID) {
		return Answered{}, ErrBadAsk
	}
	target, err := askclient.Launcher(dir) // the verified launcher pidfd stays open through the exchange
	if err != nil {
		return Answered{}, err
	}
	defer func() { _ = target.Close() }()
	d, err := askclient.Answer(ctx, dir, target.PID(), askID, approve, always)
	if err != nil {
		return Answered{}, err
	}
	return Answered{Run: run, Decision: d, Word: AnswerWord(d, always)}, nil
}

// AnswerWord is internal/cli's answerWord: what became of an answer in words of what happened, not of what was asked
// for; asked says whether it was sent with always.
func AnswerWord(d askproto.Decision, asked bool) string {
	word := "approved"
	switch {
	case d.Approved:
	case d.Reason == reasonDenied:
		word = "denied"
	case d.Always:
		return "recorded, and stands for every later request for the same operation, rule and target in this run; " + endedFirst
	case d.Reason == reasonTimeout:
		return "not approved: the hold timed out first, so the operation was refused"
	default:
		return "not approved: the answer could not be kept (the run ended, was cancelled, or its ledger refused the line), so the operation was refused"
	}
	switch {
	case d.Always:
		word += ", and every later request for the same operation, rule and target in this run"
	case asked:
		word += ", for this request only: the answer could not be made to stand for later requests"
	}
	return word
}

// lockInfoWait bounds how long Stop waits for a holder that has taken the lock but not yet written who it is.
const lockInfoWait = 2 * time.Second

// Stopped is what a stop did, in the words `tego stop` prints after "<run>: ".
type Stopped struct {
	Run  string
	Word string
	// Ended is true when the run's lock was free when Stop returned.
	Ended bool
}

// Stop stops run under root as `tego stop <run>` does, and waits at most wait for the launcher to end it.
func Stop(ctx context.Context, root, run string, wait time.Duration) (Stopped, error) {
	dir, err := runDir(root, run)
	if err != nil {
		return Stopped{}, err
	}
	notRunning := Stopped{Run: run, Word: "not running", Ended: true}
	held, info, err := runlock.ProbeLock(dir)
	if err != nil {
		return Stopped{}, err
	}
	for deadline := time.Now().Add(lockInfoWait); held && info.PID <= 0 && time.Now().Before(deadline); {
		select {
		case <-ctx.Done():
			return Stopped{}, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
		if held, info, err = runlock.ProbeLock(dir); err != nil {
			return Stopped{}, err
		}
	}
	if !held {
		return notRunning, nil
	}
	if info.PID <= 0 {
		return Stopped{}, errors.New("the run's lock is held but names no launcher process")
	}
	// The launcher is verified before the marker is placed: a marker left by a stop that then failed would turn
	// the run's next Ctrl-C into reason=stopped (R22).
	target, err := runlock.OpenStopTargetFor(dir, info)
	if errors.Is(err, runlock.ErrStale) {
		return notRunning, nil
	}
	if err != nil {
		return Stopped{}, err
	}
	defer func() { _ = target.Close() }()
	// No grace in the marker: the launcher keeps the machine's stop_grace, as for a plain `tego stop`. An existing
	// marker (an earlier stop) is kept, and the SIGTERM goes again, as the CLI does.
	err = ledger.PlaceNewFileThen(ctx, dir, ledger.StopRequestFile, nil, func(bool) error {
		if err := target.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	})
	if err != nil {
		return Stopped{}, fmt.Errorf("stop: %w", err)
	}
	for deadline := time.Now().Add(wait); ; {
		held, _, err := runlock.ProbeLock(dir)
		if err == nil && !held {
			return Stopped{Run: run, Word: "stopped", Ended: true}, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return Stopped{Run: run, Word: fmt.Sprintf("stop requested; still running after %s (the launcher's stop_grace still applies)", wait)}, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Stopping reports whether a stop was asked of run under root: its stop marker is in place. The run page says
// Stopping from then until run_end, since Stop returns before a slow run has ended.
func Stopping(root, run string) bool {
	dir, err := runDir(root, run)
	if err != nil {
		return false
	}
	_, err = os.Lstat(filepath.Join(dir, ledger.StopRequestFile))
	return err == nil
}

// Blocked is what a live block's add or remove did.
type Blocked struct {
	Run  string
	Rule string
	// Word is what was done, in the words the page shows.
	Word string
	// Real is, for a path, read or write block the overlay now holds, the path its value led to through a link when it
	// was added (liveblock.Entry.Real): the block refuses that spelling too. "" when there is none.
	Real string
	// Uncovered is the path the value leads to through a link that the block does not refuse, because the run's
	// launcher predates the real path; RealUnknown is a value whose real path could not be worked out in time. Either
	// way the block refuses its value as written only (liveblock.RealOutcome).
	Uncovered   string
	RealUnknown bool
	// Observe is a watched run (run_start tier observe): its supervisor records what the block names and lets it go
	// on, so the block is recorded, not enforced. ReadsSeen is a run whose supervisor sees every read open, so a path
	// block refuses reads too (livestatus.Facts). Both are false when run_start could not be read.
	Observe, ReadsSeen bool
	// Serial is the overlay's serial after the change: the launcher's gap line carrying it (or a later one) says it
	// is in force (ledgerview.LiveFacts).
	Serial uint64
	// Until is the change's time limit (ADR 0125): for an add, when the block the overlay now holds ends (an add never
	// shortens a block, so it may be later than the one asked for); for a remove, when the unblocked block refuses
	// again. Zero is no end.
	Until time.Time
	// File and Names are, for an exec block on an absolute path just placed, the file the path leads to and how many
	// names that file has here (liveblock.ReachOf): with Names above 1, as with a multi-call program's applets, the
	// block refuses it under each of them. Renamed is a path that leads to File through a link named otherwise (as
	// busybox's applets are), so the block refuses File under every name that leads there. Zero for any other block.
	File    string
	Names   uint64
	Renamed bool
}

// Block adds (add true) or removes a live block of kind on value on run under root (internal/liveblock), as
// `tego block` and `tego unblock` would: the run's launcher reads it within about a second and records the change in
// the run's ledger. Both are refused for a run that is not running (ErrNotRunning, liveblock.CheckBlock): nothing
// would enforce a block, and the run's blocks ended with it, so its overlay is left as it was. A remove is refused to
// a caller inside a run too (SelfGoverned): a governed agent may tighten a run, never loosen one. It is BlockUntil
// with no time limit, by the dashboard.
func Block(ctx context.Context, root, run, kind, value string, add bool) (Blocked, error) {
	return BlockUntil(ctx, root, run, kind, value, add, time.Time{}, "dashboard")
}

// BlockUntil is Block with a time limit and the writer's via ("cli" or "dashboard", liveblock.By): a block added until
// until ends by itself then, and a block removed until until refuses again then (ADR 0125 decision 4); a zero until is
// no end. A limit is held to liveblock.CheckUntil (1 minute to 400 days). The run's own refusals are
// liveblock.CheckBlock's, the checks and the words `tego block` and `tego unblock` give too: a run that is not running
// (ErrNotRunning), a limit its launcher does not read (ErrNoTimeLimits: that launcher would refuse the whole overlay
// and ignore every later change), a read or write block it does not know (ErrOldLauncher), and a read block on a run
// whose reads are not seen (ErrReadsUnseen).
func BlockUntil(ctx context.Context, root, run, kind, value string, add bool, until time.Time, via string) (Blocked, error) {
	dir, err := runDir(root, run)
	if err != nil {
		return Blocked{}, err
	}
	k, err := liveblock.ParseKind(kind)
	if err != nil {
		return Blocked{}, err
	}
	v, err := liveblock.Normalize(k, value)
	if err != nil {
		return Blocked{}, err
	}
	if in, _ := SelfGoverned(); !add && in { // fails closed: a cgroup it cannot judge refuses too
		return Blocked{}, fmt.Errorf("%w (run %s)", ErrGoverned, run)
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		return Blocked{}, err
	}
	out := Blocked{Run: run, Rule: liveblock.Rule(k, v), Until: until}
	f := StartFacts(dir)
	out.Observe, out.ReadsSeen = f.Observe, f.ReadsSeen
	if err := liveblock.CheckBlock(liveTarget(run, held, f), k, add, until); err != nil {
		return out, err
	}
	if !until.IsZero() {
		if err := liveblock.CheckUntil(time.Now(), until); err != nil {
			return out, err
		}
	}
	var placed liveblock.Entry
	o, err := liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		var ok bool
		var err error
		if add {
			// An add only narrows (AddUntil): the block it leaves ends at the later of its own end and until, and a
			// block already held to no sooner is left as it is ("already blocked"). out.Until is that block's end.
			_, ok, err = o.AddUntil(k, v, liveblock.By(via), time.Now(), until)
			if e, found := o.Find(k, v); found && err == nil {
				out.Until, placed = e.Until, e
			}
		} else {
			_, ok, err = o.RemoveUntil(k, v, liveblock.By(via), time.Now(), until)
		}
		out.Word = liveblock.BlockWord(add, ok)
		return ok, err
	})
	if o != nil {
		out.Serial = o.Serial
	}
	if err == nil && add {
		// A path written through a link is blocked by where it leads too, since the supervisor matches a file action
		// by where its lookup lands. The block is in force with its value alone already; its real path is worked out
		// now, with a budget, and added in a second write, which only narrows (liveblock.AddReal). That write failing
		// leaves the block as it is, said as Unknown.
		r, _ := liveblock.AddReal(ctx, dir, run, k, v, placed)
		out.Real, out.Uncovered, out.RealUnknown = r.Real, r.Uncovered, r.Unknown
		if k == liveblock.KindExec {
			// An absolute program is matched by its file's identity too, so the block refuses that file under every
			// name it has; the page says so. No PATH is searched: the dashboard's is not the run's.
			x := liveblock.ReachOf(v, "")
			out.File, out.Names, out.Renamed = x.File, x.Names, x.Renamed
		}
	}
	return out, err
}

// liveTarget is liveblock's Target of run, held or not by a launcher, from the facts its run_start gives: what
// liveblock.CheckBlock and liveblock.CheckFence decide on.
func liveTarget(run string, held bool, f livestatus.Facts) liveblock.Target {
	return liveblock.Target{Run: run, Running: held, Timed: f.Timed, NarrowKinds: f.NarrowKinds(), ReadsSeen: f.ReadsSeen,
		Adjustable: f.Adjustable}
}

// StartFacts is what the run in dir says of how it can enforce a live block, read from its run_start line
// (livestatus.FromStartJSON): no facts when that line cannot be read.
func StartFacts(dir string) livestatus.Facts {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return livestatus.Facts{}
	}
	defer func() { _ = rd.Close() }() // read-only
	for line, err := range rd.Lines() {
		if err != nil {
			break
		}
		e, err := record.Decode(line)
		if err != nil || e.Kind != record.KindRunStart {
			break
		}
		return livestatus.FromStartJSON(e.Payload)
	}
	return livestatus.Facts{}
}

// LiveBlocks is a run's live blocks now with the overlay serial of each one's add.
type LiveBlocks struct {
	Blocks []liveblock.Entry
	// Serials maps each block's key (Entry.Key) to the serial of the change that added it; a block whose add the
	// overlay no longer lists (it keeps the newest liveblock.MaxChanges) maps to Serial.
	Serials map[string]uint64
	// Serial is the overlay's own serial, its last change's.
	Serial uint64
}

// Entry is the block of key (liveblock.Entry.Key) in lb, with its time limit; ok is false when lb holds none.
func (lb LiveBlocks) Entry(key string) (e liveblock.Entry, ok bool) {
	for _, b := range lb.Blocks {
		if b.Key() == key {
			return b, true
		}
	}
	return liveblock.Entry{}, false
}

// Live is run's live blocks now with their serials; none when the run has no overlay.
func Live(root, run string) (LiveBlocks, error) {
	dir, err := runDir(root, run)
	if err != nil {
		return LiveBlocks{}, err
	}
	o, err := liveblock.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		return LiveBlocks{}, nil
	}
	if err != nil {
		return LiveBlocks{}, err
	}
	return liveOf(o), nil
}

// liveOf is an overlay's blocks with the serial of each one's latest add.
func liveOf(o *liveblock.Overlay) LiveBlocks {
	lb := LiveBlocks{Blocks: o.Blocks, Serials: make(map[string]uint64, len(o.Blocks)), Serial: o.Serial}
	for _, b := range o.Blocks {
		lb.Serials[b.Key()] = o.Serial
	}
	for _, c := range o.Changes {
		k := liveblock.Key(c.Kind, c.Value)
		if _, ok := lb.Serials[k]; ok && c.Op == liveblock.OpAdd {
			lb.Serials[k] = c.Serial
		}
	}
	return lb
}

// Blocks is run's live blocks now; none when the run has no overlay.
func Blocks(root, run string) ([]liveblock.Entry, error) {
	dir, err := runDir(root, run)
	if err != nil {
		return nil, err
	}
	o, err := liveblock.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return o.Blocks, nil
}

// The refusals of a live change the run cannot take are liveblock's (liveblock.CheckBlock, CheckFence and LiftKey),
// so `tego block`, `tego unblock`, `tego lift`, `tego grant` and `tego restore` refuse the same changes in the same
// words; the names below are theirs.
var (
	// ErrNotRunning is a change asked of a run no launcher holds: a block, its removal, a lift or a restore.
	ErrNotRunning = liveblock.ErrNotRunning
	// ErrOldLauncher is a read or write block asked of a run started by a tego that has no such blocks (run_start's
	// record_minor below record.MinorLiveControl, or not known).
	ErrOldLauncher = liveblock.ErrOldLauncher
	// ErrNoTimeLimits is a time limit asked of a run whose launcher does not read one (run_start's record_minor below
	// record.MinorLiveModes, or not known).
	ErrNoTimeLimits = liveblock.ErrNoTimeLimits
	// ErrReadsUnseen is a read block asked of a run whose supervisor does not see its reads (neither held nor
	// recorded): it would refuse nothing there.
	ErrReadsUnseen = liveblock.ErrReadsUnseen
)
