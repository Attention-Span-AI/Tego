// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// Undo and live blocks: a change saved with "Also apply now" (or applied later with Apply now) placed
// live blocks on running runs of its rules file. Undoing the change gives the file its old text, which reaches only
// the file's next run; the blocks stay on the running runs. The Undo therefore offers to lift them too ("Also lift the
// live blocks this change placed"): only the blocks the journal records this change placing, on runs of the same file
// that still run and still hold them, and none that another change of the file still standing also placed there.
// Lifting lets a running run do more at once, so it is confirmed like a widening: the Undo's own acknowledgement is
// required with it whatever the Undo's direction. Each lift is runact.Block with add false, which a caller inside a
// run is refused (runact.SelfGoverned), and what it did is journaled on the revert with "lift": true
// (rulefile.Live.Lift), so the history says it and Apply now never counts a lifted block as placed.
//
// Whose block it is. The overlay keeps one entry per key, with no word of who wants it, so the Undo cannot lift on the
// key alone: a person may have lifted the change's block on the run's page and placed the same block again, or held
// it before the change asked. The journal therefore records, with each block a change placed, the serial of the add
// that made it (rulefile.Live Serial, Epoch and At: liveblock.Own, Overlay.AddIdentity), and an Undo lifts a block only while the overlay's
// newest word on that key is that very add; the removal repeats the check under the overlay's lock (runact.UnblockOwned),
// so a person's change between the offer and the lift is a refusal and not a lift. A block the change found held
// is recorded as Held and never offered. A block placed before the journal kept serials cannot be shown to be the
// change's own: it stays (Kept), and the answer says it stays until the run ends or the person removes it. Whatever
// cannot be shown to be the change's is left, never lifted.
//
// A lift is written to the journal first as begun (Pending) and again as done or failed; an Undo whose own journal
// line failed (rulefile.ErrJournal) lifts nothing, and a lift whose begun line cannot be written is not made. So the
// journal never lacks a lift that is in force; at worst it shows one as begun with no end. A Redo (undoing an Undo)
// puts back the blocks that Undo lifted, by the same rules (restore).

// LiftOption is one live block an Undo can lift with the change it undoes: a block that change placed on a run that
// still runs and still holds it.
type LiftOption struct {
	Run string
	// Kind and Value are the live block's (internal/liveblock); Block is Kind:Value, as the journal spells it.
	Kind, Value, Block string
	// Cwd is the run's working folder, so a page can say Value as the person wrote it.
	Cwd string
	// Observe is a watched run, where the block was recorded only: lifting it stops the marks, refuses nothing less.
	Observe bool
	// Own is the identity of the add that made the block (overlay Epoch, serial and instant), as the journal recorded it;
	// the lift is made only while the overlay still lists that add as the block's newest change. Not Known: the block is
	// not Mine.
	Own liveblock.Own
	// Mine says the change made this block and still owns it: its add is the overlay's newest word on the key. Only
	// such a block is offered to a lift. A block that is not Mine and holds is what an Undo leaves in force (Kept).
	Mine bool
}

// liftable is what an Undo of e (a journal entry as History folds it: its live outcomes merged) would do now with the
// blocks e placed, from the contract's history hist: every block e placed on a run of e's rules file that still runs and
// still holds it in its overlay, unless another entry of hist that stands (not undone, not e) placed it on that run too.
// The text an Undo of e gives back still holds that other change, so its block stays. A block lifted already, by hand
// or by an earlier Undo, is not in the overlay and so is not listed. Each listed block says whether it is Mine: the
// change's own block, shown by the serial of its add; the others stay in force whatever the Undo's box says (lift.go).
func (s *Service) liftable(e rulefile.Entry, hist []rulefile.Entry) []LiftOption {
	var out []LiftOption
	var runs map[string]start
	for _, l := range e.Live {
		if !l.Placed() || slices.ContainsFunc(out, func(o LiftOption) bool { return o.Run == l.Run && o.Block == l.Block }) {
			continue
		}
		if runs == nil {
			runs = s.startsByRun()
		}
		st, ok := runs[l.Run]
		if !ok || st.Resolved != e.Contract || !s.isLive(filepath.Join(s.Ledger, l.Run)) {
			continue // the run ended, or is not a run of this file: there is nothing to lift
		}
		adds, known := s.blocksOn(l.Run)
		cur, held := adds[l.Block]
		if !known || !held {
			continue // lifted already (by hand, or by an earlier Undo); or the overlay cannot be read: nothing is offered
		}
		if heldByOther(e.ID, l.Run, l.Block, hist) {
			continue
		}
		k, v, ok := strings.Cut(l.Block, ":")
		if !ok {
			continue
		}
		kind, err := liveblock.ParseKind(k)
		if err != nil {
			continue
		}
		// A change may have placed the same block on the run more than once (placed, lifted by hand, placed again by Apply
		// now): the placement that is the overlay's block now is the one that counts, else the newest.
		p := placement(e.Live, l.Run, l.Block, cur)
		out = append(out, LiftOption{Run: l.Run, Kind: string(kind), Value: v, Block: l.Block, Cwd: st.Cwd,
			Observe: s.runFacts(l.Run).Observe, Own: ownOf(p), Mine: ownOf(p).Is(cur)})
	}
	return out
}

// ownOf is the identity of the add a journal outcome records.
func ownOf(l rulefile.Live) liveblock.Own {
	return liveblock.Own{Epoch: l.Epoch, Serial: l.Serial, At: l.At}
}

// placement is the outcome of ls that placed block on run and is the add now in the overlay (cur) if there is one, else
// the newest that placed it.
func placement(ls []rulefile.Live, run, block string, cur liveblock.Own) rulefile.Live {
	var last rulefile.Live
	for _, l := range ls {
		if !l.Placed() || l.Run != run || l.Block != block {
			continue
		}
		if ownOf(l).Is(cur) {
			return l
		}
		last = l
	}
	return last
}

// mine is the options of opts that are the change's own blocks (LiftOption.Mine), the ones an Undo may lift.
func mine(opts []LiftOption) []LiftOption {
	var out []LiftOption
	for _, o := range opts {
		if o.Mine {
			out = append(out, o)
		}
	}
	return out
}

// theirs is the options of opts that are not (the blocks an Undo leaves in force whatever its box says).
func theirs(opts []LiftOption) []LiftOption {
	var out []LiftOption
	for _, o := range opts {
		if !o.Mine {
			out = append(out, o)
		}
	}
	return out
}

// asked reports whether l says its change asked for the block and it stands on the run: placed by the change, or found
// already held when the change asked (Held). Either way the change's text still wants the block, so another change's Undo
// must not lift it.
func asked(l rulefile.Live) bool {
	return l.Placed() || l.Held && !l.Lift && !l.Pending && l.Block != ""
}

// heldByOther reports whether an entry of hist other than id that still stands placed block on run: undoing id must
// not lift what that other change still puts in force. An entry stands while no revert that stands undoes it, and
// undoing id changes that for two: id itself stops standing, and, when id is a revert that undid another revert (a
// Redo: id undid an Undo), the change that Undo had undone does not stand either, since the text goes back to the one
// before it.
func heldByOther(id, run, block string, hist []rulefile.Entry) bool {
	gone := map[string]bool{id: true}
	byID := func(x string) (rulefile.Entry, bool) {
		i := slices.IndexFunc(hist, func(h rulefile.Entry) bool { return h.ID == x })
		if i < 0 {
			return rulefile.Entry{}, false
		}
		return hist[i], true
	}
	if e, ok := byID(id); ok && e.Op == rulefile.OpRevert {
		if r, ok := byID(e.Reverts); ok && r.Op == rulefile.OpRevert {
			gone[r.Reverts] = true
		}
	}
	return slices.ContainsFunc(hist, func(h rulefile.Entry) bool {
		return !gone[h.ID] && h.UndoneBy == "" && slices.ContainsFunc(h.Live, func(l rulefile.Live) bool {
			return asked(l) && l.Run == run && l.Block == block
		})
	})
}

// startsByRun is every run's start by run id.
func (s *Service) startsByRun() map[string]start {
	sts, err := s.starts()
	if err != nil {
		return map[string]start{}
	}
	out := make(map[string]start, len(sts))
	for _, st := range sts {
		out[st.Run] = st
	}
	return out
}

// blocksOn is the live blocks of run now by key, each with the identity of the add that made it (not Known when the overlay
// does not show that add: runact.LiveAdds); known is false when its overlay cannot be read, and then nothing is offered.
func (s *Service) blocksOn(run string) (adds map[string]liveblock.Own, known bool) {
	if s.overlay != nil {
		return s.overlay(run), true
	}
	adds, err := runact.LiveAdds(s.Ledger, run)
	return adds, err == nil
}

// lift removes the live blocks of opts from their runs and says what each removal did, each made only while the block
// is still the one its change placed (runact.UnblockOwned). A removal that fails is reported, never a reason to take the
// Undo back: the file already holds its old text.
func (s *Service) lift(ctx context.Context, opts []LiftOption) []LiveResult {
	out := make([]LiveResult, 0, len(opts))
	for _, o := range opts {
		r := LiveResult{Run: o.Run, Block: o.Block, OK: true, Observe: o.Observe, Lift: true, By: rulefile.LiveByUndo}
		var err error
		if s.unblock != nil {
			err = s.unblock(ctx, o.Run, o.Kind, o.Value, o.Own)
		} else {
			var b runact.Blocked
			b, err = runact.UnblockOwned(ctx, s.Ledger, o.Run, o.Kind, o.Value, o.Own)
			r.Serial = b.Serial
		}
		if err != nil {
			r.OK, r.Err = false, fmt.Sprintf("not lifted: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// restorable is what a Redo of the revert e puts back: each block e's Undo lifted, on a run of e's rules file that still
// runs, unless the run holds the block now (a person placed it again: it is theirs, and stays so). Only a lift an Undo
// made counts; a line that is not a finished lift, or was made by another writer, is not a block to put back. Every
// lifted block it does not put back is in skipped, each with why, so the answer can say what the Redo left.
func (s *Service) restorable(e rulefile.Entry) (back []LiftOption, skipped []LiveResult) {
	var runs map[string]start
	skip := func(l rulefile.Live, held bool, why string) {
		skipped = append(skipped, LiveResult{Run: l.Run, Block: l.Block, By: rulefile.LiveByRedo, Held: held, Err: why})
	}
	var seen []string
	for _, l := range e.Live {
		if !l.Lifted() || l.By != "" && l.By != rulefile.LiveByUndo || slices.Contains(seen, l.Run+" "+l.Block) {
			continue
		}
		seen = append(seen, l.Run+" "+l.Block)
		if runs == nil {
			runs = s.startsByRun()
		}
		st, ok := runs[l.Run]
		if !ok || st.Resolved != e.Contract || !s.isLive(filepath.Join(s.Ledger, l.Run)) {
			skip(l, false, "not put back: its run has ended, or is not running this rules file")
			continue
		}
		adds, known := s.blocksOn(l.Run)
		if !known {
			skip(l, false, "not put back: the run's live rules cannot be read")
			continue
		}
		if _, held := adds[l.Block]; held {
			skip(l, true, whyHeld)
			continue
		}
		k, v, ok := strings.Cut(l.Block, ":")
		kind, err := liveblock.ParseKind(k)
		if !ok || err != nil {
			skip(l, false, "not put back: the journal names no block Tego can place")
			continue
		}
		back = append(back, LiftOption{Run: l.Run, Kind: string(kind), Value: v, Block: l.Block, Cwd: st.Cwd,
			Observe: s.runFacts(l.Run).Observe})
	}
	return back, skipped
}

// restore places the blocks of opts again, as a rules change's placement does, and says what each did; a block the run
// holds by then is not the Redo's, is not recorded as its own, and is said so (Held).
func (s *Service) restore(ctx context.Context, opts []LiftOption) []LiveResult {
	out := make([]LiveResult, 0, len(opts))
	for _, o := range opts {
		r := LiveResult{Run: o.Run, Block: o.Block, OK: true, Observe: o.Observe, By: rulefile.LiveByRedo}
		b, err := s.placeBlock(ctx, o.Run, o.Kind, o.Value)
		switch {
		case err != nil:
			r.OK, r.Err = false, "not put back: "+err.Error()
		case !b.Fresh:
			r.OK, r.Held, r.Err = false, true, whyHeld
		default:
			r.Serial, r.Epoch, r.At = b.Serial, b.Epoch, b.At
		}
		out = append(out, r)
	}
	return out
}

// journaled makes a lift or a placement that must not be in force unless the journal shows it: it writes begun (one
// Pending line per block of opts, in the journal of the entry id) first, and only then runs do and writes its outcomes.
// If the begun lines cannot be written nothing is made, and every block says so; if the outcomes cannot be written
// the begun lines stay and say the work was started and its end was not recorded. The error says which.
func (s *Service) journaled(ctx context.Context, id string, opts []LiftOption, lift bool, do func(context.Context, []LiftOption) []LiveResult) ([]LiveResult, error) {
	if len(opts) == 0 {
		return nil, nil
	}
	by, what := rulefile.LiveByRedo, "put back"
	if lift {
		by, what = rulefile.LiveByUndo, "lifted"
	}
	begun := make([]LiveResult, 0, len(opts))
	for _, o := range opts {
		begun = append(begun, LiveResult{Run: o.Run, Block: o.Block, Lift: lift, By: by, Pending: true, Observe: o.Observe,
			Err: what + " was begun and its end was not recorded"})
	}
	if err := s.writer().AppendLive(ctx, id, journalLive(begun)); err != nil {
		out := make([]LiveResult, 0, len(opts))
		for _, o := range opts {
			out = append(out, LiveResult{Run: o.Run, Block: o.Block, Lift: lift, By: by, Observe: o.Observe,
				Err: "not " + what + ": the journal could not record it first, so the block is left as it is"})
		}
		return out, fmt.Errorf("the live blocks were not %s: the journal could not record them first: %w", what, err)
	}
	res := do(ctx, opts)
	if err := s.writer().AppendLive(ctx, id, journalLive(res)); err != nil {
		return res, fmt.Errorf("the live blocks were %s but their outcome was not journaled (the journal shows them as begun): %w", what, err)
	}
	return res, nil
}
