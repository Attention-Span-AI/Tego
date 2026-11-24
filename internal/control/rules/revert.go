// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// RevertReq undoes the journal's change (or revert) ID of a contract of the set.
type RevertReq struct {
	ID string
	// Base is the sha256 of the text the page showed; the revert is refused when the contract holds other text.
	Base string
	// Ack acknowledges a revert that is not a narrowing: undoing a narrowing widens, and undoing a free edit or a
	// mixed change cannot be classified. It is the Ack the Undo was offered with (HistoryEntry.Ack, ActPlan.UndoAck),
	// which names this entry, the text it wrote and the text the revert gives back (ack.go).
	Ack string
	// Lift also lifts the live blocks the entry placed on runs that still run and hold them (lift.go): it lets those
	// runs do more at once, so it wants Ack whatever the revert's direction.
	Lift bool
	// Via is the writer the journal records for the revert: "" is the dashboard's (Via), ViaCLI the terminal's
	// (`tego rules undo`). Any other word is refused, so a caller cannot put a name of its choosing in the journal.
	Via string
}

// Reverted is a revert written.
type Reverted struct {
	// ID is the revert's journal entry and Of the entry it undid.
	ID, Of   string
	Ref      string
	Contract string
	Bak      string
	// Direction is the revert's own: the opposite of the change undone.
	Direction string
	// Lifted is what lifting the undone change's live blocks did (RevertReq.Lift), each with Lift set; Kept is the
	// blocks it placed that still hold on running runs because the Undo did not lift them.
	Lifted []LiveResult
	Kept   []LiftOption
	// Restored is what a Redo (this revert undoes an Undo) did to put back the live blocks that Undo lifted, each by
	// the Redo, with Serial set to the add that made it (restorable, restore).
	Restored []LiveResult
}

// What is the entry in one plain line: a revert's Words, else a change's Sentences joined by "; ", else its Summary, else
// "a change". It is the one wording of an entry: the dashboard's history list and `tego rules history` both print it.
func (h HistoryEntry) What() string {
	switch {
	case h.Words != "":
		return h.Words
	case len(h.Sentences) > 0:
		return strings.Join(h.Sentences, "; ")
	case h.Summary != "":
		return h.Summary
	}
	return "a change"
}

// Undoable says whether an Undo of the entry is offered for a contract whose text now has the sha256 base: the entry's
// text is the contract's text now (Current), it is not undone already, and the reader knows the contract's text (base
// is not empty). It is the rule the dashboard's Undo button and `tego rules undo` share; Revert still checks the text
// itself under the writers' lock.
func (h HistoryEntry) Undoable(base string) bool { return h.Current && h.UndoneBy == "" && base != "" }

// UndoDirection is the direction undoing the entry moves the contract: the opposite of the entry's own (inverse), and
// "mixed" for a free edit or an entry with no direction. Only "narrows" needs no acknowledgement.
func (h HistoryEntry) UndoDirection() string { return inverse(h.Direction) }

// HistoryEntry is one journal entry of a contract, newest first (History).
type HistoryEntry struct {
	ID, Op    string
	At        time.Time
	Via       string
	Run       string
	Line      uint64
	Summary   string
	Sentences []string
	// Words is a revert in one plain line, said from the change it undid ("Undid: Can never read ./confidential/",
	// rulesview.UndoWords); "" for a change, whose Sentences say it. A revert's Summary is the journal's raw text.
	Words     string
	Direction string
	// Reverts is the id a revert undid; UndoneBy the revert that undid this entry, "" while it stands.
	Reverts, UndoneBy string
	Live              []LiveResult
	// Current says the contract holds this entry's text now and the entry is a change or a revert: Revert can undo
	// it. A create (op create, "Set up a new agent") is never Current, since Revert refuses it: there is no older
	// text to give back, so a history list shows it as Created with no Undo.
	Current bool
	// Ack is the acknowledgement of undoing this entry while it is Current (ack.go): the Undo form carries it when
	// undoing is not a narrowing, or when it also lifts live blocks.
	Ack string
	// Lift is, while the entry is Current, the live blocks it placed that an Undo can lift with it (lift.go).
	Lift []LiftOption
}

// History is the changes and reverts of the contract ref names, newest first.
func (s *Service) History(ref string) ([]HistoryEntry, error) {
	if s.remote() {
		return remoteService[[]HistoryEntry](s, unclassified(), "History", struct{ Ref string }{ref})
	}

	c, err := s.contract(ref)
	if err != nil {
		return nil, err
	}
	es, err := rulefile.History(s.Ledger, c.newest.Resolved)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]rulefile.Entry, len(es))
	for _, e := range es {
		byID[e.ID] = e
	}
	out := make([]HistoryEntry, 0, len(es))
	for _, e := range es {
		h := HistoryEntry{ID: e.ID, Op: e.Op, At: e.At, Via: e.Via, Run: e.Run, Line: e.Line, Summary: e.Summary,
			Sentences: e.Sentences, Direction: e.Direction, Reverts: e.Reverts, UndoneBy: e.UndoneBy,
			Current: c.Base != "" && e.NewSHA256 == c.Base && e.Op != rulefile.OpCreate}
		if e.Op == rulefile.OpRevert {
			h.Words = rulesview.UndoWords(e, byID)
		}
		if h.Current {
			h.Ack = s.ack(revertRef(e.ID), e.NewSHA256, e.OldSHA256)
			h.Lift = mine(s.liftable(e, es))
		}
		for _, l := range e.Live {
			h.Live = append(h.Live, liveResult(l))
		}
		out = append(out, h)
	}
	return out, nil
}

// Revert gives the contract of the journal entry req.ID its text before that entry back, compiled in the contract's
// run context first. It is refused for an entry of a contract outside the set (ErrNoContract), when the contract
// holds other text than req.Base or than the entry wrote (ErrStale: a later change would be lost), and, for a revert
// that is not a narrowing, without the Ack the Undo was offered with (ErrNeedsAck).
func (s *Service) Revert(ctx context.Context, req RevertReq) (*Reverted, error) {
	if s.remote() {
		return remoteService[*Reverted](s, ctx, "Revert", struct{ Req RevertReq }{req})
	}

	es, err := rulefile.ReadJournal(s.Ledger)
	if err != nil {
		return nil, err
	}
	var e *rulefile.Entry
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].ID == req.ID && (es[i].Op == rulefile.OpChange || es[i].Op == rulefile.OpRevert) {
			e = &es[i]
			break
		}
	}
	if e == nil {
		return nil, fmt.Errorf("%w: %w: the journal holds no change %q", ErrRefused, rulefile.ErrNoChange, req.ID)
	}
	c, err := s.contractOfPath(e.Contract)
	if err != nil {
		return nil, err
	}
	f, err := s.readContract(c)
	if err != nil {
		return nil, err
	}
	if req.Base == "" || req.Base != f.SHA256 || f.SHA256 != e.NewSHA256 {
		return nil, fmt.Errorf("%w: %s holds other text than %s wrote, so it is not undone (that would lose a later change)",
			ErrStale, c.Path, e.ID)
	}
	// The blocks the entry placed that still hold: the journal folded for the contract has its later live outcomes.
	// Only its own blocks are lifted (liftable): the rest stay in force.
	var all []LiftOption
	var hist []rulefile.Entry
	if h, herr := rulefile.History(s.Ledger, e.Contract); herr == nil {
		hist = h
		if i := slices.IndexFunc(hist, func(h rulefile.Entry) bool { return h.ID == e.ID }); i >= 0 {
			all = s.liftable(hist[i], hist)
		}
	}
	lift := mine(all)
	via := Via
	switch req.Via {
	case "":
	case ViaCLI:
		via = ViaCLI
	default:
		return nil, fmt.Errorf("%w: %q is not a writer a revert may be journaled under", ErrRefused, req.Via)
	}
	dir := inverse(e.Direction)
	ackOK := s.ackOK(req.Ack, revertRef(e.ID), e.NewSHA256, e.OldSHA256)
	if (dir != string(rule.Narrows) || req.Lift && len(lift) > 0) && !ackOK {
		return nil, ackErr(req.Ack)
	}
	// What an undo of a revert (a Redo) puts back, taken before the write while the journal is read: the blocks that
	// revert's Undo lifted, and each it will not put back with why (what the person is told it skipped).
	var back []LiftOption
	var skipped []LiveResult
	if e.Op == rulefile.OpRevert {
		i := slices.IndexFunc(hist, func(h rulefile.Entry) bool { return h.ID == e.ID })
		if i >= 0 {
			back, skipped = s.restorable(hist[i])
		} else {
			skipped = []LiveResult{{By: rulefile.LiveByRedo, Err: "not put back: the journal could not be read, so which live blocks the Undo had lifted is not known"}}
		}
	}
	chk := s.check(ctx, c.context(s))
	r, err := s.writer().Revert(ctx, e.ID, rulefile.RevertOptions{
		// The older text that the compiler no longer accepts is a refusal (ErrNotCompiled, nothing written), not a
		// failure of the write.
		Check: func(text []byte) error {
			if err := chk(text); err != nil {
				return fmt.Errorf("%w: %w", ErrNotCompiled, err)
			}
			return nil
		},
		Change: rulefile.Change{Via: via, Direction: dir}})
	switch {
	case errors.Is(err, rulefile.ErrStale):
		return nil, fmt.Errorf("%w: %v", ErrStale, err)
	case err != nil && !errors.Is(err, rulefile.ErrJournal):
		// Still ErrRefused (the dashboard says "Nothing was written"), with the cause kept in the chain so a caller can
		// tell the older text that no longer compiles (ErrNotCompiled) from a write that failed (a permission, a guard,
		// a cancelled context).
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	out := &Reverted{Of: e.ID, Ref: c.Ref, Contract: c.Path, Direction: dir}
	if r != nil {
		out.ID, out.Bak = r.ID, r.Bak
	}
	if err != nil {
		// Written, not journaled (ErrJournal): no journal line holds the ID, so nothing offers to undo it, and no
		// live block is lifted or put back: what is in force must be what the journal shows. The blocks stay.
		out.ID = ""
		out.Kept = all
		out.Restored = skipped
		for _, o := range back {
			out.Restored = append(out.Restored, LiveResult{Run: o.Run, Block: o.Block, By: rulefile.LiveByRedo,
				Err: "not put back: the journal does not hold this undo"})
		}
		return out, fmt.Errorf("%w; no live block was lifted or put back, since the journal does not hold this undo", err)
	}
	if !req.Lift {
		out.Kept = all
	} else {
		// The file holds its old text now; the blocks follow it. A lift that fails is reported, never a reason to take
		// the Undo back, and is journaled (begun, then done) so its history says what was lifted.
		var jerr error
		out.Lifted, jerr = s.journaled(ctx, out.ID, lift, true, s.lift)
		out.Kept = theirs(all)
		if jerr != nil {
			err = jerr
		}
	}
	if len(back) > 0 {
		var jerr error
		out.Restored, jerr = s.journaled(ctx, out.ID, back, false, s.restore)
		if jerr != nil && err == nil {
			err = jerr
		}
	}
	out.Restored = append(out.Restored, skipped...)
	return out, err
}

// inverse is the direction of undoing a change of direction d: a narrowing undone widens, a widening undone narrows,
// and anything else (mixed, a free edit, an entry with no direction) stays mixed.
func inverse(d string) string {
	switch rule.Direction(d) {
	case rule.Narrows:
		return string(rule.Widens)
	case rule.Widens:
		return string(rule.Narrows)
	case rule.Mixed:
	}
	return string(rule.Mixed)
}
