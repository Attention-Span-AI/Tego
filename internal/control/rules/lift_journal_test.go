// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// flakyWriter is the service's writer with a journal that fails when told: the revert's own line (ErrJournal, after the
// file was written) or the n-th live line.
type flakyWriter struct {
	Writer
	revertErr error
	liveCalls int
	failLive  int // the 1-based AppendLive call that fails; 0 never
}

func (w *flakyWriter) Revert(ctx context.Context, id string, o rulefile.RevertOptions) (*rulefile.Entry, error) {
	e, err := w.Writer.Revert(ctx, id, o)
	if err == nil && w.revertErr != nil {
		return e, w.revertErr
	}
	return e, err
}

func (w *flakyWriter) AppendLive(ctx context.Context, of string, live []rulefile.Live) error {
	w.liveCalls++
	if w.liveCalls == w.failLive {
		return errors.New("injected: the journal cannot be written")
	}
	return w.Writer.AppendLive(ctx, of, live)
}

// flaky puts a flakyWriter in front of the service's writer, after the change under test was saved.
func (lf *liftFixture) flaky() *flakyWriter {
	w := &flakyWriter{Writer: lf.s.writer()}
	lf.s.Writer = w
	return w
}

// TestUndoWhoseJournalLineFailedLiftsNothing: the contract was written but the journal could not hold the Undo.
// No lift may be in force that the journal does not show, so no block is lifted; the answer says they stay.
func TestUndoWhoseJournalLineFailedLiftsNothing(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	w := lf.flaky()
	w.revertErr = fmt.Errorf("%w: injected", rulefile.ErrJournal)
	r, err := lf.s.Revert(context.Background(), RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if !errors.Is(err, rulefile.ErrJournal) || r == nil {
		t.Fatalf("revert: %+v %v; want the journal error and the answer", r, err)
	}
	if len(lf.lifts) != 0 || !slices.Equal(lf.keys(runA2), []string{"exec:cat"}) {
		t.Errorf("a lift was made for an Undo the journal does not hold: lifts %v, overlay %v", lf.lifts, lf.keys(runA2))
	}
	if r.ID != "" || len(r.Lifted) != 0 || len(r.Kept) != 1 || r.Kept[0].Block != "exec:cat" {
		t.Errorf("answer: %+v; want no ID, nothing lifted, the block kept", r)
	}
	if !strings.Contains(err.Error(), "no live block was lifted") {
		t.Errorf("the error does not say the blocks stay: %v", err)
	}
	if lf.text(t) != baseText {
		t.Error("the Undo's text was not left written: the file is what the journal error says it holds")
	}
}

// TestLiftNeedsItsBegunLine: a lift is made only after the journal holds the line that says it was begun; when
// that line cannot be written no lift is made and the answer says so, and the Undo itself stands.
func TestLiftNeedsItsBegunLine(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	w := lf.flaky()
	w.failLive = 1
	r, err := lf.s.Revert(context.Background(), RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err == nil || r == nil || r.ID == "" {
		t.Fatalf("revert: %+v %v; want the Undo written and an error", r, err)
	}
	if len(lf.lifts) != 0 || !slices.Equal(lf.keys(runA2), []string{"exec:cat"}) {
		t.Errorf("a lift was made with no begun line: lifts %v, overlay %v", lf.lifts, lf.keys(runA2))
	}
	if len(r.Lifted) != 1 || r.Lifted[0].OK || !strings.Contains(r.Lifted[0].Err, "not lifted") {
		t.Errorf("the answer does not say it was not lifted: %+v", r.Lifted)
	}
	if lf.text(t) != baseText {
		t.Error("a failed lift took the Undo back")
	}
}

// TestLiftOutcomeUnrecordedStaysBegun: the lift was made and its outcome line could not be written. The journal
// then shows the lift as begun with no end, which is the truth, and the answer says the outcome is missing.
func TestLiftOutcomeUnrecordedStaysBegun(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	w := lf.flaky()
	w.failLive = 2
	r, err := lf.s.Revert(context.Background(), RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err == nil || !strings.Contains(err.Error(), "not journaled") {
		t.Fatalf("revert: %+v %v; want an error that says the outcome was not journaled", r, err)
	}
	if len(lf.lifts) != 1 || len(lf.overlay[runA2]) != 0 {
		t.Fatalf("the lift was not made: lifts %v, overlay %v", lf.lifts, lf.keys(runA2))
	}
	hs, herr := lf.s.History(c.Ref)
	if herr != nil || hs[0].ID != r.ID || len(hs[0].Live) != 1 {
		t.Fatalf("history: %+v %v", hs, herr)
	}
	if l := hs[0].Live[0]; !l.Pending || !l.Lift || l.OK || l.By != rulefile.LiveByUndo || !strings.Contains(l.Err, "begun") {
		t.Errorf("the journal shows the lift as %+v; want begun, with no end recorded", l)
	}
}

// TestFinishedLiftReplacesItsBegunLine: when both lines are written, History shows the one outcome, not the
// begun line beside it.
func TestFinishedLiftReplacesItsBegunLine(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	r, err := lf.s.Revert(context.Background(), RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	hs, err := lf.s.History(c.Ref)
	if err != nil || hs[0].ID != r.ID || len(hs[0].Live) != 1 || !hs[0].Live[0].OK || hs[0].Live[0].Pending || hs[0].Live[0].By != rulefile.LiveByUndo {
		t.Fatalf("history: %+v %v", hs, err)
	}
	var live int
	for _, e := range lf.journal(t) {
		if e.Op == rulefile.OpLive && e.Of == r.ID {
			live++
		}
	}
	if live != 2 {
		t.Errorf("the journal holds %d live lines for the Undo, want its begun line and its outcome", live)
	}
}

// TestUndoLeavesABlockPlacedAgainBetweenOfferAndLift: the Undo was offered the change's own block; before it
// lifts, a person lifts it and places it again (another writer, as the dashboard and a terminal may be). The lift is
// bound to the add the change made, so it is refused and the person's block stays.
func TestUndoLeavesABlockPlacedAgainBetweenOfferAndLift(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	if len(h.Lift) != 1 || !h.Lift[0].Mine {
		t.Fatalf("lift offered: %+v", h.Lift)
	}
	was := lf.s.unblock
	lf.s.unblock = func(ctx context.Context, run, kind, value string, own liveblock.Own) error {
		lf.manualLift(run, kind+":"+value) // the person, in the window
		lf.manualBlock(run, kind+":"+value)
		return was(ctx, run, kind, value, own)
	}
	r, err := lf.s.Revert(context.Background(), RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(lf.keys(runA2), []string{"exec:cat"}) {
		t.Errorf("the person's block was lifted: %v", lf.keys(runA2))
	}
	if len(r.Lifted) != 1 || r.Lifted[0].OK || !strings.Contains(r.Lifted[0].Err, "not lifted") {
		t.Errorf("the answer: %+v; want the lift reported as not made", r.Lifted)
	}
}

// TestUndoKeepsABlockThePlacementJournalHasNoSerialFor: a block placed before the journal kept who made it (no
// serial) cannot be shown to be the change's, so an Undo never lifts it; it is said to stay.
func TestUndoKeepsABlockThePlacementJournalHasNoSerialFor(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	// Rewrite the journal as an older tego wrote it: the placement's line carries no serial and no owner.
	for _, e := range lf.journal(t) {
		if e.Op == rulefile.OpChange && e.ID == id {
			lf.dropOwners(t, id)
		}
	}
	c, h := lf.current(t)
	if h.ID != id || len(h.Lift) != 0 {
		t.Fatalf("a block with no serial is offered: %+v", h.Lift)
	}
	r, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(lf.lifts) != 0 || len(r.Lifted) != 0 || len(r.Kept) != 1 || r.Kept[0].Mine || !slices.Equal(lf.keys(runA2), []string{"exec:cat"}) {
		t.Errorf("lifts %v, answer %+v, overlay %v", lf.lifts, r, lf.keys(runA2))
	}
}

// TestRedoPutsBackWhatTheUndoLifted: the Undo of a narrowing lifted its live block; undoing that Undo narrows
// again and puts the block back on the run, as the Redo's own, which a later Undo of the Redo lifts in turn.
func TestRedoPutsBackWhatTheUndoLifted(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	undo, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil || len(undo.Lifted) != 1 || len(lf.overlay[runA2]) != 0 {
		t.Fatalf("undo: %+v %v, overlay %v", undo, err, lf.keys(runA2))
	}
	c, h = lf.current(t)
	if h.ID != undo.ID {
		t.Fatalf("current entry %s, want the undo %s", h.ID, undo.ID)
	}
	redo, err := lf.s.Revert(ctx, RevertReq{ID: undo.ID, Base: c.Base, Ack: h.Ack})
	if err != nil || redo.ID == "" {
		t.Fatalf("redo: %+v %v", redo, err)
	}
	if !slices.Equal(lf.keys(runA2), []string{"exec:cat"}) {
		t.Fatalf("the Redo did not put the block back: overlay %v", lf.keys(runA2))
	}
	if len(redo.Restored) != 1 || !redo.Restored[0].OK || redo.Restored[0].By != rulefile.LiveByRedo || redo.Restored[0].Serial == 0 {
		t.Errorf("restored: %+v", redo.Restored)
	}
	// The Redo owns what it put back: its own Undo offers to lift exactly that.
	c, h = lf.current(t)
	if h.ID != redo.ID || len(h.Lift) != 1 || !h.Lift[0].Mine || h.Lift[0].Block != "exec:cat" {
		t.Fatalf("the Redo's lift offered: %+v (current %s, want %s)", h.Lift, h.ID, redo.ID)
	}
	again, err := lf.s.Revert(ctx, RevertReq{ID: redo.ID, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil || len(again.Lifted) != 1 || !again.Lifted[0].OK || len(lf.overlay[runA2]) != 0 {
		t.Errorf("undo of the redo: %+v %v, overlay %v", again, err, lf.keys(runA2))
	}
}

// TestRedoLeavesAPersonsBlockAndPutsBackOnlyWhatTheUndoLifted: a person who placed the block again after
// the Undo keeps it as theirs (the Redo adds nothing and claims nothing); and a block the person lifted by hand, with
// no Undo lift, is not one a Redo restores.
func TestRedoLeavesAPersonsBlockAndPutsBackOnlyWhatTheUndoLifted(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()

	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	undo, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	lf.manualBlock(runA2, "exec:cat") // the person places it again by hand
	was := lf.serial[runA2]
	c, h = lf.current(t)
	redo, err := lf.s.Revert(ctx, RevertReq{ID: undo.ID, Base: c.Base, Ack: h.Ack})
	if err != nil || len(redo.Restored) != 1 || redo.Restored[0].OK || !redo.Restored[0].Held || redo.Restored[0].By != rulefile.LiveByRedo || lf.serial[runA2] != was || !slices.Equal(lf.keys(runA2), []string{"exec:cat"}) {
		t.Fatalf("redo over a person's block: %+v %v, serial %d -> %d", redo, err, was, lf.serial[runA2])
	}
	// The Redo's Undo must not lift the person's block either: the Redo made none.
	if _, h = lf.current(t); len(h.Lift) != 0 {
		t.Errorf("the Redo's Undo offers the person's block: %+v", h.Lift)
	}

	// A second change, undone WITHOUT the lift box: the Undo lifted nothing, so a Redo has nothing to put back, even
	// though the person then lifted the block by hand.
	lf.manualLift(runA2, "exec:cat")
	id2 := lf.narrowNow(t, "ls")
	c, h = lf.current(t)
	undo2, err := lf.s.Revert(ctx, RevertReq{ID: id2, Base: c.Base, Ack: h.Ack})
	if err != nil {
		t.Fatal(err)
	}
	lf.manualLift(runA2, "exec:ls")
	c, h = lf.current(t)
	redo2, err := lf.s.Revert(ctx, RevertReq{ID: undo2.ID, Base: c.Base, Ack: h.Ack})
	if err != nil || len(redo2.Restored) != 0 || len(lf.overlay[runA2]) != 0 {
		t.Errorf("redo of an Undo that lifted nothing: %+v %v, overlay %v", redo2, err, lf.keys(runA2))
	}
}

// TestRedoWhoseJournalLineFailedPlacesNothing: a placement is made only after the journal holds its begun
// line, as a lift is.
func TestRedoWhoseJournalLineFailedPlacesNothing(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	undo, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	c, h = lf.current(t)
	w := lf.flaky()
	w.failLive = 1
	redo, err := lf.s.Revert(ctx, RevertReq{ID: undo.ID, Base: c.Base, Ack: h.Ack})
	if err == nil || redo == nil || len(lf.overlay[runA2]) != 0 {
		t.Fatalf("redo with no journal for the placement: %+v %v, overlay %v", redo, err, lf.keys(runA2))
	}
	if len(redo.Restored) != 1 || redo.Restored[0].OK || !strings.Contains(redo.Restored[0].Err, "not put back") {
		t.Errorf("restored: %+v", redo.Restored)
	}
}

// dropOwners rewrites the live lines of change id as a tego from before the journal kept who made a block wrote them:
// no serial and no owner on any outcome.
func (lf *liftFixture) dropOwners(t *testing.T, id string) {
	t.Helper()
	p := filepath.Join(lf.ledger, rulefile.JournalDirName, rulefile.JournalFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		if m["op"] == rulefile.OpLive && m["of"] == id {
			for _, l := range m["live"].([]any) {
				delete(l.(map[string]any), "serial")
				delete(l.(map[string]any), "epoch")
				delete(l.(map[string]any), "at")
				delete(l.(map[string]any), "by")
			}
			if line, err = json.Marshal(m); err != nil {
				t.Fatal(err)
			}
		}
		out = append(out, line)
	}
	if err := os.WriteFile(p, append(bytes.Join(out, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUndoKeepsAPersonsBlockInARecreatedOverlay: the change placed exec:cat as the run's first overlay write (serial 1).
// The overlay file was removed, and the person blocked exec:cat by hand: serial 1 again, in a file of its own. The
// change's Undo must neither offer nor lift it.
func TestUndoKeepsAPersonsBlockInARecreatedOverlay(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	id := lf.narrowNow(t, "cat")
	lf.recreate(runA2)
	lf.manualBlock(runA2, "exec:cat")
	if lf.overlay[runA2]["exec:cat"].Serial != 1 {
		t.Fatalf("fixture: the person's add is serial %d, want 1 (the change's serial)", lf.overlay[runA2]["exec:cat"].Serial)
	}
	c, h := lf.current(t)
	if h.ID != id || len(h.Lift) != 0 {
		t.Fatalf("the person's block is offered for the lift: %+v", h.Lift)
	}
	r, err := lf.s.Revert(context.Background(), RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil || len(lf.lifts) != 0 || len(r.Lifted) != 0 || !slices.Equal(lf.keys(runA2), []string{"exec:cat"}) {
		t.Errorf("revert: %+v %v; lifts %v, overlay %v", r, err, lf.lifts, lf.keys(runA2))
	}
}

// TestUndoLiftsTheLatestPlacementOfABlock: the change placed the block, the person lifted it by hand, and an Apply now
// placed it again: the journal holds two placements of the block on the run. The one that is the overlay's block now
// decides, so the Undo lifts the block the change made last.
func TestUndoLiftsTheLatestPlacementOfABlock(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	lf.manualLift(runA2, "exec:cat")
	b, err := lf.s.block(ctx, runA2, "exec", "cat")
	if err != nil || !b.Fresh {
		t.Fatal(b, err)
	}
	if err := rulefile.AppendLive(ctx, lf.ledger, id, []rulefile.Live{{Run: runA2, Block: "exec:cat", OK: true, By: rulefile.LiveByChange,
		Serial: b.Serial, Epoch: b.Epoch, At: b.At}}); err != nil {
		t.Fatal(err)
	}
	c, h := lf.current(t)
	if h.ID != id || len(h.Lift) != 1 || !h.Lift[0].Mine {
		t.Fatalf("lift offered: %+v; want the second placement's block", h.Lift)
	}
	r, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil || len(r.Lifted) != 1 || !r.Lifted[0].OK || len(lf.overlay[runA2]) != 0 {
		t.Errorf("revert: %+v %v, overlay %v", r, err, lf.keys(runA2))
	}
}

// TestHeldLineStillHoldsTheBlock: a later change that found the block already held (a held line) still asks for it, so
// the earlier change's Undo does not lift what that standing change wants; an undone one does not.
func TestHeldLineStillHoldsTheBlock(t *testing.T) {
	held := rulefile.Entry{ID: "rc-later", Op: rulefile.OpChange, Live: []rulefile.Live{{Run: runA2, Block: "exec:cat", Held: true, By: rulefile.LiveByChange}}}
	if !heldByOther("rc-earlier", runA2, "exec:cat", []rulefile.Entry{held}) {
		t.Error("a standing change that found the block held does not hold it")
	}
	held.UndoneBy = "rc-y"
	if heldByOther("rc-earlier", runA2, "exec:cat", []rulefile.Entry{held}) {
		t.Error("an undone change holds the block")
	}
	held.UndoneBy, held.Live[0].Pending = "", true
	if heldByOther("rc-earlier", runA2, "exec:cat", []rulefile.Entry{held}) {
		t.Error("a begun line holds the block")
	}
}

// TestRedoNeverClaimsAPersonsBlockPlacedInTheWindow: between what the Redo reads and what it places, a person blocks the
// same key. The placement finds it held: the Redo records no ownership and says it was already there, and its own Undo
// offers nothing.
func TestRedoNeverClaimsAPersonsBlockPlacedInTheWindow(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	undo, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	was := lf.s.block
	lf.s.block = func(ctx context.Context, run, kind, value string) (runact.Blocked, error) {
		lf.manualBlock(run, kind+":"+value) // the person, in the window
		return was(ctx, run, kind, value)
	}
	c, h = lf.current(t)
	redo, err := lf.s.Revert(ctx, RevertReq{ID: undo.ID, Base: c.Base, Ack: h.Ack})
	if err != nil || len(redo.Restored) != 1 {
		t.Fatalf("redo: %+v %v", redo, err)
	}
	if r := redo.Restored[0]; r.OK || !r.Held || r.Serial != 0 || r.Epoch != "" || r.By != rulefile.LiveByRedo {
		t.Errorf("restored: %+v; want held, with no ownership", r)
	}
	for _, e := range lf.journal(t) {
		if e.Op == rulefile.OpLive && e.Of == redo.ID {
			for _, l := range e.Live {
				if l.Placed() || l.Serial != 0 {
					t.Errorf("the Redo journaled ownership of the person's block: %+v", l)
				}
			}
		}
	}
	if _, h = lf.current(t); len(h.Lift) != 0 {
		t.Errorf("the Redo's Undo offers the person's block: %+v", h.Lift)
	}
}

// TestRedoSaysWhatItSkipped: a Redo that does not put a block back says which and why: its run ended.
func TestRedoSaysWhatItSkipped(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	undo, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	lf.live[runA2] = false // the run ended
	c, h = lf.current(t)
	redo, err := lf.s.Revert(ctx, RevertReq{ID: undo.ID, Base: c.Base, Ack: h.Ack})
	if err != nil || len(redo.Restored) != 1 || redo.Restored[0].OK || redo.Restored[0].Block != "exec:cat" ||
		!strings.Contains(redo.Restored[0].Err, "ended") {
		t.Errorf("redo: %+v %v; want the skipped block and why", redo, err)
	}
	if len(lf.overlay[runA2]) != 0 {
		t.Errorf("a block was placed on an ended run: %v", lf.keys(runA2))
	}
}
