// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// liftFixture is newFixture with an overlay per run that placing and lifting change, and the lifts it was asked.
type liftFixture struct {
	*fixture
	overlay map[string][]string
	lifts   []string
	liftErr error
}

func newLiftFixture(t *testing.T) *liftFixture {
	t.Helper()
	lf := &liftFixture{fixture: newFixture(t), overlay: map[string][]string{}}
	lf.s.block = func(_ context.Context, run, kind, value string) error {
		lf.blocks = append(lf.blocks, run+" "+kind+":"+value)
		if k := kind + ":" + value; !slices.Contains(lf.overlay[run], k) {
			lf.overlay[run] = append(lf.overlay[run], k)
		}
		return nil
	}
	lf.s.unblock = func(_ context.Context, run, kind, value string) error {
		lf.lifts = append(lf.lifts, run+" "+kind+":"+value)
		if lf.liftErr != nil {
			return lf.liftErr
		}
		lf.overlay[run] = slices.DeleteFunc(lf.overlay[run], func(k string) bool { return k == kind+":"+value })
		return nil
	}
	lf.s.overlay = func(run string) []string { return lf.overlay[run] }
	return lf
}

// narrowNow saves "remove exec.allow <prog>" with Also apply now on runA2 and returns its journal id.
func (lf *liftFixture) narrowNow(t *testing.T, prog string) string {
	t.Helper()
	c := lf.ref(t, lf.contract)
	a, err := lf.s.ApplyChange(context.Background(), ChangeReq{Ref: c.Ref, Base: c.Base,
		Edits: []Edit{{"remove", "exec.allow", prog}}, AlsoNow: []string{runA2}})
	if err != nil || a.ID == "" || len(a.Live) != 1 || !a.Live[0].OK {
		t.Fatalf("apply: %+v %v", a, err)
	}
	return a.ID
}

func (lf *liftFixture) current(t *testing.T) (ContractRef, HistoryEntry) {
	t.Helper()
	c := lf.ref(t, lf.contract)
	hs, err := lf.s.History(c.Ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hs {
		if h.Current {
			return c, h
		}
	}
	t.Fatalf("no current entry: %+v", hs)
	return c, HistoryEntry{}
}

// TestUndoLiftsLiveBlocks: a narrowing saved with "Also apply now" offers, while its run runs and holds the block,
// to lift that block with its Undo; the lift wants the Undo's acknowledgement, removes exactly that block, and is
// journaled on the revert with lift set, which History shows and Apply now does not count as placed.
func TestUndoLiftsLiveBlocks(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	if h.ID != id || len(h.Lift) != 1 || h.Lift[0].Run != runA2 || h.Lift[0].Block != "exec:cat" || h.Lift[0].Kind != "exec" ||
		h.Lift[0].Value != "cat" || h.Lift[0].Cwd != lf.proj {
		t.Fatalf("lift offered: %+v", h.Lift)
	}
	if _, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Lift: true}); !errors.Is(err, ErrNeedsAck) {
		t.Fatalf("lift without the ack: %v", err)
	}
	r, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil || r.ID == "" {
		t.Fatalf("revert: %+v %v", r, err)
	}
	if !slices.Equal(lf.lifts, []string{runA2 + " exec:cat"}) || len(lf.overlay[runA2]) != 0 {
		t.Errorf("lifts %v, overlay %v", lf.lifts, lf.overlay[runA2])
	}
	if len(r.Lifted) != 1 || !r.Lifted[0].OK || !r.Lifted[0].Lift || r.Lifted[0].Block != "exec:cat" || len(r.Kept) != 0 {
		t.Errorf("reverted: %+v", r)
	}
	es := lf.journal(t)
	last := es[len(es)-1]
	if last.Op != rulefile.OpLive || last.Of != r.ID || len(last.Live) != 1 || !last.Live[0].Lift || last.Live[0].Placed() {
		t.Errorf("journal's last line: %+v", last)
	}
	hs, err := lf.s.History(c.Ref)
	if err != nil || hs[0].ID != r.ID || len(hs[0].Live) != 1 || !hs[0].Live[0].Lift {
		t.Fatalf("history: %+v %v", hs, err)
	}
	// The revert is a pending change of runA2 now; its lift is not a block placed there.
	if p, ok := lf.s.PendingOn(ctx, runA2, []string{r.ID})[r.ID]; ok && len(p.Placed) != 0 {
		t.Errorf("a lift counted as placed: %+v", p)
	}
	// Undoing the undo (a narrowing again) offers no lift: the revert placed nothing.
	if _, h := lf.current(t); h.ID != r.ID || len(h.Lift) != 0 {
		t.Errorf("the revert offers a lift: %+v", h)
	}
}

// TestUndoLiftsNarrowKinds: the blocks Apply now places for a file narrowing, a write block for a removed
// fs.write folder and a read block for an added fs.deny_read, are offered and lifted by the change's Undo with their
// own kinds, as an exec block is.
func TestUndoLiftsNarrowKinds(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	lf.held = true // the run's reads reach its supervisor, so a read block refuses something
	ctx := context.Background()
	c := lf.ref(t, lf.contract)
	a, err := lf.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base,
		Edits: []Edit{{"remove", "fs.write", "./out/"}, {"add", "fs.deny_read", "./vault/"}}, AlsoNow: []string{runA2}})
	if err != nil || len(a.Live) != 2 || !a.Live[0].OK || !a.Live[1].OK {
		t.Fatalf("apply: %+v %v", a, err)
	}
	write, read := "write:"+filepath.Join(lf.proj, "out"), "read:"+filepath.Join(lf.proj, "vault")
	if got := slices.Sorted(slices.Values(lf.overlay[runA2])); !slices.Equal(got, []string{read, write}) {
		t.Fatalf("placed %q, want %q and %q", got, read, write)
	}
	c, h := lf.current(t)
	kinds := map[string]string{}
	for _, o := range h.Lift {
		kinds[o.Block] = o.Kind
	}
	if h.ID != a.ID || len(h.Lift) != 2 || kinds[write] != "write" || kinds[read] != "read" {
		t.Fatalf("lift offered: %+v", h.Lift)
	}
	r, err := lf.s.Revert(ctx, RevertReq{ID: a.ID, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil || len(r.Lifted) != 2 || !r.Lifted[0].OK || !r.Lifted[1].OK || len(r.Kept) != 0 {
		t.Fatalf("revert: %+v %v", r, err)
	}
	if got := slices.Sorted(slices.Values(lf.lifts)); !slices.Equal(got, []string{runA2 + " " + read, runA2 + " " + write}) {
		t.Errorf("lifts %q", got)
	}
	if len(lf.overlay[runA2]) != 0 {
		t.Errorf("left on the run: %q", lf.overlay[runA2])
	}
}

// TestUndoKeepsLiveBlocks: an Undo without the box lifts nothing and says which blocks stay; a block whose run ended,
// one removed already, and one another standing change placed too are never offered.
func TestUndoKeepsLiveBlocks(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	c, h := lf.current(t)
	r, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack})
	if err != nil || len(lf.lifts) != 0 || len(r.Lifted) != 0 || len(r.Kept) != 1 || r.Kept[0].Block != "exec:cat" {
		t.Fatalf("undo without lift: %+v %v, lifts %v", r, err, lf.lifts)
	}
	if !slices.Equal(lf.overlay[runA2], []string{"exec:cat"}) {
		t.Errorf("overlay %v", lf.overlay[runA2])
	}

	cases := []struct {
		name  string
		setup func(t *testing.T) string // returns the id of the change to look at
	}{
		{"run ended", func(t *testing.T) string {
			id := lf.narrowNow(t, "ls")
			lf.live[runA2] = false
			return id
		}},
		{"removed by hand", func(t *testing.T) string {
			lf.live[runA2] = true
			id := lf.narrowNow(t, "cat")
			lf.overlay[runA2] = nil
			return id
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.setup(t)
			_, h := lf.current(t)
			if h.ID != id || len(h.Lift) != 0 {
				t.Errorf("offered %+v", h.Lift)
			}
		})
	}
}

// TestUndoLiftHeldByOther: when a later change placed the same block on the run and still stands, undoing the earlier
// one (after the later is undone without its lift, so the file holds the earlier text again) still lifts nothing that
// the standing one needs; a failed lift is reported and journaled, never a reason to keep the old text.
func TestUndoLiftHeldByOther(t *testing.T) {
	lf := newLiftFixture(t)
	lf.live[runA2] = true
	ctx := context.Background()
	id := lf.narrowNow(t, "cat")
	// A second, standing entry that placed exec:cat on runA2 too (an Apply now of a revert, say), written by hand.
	if err := rulefile.AppendLive(ctx, lf.ledger, "rc-other-standing", []rulefile.Live{{Run: runA2, Block: "exec:cat", OK: true}}); err != nil {
		t.Fatal(err)
	}
	_, h := lf.current(t)
	if h.ID != id || len(h.Lift) != 1 {
		t.Fatalf("an OpLive of no entry of this file must not hold the block: %+v", h.Lift)
	}
	hist, err := rulefile.History(lf.ledger, resolvedPath(lf.contract))
	if err != nil {
		t.Fatal(err)
	}
	other := rulefile.Entry{ID: "rc-x", Op: rulefile.OpChange, Live: []rulefile.Live{{Run: runA2, Block: "exec:cat", OK: true}}}
	if !heldByOther(id, runA2, "exec:cat", append(hist, other)) {
		t.Error("a standing entry that placed the block does not hold it")
	}
	other.UndoneBy = "rc-y"
	if heldByOther(id, runA2, "exec:cat", append(hist, other)) {
		t.Error("an undone entry holds the block")
	}
	other.UndoneBy, other.Live[0].Lift = "", true
	if heldByOther(id, runA2, "exec:cat", append(hist, other)) {
		t.Error("a lift holds the block")
	}

	lf.liftErr = errors.New("the run is not running")
	c, h := lf.current(t)
	r, err := lf.s.Revert(ctx, RevertReq{ID: id, Base: c.Base, Ack: h.Ack, Lift: true})
	if err != nil || r.ID == "" || len(r.Lifted) != 1 || r.Lifted[0].OK || !strings.Contains(r.Lifted[0].Err, "not lifted") {
		t.Fatalf("failed lift: %+v %v", r, err)
	}
	if lf.text(t) != baseText {
		t.Error("a failed lift took the Undo back")
	}
	es := lf.journal(t)
	if last := es[len(es)-1]; last.Op != rulefile.OpLive || len(last.Live) != 1 || last.Live[0].OK || !last.Live[0].Lift {
		t.Errorf("journal: %+v", last)
	}
}

// TestUndoOfWideningNeedsNoAckToLiftNothing: an Undo that narrows (of a widening) with the lift box and nothing to
// lift writes without an acknowledgement, as before.
func TestUndoOfWideningNeedsNoAckToLiftNothing(t *testing.T) {
	lf := newLiftFixture(t)
	ctx := context.Background()
	c := lf.ref(t, lf.contract)
	git := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "git"}}}
	git.Ack = changeAck(t, lf.s, git)
	a, err := lf.s.ApplyChange(ctx, git)
	if err != nil {
		t.Fatal(err)
	}
	c = lf.ref(t, lf.contract)
	r, err := lf.s.Revert(ctx, RevertReq{ID: a.ID, Base: c.Base, Lift: true})
	if err != nil || r.Direction != "narrows" || len(r.Lifted) != 0 || len(lf.lifts) != 0 {
		t.Fatalf("revert: %+v %v", r, err)
	}
}
