// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestBlockSaysWhoMadeIt: an add that finds the block held made none (Fresh false) and a lift of the person's
// own block, bound to another add, is refused and leaves the block.
func TestBlockSaysWhoMadeIt(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":41`)
	holdRunLock(t, dir)
	first, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
	if err != nil || !first.Fresh || first.Serial != 1 {
		t.Fatalf("the first add: %+v, %v", first, err)
	}
	again, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
	if err != nil || again.Fresh {
		t.Fatalf("an add of a held block is not Fresh: %+v, %v", again, err)
	}
	adds, err := LiveAdds(root, liveRun)
	if err != nil || !adds["exec:cat"].Is(first.Own()) || len(adds) != 1 || !first.Own().Known() {
		t.Fatalf("LiveAdds = %v, %v; want exec:cat made by the first add %+v", adds, err, first.Own())
	}

	// The person lifts the block and puts it back: the same key, an add of its own.
	if _, err := Block(ctx, root, liveRun, "exec", "cat", false); err != nil {
		t.Fatal(err)
	}
	mine, err := Block(ctx, root, liveRun, "exec", "cat", true)
	if err != nil || !mine.Fresh || mine.Serial != 3 {
		t.Fatalf("the person's add: %+v, %v", mine, err)
	}
	// The change's Undo, bound to its own add (serial 1), must leave it.
	if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", first.Own()); !errors.Is(err, ErrOverlayMoved) {
		t.Fatalf("a lift of a block another add made: %v, want ErrOverlayMoved", err)
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil || len(o.Blocks) != 1 || o.Serial != 3 {
		t.Fatalf("overlay after the refused lift: %+v, %v", o, err)
	}
	// Bound to the identity of the add the overlay lists now, the removal is made.
	now, err := LiveAdds(root, liveRun)
	if err != nil || now["exec:cat"].Serial != mine.Serial || !now["exec:cat"].Known() {
		t.Fatalf("LiveAdds = %v, %v", now, err)
	}
	if b, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", now["exec:cat"]); err != nil || b.Word != "block removed" || b.Serial != 4 {
		t.Fatalf("a lift of its own block: %+v, %v", b, err)
	}
	// A block already gone is not removed, and nothing is written.
	if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", now["exec:cat"]); !errors.Is(err, ErrOverlayMoved) {
		t.Fatalf("a lift of a block that is gone: %v", err)
	}
	if o, err := liveblock.Read(dir, liveRun); err != nil || o.Serial != 4 {
		t.Fatalf("overlay: %+v, %v", o, err)
	}
}

// TestUnblockOwnedLeavesADormantBlock: an unblock for a while keeps the block dormant, so the newest change of its key
// is not an add and a lift bound to the old add leaves it.
func TestUnblockOwnedLeavesADormantBlock(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":41`)
	holdRunLock(t, dir)
	b, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
	if err != nil || !b.Own().Known() {
		t.Fatal(err)
	}
	if _, err := BlockUntil(ctx, root, liveRun, "exec", "cat", false, time.Now().Add(time.Hour), "dashboard"); err != nil {
		t.Fatal(err)
	}
	if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", b.Own()); !errors.Is(err, ErrOverlayMoved) {
		t.Fatalf("a lift of a dormant block: %v, want ErrOverlayMoved", err)
	}
	adds, err := LiveAdds(root, liveRun)
	if err != nil || adds["exec:cat"].Known() {
		t.Fatalf("a dormant block has no add to own: %v, %v", adds, err)
	}
	if o, err := liveblock.Read(dir, liveRun); err != nil || len(o.Blocks) != 1 {
		t.Fatalf("overlay: %+v, %v", o, err)
	}
}

// TestLiftAtRefusesAMovedOverlay: the lift the dashboard confirms is written only while the overlay is at the
// serial its acknowledgement was made for; another writer's change in between (a restore in a terminal, a block) is
// ErrOverlayMoved and nothing is written.
func TestLiftAtRefusesAMovedOverlay(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, adjustableStart)
	holdRunLock(t, dir)
	if _, err := liveblock.WriteKey(dir); err != nil {
		t.Fatal(err)
	}
	seen, err := Live(root, liveRun)
	if err != nil || seen.Serial != 0 {
		t.Fatalf("Live: %+v, %v", seen, err)
	}
	// Another writer changes the overlay after the preview was acknowledged.
	if _, err := Block(ctx, root, liveRun, "exec", "curl", true); err != nil {
		t.Fatal(err)
	}
	if _, err := LiftAt(ctx, root, liveRun, "read", "/srv/exports", time.Time{}, "dashboard", seen.Serial); !errors.Is(err, ErrOverlayMoved) {
		t.Fatalf("a lift on a moved overlay: %v, want ErrOverlayMoved", err)
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil || o.Serial != 1 || len(o.Changes) != 1 {
		t.Fatalf("a refused lift wrote: %+v, %v", o, err)
	}
	// At the serial the person saw, it is written.
	l, err := LiftAt(ctx, root, liveRun, "read", "/srv/exports", time.Time{}, "dashboard", o.Serial)
	if err != nil || l.Serial != 2 {
		t.Fatalf("a lift at the serial read: %+v, %v", l, err)
	}
}

// TestAnOverlayRecreatedDoesNotLendItsSerials: a change placed exec:cat as the run's first overlay write (serial 1). The
// overlay file was then removed (the tool itself says to, when it cannot read it) and the person blocked exec:cat by
// hand, which is serial 1 again in the new file. The change's lift is bound to its own add, so it must be refused and
// the person's block stays.
func TestAnOverlayRecreatedDoesNotLendItsSerials(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":41`)
	holdRunLock(t, dir)
	first, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
	if err != nil || !first.Fresh || first.Serial != 1 {
		t.Fatalf("the change's add: %+v, %v", first, err)
	}
	if err := os.Remove(filepath.Join(dir, liveblock.FileName)); err != nil {
		t.Fatal(err)
	}
	mine, err := Block(ctx, root, liveRun, "exec", "cat", true)
	if err != nil || !mine.Fresh || mine.Serial != first.Serial {
		t.Fatalf("the person's add: %+v, %v; want serial %d again", mine, err, first.Serial)
	}
	if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", first.Own()); !errors.Is(err, ErrOverlayMoved) {
		t.Fatalf("a lift bound to the change's add of the old file: %v, want ErrOverlayMoved", err)
	}
	if o, err := liveblock.Read(dir, liveRun); err != nil || len(o.Blocks) != 1 {
		t.Fatalf("the person's block was lifted: %+v, %v", o, err)
	}
}

// TestAnAddThatExtendsAPersonsTimedBlockMadeNone: the person blocked exec:cat for an hour; a rules change then asks for the
// same block with no end. The overlay changes (the block is now permanent), but the block was in force before the add,
// so the add is not Fresh and owns nothing: its Undo leaves the person's block.
func TestAnAddThatExtendsAPersonsTimedBlockMadeNone(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":41`)
	holdRunLock(t, dir)
	if _, err := BlockUntil(ctx, root, liveRun, "exec", "cat", true, time.Now().Add(time.Hour), "cli"); err != nil {
		t.Fatal(err)
	}
	b, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
	if err != nil || b.Fresh || b.Own().Known() || b.Serial != 2 {
		t.Fatalf("an add over the person's timed block: %+v, %v; want a change (serial 2) that made none", b, err)
	}
	if o, err := liveblock.Read(dir, liveRun); err != nil || len(o.Blocks) != 1 || !o.Blocks[0].Until.IsZero() {
		t.Fatalf("overlay: %+v, %v; want the block extended to no end", o, err)
	}
	if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", b.Own()); !errors.Is(err, ErrOverlayMoved) {
		t.Fatalf("a lift bound to the identity an add that made none has: %v", err)
	}
}

// TestAnAddOverAnEndedOrDormantBlockIsTheAdds: a block that has ended (kept in the file a day) or is dormant under an unblock
// for a while is not in force; an add of its key re-arms it, so the block is the add's own and its Undo may lift it.
func TestAnAddOverAnEndedOrDormantBlockIsTheAdds(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		e    func(now time.Time) liveblock.Entry
	}{
		{"ended", func(now time.Time) liveblock.Entry {
			return liveblock.Entry{Kind: liveblock.KindExec, Value: "cat", By: "uid:1 pid:2 cli", At: now.Add(-3 * time.Hour), Until: now.Add(-2 * time.Hour)}
		}},
		{"dormant", func(now time.Time) liveblock.Entry {
			return liveblock.Entry{Kind: liveblock.KindExec, Value: "cat", By: "uid:1 pid:2 cli", At: now.Add(-time.Hour), From: now.Add(time.Hour)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":41`)
			holdRunLock(t, dir)
			now := time.Now().UTC().Round(time.Millisecond)
			if _, err := liveblock.Update(ctx, dir, liveRun, func(o *liveblock.Overlay) (bool, error) {
				o.Blocks = []liveblock.Entry{tc.e(now)}
				o.Serial = 1
				o.Changes = []liveblock.Change{{Serial: 1, Op: liveblock.OpAdd, Kind: liveblock.KindExec, Value: "cat", By: "uid:1 pid:2 cli", At: now.Add(-time.Hour)}}
				return true, nil
			}); err != nil {
				t.Fatal(err)
			}
			b, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
			if err != nil || !b.Fresh || !b.Own().Known() || b.Serial != 2 {
				t.Fatalf("an add over a block not in force: %+v, %v; want Fresh with an identity", b, err)
			}
			if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", b.Own()); err != nil {
				t.Errorf("the add's own block is not lifted: %v", err)
			}
		})
	}
}

// TestASecondChangeInARecreatedOverlayIsNotTheFirstChanges: two rules changes each place exec:cat as the first write of
// a file of its own (serial 1 both times: the file was removed between). The first change's Undo is bound to the first
// file's identity, so it leaves the second change's block.
func TestASecondChangeInARecreatedOverlayIsNotTheFirstChanges(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":41`)
	holdRunLock(t, dir)
	first, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
	if err != nil || !first.Own().Known() {
		t.Fatalf("the first change's add: %+v, %v", first, err)
	}
	if err := os.Remove(filepath.Join(dir, liveblock.FileName)); err != nil {
		t.Fatal(err)
	}
	second, err := BlockFromContract(ctx, root, liveRun, "exec", "cat")
	if err != nil || !second.Fresh || second.Serial != first.Serial || second.Epoch == first.Epoch {
		t.Fatalf("the second change's add: %+v, %v; want serial %d again in a file of its own", second, err, first.Serial)
	}
	forged := first.Own()
	forged.At = second.At // even an instant the two adds share does not make them one
	if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", forged); !errors.Is(err, ErrOverlayMoved) {
		t.Fatalf("a lift bound to another file's add: %v, want ErrOverlayMoved", err)
	}
	if _, err := UnblockOwned(ctx, root, liveRun, "exec", "cat", second.Own()); err != nil {
		t.Errorf("the second change's own lift: %v", err)
	}
}
