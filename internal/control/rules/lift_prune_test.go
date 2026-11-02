// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// TestUndoAfterPruneLiftsNoBlockAnotherChangeHolds: two changes that stand placed one live block on a running run,
// and the older is far past the retention's edge and past the newest changes a Prune keeps of a file. The Prune (`tego
// gc`, a run start's pass) leaves the older change, so the Undo of the newer still offers no lift and an Undo asked to
// lift lifts nothing: the text it gives back still holds the older change, whose block must stay. Once with the
// fixture's runs, which started before both changes, and once with the only run of the file started after them by its
// run_start line (a clock set back), where only the live block the older change recorded on that run keeps it.
func TestUndoAfterPruneLiftsNoBlockAnotherChangeHolds(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprint("run started after the changes ", late), func(t *testing.T) {
			lf := newLiftFixture(t)
			run := runA2
			if late {
				for _, r := range []string{runA, runA2, runB, runG} {
					if err := os.RemoveAll(filepath.Join(lf.ledger, r)); err != nil {
						t.Fatal(err)
					}
				}
				run = "r-aaaa-0009-rules"
				lf.writeRun(t, run, lf.contract, 80*365*24*60) // 80 years on: every change reads older than the run
			}
			lf.live[run] = true
			ctx := context.Background()
			c := lf.ref(t, lf.contract)
			h, err := lf.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base,
				Edits: []Edit{{"add", "fs.deny_write", "./out/"}}, AlsoNow: []string{run}})
			if err != nil || h.ID == "" || len(h.Live) != 1 || !h.Live[0].OK {
				t.Fatalf("the older change: %+v %v", h, err)
			}
			for i := range rulefile.KeepChanges + 1 {
				c = lf.ref(t, lf.contract)
				if a, err := lf.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base,
					Edits: []Edit{{"add", "fs.deny_read", fmt.Sprintf("./d%d/", i)}}}); err != nil || a.ID == "" {
					t.Fatalf("change %d: %+v %v", i, a, err)
				}
			}
			c = lf.ref(t, lf.contract)
			e, err := lf.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base,
				Edits: []Edit{{"remove", "fs.write", "./out/"}}, AlsoNow: []string{run}})
			if err != nil || e.ID == "" {
				t.Fatalf("the newer change: %+v %v", e, err)
			}
			block := "write:" + filepath.Join(lf.proj, "out")
			if !slices.Contains(lf.overlay[run], block) {
				t.Fatalf("the overlay of %s is %v, want %s placed", run, lf.overlay[run], block)
			}
			if _, cur := lf.current(t); cur.ID != e.ID || len(cur.Lift) != 0 {
				t.Fatalf("before the Prune, the Undo of the newer change offers %+v", cur.Lift)
			}
			// An edge an hour ahead: every line is older than the retention, so only what a reader needs stays.
			if _, err := rulefile.Prune(ctx, lf.ledger, rulefile.PruneOptions{Before: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(lf.journal(t), func(x rulefile.Entry) bool { return x.ID == h.ID }) {
				t.Errorf("the Prune removed the older change %s, which holds %s on the running %s", h.ID, block, run)
			}
			_, cur := lf.current(t)
			if len(cur.Lift) != 0 {
				t.Errorf("after the Prune, the Undo of the newer change offers to lift %+v, which the older still holds", cur.Lift)
			}
			cr := lf.ref(t, lf.contract)
			r, err := lf.s.Revert(ctx, RevertReq{ID: e.ID, Base: cr.Base, Ack: cur.Ack, Lift: true})
			if err != nil || len(r.Lifted) != 0 || len(lf.lifts) != 0 || !slices.Contains(lf.overlay[run], block) {
				t.Errorf("an Undo asked to lift: %+v, %v; lifts %v, overlay %v; want %s still on %s", r, err, lf.lifts,
					lf.overlay[run], block, run)
			}
		})
	}
}
