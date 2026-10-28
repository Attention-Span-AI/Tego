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
}

// liftable is what an Undo of e (a journal entry as History folds it: its live outcomes merged) would lift now, from
// the contract's history hist: every block e placed on a run of e's rules file that still runs and still holds it in
// its overlay, unless another entry of hist that stands (not undone, not e) placed it on that run too. The text an
// Undo of e gives back still holds that other change, so its block stays. A block lifted already, by hand or by an
// earlier Undo, is not in the overlay and so is not offered.
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
		if !slices.Contains(s.blocksOn(l.Run), l.Block) {
			continue // lifted already (by hand, or by an earlier Undo)
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
		out = append(out, LiftOption{Run: l.Run, Kind: string(kind), Value: v, Block: l.Block, Cwd: st.Cwd,
			Observe: s.runFacts(l.Run).Observe})
	}
	return out
}

// heldByOther reports whether an entry of hist other than id that still stands placed block on run: undoing id must
// not lift what that other change still puts in force.
func heldByOther(id, run, block string, hist []rulefile.Entry) bool {
	return slices.ContainsFunc(hist, func(h rulefile.Entry) bool {
		return h.ID != id && h.UndoneBy == "" && slices.ContainsFunc(h.Live, func(l rulefile.Live) bool {
			return l.Placed() && l.Run == run && l.Block == block
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

// blocksOn is the keys of run's live blocks now (runact.Live); none when its overlay cannot be read.
func (s *Service) blocksOn(run string) []string {
	if s.overlay != nil {
		return s.overlay(run)
	}
	lb, err := runact.Live(s.Ledger, run)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(lb.Blocks))
	for _, b := range lb.Blocks {
		out = append(out, b.Key())
	}
	return out
}

// lift removes the live blocks of opts from their runs and says what each removal did. A removal that fails is
// reported, never a reason to take the Undo back: the file already holds its old text.
func (s *Service) lift(ctx context.Context, opts []LiftOption) []LiveResult {
	out := make([]LiveResult, 0, len(opts))
	for _, o := range opts {
		r := LiveResult{Run: o.Run, Block: o.Block, OK: true, Observe: o.Observe, Lift: true}
		var err error
		if s.unblock != nil {
			err = s.unblock(ctx, o.Run, o.Kind, o.Value)
		} else {
			var b runact.Blocked
			b, err = runact.Block(ctx, s.Ledger, o.Run, o.Kind, o.Value, false)
			r.Serial = b.Serial
		}
		if err != nil {
			r.OK, r.Err = false, fmt.Sprintf("not lifted: %v", err)
		}
		out = append(out, r)
	}
	return out
}
