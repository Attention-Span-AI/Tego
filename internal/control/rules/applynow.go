// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// Apply now: a change of a rules file saved while a run of it runs, without "Also apply now", can
// still be put in force on that run later, from the Rules page's "Changed since this run started" panel. Its list
// changes are read from the journal (the text before and after the change, rawChanges), mapped to live blocks as
// "Also apply now" maps them (nowOptions), against the file as it stands now, so a change a later one took back offers
// nothing; and only blocks not yet placed on the run are offered. Placing them only tightens the run, as every live
// block does, and is journaled after the change (rulefile.AppendLive).

// ErrNotPending is an Apply now of a change that is not one of the run's pending changes: not in the journal, undone
// since, of another rules file than the run's, or the run is no running run of it.
var ErrNotPending = errors.New("this change cannot be applied to that run now")

// PendingNow is one pending change on one running run: the live blocks the journal says were placed on it, and what
// Apply now would place now (OK options) or why each list change waits for the next run.
type PendingNow struct {
	ID string
	// Placed are the live blocks the journal records placing on the run for the change ("Also apply now", or an
	// earlier Apply now), each a liveblock key.
	Placed []string
	// Options are the change's list changes on the run, a block already placed left out.
	Options []NowOption
}

// CanApply reports whether Apply now has a block to place.
func (p PendingNow) CanApply() bool {
	return slices.ContainsFunc(p.Options, func(o NowOption) bool { return o.OK })
}

// PendingOn is, for each journal change of ids (the run's pending changes, rulesview.Pending), what it is on run now
// (PendingNow). A change that cannot be read, or is not run's (ErrNotPending), is left out.
func (s *Service) PendingOn(ctx context.Context, run string, ids []string) map[string]PendingNow {
	out := map[string]PendingNow{}
	for _, id := range ids {
		if p, err := s.pendingOn(ctx, run, id); err == nil {
			out[id] = p
		}
	}
	return out
}

// ApplyNowReq is one Apply now: journal change ID on running run Run.
type ApplyNowReq struct {
	ID, Run string
}

// ApplyNow places on r.Run the live blocks of journal change r.ID that are not placed there yet and journals what it
// did after the change. A change with none to place is ErrRefused; one that is not the run's pending change,
// ErrNotPending.
func (s *Service) ApplyNow(ctx context.Context, r ApplyNowReq) ([]LiveResult, error) {
	p, err := s.pendingOn(ctx, r.Run, r.ID)
	if err != nil {
		return nil, err
	}
	if !p.CanApply() {
		why := "it has no live block that can be placed on this run now"
		for _, o := range p.Options {
			if o.Why != "" {
				why = o.Why
				break
			}
		}
		return nil, fmt.Errorf("%w: %s", ErrRefused, why)
	}
	res := s.applyNow(ctx, p.Options, []string{r.Run})
	if err := s.writer().AppendLive(ctx, r.ID, journalLive(res)); err != nil {
		return res, fmt.Errorf("the live blocks were placed but not journaled: %w", err)
	}
	return res, nil
}

// pendingOn is change id on run: refused unless id is a change or revert in the journal that stands (not undone), of
// the rules file run runs, and run is running.
func (s *Service) pendingOn(ctx context.Context, run, id string) (PendingNow, error) {
	if !runID(run) || id == "" {
		return PendingNow{}, ErrNotPending
	}
	st, err := readStart(filepath.Join(s.Ledger, run))
	if err != nil || st.Contract == "" || !slices.Contains(s.liveRunsOf(st.Contract), run) {
		return PendingNow{}, fmt.Errorf("%w: run %s is not a running run of a rules file", ErrNotPending, run)
	}
	hist, err := rulefile.History(s.Ledger, st.Resolved)
	if err != nil {
		return PendingNow{}, err
	}
	i := slices.IndexFunc(hist, func(e rulefile.Entry) bool { return e.ID == id })
	if i < 0 {
		return PendingNow{}, fmt.Errorf("%w: no change %s of %s", ErrNotPending, id, st.Contract)
	}
	e := hist[i]
	if (e.Op != rulefile.OpChange && e.Op != rulefile.OpRevert) || e.UndoneBy != "" || !e.At.After(st.At) {
		return PendingNow{}, fmt.Errorf("%w: change %s is undone, or older than the run", ErrNotPending, id)
	}
	old, err := rulefile.Blob(s.Ledger, e.OldSHA256)
	if err != nil {
		return PendingNow{}, err
	}
	nw, err := rulefile.Blob(s.Ledger, e.NewSHA256)
	if err != nil {
		return PendingNow{}, err
	}
	// The file as it stands now decides what still narrows: a later change that took an entry back offers nothing.
	cur, err := s.writer().Read(st.Contract)
	if err != nil {
		return PendingNow{}, fmt.Errorf("%w: %v", ErrNotWritable, err)
	}
	if cur.Path != st.Resolved {
		return PendingNow{}, fmt.Errorf("%w: the rules file's folder now points elsewhere (%s, not %s)", ErrNotWritable, cur.Path, st.Resolved)
	}
	cwd := st.Cwd
	if cwd == "" {
		cwd = filepath.Dir(st.Contract)
	}
	p := PendingNow{ID: id}
	for _, l := range e.Live {
		if l.Run == run && l.Placed() && !slices.Contains(p.Placed, l.Block) {
			p.Placed = append(p.Placed, l.Block)
		}
	}
	inOverlay := map[string]bool{}
	if lb, err := runact.Live(s.Ledger, run); err == nil {
		for _, b := range lb.Blocks {
			inOverlay[b.Key()] = true
		}
	}
	for _, o := range s.nowOptions(ctx, []string{run}, rawChanges(old, nw), cwd, entriesOf(cur.Text)) {
		if o.Block != "" && (slices.Contains(p.Placed, o.Block) || inOverlay[o.Block]) {
			continue // placed already: its state is the run's, not an offer
		}
		p.Options = append(p.Options, o)
	}
	return p, nil
}
