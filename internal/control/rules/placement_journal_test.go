// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// "Also apply now" and "Apply now" used to place the block and then journal it, so a journal that could not be
// written left a block in force that the journal did not show. They are begun first, as an Undo's lift and a Redo's
// placement are: the begun line is written before the block is placed, and a block is not placed when it cannot be.
type placeWriter struct {
	Writer
	replaceErr error
	liveCalls  int
	failLive   int
}

func (w *placeWriter) Replace(ctx context.Context, path, base string, text []byte, c rulefile.Change) (*rulefile.Entry, error) {
	e, err := w.Writer.Replace(ctx, path, base, text, c)
	if err == nil && w.replaceErr != nil {
		return e, w.replaceErr
	}
	return e, err
}

func (w *placeWriter) AppendLive(ctx context.Context, of string, live []rulefile.Live) error {
	w.liveCalls++
	if w.liveCalls == w.failLive {
		return errors.New("injected: the journal cannot be written")
	}
	return w.Writer.AppendLive(ctx, of, live)
}

func (f *fixture) placementFlaky() *placeWriter {
	w := &placeWriter{Writer: f.s.writer()}
	f.s.Writer = w
	return w
}

func TestAlsoApplyNowPlacesNothingTheJournalDoesNotShow(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		set         func(*placeWriter)
		blocks      int    // blocks in force afterwards
		warn        string // what the answer says went wrong
		resultWords string // what the block's own result says
	}{
		{"the begun line cannot be written", func(w *placeWriter) { w.failLive = 1 }, 0, "journal could not record them first", "not placed"},
		{"the change's own journal line failed", func(w *placeWriter) { w.replaceErr = fmt.Errorf("%w: injected", rulefile.ErrJournal) }, 0, "no live block was made that it could not show", "not placed"},
		{"the outcome cannot be written", func(w *placeWriter) { w.failLive = 2 }, 1, "the journal shows them as begun", ""},
		{"everything is written", func(*placeWriter) {}, 1, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.live[runA2] = true
			c := f.ref(t, f.contract)
			req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "ls"}}, AlsoNow: []string{runA2}}
			p, err := f.s.PlanChange(ctx, req)
			if err != nil || p.Err != "" {
				t.Fatalf("plan: %+v %v", p, err)
			}
			req.Ack = p.Ack
			tc.set(f.placementFlaky())
			a, err := f.s.ApplyChange(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.blocks) != tc.blocks {
				t.Fatalf("blocks in force = %v, want %d", f.blocks, tc.blocks)
			}
			if tc.warn == "" && a.Warn != "" || tc.warn != "" && !strings.Contains(a.Warn, tc.warn) {
				t.Fatalf("warn = %q, want it to say %q", a.Warn, tc.warn)
			}
			if tc.resultWords != "" && (len(a.Live) != 1 || a.Live[0].OK || !strings.Contains(a.Live[0].Err, tc.resultWords)) {
				t.Fatalf("the block's result does not say it was not placed: %+v", a.Live)
			}
			if tc.name == "everything is written" {
				var begun, done bool
				for _, e := range f.journal(t) {
					for _, l := range e.Live {
						begun = begun || l.Pending && l.Block == "exec:ls"
						done = done || l.Placed() && l.Block == "exec:ls"
					}
				}
				if !begun && !done {
					t.Fatalf("the journal does not show the block: %+v", f.journal(t))
				}
				if !done {
					t.Fatalf("the journal shows the block as begun and never finished: %+v", f.journal(t))
				}
			}
		})
	}
}

func TestApplyNowLaterPlacesNothingTheJournalDoesNotShow(t *testing.T) {
	ctx := context.Background()
	for _, fail := range []int{1, 2} {
		t.Run(fmt.Sprint("line ", fail), func(t *testing.T) {
			f := newFixture(t)
			f.live[runA2] = true
			c := f.ref(t, f.contract)
			a, err := f.applyReviewed(t, ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "ls"}}})
			if err != nil || a.ID == "" {
				t.Fatalf("apply: %+v %v", a, err)
			}
			f.placementFlaky().failLive = fail
			res, err := f.s.ApplyNow(ctx, ApplyNowReq{ID: a.ID, Run: runA2})
			if err == nil {
				t.Fatalf("a journal that failed was not reported: %+v", res)
			}
			want := 0
			if fail == 2 {
				want = 1 // placed; the journal shows it as begun
			}
			if len(f.blocks) != want {
				t.Fatalf("blocks in force = %v, want %d (%v)", f.blocks, want, err)
			}
		})
	}
}
