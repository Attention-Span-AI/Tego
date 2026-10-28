// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestApplyNowLater: a narrowing saved without "Also apply now" while a run of the file runs is pending on that run
// with Apply now offered; Apply now places its live block and journals it, after which the change shows the block as
// placed and offers nothing; a second Apply now is refused. A change of another rules file, one undone since, a
// removal a later change took back and an addition a later change took back offer nothing.
func TestApplyNowLater(t *testing.T) {
	f := newFixture(t)
	f.live[runA2] = true
	ctx := context.Background()
	c := f.ref(t, f.contract)
	a, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "ls"}}})
	if err != nil || a.ID == "" {
		t.Fatalf("apply: %+v %v", a, err)
	}
	pend := f.s.PendingOn(ctx, runA2, []string{a.ID, "no-such-id"})
	p, ok := pend[a.ID]
	if !ok || !p.CanApply() || len(p.Placed) != 0 || len(pend) != 1 {
		t.Fatalf("pending: %+v", pend)
	}
	if i := slices.IndexFunc(p.Options, func(o NowOption) bool { return o.Block == "exec:ls" && o.OK }); i < 0 {
		t.Errorf("options %+v lack exec:ls", p.Options)
	}
	res, err := f.s.ApplyNow(ctx, ApplyNowReq{ID: a.ID, Run: runA2})
	if err != nil || len(res) != 1 || !res[0].OK || res[0].Block != "exec:ls" {
		t.Fatalf("apply now: %+v %v", res, err)
	}
	if !slices.Equal(f.blocks, []string{runA2 + " exec:ls"}) {
		t.Errorf("placed %q", f.blocks)
	}
	p = f.s.PendingOn(ctx, runA2, []string{a.ID})[a.ID]
	if !slices.Equal(p.Placed, []string{"exec:ls"}) || p.CanApply() {
		t.Errorf("after Apply now: %+v", p)
	}
	if _, err := f.s.ApplyNow(ctx, ApplyNowReq{ID: a.ID, Run: runA2}); !errors.Is(err, ErrRefused) {
		t.Errorf("a second Apply now: %v, want ErrRefused", err)
	}
	// Not a running run of this file, or not a run at all.
	for _, run := range []string{runB, runA, "../x"} {
		if _, err := f.s.ApplyNow(ctx, ApplyNowReq{ID: a.ID, Run: run}); !errors.Is(err, ErrNotPending) {
			t.Errorf("Apply now on %s: %v, want ErrNotPending", run, err)
		}
	}

	// A later change that takes the entry back: the earlier removal no longer narrows the file, so nothing is offered.
	c = f.ref(t, f.contract)
	b, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}})
	if err != nil {
		t.Fatal(err)
	}
	c = f.ref(t, f.contract)
	back, err := f.s.PlanChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "cat"}}})
	if err != nil || back.Err != "" {
		t.Fatalf("plan the add back: %+v %v", back, err)
	}
	if _, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "cat"}}, Ack: back.Ack}); err != nil {
		t.Fatal(err)
	}
	p = f.s.PendingOn(ctx, runA2, []string{b.ID})[b.ID]
	if p.CanApply() || len(p.Options) != 1 || !strings.Contains(p.Options[0].Why, "still allows") {
		t.Errorf("a removal taken back: %+v", p)
	}

	// A later change that takes an addition back: the run's live block would refuse what the file allows now, so
	// Apply now offers nothing (deny_read added, then removed again).
	f.held = true
	c = f.ref(t, f.contract)
	d, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "fs.deny_read", "./vault/"}}})
	if err != nil {
		t.Fatal(err)
	}
	if p := f.s.PendingOn(ctx, runA2, []string{d.ID})[d.ID]; !p.CanApply() {
		t.Fatalf("the deny_read add is not offered before it is taken back: %+v", p)
	}
	c = f.ref(t, f.contract)
	undo, err := f.s.PlanChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "fs.deny_read", "./vault/"}}})
	if err != nil || undo.Err != "" {
		t.Fatalf("plan the removal: %+v %v", undo, err)
	}
	if _, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "fs.deny_read", "./vault/"}}, Ack: undo.Ack}); err != nil {
		t.Fatal(err)
	}
	p = f.s.PendingOn(ctx, runA2, []string{d.ID})[d.ID]
	if p.CanApply() || len(p.Options) != 1 || !strings.Contains(p.Options[0].Why, "took this entry back") {
		t.Errorf("an addition taken back: %+v", p)
	}
	if _, err := f.s.ApplyNow(ctx, ApplyNowReq{ID: d.ID, Run: runA2}); !errors.Is(err, ErrRefused) {
		t.Errorf("Apply now of an addition taken back: %v, want ErrRefused", err)
	}

	// An undone change is not pending.
	c = f.ref(t, f.contract)
	n, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "net.allow", "api.example.com:443"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.PendingOn(ctx, runA2, []string{n.ID})[n.ID]; !ok {
		t.Fatal("the net change is not pending")
	}
	hs, err := f.s.History(c.Ref)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(hs, func(h HistoryEntry) bool { return h.ID == n.ID })
	if i < 0 {
		t.Fatalf("history %+v lacks %s", hs, n.ID)
	}
	if _, err := f.s.Revert(ctx, RevertReq{ID: n.ID, Base: f.ref(t, f.contract).Base, Ack: hs[i].Ack}); err != nil {
		t.Fatal(err)
	}
	if p, ok := f.s.PendingOn(ctx, runA2, []string{n.ID})[n.ID]; ok {
		t.Errorf("an undone change is pending: %+v", p)
	}
	if _, err := f.s.ApplyNow(ctx, ApplyNowReq{ID: n.ID, Run: runA2}); !errors.Is(err, ErrNotPending) {
		t.Errorf("Apply now of an undone change: %v, want ErrNotPending", err)
	}
}
