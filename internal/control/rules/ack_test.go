// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// changeAck is the Ack PlanChange shows for req: what the preview's checkbox posts.
func changeAck(t *testing.T, s *Service, req ChangeReq) string {
	t.Helper()
	p, err := s.PlanChange(context.Background(), req)
	if err != nil || p.Err != "" || p.Ack == "" {
		t.Fatalf("plan %+v: %+v %v", req, p, err)
	}
	return p.Ack
}

// rawAck is the Ack PlanRaw (the editor's Check) shows for req.
func rawAck(t *testing.T, s *Service, req RawReq) string {
	t.Helper()
	p, err := s.PlanRaw(context.Background(), req)
	if err != nil || p.Err != "" || p.Ack == "" {
		t.Fatalf("check %+v: %+v %v", req, p, err)
	}
	return p.Ack
}

// historyAck is the Ack History offers to undo entry id of the contract ref.
func historyAck(t *testing.T, s *Service, ref, id string) string {
	t.Helper()
	hs, err := s.History(ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hs {
		if h.ID == id && h.Current && h.Ack != "" {
			return h.Ack
		}
	}
	t.Fatalf("history of %s offers no Undo of %s: %+v", ref, id, hs)
	return ""
}

// TestAckIsDeterministicAndBound: the same preview gives the same Ack (no nonce, no clock: a live region re-rendered
// on every revision keeps its HTML), and a different change, base or key gives another. A widening confirmed with
// the Ack of another preview writes nothing; the matching one writes; a narrowing needs none.
func TestAckIsDeterministicAndBound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.ref(t, f.contract)
	git := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "git"}}}
	curl := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "curl"}}}
	a1, a2 := changeAck(t, f.s, git), changeAck(t, f.s, git)
	if a1 != a2 || len(a1) != 64 {
		t.Fatalf("two previews of one change: %q and %q", a1, a2)
	}
	curlAck := changeAck(t, f.s, curl)
	if curlAck == a1 {
		t.Fatal("two changes share an Ack")
	}
	other := &Service{AckKey: []byte("another key")}
	if other.ack(contractAckRef(c.Ref), c.Base, "x") == f.s.ack(contractAckRef(c.Ref), c.Base, "x") {
		t.Fatal("two keys give one Ack")
	}
	if f.s.ack("a", "bc", "d") == f.s.ack("ab", "c", "d") {
		t.Fatal("the fields are not delimited")
	}
	// The preview of git, posted on a change of curl (a wider entry than the one looked at): nothing is written.
	curl.Ack = a1
	if _, err := f.s.ApplyChange(ctx, curl); !errors.Is(err, ErrAckMismatch) || !errors.Is(err, ErrNeedsAck) {
		t.Fatalf("a confirm carrying another preview's Ack: %v", err)
	}
	if f.text(t) != baseText || len(f.journal(t)) != 0 {
		t.Fatal("a confirm with another preview's Ack wrote")
	}
	git.Ack = a1
	if _, err := f.s.ApplyChange(ctx, git); err != nil || !strings.Contains(f.text(t), "git") {
		t.Fatalf("the matching Ack: %v", err)
	}
	// After the write, the base moved: the old Ack is no longer this text's.
	c = f.ref(t, f.contract)
	if again := changeAck(t, f.s, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "curl"}}}); again == curlAck {
		t.Fatal("an Ack outlived its base")
	}
	// A narrowing carries no Ack and is written.
	if _, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}}); err != nil {
		t.Fatalf("a narrowing without an Ack: %v", err)
	}
}

// TestRevertAckNamesTheEntry: an Undo that widens needs the Ack History offered for that entry; the Ack of another
// entry, or none, undoes nothing.
func TestRevertAckNamesTheEntry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.ref(t, f.contract)
	a, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}})
	if err != nil {
		t.Fatal(err)
	}
	c = f.ref(t, f.contract)
	undo := historyAck(t, f.s, c.Ref, a.ID)
	for name, ack := range map[string]string{"none": "", "forged": strings.Repeat("a", 64),
		"another entry's": f.s.ack(revertRef("rc-other"), c.Base, "x")} {
		if _, err := f.s.Revert(ctx, RevertReq{ID: a.ID, Base: c.Base, Ack: ack}); !errors.Is(err, ErrNeedsAck) {
			t.Errorf("%s Ack: %v", name, err)
		}
	}
	if strings.Contains(f.text(t), "cat") {
		t.Fatal("a refused Undo wrote")
	}
	if _, err := f.s.Revert(ctx, RevertReq{ID: a.ID, Base: c.Base, Ack: undo}); err != nil || f.text(t) != baseText {
		t.Fatalf("Undo with its Ack: %v", err)
	}
}

// TestActAckIsThePreviews: ActOn's preview carries the Ack its confirm needs; the same preview twice gives the same
// Ack, and the Ack of another change (one previewed on Change rules) does not confirm it.
func TestActAckIsThePreviews(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1})
	if err != nil || p.EntryScope == nil {
		t.Fatalf("plan: %+v %v", p, err)
	}
	sc := *p.EntryScope
	one, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "allow", Scope: sc})
	if err != nil || one.Ack == "" {
		t.Fatalf("allow preview: %+v %v", one, err)
	}
	two, _ := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "allow", Scope: sc})
	if one.Ack != two.Ack {
		t.Fatalf("two previews: %q %q", one.Ack, two.Ack)
	}
	c := f.ref(t, f.contract)
	foreign := changeAck(t, f.s, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "git"}}})
	w, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "allow", Scope: sc, Write: true, Base: one.Base, Ack: foreign})
	if err != nil || w.Saved || !w.NeedsAck || !strings.Contains(w.PickErr, "another change") || f.text(t) != baseText {
		t.Fatalf("another change's Ack: %+v %v", w, err)
	}
	w, err = f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "allow", Scope: sc, Write: true, Base: one.Base, Ack: one.Ack})
	if err != nil || !w.Saved || w.UndoAck == "" {
		t.Fatalf("the preview's own Ack: %+v %v", w, err)
	}
	if h := historyAck(t, f.s, f.ref(t, f.contract).Ref, w.ID); h != w.UndoAck {
		t.Errorf("the Saved panel's Undo Ack %q is not History's %q", w.UndoAck, h)
	}
}
