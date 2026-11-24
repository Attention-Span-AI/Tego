// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"
	"time"
)

func TestBuilderPreviewOnlyNeverTouchesReviewStore(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := ChangeReq{Session: "same", Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}}
	person, err := f.s.PlanChange(t.Context(), req)
	if err != nil || person.Err != "" || person.ReviewID == "" || person.Ack == "" {
		t.Fatalf("person: %+v %v", person, err)
	}
	before := f.s.drafts.next
	req.PreviewOnly = true
	p, err := f.s.PlanChange(t.Context(), req)
	if err != nil || p.Err != "" || p.Diff != person.Diff {
		t.Fatalf("read-only: %+v %v", p, err)
	}
	if p.ReviewID != "" || p.Ack != "" {
		t.Error("read-only Preview minted a review identity or acknowledgement")
	}
	if len(f.s.drafts.entries) != 1 || f.s.drafts.next != before {
		t.Error("read-only Preview touched review store")
	}
	req.PreviewOnly = false
	req.Ack = person.Ack
	if _, err := f.s.ApplyChange(t.Context(), req); err != nil {
		t.Fatalf("person review lost: %v", err)
	}
}

func TestBuilderNewPreviewOnlyNeverTouchesReviewStore(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.s.Now = func() time.Time { return now }
	f.s.drafts.put("expired-sentinel", draftState{at: now.Add(-draftTTL), payload: []byte("sentinel")})
	before := f.s.drafts.next
	req := NewReq{Session: "same", PreviewOnly: true, PrepareDirectories: true, Dir: f.newProject(t, "readonly"), Name: "readonly", Blank: true}
	p, err := f.s.PlanNew(t.Context(), req)
	if err != nil || !p.OK {
		t.Fatalf("read-only: %+v %v", p, err)
	}
	if p.ReviewID != "" || p.Base != "" || p.Draft != "" {
		t.Error("read-only new Preview minted a draft or review")
	}
	if len(f.s.drafts.entries) != 1 || f.s.drafts.next != before {
		t.Error("read-only new Preview touched review store")
	}
	req.Draft = "expired-sentinel"
	p, err = f.s.PlanNew(t.Context(), req)
	if err != nil || p.OK || len(p.Problems) == 0 {
		t.Fatalf("read-only retained composition was not refused: %+v %v", p, err)
	}
	if len(f.s.drafts.entries) != 1 || f.s.drafts.next != before {
		t.Error("read-only draft restoration touched review store")
	}
}
