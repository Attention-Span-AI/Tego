// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

// Two editor paths can review the same final bytes while retaining different
// request metadata. A later review must not replace the earlier proposal.
func TestBuilderStructuredReviewSurvivesEquivalentRawReview(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}}
	first, err := f.s.PlanChange(t.Context(), req)
	if err != nil || first.Err != "" {
		t.Fatalf("structured Preview: %+v %v", first, err)
	}
	want := bytes.Clone(first.text)
	raw, err := f.s.PlanRaw(t.Context(), RawReq{Ref: c.Ref, Base: c.Base, Text: want})
	if err != nil || raw.Err != "" || !bytes.Equal(raw.text, want) {
		t.Fatalf("equivalent raw Preview: %+v %v", raw, err)
	}
	req.Ack = first.Ack
	if _, err := f.s.ApplyChange(t.Context(), req); err != nil {
		t.Fatalf("raw review replaced earlier structured proposal: %v", err)
	}
	got, err := os.ReadFile(c.Path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("saved bytes differ from structured review: %v", err)
	}
}

// Restoring either quoted placeholder yields the same exact secret-bearing
// candidate. Each original input must retain its own reviewed proposal.
func TestBuilderRawReviewSurvivesEquivalentPlaceholderSpelling(t *testing.T) {
	f := newFixture(t)
	original := baseText + "env:\n  set:\n    TOKEN: private-collision-value\n"
	writeFile(t, f.contract, original)
	c := f.ref(t, f.contract)
	edited := strings.Replace(original, "cat, ls", "ls", 1)
	firstText := strings.Replace(edited, "private-collision-value", "'"+rulesview.Hidden+"'", 1)
	nextText := strings.Replace(edited, "private-collision-value", "\""+rulesview.Hidden+"\"", 1)
	req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(firstText)}
	first, err := f.s.PlanRaw(t.Context(), req)
	if err != nil || first.Err != "" {
		t.Fatalf("first raw Preview: %+v %v", first, err)
	}
	want := bytes.Clone(first.text)
	next, err := f.s.PlanRaw(t.Context(), RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(nextText)})
	if err != nil || next.Err != "" || !bytes.Equal(next.text, want) {
		t.Fatalf("equivalent placeholder Preview: %+v %v", next, err)
	}
	req.Ack = first.Ack
	if _, err := f.s.ApplyRaw(t.Context(), req); err != nil {
		t.Fatalf("placeholder spelling replaced earlier raw proposal: %v", err)
	}
	got, err := os.ReadFile(c.Path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("saved bytes differ from first raw review: %v", err)
	}
}

func TestBuilderStructuredReviewSurvivesReorderedEdits(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}, {"remove", "exec.allow", "ls"}}}
	first, err := f.s.PlanChange(t.Context(), req)
	if err != nil || first.Err != "" {
		t.Fatalf("first Preview: %+v %v", first, err)
	}
	other := req
	other.Edits = []Edit{req.Edits[1], req.Edits[0]}
	next, err := f.s.PlanChange(t.Context(), other)
	if err != nil || next.Err != "" || !bytes.Equal(first.text, next.text) {
		t.Fatalf("equivalent Preview: %+v %v", next, err)
	}
	req.Ack = first.Ack
	if _, err := f.s.ApplyChange(t.Context(), req); err != nil {
		t.Fatalf("reordered preview replaced earlier proposal: %v", err)
	}
	if got := f.text(t); got != string(first.text) {
		t.Fatal("reviewed bytes changed")
	}
}
