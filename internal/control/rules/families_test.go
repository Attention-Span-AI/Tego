// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
)

func (f *fixture) planRaw(t *testing.T, now, next string) *ChangePlan {
	t.Helper()
	writeFile(t, f.contract, directionHead+now)
	c := f.ref(t, f.contract)
	p, err := f.s.PlanRaw(t.Context(), RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(directionHead + next)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A whole-text edit is described by what the compiled contract does differently, not by "free edit of the whole text":
// the families it moved, each with the direction the comparison ordered it in. The journal holds this line.
func TestAWholeTextEditSaysWhatItDoes(t *testing.T) {
	for _, tc := range []struct {
		name, now, next string
		summary         string // what the one-line summary holds
		families        map[string]string
		words           string // a substring of the words of the first family
	}{
		{"narrowed", "fs:\n  write: [./out/, ./docs/]\n", "fs:\n  write: [./out/]\n",
			"free edit: filesystem narrowed", map[string]string{"filesystem": "narrows"}, "the next run may do less than before"},
		{"widened", "fs:\n  write: [./out/]\n", "fs:\n  write: [./out/, ./docs/]\n",
			"free edit: filesystem widened", map[string]string{"filesystem": "widens"}, "Files it may change: the next run may do more than before"},
		{"both ways", "fs:\n  write: [./out/]\n", "fs:\n  write: [./out/, ./docs/]\nnet:\n  allow: [example.com:443]\n",
			"free edit: filesystem widened, destinations narrowed", map[string]string{"filesystem": "widens", "destinations": "narrows"}, ""},
		{"a comment only", "fs:\n  write: [./out/]\n", "# a note\nfs:\n  write: [./out/]\n",
			"free edit: nothing the compiled contract allows changed", map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRealPlan(t, tc.now, tc.next)
			if p.Err != "" {
				t.Fatalf("refused: %s", p.Err)
			}
			if p.Summary != tc.summary {
				t.Errorf("summary %q, want %q", p.Summary, tc.summary)
			}
			if !strings.Contains(p.Why, "the compiled contract before and after: ") || strings.Contains(p.Why, "cannot be classified") {
				t.Errorf("why %q does not say what the compiled comparison found", p.Why)
			}
			// A free edit is still confirmed like a widening, whatever the comparison found.
			if p.Direction != "mixed" || !p.NeedsAck || !p.Raw {
				t.Errorf("a free edit is confirmed like a widening: %+v", p)
			}
			got := map[string]string{}
			for _, fc := range p.Families {
				got[fc.Family] = fc.Direction
			}
			if len(got) != len(tc.families) {
				t.Fatalf("families %v, want %v", got, tc.families)
			}
			for fam, dir := range tc.families {
				if got[fam] != dir {
					t.Errorf("family %s is %q, want %q (all %v)", fam, got[fam], dir, got)
				}
			}
			if tc.words != "" && !strings.Contains(p.Families[0].Words, tc.words) {
				t.Errorf("words %q lack %q", p.Families[0].Words, tc.words)
			}
		})
	}
}

func newRealPlan(t *testing.T, now, next string) *ChangePlan {
	t.Helper()
	return realFixture(t).planRaw(t, now, next)
}

// The edit form's sentences cover the lists it changes; the preview also names every other compiled family the change
// moves, so a command entry (which changes what a program may be run with) is not said as a program alone.
func TestThePreviewNamesEveryFamilyTheChangeMoves(t *testing.T) {
	f := realFixture(t)
	p := f.plan(t, "", Edit{"add", "exec.allow", "cat status"})
	if p.Err != "" {
		t.Fatalf("refused: %s", p.Err)
	}
	var changed []string
	for _, r := range p.rows {
		if r.Direction != agentdiff.Unchanged {
			changed = append(changed, r.Family)
		}
	}
	if len(changed) == 0 {
		t.Fatal("the fixture's change moved no compiled family")
	}
	if len(p.Families) != len(changed) {
		t.Fatalf("the preview names %d families, the comparison moved %d (%v)", len(p.Families), len(changed), changed)
	}
	var args *FamilyChange
	for i := range p.Families {
		if p.Families[i].Family == "program arguments" {
			args = &p.Families[i]
		}
	}
	if args == nil {
		t.Fatalf("program arguments are not named: %+v", p.Families)
	}
	if args.Direction != "mixed" || !strings.Contains(args.Words, "Tego cannot tell whether the next run may do more") ||
		!strings.HasPrefix(args.Words, "The arguments a program may run with: ") {
		t.Errorf("program arguments are said as %+v", *args)
	}
}
