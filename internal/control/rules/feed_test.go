// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// TestFeed: every rules file's changes and undos, newest first, each in one plain line with the agent its text names,
// its live outcomes, and the runs of its file that started before it; a second read with no new journal line is the
// cached one, and a new line is read.
func TestFeed(t *testing.T) {
	f := newLiftFixture(t) // its overlay holds what "Also apply now" placed, so the Undo lifts it
	f.live[runA2] = true
	ctx := context.Background()
	if fe, err := f.s.Feed(); err != nil || fe != nil {
		t.Fatalf("no journal: %+v %v", fe, err)
	}
	c := f.ref(t, f.contract)
	a, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}, AlsoNow: []string{runA2}})
	if err != nil {
		t.Fatal(err)
	}
	o := f.ref(t, f.other)
	b, err := f.s.ApplyChange(ctx, ChangeReq{Ref: o.Ref, Base: o.Base, Edits: []Edit{{"add", "fs.deny_read", "./secrets/"}}})
	if err != nil {
		t.Fatal(err)
	}
	fe, err := f.s.Feed()
	if err != nil || len(fe) != 2 || fe[0].ID != b.ID || fe[1].ID != a.ID {
		t.Fatalf("feed: %+v %v", fe, err)
	}
	ca := fe[1]
	if ca.Agent != "tester" || ca.Ref != c.Ref || ca.Direction != "narrows" || !strings.Contains(ca.Words, "→") || ca.Via != Via {
		t.Errorf("the change of the first file: %+v", ca)
	}
	if len(ca.Live) != 1 || ca.Live[0].Run != runA2 || ca.Live[0].Block != "exec:cat" || !ca.Live[0].OK {
		t.Errorf("its live outcome: %+v", ca.Live)
	}
	if !slices.Equal(sorted(ca.Runs), []string{runA, runA2}) || !slices.Equal(fe[0].Runs, []string{runB}) || fe[0].Agent != "other" {
		t.Errorf("runs %v and %v, agent %q", ca.Runs, fe[0].Runs, fe[0].Agent)
	}
	again, _ := f.s.Feed()
	if &again[0] != &fe[0] {
		t.Error("an unchanged journal was read again")
	}
	ack := historyAck(t, f.s, c.Ref, a.ID)
	cur := f.ref(t, f.contract)
	r, err := f.s.Revert(ctx, RevertReq{ID: a.ID, Base: cur.Base, Ack: ack, Lift: true})
	if err != nil {
		t.Fatal(err)
	}
	fe, err = f.s.Feed()
	if err != nil || len(fe) != 3 || fe[0].ID != r.ID || !strings.HasPrefix(fe[0].Words, "Undid: ") || fe[2].UndoneBy != r.ID {
		t.Fatalf("after the undo: %+v %v", fe, err)
	}
	if len(fe[0].Live) != 1 || !fe[0].Live[0].Lift {
		t.Errorf("the undo's lift: %+v", fe[0].Live)
	}
	if fe[0].Created() {
		t.Error("an undo reads as a new file")
	}
	if es := f.journal(t); es[len(es)-1].Op != rulefile.OpLive {
		t.Errorf("the lift was not journaled: %+v", es[len(es)-1])
	}
}

func sorted(xs []string) []string {
	out := slices.Clone(xs)
	slices.Sort(out)
	return out
}
