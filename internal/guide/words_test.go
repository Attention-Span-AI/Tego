// SPDX-License-Identifier: Apache-2.0

package guide_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

// TestOnlyComputeBuildsACommand: every fixture's next step, as Compute returns it, is marked built (Next.Built), the
// mark the dashboard reads before it offers a command to copy; the same next step through its JSON is not, so a
// command read from a file is never one Tego built.
func TestOnlyComputeBuildsACommand(t *testing.T) {
	for _, name := range guidetest.Names {
		f := guidetest.Make(t, name)
		s := stored(t, f)
		if !s.Next.Built() {
			t.Errorf("%s: Compute's next step %+v is not marked built", name, s.Next)
		}
		b, err := json.Marshal(s.Next)
		if err != nil {
			t.Fatal(err)
		}
		var back guide.Next
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Built() || back != (guide.Next{Step: s.Next.Step, Rule: s.Next.Rule, Text: s.Next.Text, Command: s.Next.Command,
			NeedsRoot: s.Next.NeedsRoot, Placeholder: s.Next.Placeholder}) {
			t.Errorf("%s: the next step decoded from its JSON is %+v, built %t", name, back, back.Built())
		}
	}
}

// TestWordsAreWhatSetupPrints: State.Words, the form tego setup prints and the dashboard shows, writes a path under
// the home as ~/, a step whose source could not be read as NotKnownFact, and a character that does not print as
// itself made visible.
func TestWordsAreWhatSetupPrints(t *testing.T) {
	home := "/home/dana"
	fact := "ran under /home/dana/bot/agent.yaml \x1b[31m"
	s := &guide.State{Steps: []guide.Step{{ID: guide.StepContract, Title: "Make its contract", State: guide.Skipped,
		Fact: &fact, Source: "/home/dana/.tego/runs/r-x"}, {ID: guide.StepEnforce, Title: "Enforce it", State: guide.NotKnown}},
		NotKnown: []string{"the record under /home/dana/.tego/runs: denied"}}
	w := s.Words(home)
	if got := w.Steps[0]; got.N != 1 || !strings.HasPrefix(got.Fact, "ran under ~/bot/agent.yaml ") || strings.Contains(got.Fact, "\x1b") ||
		got.Source != "~/.tego/runs/r-x" {
		t.Errorf("step 1 in words: %+v", got)
	}
	if got := w.Steps[1]; got.N != 2 || got.Fact != guide.NotKnownFact {
		t.Errorf("step 2 in words: %+v", got)
	}
	if w.NotKnown[0] != "the record under ~/.tego/runs: denied" {
		t.Errorf("not known in words: %q", w.NotKnown)
	}
}
