// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fixturePath is the frozen ledger every view is built against.
func fixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl")
}

// readFixture decodes the frozen ledger in order.
func readFixture(t *testing.T) []*record.Event {
	t.Helper()
	f, err := os.Open(fixturePath(t))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	defer f.Close()
	var out []*record.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		ev, err := record.Decode(line)
		if err != nil {
			t.Fatalf("fixture line %d: %v", len(out), err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return out
}

// The acceptance, replayed over the frozen 20-step run. Every action after the
// run's first model call is attributed to a step; the steps are the turns the ledger already numbered
// on its decision lines; and the numbers never go backwards (R33–R36, I7). An action that fell inside
// a reply's one tool window names that reply's tool_use (R42): the fixture's requests predate
// tool_results, so each one leaves every window of the run of unknown state, which no later request
// reports, and only the first reply's window names its reply, until the second request.
func TestFixtureAttributesEveryAction(t *testing.T) {
	events := readFixture(t)
	steps := derive.NewSteps("api.anthropic.com")

	var (
		firstRequest = -1
		lastStep     int
		before       int
		attributed   int
		byToolUse    int
		toolUses     = map[int][]string{} // step -> the tool_use ids its reply asked for
	)
	for i, e := range events {
		// The fixture carries what a P0 writer stamped before this derivation existed: the honest
		// {unattributed, none}. Replaying it is exactly what a view does.
		steps.Apply(e)
		switch {
		case e.Kind == record.KindSSLRequest && firstRequest < 0:
			firstRequest = i
		case e.Kind == record.KindDecision:
			var p record.DecisionPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatalf("decision at %d: %v", i, err)
			}
			if p.Step != steps.Count() {
				t.Errorf("decision at seq %d: step %d, want the turn this derivation numbered %d",
					e.Seq, p.Step, steps.Count())
			}
			if p.ToolUseID != "" {
				toolUses[p.Step] = append(toolUses[p.Step], p.ToolUseID)
			}
		case e.Kind.IsAction():
			if e.Attr == nil || !e.Attr.Valid() {
				t.Fatalf("action at seq %d has no valid attribution", e.Seq)
			}
			switch ids := toolUses[e.Attr.Step]; e.Attr.Method {
			case record.MethodTime:
			case record.MethodToolID:
				if len(ids) != 1 || e.Attr.ToolUseID != ids[0] || e.Attr.Step != steps.Count() || e.Attr.Step != 1 {
					t.Errorf("action at seq %d: %+v, want step %d's one tool_use of %q, in step 1", e.Seq, e.Attr, steps.Count(), ids)
				}
				byToolUse++
			default:
				t.Errorf("action at seq %d: method %q, want time or tool_id", e.Seq, e.Attr.Method)
			}
			if firstRequest < 0 {
				before++
				if e.Attr.Confidence != record.ConfidenceUnattributed || e.Attr.Step != 0 {
					t.Errorf("action at seq %d precedes every model call and must be unattributed: %+v",
						e.Seq, e.Attr)
				}
				continue
			}
			if e.Attr.Confidence != record.ConfidenceLikely || e.Attr.Step == 0 {
				t.Errorf("action at seq %d: %+v, want a step by time", e.Seq, e.Attr)
				continue
			}
			attributed++
			if e.Attr.Step < lastStep {
				t.Errorf("action at seq %d: step %d after step %d — steps never go backwards (I7)",
					e.Seq, e.Attr.Step, lastStep)
			}
			lastStep = e.Attr.Step
		}
	}
	if steps.Count() != 20 {
		t.Errorf("%d steps, want the fixture's 20", steps.Count())
	}
	if before == 0 {
		t.Error("the fixture has no action before its first model call; the unattributed case is untested")
	}
	if attributed == 0 {
		t.Fatal("no action was attributed")
	}
	if byToolUse == 0 {
		t.Error("no action was attributed to the reply that asked for its tool")
	}
	if lastStep != 20 {
		t.Errorf("the last attributed step is %d, want 20", lastStep)
	}
}

// Replaying the fixture twice through one tracker is not how a run works, but
// replaying it through two trackers must give the same answer — the derivation is a function of the
// stream alone.
func TestFixtureReplayIsDeterministic(t *testing.T) {
	first := readFixture(t)
	second := readFixture(t)
	a, b := derive.NewSteps("api.anthropic.com"), derive.NewSteps("api.anthropic.com")
	for i := range first {
		a.Apply(first[i])
		b.Apply(second[i])
		if first[i].Kind.IsAction() && *first[i].Attr != *second[i].Attr {
			t.Fatalf("seq %d: %+v != %+v", first[i].Seq, first[i].Attr, second[i].Attr)
		}
	}
	if a.Count() != b.Count() {
		t.Errorf("%d steps != %d steps", a.Count(), b.Count())
	}
}
