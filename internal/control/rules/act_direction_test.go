// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"
)

// "Act on this" gives the picked change the compiled comparison's direction, as Change rules does, and names what the
// change newly allows (here "Always allow" on an ask widens reads and drops the approval broker: mixed, not the action's "widens") for the confirmation (ActPlan.Review), which the action's own word never could.
func TestActOnTakesItsDirectionFromTheCompiledComparison(t *testing.T) {
	f := realFixture(t)
	writeFile(t, f.contract, directionHead+"fs:\n  ask_read: [./docs/]\n")
	f.ref(t, f.contract)
	pick, err := f.s.ActOn(t.Context(), ActReq{Run: runA, Seq: 1, Action: "allow", Scope: Scope{Level: 1}})
	if err != nil || pick.PickErr != "" || pick.Direction != "mixed" || len(pick.Review) == 0 || len(pick.Sentences) == 0 || pick.Sentences[0].Direction != "mixed" {
		t.Fatalf("%+v %v", pick, err)
	}
}

// A comparison that cannot be made proposes nothing.
func TestActOnWithoutAComparisonProposesNothing(t *testing.T) {
	f := realFixture(t)
	writeFile(t, f.contract, directionHead+"fs:\n  ask_read: [./docs/]\n")
	f.ref(t, f.contract)
	f.s.Machine = nil
	pick, err := f.s.ActOn(t.Context(), ActReq{Run: runA, Seq: 1, Action: "allow", Scope: Scope{Level: 1}})
	if err == nil && (pick.Diff != "" || pick.Ack != "" && pick.Direction != "") {
		t.Fatalf("a change that cannot be compared was proposed: %+v", pick)
	}
}
