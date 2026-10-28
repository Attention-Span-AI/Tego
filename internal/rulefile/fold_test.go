// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"testing"
)

// TestFold: every contract's entries newest first, a live line merged into the entry it names (a lift kept as a
// lift, never as a block placed), a revert's target marked undone, and keep narrowing to one contract as History does.
func TestFold(t *testing.T) {
	es := []Entry{
		{V: 1, ID: "rc-1", Op: OpChange, Contract: "/a.yaml", Live: []Live{{Run: "r1", Block: "exec:cat", OK: true}}},
		{V: 1, ID: "rc-2", Op: OpChange, Contract: "/b.yaml"},
		{V: 1, ID: "rc-3", Op: OpLive, Of: "rc-1", Live: []Live{{Run: "r2", Block: "exec:cat", OK: true}}},
		{V: 1, ID: "rc-4", Op: OpRevert, Contract: "/a.yaml", Reverts: "rc-1"},
		{V: 1, ID: "rc-5", Op: OpLive, Of: "rc-4", Live: []Live{{Run: "r1", Block: "exec:cat", OK: true, Lift: true}}},
	}
	all := Fold(es, nil)
	if len(all) != 3 || all[0].ID != "rc-4" || all[1].ID != "rc-2" || all[2].ID != "rc-1" {
		t.Fatalf("fold = %+v", all)
	}
	if all[2].UndoneBy != "rc-4" || len(all[2].Live) != 2 || !all[2].Live[1].Placed() {
		t.Errorf("rc-1 = %+v", all[2])
	}
	if len(all[0].Live) != 1 || all[0].Live[0].Placed() || !all[0].Live[0].Lift {
		t.Errorf("rc-4's lift = %+v", all[0].Live)
	}
	a := Fold(es, func(e Entry) bool { return e.Contract == "/a.yaml" })
	if len(a) != 2 || a[0].ID != "rc-4" || a[1].ID != "rc-1" {
		t.Errorf("keep /a.yaml = %+v", a)
	}
	// The input keeps its own Live: folding twice gives the same.
	if len(es[0].Live) != 1 || len(Fold(es, nil)[2].Live) != 2 {
		t.Errorf("Fold changed its input: %+v", es[0].Live)
	}
}
