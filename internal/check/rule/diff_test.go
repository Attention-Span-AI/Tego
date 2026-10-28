// SPDX-License-Identifier: Apache-2.0

package rule

import "testing"

// TestDiffRemovedBeforeAdded: a changed line reads old above new (F13), golden.
func TestDiffRemovedBeforeAdded(t *testing.T) {
	a := "exec:\n  allow: [bash, cat, ls]\ntier: landlock\n"
	b := "exec:\n  allow: [bash, cat]\ntier: landlock\n"
	want := "--- agent.yaml\n+++ agent.yaml (new)\n@@ line 1 @@\n exec:\n-  allow: [bash, cat, ls]\n+  allow: [bash, cat]\n tier: landlock\n"
	if got := Diff("agent.yaml", []byte(a), []byte(b)); got != want {
		t.Errorf("diff:\n%s\nwant:\n%s", got, want)
	}
	// Two changed lines in a row: both removals, then both additions.
	a2 := "x\na\nb\ny\n"
	b2 := "x\nA\nB\ny\n"
	want2 := "--- f\n+++ f (new)\n@@ line 1 @@\n x\n-a\n-b\n+A\n+B\n y\n"
	if got := Diff("f", []byte(a2), []byte(b2)); got != want2 {
		t.Errorf("diff:\n%s\nwant:\n%s", got, want2)
	}
}
