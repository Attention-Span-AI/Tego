// SPDX-License-Identifier: Apache-2.0

package drift

import "testing"

// TestDriftedIgnoresUndeclaredWhenDeclaredUnknown: with the declared entries unrecompilable, a used rule no
// entry covers is unknown, not drift; a refusal still is (R16).
func TestDriftedIgnoresUndeclaredWhenDeclaredUnknown(t *testing.T) {
	rep := &Report{DeclaredUnknown: true, Exec: []RuleCount{{Section: SectionExec, Rule: "exec[/usr/bin/git]", Allow: 3}}}
	if rep.Drifted() {
		t.Error("an undeclared rule drifted a report whose declared entries are unknown")
	}
	rep.Exec[0].Refused = 1
	if !rep.Drifted() {
		t.Error("a refusal no longer drifts")
	}
	rep.Exec[0].Refused, rep.DeclaredUnknown = 0, false
	if !rep.Drifted() {
		t.Error("an undeclared rule no longer drifts when the entries are known")
	}
}
