// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAbsentRowIsTheCompilersEntry (ADR 0067 D3): a read the Landlock ruleset
// refuses for a built-in row absent at compile is recorded under the row's name, which no FS rule carries. The table's
// AbsentDenyRead declares it as the compiler's entry, as an existing built-in row is: the refusal is reported (a
// refusal drifts) under a declared entry, and an untouched row is left out of the report like any compiler entry.
func TestAbsentRowIsTheCompilersEntry(t *testing.T) {
	rt := &agent.RuleTable{AbsentDenyRead: []agent.AbsentRow{
		{Path: "/h/.codex/auth.json", Resolved: "/h/.codex/auth.json", At: "/h/.codex"},
		{Path: "/h/.pgpass", Resolved: "/h/.pgpass", At: "/h/.pgpass"},
	}}
	rep := &Report{Runs: 1}
	b := newBuckets()
	b.declare(rt)
	b.count(SectionFS, "fs.deny_read[/h/.codex/auth.json]", record.VerdictRefused)
	b.fill(rep)
	seen := map[string]RuleCount{}
	for _, s := range rep.Sections() {
		for _, c := range s.Counts {
			seen[c.Rule] = c
		}
	}
	if c, ok := seen["fs.deny_read[/h/.codex/auth.json]"]; !ok || !c.Declared || c.Refused != 1 {
		t.Errorf("the refused absent row = %+v, %v; want a declared entry with one refusal", c, ok)
	}
	if c, ok := seen["fs.deny_read[/h/.pgpass]"]; ok {
		t.Errorf("an absent row with no events is reported: %+v", c)
	}
	if !rep.Drifted() {
		t.Error("a refusal under an absent row did not drift")
	}
}
