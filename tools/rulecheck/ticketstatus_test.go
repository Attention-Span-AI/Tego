// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

const planFixture = `| T3 | Step A. **Done 2026-09-29** | x | T2 | y |
| T7 | Tier wiring. **Done 2026-09-29** (enforce-plane §2.10) | x | T6 | y |
| T9 | Record. **Built 2026-09-29** | x | T3 | y |
| T11 | Suites | x | T6 | y |
| T16 | Step E. **Mechanism built 2026-09-30, not enabled** | x | T13 | y |
`

// TestBuiltTickets reads the plan's marks: Done or Built in bold; a mechanism built but not enabled and an
// unmarked row are not built.
func TestBuiltTickets(t *testing.T) {
	got := BuiltTickets(planFixture)
	for id, want := range map[string]bool{"T3": true, "T7": true, "T9": true, "T11": false, "T16": false} {
		if got[id] != want {
			t.Errorf("%s built = %v, want %v", id, got[id], want)
		}
	}
}

// TestCheckTicketStatusFlagsAPlantedMismatch: a note that lists a ticket the plan marks built fails, in the forms
// the notes use (a range, a parenthesised ID, "unbuilt"); a note that lists only unbuilt tickets passes.
func TestCheckTicketStatusFlagsAPlantedMismatch(t *testing.T) {
	notes := map[string]string{
		"docs/FEATURES.md": "| E8 | Built: T3. Not built: steps B to D (T2 to T4), the suites (T11). |\n" +
			"| E54 | tier bpflsm itself, not built (T7), still needs the line. |\n" +
			"| E9 | the record (T9) is unbuilt. |\n",
		"spec/backend/CAPABILITIES.md": "Not built: the suites (T11) and step E's enabling (T16).\n",
	}
	var lines []string
	for _, f := range CheckTicketStatus(planFixture, notes) {
		lines = append(lines, f.String())
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"docs/FEATURES.md:1: says T3 is not built", "docs/FEATURES.md:2: says T7 is not built"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no finding %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "CAPABILITIES") || strings.Contains(joined, "T11") || strings.Contains(joined, "T16") {
		t.Errorf("a ticket the plan does not mark built was flagged:\n%s", joined)
	}
	if got := CheckTicketStatus(planFixture, map[string]string{"n.md": "Not built: T11 and T16.\n"}); len(got) != 0 {
		t.Errorf("a consistent note failed: %v", got)
	}
}

// TestTicketStatusOnTheTree holds FEATURES.md and CAPABILITIES.md to TIER3-PLAN §10's marks.
func TestTicketStatusOnTheTree(t *testing.T) {
	plan, notes := loadTicketStatus(filepath.Join("..", ".."))
	if plan == "" {
		t.Skip("no docs/p0/TIER3-PLAN.md here")
	}
	if len(BuiltTickets(plan)) < 5 {
		t.Fatalf("the plan's table reads as %d built tickets", len(BuiltTickets(plan)))
	}
	for _, f := range CheckTicketStatus(plan, notes) {
		t.Errorf("%s", f)
	}
}
