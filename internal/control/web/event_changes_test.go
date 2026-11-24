// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
)

// TestEventPageListsRuleChangesMadeFromItsLine (C147): a rule written from a line is a journal entry that names the line,
// and the line's own page lists it (what changed in words, its direction, a way to its History and Undo), whether or not
// the page was reached by the Saved panel's link. Another line of the run lists none.
func TestEventPageListsRuleChangesMadeFromItsLine(t *testing.T) {
	s, line, _ := savedWithBlock(t)
	c := login(t, s)
	page := do(s, "GET", line, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the line page after a change was saved from it", page, "Rules changed from this line", "Cannot run git", "History")
	if other := do(s, "GET", "/runs/"+actRun+"/lines/3", "127.0.0.1:8484", c).Body.String(); strings.Contains(other, "Rules changed from this line") {
		t.Error("a line no change was made from lists one")
	}
}
