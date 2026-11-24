// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"strings"
	"testing"
)

// TestObservedRunIDIsReportedOnlyWhenItIsOne: TEGO_RUN_ID is read from another process's environment, so a sighting
// carries it, in its field and in its note, only when it is a run id; any other value is never echoed (rules (a) to
// (c) of pkg/spec/identity envtext.go).
func TestObservedRunIDIsReportedOnlyWhenItIsOne(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000003-record"
	if outside, _, note := governance(run, ""); !outside || !strings.Contains(note, "TEGO_RUN_ID names "+run) {
		t.Errorf("a validated run id is not named: %q", note)
	}
	for _, v := range []string{"xy", "sk-live-qz", "r-not a run id", "../../etc"} {
		outside, _, note := governance(v, "")
		if !outside || strings.Contains(note, v) || !strings.Contains(note, "TEGO_RUN_ID is set to a value that is not a run id (not shown)") {
			t.Errorf("governance(%q): note %q", v, note)
		}
	}
}
