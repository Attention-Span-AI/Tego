// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"
)

func TestDoctorAnnouncesListenerStartupLimits(t *testing.T) {
	got := planeSummary(&PlaneState{Selected: PlaneFanotify}, false)
	for _, want := range []string{"setuid: true", "deny_read", "built-in list", "unmarked mount copies", "compiled deny_read paths visible under another name on the same filesystem instance", "name-entry scopes receive no alias check", "different filesystem instances showing the same data are not recognised at any tier", "later host mounts and ancestor renames"} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor omitted %q: %s", want, got)
		}
	}
	if got := planeSummary(&PlaneState{Selected: "lsm"}, true); strings.Contains(got, "refuses setuid: true") {
		t.Errorf("plane inherits listener limit: %s", got)
	}
}
