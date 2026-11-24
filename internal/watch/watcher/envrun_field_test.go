// SPDX-License-Identifier: Apache-2.0

package watcher

import "testing"

// TestSightingCarriesOnlyARunID: the field a sighting carries for the observed TEGO_RUN_ID holds a run id or
// nothing (see TestObservedRunIDIsReportedOnlyWhenItIsOne for the note).
func TestSightingCarriesOnlyARunID(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000003-record"
	if envRunID(run) != run {
		t.Fatalf("the run id %s is not carried", run)
	}
	for _, v := range []string{"xy", "sk-live-qz", "r-not a run id", "../../etc", ""} {
		if got := envRunID(v); got != "" {
			t.Errorf("envRunID(%q) = %q: a value that is not a run id is carried", v, got)
		}
	}
}
