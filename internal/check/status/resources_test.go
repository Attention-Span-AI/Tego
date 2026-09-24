// SPDX-License-Identifier: Apache-2.0

package status

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDeriveReadsTheResourcePeaks is R-res's read half: the snapshot carries run_end's resources exactly as
// recorded, a key the record lacks stays unknown, and a run with no run_end yet says it has none until it
// ends rather than a row of unknowns or zeros.
func TestDeriveReadsTheResourcePeaks(t *testing.T) {
	peak, zero := uint64(1<<30), uint64(0)
	dir := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit,
		Resources: &record.Resources{MemoryPeak: &peak, CPUNrThrottled: &zero}})
	s := derive(t, dir, false, base, 0)
	if !s.Ended || s.Resources == nil || *s.Resources.MemoryPeak != peak || s.Resources.PidsPeak != nil {
		t.Fatalf("snapshot ended %v resources %+v, want run_end's own", s.Ended, s.Resources)
	}
	if want := `{"memory_peak":1073741824,"cpu_nr_throttled":0}`; string(s.ResourcesRecorded) != want {
		t.Errorf("ResourcesRecorded %s, want run_end's object as written, %s", s.ResourcesRecorded, want)
	}
	line := ResourcesLine(s)
	for _, want := range []string{"memory peak 1.0 GiB (1073741824 B)", "pids peak unknown", "cpu throttled 0 times for unknown"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q lacks %q", line, want)
		}
	}

	old := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit})
	if s := derive(t, old, false, base, 0); !s.Ended || s.Resources != nil || s.ResourcesRecorded != nil ||
		!strings.HasPrefix(ResourcesLine(s), "memory peak unknown, pids peak unknown") {
		t.Fatalf("a run_end with no resources: ended %v resources %+v line %q", s.Ended, s.Resources, ResourcesLine(s))
	}

	live := write(t, true, runStart(""), nil)
	if s := derive(t, live, true, base, 0); s.Ended || s.ResourcesRecorded != nil || ResourcesLine(s) != "unknown until the run ends" {
		t.Fatalf("a live run: ended %v line %q", s.Ended, ResourcesLine(s))
	}
}
