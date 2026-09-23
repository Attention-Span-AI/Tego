// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"testing"
)

// TestRunEndResourcesAreAdditive pins run_end.resources as an optional v1 field (docs/VERSIONING.md §2): a
// line without it is exactly the line an older binary wrote, a zero is written where the kernel said zero,
// and a key the kernel did not give is absent, so a reader can tell "used nothing" from "unknown".
func TestRunEndResourcesAreAdditive(t *testing.T) {
	t.Parallel()
	old := `{"reason":"exit","supervisor":{"notifications":1,"held_ms":0}}`
	var end RunEndPayload
	if err := json.Unmarshal([]byte(old), &end); err != nil {
		t.Fatal(err)
	}
	if end.Resources != nil {
		t.Fatalf("an older line decoded with resources %+v", end.Resources)
	}
	b, err := json.Marshal(end)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != old {
		t.Fatalf("a line without resources re-encodes as %s, want %s", b, old)
	}
	zero, peak := uint64(0), uint64(1<<26)
	end.Resources = &Resources{MemoryPeak: &peak, CPUNrThrottled: &zero, MemoryEvents: &MemoryEvents{OOMKill: &zero}}
	if b, err = json.Marshal(end); err != nil {
		t.Fatal(err)
	}
	want := `{"reason":"exit","supervisor":{"notifications":1,"held_ms":0},"resources":{"memory_peak":67108864,` +
		`"cpu_nr_throttled":0,"memory_events":{"oom_kill":0}}}`
	if string(b) != want {
		t.Fatalf("run_end = %s, want %s", b, want)
	}
	var back RunEndPayload
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Resources == nil || back.Resources.PidsPeak != nil || *back.Resources.MemoryPeak != peak ||
		back.Resources.MemoryEvents.High != nil || *back.Resources.MemoryEvents.OOMKill != 0 {
		t.Fatalf("round trip = %+v", back.Resources)
	}
}
