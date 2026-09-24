// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func u(v uint64) *uint64 { return &v }

// TestFieldsShowAnAbsentKeyAsUnknown is docs/VERSIONING.md §2 for the resource views: a key run_end did not
// carry reads "unknown", a 0 that it did carry reads 0, and neither is ever turned into the other.
func TestFieldsShowAnAbsentKeyAsUnknown(t *testing.T) {
	cases := []struct {
		name string
		r    *record.Resources
		want map[string]string
	}{
		{"no resources object", nil, map[string]string{
			"memory peak": Unknown, "pids peak": Unknown, "cpu": "unknown (user unknown, system unknown)",
			"cpu throttled": Unknown, "memory events": Unknown,
		}},
		{"every key, some of them the kernel's zero", &record.Resources{
			MemoryPeak: u(64 << 20), PidsPeak: u(20),
			CPUUsageUsec: u(1_234_567), CPUUserUsec: u(1_000_000), CPUSystemUsec: u(234_567),
			CPUNrThrottled: u(0), CPUThrottledUsec: u(0),
			MemoryEvents: &record.MemoryEvents{High: u(0), Max: u(3), OOM: u(0), OOMKill: u(1)},
		}, map[string]string{
			"memory peak": "64.0 MiB (67108864 B)", "pids peak": "20",
			"cpu":           "1.235s (user 1s, system 235ms)",
			"cpu throttled": "0 times for 0s", "memory events": "high 0, max 3, oom 0, oom_kill 1",
		}},
		{"a kernel below 5.19 and no cpu or memory controller", &record.Resources{
			PidsPeak: u(0), CPUUsageUsec: u(900), CPUUserUsec: u(0), CPUSystemUsec: u(900),
		}, map[string]string{
			"memory peak": Unknown, "pids peak": "0", "cpu": "1ms (user 0s, system 1ms)",
			"cpu throttled": Unknown, "memory events": Unknown,
		}},
		{"a memory.events file without some keys", &record.Resources{
			MemoryPeak: u(512), MemoryEvents: &record.MemoryEvents{OOMKill: u(0)},
			CPUNrThrottled: u(2),
		}, map[string]string{
			"memory peak": "512 B", "cpu throttled": "2 times for unknown",
			"memory events": "high unknown, max unknown, oom unknown, oom_kill 0",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := Fields(tc.r)
			labels := make([]string, len(fs))
			for i, f := range fs {
				labels[i] = f.Label
				if want, ok := tc.want[f.Label]; ok && f.Value != want {
					t.Errorf("%s = %q, want %q", f.Label, f.Value, want)
				}
			}
			if got := strings.Join(labels, ","); got != "memory peak,pids peak,cpu,cpu throttled,memory events" {
				t.Errorf("fields %s: the rows a view prints must not depend on what one run recorded", got)
			}
		})
	}
}

// TestLineSaysALiveRunHasNoneYet: the resources are read once at shutdown, so a run without run_end has
// nothing to show, and the line says why rather than printing a row of unknowns.
func TestLineSaysALiveRunHasNoneYet(t *testing.T) {
	if got := Line(&record.Resources{PidsPeak: u(3)}, false); got != "unknown until the run ends" {
		t.Errorf("live run: %q", got)
	}
	got := Line(&record.Resources{PidsPeak: u(3)}, true)
	if !strings.HasPrefix(got, "memory peak unknown, pids peak 3, cpu ") {
		t.Errorf("ended run: %q", got)
	}
}

// TestRecordedKeepsKeysThisBinaryDoesNotKnow: the --json views give run_end.resources as the ledger holds it, so
// a key a newer binary adds (additive, docs/VERSIONING.md §2), which record.Resources would drop, reaches the
// reader; a run_end with no resources object, or null, or something that is not an object, gives none.
func TestRecordedKeepsKeysThisBinaryDoesNotKnow(t *testing.T) {
	const obj = `{"memory_peak":1024,"io_bytes_read":77,"memory_events":{"oom_kill":0,"sock_throttled":3}}`
	for _, tc := range []struct{ payload, want string }{
		{`{"reason":"exit","resources":` + obj + `}`, obj},
		{`{"reason":"exit"}`, ""},
		{`{"reason":"exit","resources":null}`, ""},
		{`{"reason":"exit","resources":[1]}`, ""},
		{``, ""},
	} {
		e := &record.Event{Kind: record.KindRunEnd, Payload: json.RawMessage(tc.payload)}
		if got := string(Recorded(e)); got != tc.want {
			t.Errorf("payload %s: Recorded %q, want %q", tc.payload, got, tc.want)
		}
	}
	if Recorded(nil) != nil {
		t.Error("Recorded(nil) is not nil")
	}
}

// TestUsecDoesNotWrapPastInt64Nanoseconds: a cpu.stat total past MaxInt64/1000 microseconds (about 106
// CPU-days) wrapped time.Duration and printed a negative figure.
func TestUsecDoesNotWrapPastInt64Nanoseconds(t *testing.T) {
	for _, v := range []uint64{9_300_000_000_000, 1 << 63, ^uint64(0)} {
		if got := usec(u(v)); strings.HasPrefix(got, "-") {
			t.Errorf("usec(%d) = %q, negative", v, got)
		}
	}
}
