// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func intp(n int) *int { return &n }

func int64p(n int64) *int64 { return &n }

// TestAppliedLimitsFollowTheRevisionRules (A52): applied_limits is refused below record_minor 40, must name at least one
// kernel value in its kernel spelling, and a ledger written before the field still reads.
func TestAppliedLimitsFollowTheRevisionRules(t *testing.T) {
	full := &AppliedLimits{CPUMax: "50000 100000", CPUWeight: intp(20), PidsMax: intp(64)}
	if !SupportsMinor(MinorAppliedLimits) || !SupportsMinor(MinorEveryLaunch) || SupportsMinor(MinorEveryLaunch+1) || Minor != MinorEveryLaunch {
		t.Fatalf("minor 40 supported %t, 41 supported %t, 42 supported %t, Minor %d", SupportsMinor(MinorAppliedLimits), SupportsMinor(MinorEveryLaunch), SupportsMinor(MinorEveryLaunch+1), Minor)
	}
	for _, tc := range []struct {
		name  string
		minor int
		l     *AppliedLimits
		code  string // "" accepts
	}{
		{"all three at 40", MinorAppliedLimits, full, ""},
		{"cpu_max with no quota", MinorAppliedLimits, &AppliedLimits{CPUMax: "max 100000"}, ""},
		{"pids alone", MinorAppliedLimits, &AppliedLimits{PidsMax: intp(1)}, ""},
		{"all three at 41, which includes revision 40's meaning", MinorEveryLaunch, full, ""},
		{"below 40", MinorLearn, full, "below-minor"},
		{"empty block", MinorAppliedLimits, &AppliedLimits{}, "applied-limits"},
		{"cpu_max not the kernel's", MinorAppliedLimits, &AppliedLimits{CPUMax: "0.5"}, "applied-limits"},
		{"cpu_max with a zero period", MinorAppliedLimits, &AppliedLimits{CPUMax: "50000 0"}, "applied-limits"},
		{"cpu_weight 0", MinorAppliedLimits, &AppliedLimits{CPUWeight: intp(0)}, "applied-limits"},
		{"cpu_weight 10001", MinorAppliedLimits, &AppliedLimits{CPUWeight: intp(10001)}, "applied-limits"},
		{"pids 0", MinorAppliedLimits, &AppliedLimits{PidsMax: intp(0)}, "applied-limits"},
		// A launch's memory (GAPS C221): from the revision every launch writes, never below it, and never negative.
		{"memory at 41", MinorEveryLaunch, &AppliedLimits{MemoryMax: int64p(1 << 30), MemoryHigh: int64p(1 << 29)}, ""},
		{"a memory cap of nothing at 41", MinorEveryLaunch, &AppliedLimits{MemoryMax: int64p(0)}, ""},
		{"memory alone is a block", MinorEveryLaunch, &AppliedLimits{MemoryHigh: int64p(4096)}, ""},
		{"memory at 40", MinorAppliedLimits, &AppliedLimits{MemoryMax: int64p(1 << 30)}, "below-minor"},
		{"memory_max negative", MinorEveryLaunch, &AppliedLimits{MemoryMax: int64p(-1)}, "applied-limits"},
		{"memory_high negative", MinorEveryLaunch, &AppliedLimits{CPUMax: "max 100000", MemoryHigh: int64p(-5)}, "applied-limits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := RunStartPayload{RecordMinor: tc.minor, AppliedLimits: tc.l}
			err := p.ValidateFields()
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var fe *FieldError
			if err == nil || !errors.As(err, &fe) || fe.Code != tc.code {
				t.Fatalf("got %v, want a %s refusal", err, tc.code)
			}
		})
	}
}

// A revision above the baseline's may carry no baseline when the run had none, which the baseline's own revision may
// not; and a reader asks whether the run recorded one, not whether the revision is at least 39.
func TestAppliedLimitsRevisionNeedsNoBaseline(t *testing.T) {
	at40 := RunStartPayload{RecordMinor: MinorAppliedLimits}
	if err := at40.ValidateBaseline(); err != nil || at40.BaselineRecorded() {
		t.Fatalf("revision 40 with no baseline: %v, recorded %t", err, at40.BaselineRecorded())
	}
	partial := RunStartPayload{RecordMinor: MinorAppliedLimits, EffectiveHash: strings.Repeat("a", 64)}
	if err := partial.ValidateBaseline(); err == nil {
		t.Fatal("an effective hash with no baseline block was accepted at revision 40")
	}
	at39 := RunStartPayload{RecordMinor: MinorBaseline}
	if err := at39.ValidateBaseline(); err == nil {
		t.Fatal("the baseline revision accepted no baseline block")
	}
}

func TestAppliedLimitsRoundTripAndOlderLedgers(t *testing.T) {
	raw := `{"launcher_pid":1,"tier":"cgroup","record_minor":40,"applied_limits":{"cpu_max":"max 100000","pids_max":8}}`
	var p RunStartPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.AppliedLimits == nil || p.AppliedLimits.CPUMax != "max 100000" || p.AppliedLimits.PidsMax == nil || *p.AppliedLimits.PidsMax != 8 ||
		p.AppliedLimits.CPUWeight != nil {
		t.Fatalf("decoded %+v", p.AppliedLimits)
	}
	b, err := json.Marshal(p.AppliedLimits)
	if err != nil || string(b) != `{"cpu_max":"max 100000","pids_max":8}` {
		t.Fatalf("encoded %s (%v)", b, err)
	}
	// A ledger from before the field has none, and reads as it always did.
	var old RunStartPayload
	if err := json.Unmarshal([]byte(`{"launcher_pid":1,"tier":"cgroup","record_minor":31}`), &old); err != nil || old.AppliedLimits != nil {
		t.Fatalf("a revision 31 run_start: %+v, %v", old.AppliedLimits, err)
	}
	// A block at a revision that does not know it is refused when the line is validated.
	if err := (&RunStartPayload{RecordMinor: 31, AppliedLimits: p.AppliedLimits}).ValidateFields(); err == nil {
		t.Fatal("applied_limits accepted at revision 31")
	}
}
