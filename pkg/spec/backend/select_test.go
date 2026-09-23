// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"errors"
	"testing"
)

func TestSelect(t *testing.T) {
	all := Probe{TierLandlock: true, TierCgroup: true, TierBPFLSM: true}
	user := Probe{TierLandlock: true}
	none := Probe{}
	cases := []struct {
		name       string
		ceiling    Tier
		pinned     Tier
		probe      Probe
		want       Tier
		wantErr    bool
		wantPinned bool
		wantTier   Tier
	}{
		{name: "auto picks the highest allowed", ceiling: TierAuto, probe: all, want: TierBPFLSM},
		{name: "empty ceiling is unbounded", ceiling: "", probe: all, want: TierBPFLSM},
		{name: "ceiling lowers the pick", ceiling: TierCgroup, probe: all, want: TierCgroup},
		{name: "unprivileged box as uid 1000", ceiling: TierAuto, probe: user, want: TierLandlock},
		{name: "probe gap skipped", ceiling: TierAuto, probe: Probe{TierLandlock: true, TierBPFLSM: false, TierCgroup: true}, want: TierCgroup},
		{name: "nothing available", ceiling: TierAuto, probe: none, wantErr: true, wantTier: TierBPFLSM},
		{name: "nothing available under ceiling", ceiling: TierLandlock, probe: Probe{TierCgroup: true}, wantErr: true, wantTier: TierLandlock},
		{name: "pinned available", ceiling: TierAuto, pinned: TierCgroup, probe: all, want: TierCgroup},
		{name: "pinned unavailable -> tier-unavailable", ceiling: TierAuto, pinned: TierBPFLSM, probe: user, wantErr: true, wantPinned: true, wantTier: TierBPFLSM},
		{name: "pinned above ceiling is lowered to it", ceiling: TierLandlock, pinned: TierBPFLSM, probe: all, want: TierLandlock},
		{name: "pinned auto means none", ceiling: TierCgroup, pinned: TierAuto, probe: all, want: TierCgroup},
		{name: "nil probe", ceiling: TierAuto, probe: nil, wantErr: true, wantTier: TierBPFLSM},
		{name: "observe is never a candidate", ceiling: TierAuto, probe: Probe{TierObserve: true}, wantErr: true},
		{name: "observe pin refused", ceiling: TierAuto, pinned: TierObserve, probe: all, wantErr: true},
		{name: "unknown pin refused", ceiling: TierAuto, pinned: "quantum", probe: all, wantErr: true},
		{name: "unknown ceiling refused", ceiling: "quantum", probe: all, wantErr: true},
		{name: "observe ceiling refused", ceiling: TierObserve, probe: all, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Select(tc.ceiling, tc.pinned, tc.probe)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Select = %q, want error", got)
				}
				if !errors.Is(err, ErrTierUnavailable) {
					t.Fatalf("error %v does not wrap ErrTierUnavailable", err)
				}
				var tu *TierUnavailableError
				if errors.As(err, &tu) {
					if tu.Pinned != tc.wantPinned || (tc.wantTier != "" && tu.Tier != tc.wantTier) {
						t.Errorf("error = %+v, want pinned=%v tier=%s", tu, tc.wantPinned, tc.wantTier)
					}
					if tu.Code() != CodeTierUnavailable {
						t.Errorf("code = %q", tu.Code())
					}
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Select = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestTierUnavailableErrorMessages(t *testing.T) {
	pinned := &TierUnavailableError{Tier: TierBPFLSM, Pinned: true}
	if pinned.Error() != "tier bpflsm pinned but not available" {
		t.Errorf("pinned message %q", pinned.Error())
	}
	auto := &TierUnavailableError{Tier: TierBPFLSM}
	if auto.Error() != "no enforcement tier available on this machine" {
		t.Errorf("auto message %q", auto.Error())
	}
}

func BenchmarkSelect(b *testing.B) {
	probe := Probe{TierLandlock: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Select(TierAuto, "", probe); err != nil {
			b.Fatal(err)
		}
	}
}
