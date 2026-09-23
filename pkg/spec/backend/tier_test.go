// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"errors"
	"testing"
)

// Full pairwise AtOrBelow including TierObserve (I6, R17).
// identity-config.md I6: Rank is a total order with no ties among defined values, TierObserve excluded from AtOrBelow.
func TestTierAtOrBelow(t *testing.T) {
	all := []Tier{TierObserve, TierLandlock, TierCgroup, TierBPFLSM, TierAuto, Tier("quantum")}
	for _, a := range all {
		for _, b := range all {
			want := a != TierObserve && a.Valid() && b.Valid() && a.Rank() <= b.Rank()
			if got := a.AtOrBelow(b); got != want {
				t.Errorf("%s.AtOrBelow(%s) = %v, want %v", a, b, got, want)
			}
		}
	}
	ranks := map[int]bool{}
	for _, tier := range []Tier{TierObserve, TierLandlock, TierCgroup, TierBPFLSM} {
		if ranks[tier.Rank()] {
			t.Errorf("rank tie at %d", tier.Rank())
		}
		ranks[tier.Rank()] = true
		if !tier.Valid() {
			t.Errorf("%s not valid", tier)
		}
	}
	if TierAuto.Valid() || Tier("").Valid() || TierAuto.Rank() != -1 {
		t.Error("auto/empty must be invalid with rank -1")
	}
	if got := Tiers(); len(got) != 3 || got[0] != TierLandlock || got[2] != TierBPFLSM {
		t.Errorf("Tiers = %v", got)
	}
}

func TestParseTier(t *testing.T) {
	cases := []struct {
		in   string
		want Tier
		ok   bool
	}{
		{"landlock", TierLandlock, true},
		{"cgroup", TierCgroup, true},
		{"bpflsm", TierBPFLSM, true},
		{"observe", TierObserve, true},
		{"auto", "", false},
		{"", "", false},
		{"Landlock", "", false},
		{"quantum", "", false},
	}
	for _, tc := range cases {
		got, err := ParseTier(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseTier(%q) = %q, %v; want %q ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrTier) {
			t.Errorf("ParseTier(%q) error does not wrap ErrTier: %v", tc.in, err)
		}
	}
}

// Capture is symmetric with Tier (R25).
// identity-config.md R25 (Valid/ParseCapture symmetric with Tier) and I6 (Capture rank order).
func TestCapture(t *testing.T) {
	order := []Capture{CaptureOff, CaptureForwarder, CaptureUprobe}
	for i, a := range order {
		if !a.Valid() || a.Rank() != i {
			t.Errorf("%s: valid=%v rank=%d", a, a.Valid(), a.Rank())
		}
		for j, b := range order {
			if got := a.AtOrBelow(b); got != (i <= j) {
				t.Errorf("%s.AtOrBelow(%s) = %v", a, b, got)
			}
		}
		if a.AtOrBelow(Capture("auto")) || Capture("auto").AtOrBelow(a) {
			t.Error("invalid capture compared true")
		}
	}
	for _, bad := range []string{"auto", "", "Uprobe", "tap"} {
		if c, err := ParseCapture(bad); err == nil || c != "" || !errors.Is(err, ErrCapture) {
			t.Errorf("ParseCapture(%q) = %q, %v", bad, c, err)
		}
	}
	if c, err := ParseCapture("forwarder"); err != nil || c != CaptureForwarder {
		t.Errorf("ParseCapture(forwarder) = %q, %v", c, err)
	}
}
