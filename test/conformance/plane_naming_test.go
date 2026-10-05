// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// planeNaming checks how a ledger line names the mechanism that decided it. Where no plane decides (mode ""), no line
// carries a mechanism or a decision_plane, save one: a refused read-denied line on tier landlock's axis may name
// mechanism landlock with no decision_plane (record minor 23, ADR 0077: a read the supervisor continued and the
// Landlock ruleset refused), and nowhere else. Where a plane decides, a line that names a mechanism names the plane
// and the axis' own mode, never another (a stale or empty decision_plane, fmod_ret under an lsm pin). It returns ""
// when the line is coherent.
func planeNaming(line map[string]any, mode string, tier Tier) string {
	if line == nil {
		return ""
	}
	mech, hasMech := line["mechanism"]
	dp, hasDP := line["decision_plane"]
	if hasMech && fmt.Sprint(mech) == record.MechanismLandlock {
		switch {
		case hasDP:
			return fmt.Sprintf("the ledger line names mechanism landlock with decision_plane %v", dp)
		case mode != "" || tier != TierLandlock:
			return fmt.Sprintf("the ledger line names mechanism landlock on tier %s's axis (plane mode %q)", tier, mode)
		case fmt.Sprint(line["verdict"]) != string(record.VerdictRefused) || fmt.Sprint(line["reason"]) != string(record.ReasonReadDenied):
			return fmt.Sprintf("the ledger line names mechanism landlock on a %v %v line, not a refused read-denied one",
				line["verdict"], line["reason"])
		}
		return ""
	}
	switch {
	case mode == "" && (hasMech || hasDP):
		return fmt.Sprintf("the ledger line names mechanism %v, decision_plane %v with no plane deciding", mech, dp)
	case mode != "" && hasMech && fmt.Sprint(mech) != "plane":
		return fmt.Sprintf("the ledger line names mechanism %v, want plane", mech)
	case mode != "" && hasMech && fmt.Sprint(dp) != mode:
		return fmt.Sprintf("the ledger line names decision_plane %v under plane mode %s", dp, mode)
	case mode != "" && !hasMech && hasDP:
		return fmt.Sprintf("the ledger line names decision_plane %v without mechanism plane", dp)
	}
	return ""
}

func TestPlaneNaming(t *testing.T) {
	plane := map[string]any{"mechanism": "plane", "decision_plane": "lsm"}
	cases := []struct {
		name string
		line map[string]any
		mode string
		bad  bool
	}{
		{"plane line under its mode", plane, "lsm", false},
		{"no line", nil, "lsm", false},
		{"kernel line without plane fields under a plane", map[string]any{"verdict": "refused"}, "lsm", false},
		{"fmod_ret line under an lsm pin", map[string]any{"mechanism": "plane", "decision_plane": "fmod_ret"}, "lsm", true},
		{"empty decision_plane", map[string]any{"mechanism": "plane", "decision_plane": ""}, "lsm", true},
		{"wrong mechanism", map[string]any{"mechanism": "fanotify", "decision_plane": "lsm"}, "lsm", true},
		{"decision_plane without mechanism", map[string]any{"decision_plane": "lsm"}, "lsm", true},
		{"plane fields on the fanotify axis", plane, "", true},
		{"plain line on the fanotify axis", map[string]any{"verdict": "refused"}, "", false},
	}
	for _, c := range cases {
		if got := planeNaming(c.line, c.mode, TierCgroup); (got != "") != c.bad {
			t.Errorf("%s: planeNaming = %q, want bad=%v", c.name, got, c.bad)
		}
	}
}

// TestPlaneNamingLandlockMechanism: since record minor 23 (ADR 0077) a refused read-denied line of a read the
// supervisor continued at tier landlock and the ruleset refused names mechanism landlock, and no plane: on tier
// landlock's axis that line is coherent; anywhere else, on another verdict or reason, or with a decision_plane, it is
// not.
func TestPlaneNamingLandlockMechanism(t *testing.T) {
	refused := func(extra map[string]any) map[string]any {
		l := map[string]any{"verdict": "refused", "reason": "read-denied", "mechanism": "landlock"}
		for k, v := range extra {
			l[k] = v
		}
		return l
	}
	cases := []struct {
		name string
		line map[string]any
		mode string
		tier Tier
		bad  bool
	}{
		{"landlock's refused read on its axis", refused(nil), "", TierLandlock, false},
		{"landlock's refused read on the fanotify axis", refused(nil), "", TierCgroup, true},
		{"landlock's refused read under a plane", refused(nil), "lsm", TierCgroup, true},
		{"landlock's refused read at tier bpflsm", refused(nil), "lsm", TierBPFLSM, true},
		{"landlock mechanism on an allow", refused(map[string]any{"verdict": "allow"}), "", TierLandlock, true},
		{"landlock mechanism on another reason", refused(map[string]any{"reason": "write-denied"}), "", TierLandlock, true},
		{"landlock mechanism with a decision_plane", refused(map[string]any{"decision_plane": "lsm"}), "", TierLandlock, true},
		{"another mechanism on tier landlock's axis", refused(map[string]any{"mechanism": "cgroup"}), "", TierLandlock, true},
	}
	for _, c := range cases {
		if got := planeNaming(c.line, c.mode, c.tier); (got != "") != c.bad {
			t.Errorf("%s: planeNaming = %q, want bad=%v", c.name, got, c.bad)
		}
	}
}
