// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"sort"
	"testing"
)

// TestJudgeCatchesSyntheticOutcomes is the invariants' self-test over the fs grid (plan C6): an outcome map that
// makes every generated action succeed hits every filesystem invariant class somewhere in space 1, at the tier
// where it binds, and one that refuses every action hits none. The effect classes are TestJudgeEffects'.
func TestJudgeCatchesSyntheticOutcomes(t *testing.T) {
	want := map[string]Tier{
		"a mutation succeeded outside every write entry":                                                TierLandlock,
		"a symlink was created outside every write entry":                                               TierLandlock,
		"a hard link was created outside every write entry":                                             TierLandlock,
		"a rename succeeded outside the write entries":                                                  TierLandlock,
		"a read succeeded under a deny_read the tier enforces":                                          TierLandlock,
		"a mutation succeeded under a deny_read nearer than every write entry, which the tier enforces": TierCgroup,
	}
	hit := map[string]map[Tier]bool{}
	for _, fx := range GenFSGrid() {
		for i := range fx.Cells {
			c := &fx.Cells[i]
			for _, tier := range []Tier{TierLandlock, TierCgroup, TierBPFLSM} {
				if v := Invariant(fx.Model, c, tier, Outcome{OK: true}); v != "" {
					if hit[v] == nil {
						hit[v] = map[Tier]bool{}
					}
					hit[v][tier] = true
				}
				if v := Invariant(fx.Model, c, tier, Outcome{Errno: 13}); v != "" {
					t.Errorf("%s at %s: a refusal breaks %q", fx.ID(c), tier, v)
				}
			}
		}
	}
	var missing []string
	for v, tier := range want {
		if !hit[v][tier] {
			missing = append(missing, v+" at "+string(tier))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("no grid cell whose success breaks %q", m)
	}
	// At tier landlock a deny_read nested in a write entry is unenforced (SEMANTICS §2), so no success beneath it
	// breaks the nearest-wins invariant there.
	if hit["a mutation succeeded under a deny_read nearer than every write entry, which the tier enforces"][TierLandlock] {
		t.Error("the nearest-wins mutation invariant binds at tier landlock, where the nested deny_read is unenforced")
	}
	for v := range hit {
		if _, ok := want[v]; !ok {
			t.Errorf("a grid success breaks %q, which this self-test does not expect of the fs grid", v)
		}
	}
}
