// SPDX-License-Identifier: Apache-2.0

package record

import "testing"

// TestMirrorSplitFixture reads spec/record/v1/fixtures/mirror-split.jsonl through Decode, Validate and Chain alone and
// holds it to what it is for: each of its three refused lines copies the envelope (pid, tid, cgroup, source,
// mono_ns), rule and reason of its own refused action at most 4 lines before it, as the runtime's mirror does; one has
// another line between it and its action, and two refused actions are both written before either's mirror. The views
// count three refusals in it, not five (internal/check/internal/mirror, internal/control/ledgerview pair.go).
func TestMirrorSplitFixture(t *testing.T) {
	events := readFixture(t, "mirror-split.jsonl")
	if events[0].Kind != KindRunStart || events[len(events)-1].Kind != KindRunEnd {
		t.Fatalf("lines %s to %s, want one whole run", events[0].Kind, events[len(events)-1].Kind)
	}
	actions, mirrors := 0, 0
	of := map[int]int{} // a refused action's index by its mirror's
	taken := map[int]bool{}
	for i, e := range events {
		if e.Kind.IsAction() && e.Verdict == VerdictRefused {
			actions++
		}
		if e.Kind != KindRefused {
			continue
		}
		mirrors++
		for j := i - 1; j >= 0 && j >= i-4; j-- {
			a := events[j]
			if a.Kind.IsAction() && a.Verdict == VerdictRefused && !taken[j] && a.PID == e.PID && a.TID == e.TID &&
				a.Cgroup == e.Cgroup && a.Source == e.Source && a.MonoNS == e.MonoNS && a.Rule == e.Rule && a.Reason == e.Reason {
				of[i], taken[j] = j, true
				break
			}
		}
		if _, ok := of[i]; !ok {
			t.Errorf("refused line %d copies the envelope of no refused action within 4 lines", e.Seq)
		}
	}
	if actions != 3 || mirrors != 3 {
		t.Fatalf("%d refused actions and %d refused lines, want three each", actions, mirrors)
	}
	split, early := false, false
	for m, a := range of {
		// Another line between a mirror and its action, which is not a refused action itself.
		if b := events[m-1]; a < m-1 && !(b.Kind.IsAction() && b.Verdict == VerdictRefused) && b.Kind != KindRefused {
			split = true
		}
		// A refused action written after this mirror's action and before this mirror.
		for k := a + 1; k < m; k++ {
			if events[k].Kind.IsAction() && events[k].Verdict == VerdictRefused {
				early = true
			}
		}
	}
	if !split || !early {
		t.Errorf("a line between a mirror and its action: %v; two refusals before either mirror: %v; want both", split, early)
	}
}
