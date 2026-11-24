// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"bytes"
	"slices"
	"testing"
	"time"
)

// TestAnOrphanedRefusalIsToldBySomeHook: a refusal whose process was reparented away from its
// harness (a server backgrounded from a tool shell that exited) has owners that name no harness that has a hook. It is
// shared, as every refusal was before ownership: the first hook of any session tells it, once. The same holds for one
// whose only harness is gone.
func TestAnOrphanedRefusalIsToldBySomeHook(t *testing.T) {
	post := payload(t, "post-tool-use-bash")
	now := time.Now()
	for name, owners := range map[string]string{
		"owners that name no harness at all": "4242:777",
		"owners of a harness that is gone":   "4243:3,30:300",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.ownedRefusals(t, owners, harnessA)
			f.pendingState(t, State{Harnesses: []string{harnessA, harnessB, "30:300"}})
			a := &fakeProcs{self: "11:111", harness: harnessA, now: now, live: map[string]bool{harnessB: true}}
			b := &fakeProcs{self: "21:211", harness: harnessB, now: now, live: map[string]bool{harnessA: true}}
			if got := toldOf(t, f.hookAs(t, b, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"00"}) {
				t.Fatalf("B was told %v, want the orphaned refusal (0) and not A's (1)", got)
			}
			if got := toldOf(t, f.hookAs(t, a, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"01"}) {
				t.Fatalf("A was told %v, want its own refusal (1) and not the orphaned one B took", got)
			}
		})
	}
}

// TestTheNearestHarnessOwnsANestedSession (F7): a Claude Code B started from a tool of Claude Code A has both in the
// owners of its tools' refusals, nearest first. B's hook tells them and A's does not; a refusal of A's own tool, whose
// owners hold A alone, is A's.
func TestTheNearestHarnessOwnsANestedSession(t *testing.T) {
	f := newFixture(t)
	f.ownedRefusals(t, "300:3,"+harnessB+",30:3,"+harnessA, "301:3,"+harnessA)
	f.pendingState(t, State{Harnesses: []string{harnessA, harnessB}})
	now := time.Now()
	a := &fakeProcs{self: "11:111", harness: harnessA, now: now, live: map[string]bool{harnessB: true}}
	b := &fakeProcs{self: "21:211", harness: harnessB, now: now, live: map[string]bool{harnessA: true}}
	post := payload(t, "post-tool-use-bash")
	if got := toldOf(t, f.hookAs(t, a, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"01"}) {
		t.Fatalf("A was told %v, want its own refusal (1) and not the nested session's (0)", got)
	}
	if got := toldOf(t, f.hookAs(t, b, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"00"}) {
		t.Fatalf("B was told %v, want its own refusal (0)", got)
	}
}

// TestAHookRecordsItsHarness: a hook that finds a harness adds it to the state when it writes it (every SessionStart does,
// and every claim), and drops the ones that are gone.
func TestAHookRecordsItsHarness(t *testing.T) {
	f := newFixture(t)
	f.pendingState(t, State{Harnesses: []string{"30:300", harnessB}})
	a := &fakeProcs{self: "11:111", harness: harnessA, now: time.Now(), live: map[string]bool{harnessB: true}}
	f.hookAs(t, a, &bytes.Buffer{}, payload(t, "session-start"))
	if got := f.state(t).Harnesses; !slices.Equal(got, []string{harnessB, harnessA}) {
		t.Errorf("harnesses %v, want B (alive) and A (this hook's), not the gone 30:300", got)
	}
}

// TestAnotherHarnessesClaimIsDroppedOnlyWhenItsHarnessIsGone (F8): a claim of another harness whose claimer is gone
// stays while that harness is there, however old, since its next hook tells it; it goes when the harness does.
func TestAnotherHarnessesClaimIsDroppedOnlyWhenItsHarnessIsGone(t *testing.T) {
	post := payload(t, "post-tool-use-bash")
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	for _, bAlive := range []bool{true, false} {
		f := newFixture(t)
		f.ownedRefusals(t, harnessB)
		f.pendingState(t, State{Harnesses: []string{harnessA, harnessB}, Cursor: refusalAt(0).Seq, Owned: map[string]uint64{harnessB: refusalAt(0).Seq},
			Pending: []Claim{{Owner: harnessB, By: "999:9", At: old.Unix(), Seqs: []uint64{refusalAt(0).Seq}}}})
		a := &fakeProcs{self: "11:111", harness: harnessA, now: now, live: map[string]bool{harnessB: bAlive}}
		// A has something to say, so the state is written.
		f.ownedRefusals(t, harnessB, harnessA)
		if got := toldOf(t, f.hookAs(t, a, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"01"}) {
			t.Fatalf("B alive %v: A was told %v, want its own refusal (1)", bAlive, got)
		}
		if kept := len(f.state(t).Pending) == 1; kept != bAlive {
			t.Errorf("B alive %v: B's two-day-old claim kept %v, want %v", bAlive, kept, bAlive)
		}
	}
}
