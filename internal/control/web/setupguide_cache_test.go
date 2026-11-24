// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
)

// A run_end can be visible before Close publishes its anchor. Once the anchor
// arrives, the same ended-run snapshot must not retain that temporary unknown.
func TestOverviewGuideRechecksAnAnchorThatArrives(t *testing.T) {
	for _, tc := range []struct {
		name, wantState, wantRule string
		corrupt                   bool
	}{
		{"valid", guide.Done, guide.RuleRecordDone, false},
		{"corrupt-record", guide.Blocked, guide.RuleRecordUnverified, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.HalfDone)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			s := guideServer(t, f)
			snap, err := ledgerview.Load(f.Ledger)
			if err != nil {
				t.Fatal(err)
			}
			if len(snap.Runs) != 1 || snap.Runs[0].ID != f.Runs[0] || !snap.Runs[0].Ended || snap.Runs[0].Live {
				t.Fatalf("fixture is not one ended observe run: %+v", snap.Runs)
			}
			key := func() string {
				in := s.cfg.Guide(t.Context())
				files, err := checkedGuideKeys(t.Context(), in)
				if err != nil {
					t.Fatal(err)
				}
				return guideKey(snap, in, files)
			}
			beforeKey := key()
			aside := f.Anchor + ".held-for-test"
			if err := os.Rename(f.Anchor, aside); err != nil {
				t.Fatal(err)
			}
			first := s.setupGuide(t.Context(), snap)
			step := tourFact(first, guide.StepRecord)
			why := strings.Join(first.Words.NotKnown, "\n")
			if step.State != guide.NotKnown || first.Next.Rule != guide.RuleRecordUnreadable ||
				!strings.Contains(why, "chain anchor could not be read") || !strings.Contains(why, "no such file or directory") {
				t.Fatalf("missing anchor did not produce the expected uncertainty: step=%+v next=%+v unknown=%q", step, first.Next, why)
			}
			if tc.corrupt {
				path := filepath.Join(f.Ledger, f.Runs[0], ledger.EventsFile)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				old := []byte(`"bot.py"`)
				if bytes.Count(raw, old) != 1 {
					t.Fatal("observe fixture has no unique command byte witness")
				}
				// Keep valid JSON and its width, but leave the recorded hash and
				// restored anchor unchanged: recovery must still refuse this run.
				if err := os.WriteFile(path, bytes.Replace(raw, old, []byte(`"bad.py"`), 1), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(aside, f.Anchor); err != nil {
				t.Fatal(err)
			}
			if got := key(); got != beforeKey {
				t.Fatalf("the recovery changed the guide key: before=%q after=%q", beforeKey, got)
			}
			// Reuse exactly the same ended snapshot without a sleep, clock
			// advance or memo mutation. The verifier must decide again now.
			after := s.setupGuide(t.Context(), snap)
			step = tourFact(after, guide.StepRecord)
			if step.State != tc.wantState || after.Next.Rule != tc.wantRule {
				t.Fatalf("restored anchor retained an obsolete verdict: step=%+v next=%+v; want state=%q rule=%q", step, after.Next, tc.wantState, tc.wantRule)
			}
		})
	}
}

// Not retaining a new unknown must also discard an older key's known result:
// returning to that key cannot restore facts whose anchor is still absent.
func TestOverviewGuideDoesNotResurrectAnOlderKnownResult(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	build := guidetest.Build
	inputs := s.cfg.Guide
	s.cfg.Guide = func(ctx context.Context) guide.Inputs {
		in := inputs(ctx)
		in.Build = build
		return in
	}
	snap, err := ledgerview.Load(f.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 1 || !snap.Runs[0].Ended || snap.Runs[0].Live {
		t.Fatalf("fixture is not one ended observe run: %+v", snap.Runs)
	}
	key := func() string {
		in := s.cfg.Guide(t.Context())
		files, err := checkedGuideKeys(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		return guideKey(snap, in, files)
	}
	knownKey := key()
	known := s.setupGuide(t.Context(), snap)
	if step := tourFact(known, guide.StepRecord); step.State != guide.Done || known.Next.Rule != guide.RuleRecordDone {
		t.Fatalf("initial anchored record did not check out: step=%+v next=%+v", step, known.Next)
	}
	if err := os.Rename(f.Anchor, f.Anchor+".held-for-test"); err != nil {
		t.Fatal(err)
	}
	assertUnknown := func(where string, g *setupGuide) {
		t.Helper()
		step := tourFact(g, guide.StepRecord)
		why := strings.Join(g.Words.NotKnown, "\n")
		if step.State != guide.NotKnown || !strings.Contains(why, "chain anchor could not be read") ||
			!strings.Contains(why, "no such file or directory") {
			t.Fatalf("%s reused a known record without its anchor: step=%+v next=%+v unknown=%q", where, step, g.Next, why)
		}
	}
	build = guidetest.Build + " changed"
	if key() == knownKey {
		t.Fatal("the changed build did not establish a different guide key")
	}
	// The changed build also makes the stored machine check stale, so only
	// the record's own state and anchor reason are asserted for this load.
	assertUnknown("changed key", s.setupGuide(t.Context(), snap))
	build = guidetest.Build
	if key() != knownKey {
		t.Fatal("returning to the original build did not restore the original key")
	}
	if _, err := os.Stat(f.Anchor); !os.IsNotExist(err) {
		t.Fatalf("the anchor must still be absent: %v", err)
	}
	assertUnknown("original key after uncertainty", s.setupGuide(t.Context(), snap))
}
