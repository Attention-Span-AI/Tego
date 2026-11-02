// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// profileMap is a profiles source of profile texts by name; a test changes a profile by setting its entry.
type profileMap map[string]string

// Resolve implements agent.ProfileSource.
func (m profileMap) Resolve(name string) (string, []byte, error) {
	text, ok := m[name]
	if !ok {
		return "", nil, fmt.Errorf("profile %s: %w", name, os.ErrNotExist)
	}
	return "/profiles/" + name + ".yaml", []byte(text), nil
}

// startFrom makes f's run one that started from text, its extends resolved through profiles, as tego run records
// it (the merged copy and run_start's contract_hash), and writes text as the rules file with a time before the run's
// start, so nothing after the start dates the file.
func (f *fixture) startFrom(t *testing.T, text string, profiles agent.ProfileSource) {
	t.Helper()
	c, _, err := agent.LoadBytes(f.source, []byte(text), profiles)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "contract.yaml"), canon, 0o644); err != nil {
		t.Fatal(err)
	}
	f.lines.Reset()
	f.seq = 0
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}`,
		f.proj, hex.EncodeToString(sum[:]), f.source))
	f.writeBeforeStart(t, text)
}

// writeBeforeStart writes text as the rules file with a modification time a minute before the run's start: a copy
// put back with its own older time (mv, cp -p), which no journal line and no later time dates.
func (f *fixture) writeBeforeStart(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(f.source, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	old := f.started.Add(-time.Minute)
	if err := os.Chtimes(f.source, old, old); err != nil {
		t.Fatal(err)
	}
}

// inForceWith writes the ledger and reads the view with o.
func (f *fixture) inForceWith(t *testing.T, o Options) *InForceView {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	v := InForce(context.Background(), f.root, f.run, o)
	if v.Err != "" {
		t.Fatalf("InForce: %s", v.Err)
	}
	return v
}

// TestPendingDiffersWhenAProfileChanged: a profile the rules file extends changed after the run started, and the file
// itself did not (no journal line, its time before the start). The file now loads to other rules than the run ran,
// so the next run gets other rules: Pending says the file differs, with no change to list and no edit time, and the
// positions are the run's copy. Read with no profiles, the same file cannot be compared and nothing dates a change,
// so nothing is pending: Differs is claimed only from a comparison.
func TestPendingDiffersWhenAProfileChanged(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000015-prfchg")
	profiles := profileMap{"base": "env:\n  pass: [HOME]\n"}
	f.startFrom(t, strings.Replace(sourceText, "capture: off\n", "capture: off\nextends: base\n", 1), profiles)
	o := Options{Machine: f.m, Profiles: profiles}
	if v := f.inForceWith(t, o); v.Pending != nil || v.Positions != PositionsSource {
		t.Fatalf("before the profile changed: pending %+v positions %q (%s), want none and the source's", v.Pending, v.Positions, v.PositionsWhy)
	}
	profiles["base"] = "env:\n  pass: [HOME, LANG]\n"
	v := f.inForceWith(t, o)
	if v.Positions != PositionsCopy {
		t.Errorf("positions %q, want the copy's: the file no longer loads to the run's rules", v.Positions)
	}
	if p := v.Pending; p == nil || !p.Differs || len(p.Changes) != 0 || !p.Edited.IsZero() || p.Unchecked {
		t.Fatalf("pending %+v, want an undated difference: Differs, no change, no edit time, compared", p)
	}
	if v := f.inForceWith(t, Options{Machine: f.m}); v.Pending != nil {
		t.Errorf("pending %+v for a file that could not be compared and that nothing dates", v.Pending)
	}
}

// TestPendingNeedsTheRunsHash: a run_start that recorded no contract_hash leaves nothing to compare the rules file
// with: the copy's positions say so, not that the file changed, and a file that nothing dates is not pending.
func TestPendingNeedsTheRunsHash(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000017-nohash")
	f.lines.Reset()
	f.seq = 0
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_source":{"path":"%s"}`,
		f.proj, f.source))
	f.writeBeforeStart(t, sourceText)
	v := f.inForce(t)
	if v.Pending != nil {
		t.Errorf("pending %+v for a run with no contract_hash to compare the file with", v.Pending)
	}
	if v.Positions != PositionsCopy || !strings.Contains(v.PositionsWhy, "no contract hash") {
		t.Errorf("positions %q (%s), want the copy's for want of a hash", v.Positions, v.PositionsWhy)
	}
}

// TestPendingDiffersFromAnOlderCopy: the rules file was replaced by other text whose time is before the run's start
// (a copy put back with its own time), so neither the journal nor the time dates the change: Pending says the file
// differs. A dated change is listed as before, and Differs stays unset beside it.
func TestPendingDiffersFromAnOlderCopy(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000016-oldcpy")
	f.writeBeforeStart(t, strings.Replace(sourceText, "  allow: [sh, git]\n", "  allow: [sh]\n", 1))
	v := f.inForce(t)
	if p := v.Pending; p == nil || !p.Differs || len(p.Changes) != 0 || !p.Edited.IsZero() || p.Unchecked {
		t.Fatalf("pending %+v, want an undated difference", p)
	}
	if err := os.Chtimes(f.source, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if p := f.inForce(t).Pending; p == nil || p.Edited.IsZero() || p.Differs {
		t.Errorf("pending %+v after a later time dates the edit, want Edited and no Differs", p)
	}
}
