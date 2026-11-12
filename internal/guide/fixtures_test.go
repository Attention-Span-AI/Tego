// SPDX-License-Identifier: Apache-2.0

package guide_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// object is s as the goldens hold it: indented JSON, the fixture's root written <root>.
func object(t *testing.T, f *guidetest.Fixture, s *guide.State) []byte {
	t.Helper()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(f.Normal(b), '\n')
}

// stored is the fixture's state as the dashboard will read it: the check `tego setup` stored, no check made now.
func stored(t *testing.T, f *guidetest.Fixture) *guide.State {
	t.Helper()
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	return guide.Compute(t.Context(), f.Inputs(t))
}

// TestFixturesGolden pins the object, schema tego.setup/1, for every fixture: each step's state, fact and source, the
// next step and the not-known lines (testdata/<fixture>.json; -update rewrites them).
func TestFixturesGolden(t *testing.T) {
	want := map[string]string{
		guidetest.Fresh: guide.RuleRecordTodo, guidetest.NotReady: guide.RuleCheckBlocked, guidetest.Outside: guide.RuleCheckOutside,
		guidetest.Recording: guide.RuleRecordWaiting, guidetest.HalfDone: guide.RuleRecordDone,
		guidetest.ContractMade: guide.RuleContractDone, guidetest.Finished: guide.RuleEnforceDone,
		guidetest.Tampered: guide.RuleEnforceUnverified, guidetest.HandWritten: guide.RuleEnforceDone,
	}
	for _, name := range guidetest.Names {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			s := stored(t, f)
			if s.Next.Rule != want[name] {
				t.Errorf("next rule %s, want %s: %+v", s.Next.Rule, want[name], s.Next)
			}
			if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
				t.Errorf("the next: line is wider than 80 columns: %q", line)
			}
			got := object(t, f, s)
			path := filepath.Join("testdata", name+".json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, b) {
				t.Errorf("%s differs (go test -run TestFixturesGolden -update):\n%s", path, got)
			}
		})
	}
}

// TestParityFixtures is the parity the two surfaces rest on (ADR 0142 (1)): for every fixture tree, the object
// a caller computes with the check it has just made (tego setup, Inputs.Fresh) is the object a caller computes from the
// files alone once that check is stored (the dashboard). `tego setup` prints the first, after storing the check; the
// dashboard renders the second. internal/cli's TestSetupParityWithTheFiles holds the command itself to it.
func TestParityFixtures(t *testing.T) {
	for _, name := range guidetest.Names {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			in := f.Inputs(t)
			probe := f.Probe
			in.Fresh = &probe
			now := object(t, f, guide.Compute(t.Context(), in))
			files := object(t, f, stored(t, f))
			if !bytes.Equal(now, files) {
				t.Errorf("with the check made now:\n%s\nfrom the stored check:\n%s", now, files)
			}
		})
	}
}

// TestParityWithNoWorkingDirectory: the dashboard has no working directory, so it passes Dir "". For every fixture the
// object with the check made now equals the object from the stored check then too. (A contract only in a project
// registry is seen by `tego setup` run from that folder and not by the dashboard: ADR 0142.)
func TestParityWithNoWorkingDirectory(t *testing.T) {
	for _, name := range guidetest.Names {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			in := f.Inputs(t)
			in.Dir = ""
			probe := f.Probe
			in.Fresh = &probe
			now := object(t, f, guide.Compute(t.Context(), in))
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			in.Fresh = nil
			files := object(t, f, guide.Compute(t.Context(), in))
			if !bytes.Equal(now, files) {
				t.Errorf("with the check made now:\n%s\nfrom the stored check:\n%s", now, files)
			}
		})
	}
}
