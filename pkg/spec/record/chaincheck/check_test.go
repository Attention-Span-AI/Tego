// SPDX-License-Identifier: Apache-2.0

package chaincheck_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
)

// TestCheckReadsTheAnchoredFixtures holds Check to the record fixtures that carry their anchor: each is a whole,
// anchored run, in both scopes.
func TestCheckReadsTheAnchoredFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "spec", "record", "v1", "fixtures")
	for _, name := range []string{"profiles", "run-identity", "held-reads", "reason-reads"} {
		events, err := os.ReadFile(filepath.Join(dir, name+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		anchor, err := os.ReadFile(filepath.Join(dir, name+".chain.log"))
		if err != nil {
			t.Fatal(err)
		}
		run, _, _ := strings.Cut(string(anchor), " ")
		for _, validate := range []bool{false, true} {
			rep, err := chaincheck.Check(chaincheck.Input{Dir: run, Events: events, AnchorGiven: true, Anchor: anchor,
				Validate: validate})
			if v, r := chaincheck.Reason(rep, err, nil); v != chaincheck.VerdictMatch || !rep.Anchored {
				t.Errorf("%s (validate %v): %s %s, %+v, %v", name, validate, v, r, rep, err)
			}
		}
	}
}

// TestCheckReasons gives each way the bytes can fail its code (CHAIN.md §8) on a small anchored run; the shared vectors
// (spec/record/v1/vectors/chain) hold the full set.
func TestCheckReasons(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "spec", "record", "v1", "fixtures")
	events, err := os.ReadFile(filepath.Join(dir, "profiles.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(filepath.Join(dir, "profiles.chain.log"))
	if err != nil {
		t.Fatal(err)
	}
	run, _, _ := strings.Cut(string(anchor), " ")
	lines := strings.SplitAfter(string(events), "\n")
	for _, c := range []struct {
		name, verdict, reason string
		in                    chaincheck.Input
	}{
		{"whole", "match", "ok", chaincheck.Input{Dir: run, Events: events, AnchorGiven: true, Anchor: anchor}},
		{"unanchored", "match", "ok", chaincheck.Input{Dir: run, Events: events}},
		{"no anchor line", "mismatch", "anchor-missing", chaincheck.Input{Dir: run, Events: events, AnchorGiven: true}},
		{"no anchor file", "mismatch", "anchor-missing", chaincheck.Input{Dir: run, Events: events, AnchorGiven: true,
			NoAnchorFile: true}},
		{"last line removed", "mismatch", "anchor-mismatch", chaincheck.Input{Dir: run,
			Events: []byte(lines[0] + lines[1]), AnchorGiven: true, Anchor: anchor}},
		{"byte changed", "mismatch", "id-mismatch", chaincheck.Input{Dir: run,
			Events: []byte(strings.Replace(string(events), "a.md", "b.md", 1))}},
		{"lines swapped", "mismatch", "chain-broken", chaincheck.Input{Dir: run, Events: []byte(lines[0] + lines[2] + lines[1])}},
		{"another run's directory", "mismatch", "run-mismatch", chaincheck.Input{Dir: "r-00000000-0000000000000-000000",
			Events: events}},
		{"no ledger", "cannot-check", "no-ledger", chaincheck.Input{Dir: run, NoEvents: true}},
		{"anchored, no ledger", "mismatch", "ledger-missing", chaincheck.Input{Dir: run, NoEvents: true, AnchorGiven: true,
			Anchor: anchor}},
		{"empty", "cannot-check", "no-run-start", chaincheck.Input{Dir: run}},
		{"bad anchor", "mismatch", "anchor-malformed", chaincheck.Input{Dir: run, Events: events, AnchorGiven: true,
			Anchor: []byte("x\n")}},
		{"after run_end", "mismatch", "after-run-end", chaincheck.Input{Dir: run, Events: []byte(string(events) + lines[1])}},
	} {
		rep, err := chaincheck.Check(c.in)
		if v, r := chaincheck.Reason(rep, err, nil); v != c.verdict || r != c.reason {
			t.Errorf("%s: %s %s, want %s %s (%v)", c.name, v, r, c.verdict, c.reason, err)
		}
	}
}
