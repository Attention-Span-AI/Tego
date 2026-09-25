// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestCheckLedgerNamesTheRunsNoSweepHereFinishes: a machine id that changes makes every run of this host foreign,
// which no sweep here ends or repairs, and nothing said so; an ended run whose anchor repair keeps failing stays
// listed, retried on every sweep, and nothing said that either. CheckLedger, what `tego doctor` reports, counts the
// runs of each other host and names this host's ended runs the index still lists whose launcher is gone, and writes
// nothing.
func TestCheckLedgerNamesTheRunsNoSweepHereFinishes(t *testing.T) {
	if localHost8() == "deadbeef" {
		t.Skip("this host's host8 is deadbeef")
	}
	const (
		foreign1 = "r-deadbeef-000000000000a-frgn01"
		foreign2 = "r-deadbeef-000000000000b-frgn02"
		stuck    = "r-00000000-000000000000c-stuck0"
		closing  = "r-00000000-000000000000d-clsng0"
		lost     = "r-00000000-000000000000e-lost00"
	)
	root := t.TempDir()
	if c, err := CheckLedger(root); err != nil || !c.Empty() {
		t.Fatalf("an empty ledger root: %+v %v, want nothing to report", c, err)
	}
	lostRunIn(t, root, foreign1, 0)
	lostRunIn(t, root, foreign2, 0)
	endedListedRun(t, root, stuck, 0, goneLauncher(t))
	endedListedRun(t, root, closing, 0, liveLauncher(t))
	lostRunIn(t, root, lost, 0)
	if err := ledger.MarkLive(root, lost); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, stuck, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}

	c, err := CheckLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	if c.Foreign["deadbeef"] != 2 || len(c.Foreign) != 1 {
		t.Errorf("foreign runs %v, want deadbeef: 2", c.Foreign)
	}
	if !slices.Equal(c.Unfinished, []string{stuck}) {
		t.Errorf("unfinished %v, want only the ended run whose launcher is gone (%s)", c.Unfinished, stuck)
	}
	after, err := os.ReadFile(filepath.Join(root, stuck, ledger.EventsFile))
	if err != nil || string(after) != string(before) {
		t.Fatalf("the check wrote to a ledger: %v", err)
	}
	if ids, err := ledger.LiveEntries(root); err != nil || len(ids) != 3 {
		t.Fatalf("the check changed the live index: %v %v", ids, err)
	}
}
