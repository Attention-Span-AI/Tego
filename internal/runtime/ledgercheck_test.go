// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
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
	if c, err := CheckLedger(root, false); err != nil || !c.Empty() {
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

	c, err := CheckLedger(root, false)
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

// TestCheckLedgerListsLiveRunsWithoutTheRootFloor: the root-only approval floor is fixed per run at launch, so with
// the system floor set a run that is still running and started without it keeps same-user approvals; doctor names
// those runs. A run that started under the floor, an ended run and a check made without the floor are not listed.
func TestCheckLedgerListsLiveRunsWithoutTheRootFloor(t *testing.T) {
	const (
		before = "r-00000000-000000000000a-befor0"
		under  = "r-00000000-000000000000b-undr00"
		ended  = "r-00000000-000000000000c-endd00"
	)
	root := t.TempDir()
	start := func(id string, floor, end bool) {
		t.Helper()
		w := openRun(t, root, id)
		p := record.RunStartPayload{RecordMinor: record.MinorLocalRoles, Command: []string{"/bin/true"}, Tier: "landlock"}
		if floor {
			p.LocalApprovalAuthority = &record.LocalApprovalAuthority{Mode: "owner_only", SHA256: strings.Repeat("ab", 32), AgentUID: 1001}
		}
		if err := w.WriteRunStart(p); err != nil {
			t.Fatal(err)
		}
		if err := ledger.MarkLive(root, id); err != nil {
			t.Fatal(err)
		}
		if end {
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Cleanup(func() { _ = w.Abandon() })
		}
	}
	start(before, false, false)
	start(under, true, false)
	start(ended, false, true)
	c, err := CheckLedger(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.LiveWithoutFloor, []string{before}) {
		t.Errorf("live runs without the floor %v, want only %s", c.LiveWithoutFloor, before)
	}
	if c, err := CheckLedger(root, false); err != nil || len(c.LiveWithoutFloor) != 0 {
		t.Errorf("without the system floor: %+v %v, want nothing listed", c, err)
	}
}
