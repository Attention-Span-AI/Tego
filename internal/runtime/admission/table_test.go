// SPDX-License-Identifier: Apache-2.0

package admission

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestTablePreparesEveryStageAndRechecksOnlyMutableFacts(t *testing.T) {
	var table Table
	var calls []string
	check := func(name string, rechecked bool, reason string) Check {
		return Check{Name: name, Rechecked: rechecked, SnapshotReason: reason, Run: func() error {
			calls = append(calls, name)
			return nil
		}}
	}
	if err := table.Add(check("anchor", true, ""), check("compiled contract", false, "The compiled contract is the requested input.")); err != nil {
		t.Fatal(err)
	}
	if err := table.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := table.Add(check("process", true, "")); err != nil {
		t.Fatal(err)
	}
	if err := table.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := table.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := table.Recheck(); err != nil {
		t.Fatal(err)
	}
	want := []string{"anchor", "compiled contract", "process", "anchor", "process"}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	if err := table.Add(check("late", true, "")); err == nil {
		t.Fatal("added an admission check after final admission")
	}
	if err := table.Prepare(); err == nil {
		t.Fatal("prepared after final admission")
	}
}

func TestTableRequiresPreparedEntriesBeforeAnyFinalCheck(t *testing.T) {
	var table Table
	calls := 0
	if err := table.Add(Check{Name: "prepared", Rechecked: true, Run: func() error { calls++; return nil }}); err != nil {
		t.Fatal(err)
	}
	if err := table.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := table.Add(Check{Name: "pending", Rechecked: true, Run: func() error { calls++; return nil }}); err != nil {
		t.Fatal(err)
	}
	err := table.Recheck()
	if err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("unprepared final admission = %v, want named refusal", err)
	}
	if calls != 1 {
		t.Fatalf("ran final checks before refusing pending preparation: %d calls", calls)
	}
}

func TestTableRefusesFailedPreparationAndFinalAdmission(t *testing.T) {
	for _, phase := range []string{"preparation", "final"} {
		t.Run(phase, func(t *testing.T) {
			var table Table
			denied := errors.New("anchor is a link")
			fail := phase == "preparation"
			later := 0
			if err := table.Add(
				Check{Name: "chain anchor", Rechecked: true, Run: func() error {
					if fail {
						return denied
					}
					return nil
				}},
				Check{Name: "later", Rechecked: true, Run: func() error { later++; return nil }},
			); err != nil {
				t.Fatal(err)
			}
			err := table.Prepare()
			if phase == "final" {
				if err != nil {
					t.Fatal(err)
				}
				fail = true
				err = table.Recheck()
			}
			if !errors.Is(err, denied) || !strings.Contains(err.Error(), "chain anchor") {
				t.Fatalf("admission failure = %v, want named wrapped cause", err)
			}
			wantLater := 0
			if phase == "final" {
				wantLater = 1
			}
			if later != wantLater {
				t.Fatalf("ran later checks after refusal: %d, want %d", later, wantLater)
			}
			if phase == "preparation" && table.Recheck() == nil {
				t.Fatal("failed preparation admitted final migration")
			}
		})
	}
}

func TestTableRequiresNamedExplicitClassification(t *testing.T) {
	noop := func() error { return nil }
	for _, tc := range []struct {
		name  string
		check Check
	}{
		{"unnamed", Check{Run: noop, Rechecked: true}},
		{"blank name", Check{Name: " ", Run: noop, Rechecked: true}},
		{"missing function", Check{Name: "anchor", Rechecked: true}},
		{"unclassified", Check{Name: "anchor", Run: noop}},
		{"blank reason", Check{Name: "anchor", Run: noop, SnapshotReason: " "}},
		{"both", Check{Name: "anchor", Run: noop, Rechecked: true, SnapshotReason: "snapshot"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var table Table
			err := table.Add(Check{Name: "valid", Run: noop, Rechecked: true}, tc.check)
			if err == nil || !strings.Contains(err.Error(), tc.check.Name) {
				t.Fatalf("invalid admission entry = %v", err)
			}
			if len(table.entries) != 0 {
				t.Fatal("partially added invalid batch")
			}
		})
	}
	var table Table
	valid := Check{Name: "anchor", Run: noop, Rechecked: true}
	if err := table.Add(valid); err != nil {
		t.Fatal(err)
	}
	if err := table.Add(valid); err == nil || !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("duplicate entry = %v", err)
	}
}
