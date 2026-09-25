// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationUnmeteredBudgetIsAGap: on a real run, a tokens budget a machine ceiling alone imposes, under
// capture: off, never trips; the run said nothing of it. The ledger carries gap what=record why=budget-unmetered
// binary=tokens, and the run still exits 0: the ceiling bounds every contract on the machine, most of which talk to
// no model, so its run is not refused (limits-check-doctor-cli.md R32).
func TestIntegrationUnmeteredBudgetIsAGap(t *testing.T) {
	contract := contractFor("iunmetered", []string{"/bin/true"}, []string{"/bin/true"}) + "capture: off\n"
	f := newFixture(t, contract)
	// What a machine limits.tokens ceiling compiles to for a contract that sets no tokens budget of its own.
	f.rt.Limits.Tokens = 1000
	f.rt.Limits.Set |= agent.BudgetTokens
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || res.Reason != record.RunEndExit {
		t.Fatalf("result %+v, want exit 0", res)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	var found bool
	for _, ev := range events(t, dirs[0]) {
		if ev.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.What == record.GapRecord && p.Why == GapBudgetUnmetered && p.Binary == "tokens" {
			found = true
		}
	}
	if !found {
		t.Fatal("the ledger has no gap what=record why=budget-unmetered binary=tokens")
	}
}

// TestIntegrationADeclaredBudgetNothingCountsIsRefused: a real run whose contract declares a tokens budget under
// capture: off ran to its end with a limit that never tripped (the custom-agent POC, item 1). It is now refused
// before run_start with ErrBudgetUnmetered naming the budget, the cause and the fix, leaving no run directory, and
// the agent never runs (limits-check-doctor-cli.md R32).
func TestIntegrationADeclaredBudgetNothingCountsIsRefused(t *testing.T) {
	contract := contractFor("iuncounted", []string{"/bin/touch"}, []string{"/bin/touch"})
	contract = strings.Replace(contract, "  pids: 128\n", "  pids: 128\n  tokens: 1000\n", 1) + "capture: off\n"
	f := newFixture(t, contract)
	marker := filepath.Join(f.out, "ran") // inside the contract's write entry: the agent could make it if it ran
	_, err := Run(context.Background(), f.rt, []string{"/bin/touch", marker}, f.deps(t, nil))
	if !errors.Is(err, ErrBudgetUnmetered) || !strings.Contains(err.Error(), "the contract sets capture: off") ||
		!strings.Contains(err.Error(), "Fix: set capture: auto, or remove the budget") {
		t.Fatalf("Run: %v, want ErrBudgetUnmetered naming the cause and the fix", err)
	}
	if dirs := runDirs(t, f.root); len(dirs) != 0 {
		t.Fatalf("run directories %v, want none: a refused run leaves no record", dirs)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the agent ran (%s: %v); a refused run releases nothing", marker, err)
	}
}

// TestIntegrationABudgetWhoseCaptureCannotStartIsRefused: a real run with a tokens budget whose capture source
// started inert (its mechanism-unavailable gap) is refused before run_start with ErrCaptureUnavailable, leaving
// no run directory, rather than running the agent unmetered (limits-check-doctor-cli.md R32).
func TestIntegrationABudgetWhoseCaptureCannotStartIsRefused(t *testing.T) {
	contract := contractFor("icaptureunavail", []string{"/bin/true"}, []string{"/bin/true"})
	contract = strings.Replace(contract, "  pids: 128\n", "  pids: 128\n  tokens: 1000\n", 1)
	f := newFixture(t, contract)
	deps := f.deps(t, nil)
	deps.Capture = []source.Source{&causedInert{plainSource{name: "uprobe"}, "this run has no capture ring: the host's bpf.ring_budget had no room for it"}}
	_, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
	if !errors.Is(err, ErrCaptureUnavailable) || !strings.Contains(err.Error(), "this run has no capture ring: the host's bpf.ring_budget had no room for it") {
		t.Fatalf("Run: %v, want ErrCaptureUnavailable naming the cause", err)
	}
	if dirs := runDirs(t, f.root); len(dirs) != 0 {
		t.Fatalf("run directories %v, want none: a refused run leaves no record", dirs)
	}
}
