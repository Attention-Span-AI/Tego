// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// lostWithUnreadableAgent leaves a lost run whose first line does not decode, so its ledger names no agent.
func lostWithUnreadableAgent(t *testing.T, root, rand6 string, opts ...Option) string {
	t.Helper()
	ref := record.RunRef{ID: runID(fixedStart, rand6), Agent: "retriever"}
	w, err := Open(filepath.Join(root, ref.ID), ref, append([]Option{WithAnchor(&memAnchor{}),
		WithClock(newStepClock(fixedStart, 1_000_000_000, time.Millisecond))}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 2)
	die(w)
	path := filepath.Join(root, ref.ID, EventsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[0] = 'x'
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return ref.ID
}

// TestGCDoesNotCountALostRunItCouldNotSweep: sweep returned nil for a lost run whose
// agent its ledger could not give, so GC reported it swept while nothing had killed its tree or ended it. The
// agent now comes from the contract copy, as for a run that died before run_start, and a run with neither is an
// error, not a sweep.
func TestGCDoesNotCountALostRunItCouldNotSweep(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     []Option
		wantHook bool
	}{
		{"no contract copy either", nil, false},
		{"the contract copy names the agent", []Option{WithContract([]byte("name: retriever\n"))}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			id := lostWithUnreadableAgent(t, root, "agnt01", tc.opts...)
			var hooked []record.RunRef
			hook := func(_ context.Context, _ sys.Lender, run record.RunRef) error {
				hooked = append(hooked, run)
				return nil
			}
			rep, err := GC(context.Background(), root, keepAll, false, WithSweepHook(hook))
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(rep.Swept, id) {
				t.Errorf("reported swept, but the run is still %v", mustState(t, root, id))
			}
			if rep.Errors[id] == nil {
				t.Error("a lost run the sweep could not end must be reported")
			}
			if got := len(hooked) == 1 && hooked[0].Agent == "retriever"; got != tc.wantHook {
				t.Errorf("hook ran for %v, want it with the contract's agent: %v", hooked, tc.wantHook)
			}
		})
	}
}

// mustState is the state of run id under root.
func mustState(t *testing.T, root, id string) RunState {
	t.Helper()
	st, err := NewRunRepository(root).State(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
