// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTheWatcherPublishesToTheRunsSidecar is limits-check-doctor-cli.md R9's runtime half: the activity the
// budget watcher counts without a line (here a supervisor Touch under record: off) reaches <run>/activity from
// the watcher's own loop, so `status` reads the idle the watcher kills on; the sidecar's descriptor is closed once
// the workers have stopped, and a second close is nothing.
func TestTheWatcherPublishesToTheRunsSidecar(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runs", "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	w, err := ledger.Open(dir, record.RunRef{ID: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "a"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(filepath.Join(t.TempDir(), "chain.log"))), ledger.WithFreshRunDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	r := newTestRunner(Deps{Clock: systemClock{}})
	r.writer, r.dir = w, dir
	r.rt, r.queue = &agent.RuleTable{Record: agent.RecordOff, Limits: agent.ResolvedLimits{Set: agent.BudgetStallAfter, StallAfter: time.Hour}}, NewQueue(4)
	r.newBudget()
	r.startBudgetClock()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.budget.Run(ctx) }()
	touched := systemClock{}.MonoNS()
	r.budget.Touch(touched)
	deadline := time.Now().Add(5 * time.Second)
	got, ok := ledger.ReadActivity(dir)
	for (!ok || got != touched) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		got, ok = ledger.ReadActivity(dir)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ok || got != touched {
		t.Fatalf("the sidecar reads %d, %v; want the touch's %d", got, ok, touched)
	}
	r.closeActivity()
	r.closeActivity()
	if r.activity != nil {
		t.Fatal("the sidecar is still open after closeActivity")
	}
}
