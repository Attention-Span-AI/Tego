// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestShutdownEndsWithErrorWhenAWorkerFailedAfterTheAgentExited: awaitExit records
// a failed worker as the run's end only when the failure cancelled its wait for the agent. When the agent's
// exit won the race — the tier-2 enforce listener died a moment after the agent exited — run_end said
// reason=exit over a run whose enforcement had failed. shutdown now reads the group's error after joining it.
//
// Also pins runtime-launch.md R2: after run_start a failure becomes Result.Reason and run_end, never an error from Run.
func TestShutdownEndsWithErrorWhenAWorkerFailedAfterTheAgentExited(t *testing.T) {
	const runID = "r-00000000-000000000000c-lsnr00"
	runDir := filepath.Join(t.TempDir(), runID)
	w, err := ledger.Open(runDir, record.RunRef{ID: runID, Agent: "shutdown-listener"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "cgroup"}); err != nil {
		t.Fatal(err)
	}
	g, _ := newGroup(context.Background())
	// The agent has exited (r.wait is its zero status, exit 0) and then the listener fails.
	g.Go("enforce-listener", func() error { return errors.New("fanotify: listener died: EIO") })
	deadline := time.Now().Add(5 * time.Second)
	for g.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the fake listener never failed")
		}
		time.Sleep(time.Millisecond)
	}
	cgroups := &fakeCgroups{root: t.TempDir()}
	r := &runner{
		log: slog.New(slog.DiscardHandler), group: g, writer: w, handle: &fakeHandle{},
		cgm: cgroups, cg: cgroup.Cgroup{Path: cgroups.root},
	}
	res := r.shutdown(context.Background())
	if res.Reason != record.RunEndError {
		t.Errorf("result reason %q, want error", res.Reason)
	}
	evs := events(t, runDir)
	last := evs[len(evs)-1]
	var end record.RunEndPayload
	if err := last.DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if last.Kind != record.KindRunEnd || end.Reason != record.RunEndError || !strings.Contains(end.Detail, "enforce-listener") {
		t.Fatalf("run_end %s %+v, want reason error naming the enforce listener", last.Kind, end)
	}
}

// TestShutdownKeepsTheAgentsExitWhenNothingFailed: the group's own cancellation at shutdown is no failure.
func TestShutdownKeepsTheAgentsExitWhenNothingFailed(t *testing.T) {
	const runID = "r-00000000-000000000000d-lsnr01"
	runDir := filepath.Join(t.TempDir(), runID)
	w, err := ledger.Open(runDir, record.RunRef{ID: runID, Agent: "shutdown-listener"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "cgroup"}); err != nil {
		t.Fatal(err)
	}
	g, gctx := newGroup(context.Background())
	g.Go("enforce-listener", func() error { <-gctx.Done(); return gctx.Err() })
	cgroups := &fakeCgroups{root: t.TempDir()}
	r := &runner{
		log: slog.New(slog.DiscardHandler), group: g, writer: w, handle: &fakeHandle{},
		cgm: cgroups, cg: cgroup.Cgroup{Path: cgroups.root},
	}
	if res := r.shutdown(context.Background()); res.Reason != record.RunEndExit {
		t.Errorf("result reason %q, want exit", res.Reason)
	}
}
