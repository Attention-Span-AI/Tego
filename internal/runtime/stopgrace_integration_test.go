// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationStopGraceLongerThanStopGrace is STOP-GRACE-FLAG end to end: an agent that ignores
// SIGTERM, a machine stop_grace of one second, and a stop that asks for four. The launcher used to
// escalate on its own stop_grace, so the run died after one second whatever the stop asked for.
func TestIntegrationStopGraceLongerThanStopGrace(t *testing.T) {
	f := newFixture(t, contractFor("igrace", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep"}))
	f.machine.StopGrace = config.Setting[time.Duration]{Value: time.Second}
	script, trapped := stubbornAgent(t, f)
	signals := make(chan os.Signal, 1)
	done := make(chan Result, 1)
	go func() {
		res, err := Run(context.Background(), f.rt, []string{"/bin/sh", script, trapped}, f.deps(t, signals))
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	dir := waitForRunDir(t, f.root, 10*time.Second)
	waitForFile(t, trapped, 10*time.Second) // the agent must be ignoring SIGTERM before the stop lands
	const requested = 4 * time.Second
	if err := RequestStopGrace(dir, requested); err != nil {
		t.Fatalf("RequestStopGrace: %v", err)
	}
	start := time.Now()
	signals <- syscall.SIGTERM
	select {
	case res := <-done:
		t.Fatalf("the run ended after %v, before the requested %v: %+v", time.Since(start), requested, res)
	case <-time.After(requested - time.Second):
	}
	select {
	case res := <-done:
		if res.Reason != record.RunEndStopped || res.ExitCode != identity.ExitStoppedKill {
			t.Fatalf("result %+v, want stopped/137", res)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the requested grace never escalated")
	}
	var end record.RunEndPayload
	evs := events(t, dir)
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if !end.Escalated {
		t.Fatalf("run_end must record the escalation: %+v", end)
	}
}

// TestIntegrationRunAnchorsWhereItIsTold is CHAIN-ANCHOR-PATH end to end: the head of a run lands in
// the chain.log Deps.AnchorPath names (the CLI's ~/.tego/chain.log), not beside the ledger root.
func TestIntegrationRunAnchorsWhereItIsTold(t *testing.T) {
	f := newFixture(t, contractFor("ianchor", []string{"/bin/true"}, []string{"/bin/true"}))
	anchor := filepath.Join(f.dir, ".tego", ledger.ChainLogFile)
	deps := f.deps(t, nil)
	deps.AnchorPath = anchor
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run dirs %v", dirs)
	}
	b, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatalf("the named anchor was not written: %v", err)
	}
	if !strings.HasPrefix(string(b), res.RunID+" ") {
		t.Fatalf("anchor %q does not name run %s", b, res.RunID)
	}
	if _, err := os.Stat(ledger.DefaultAnchorPath(dirs[0])); !os.IsNotExist(err) {
		t.Fatalf("the ledger's default anchor beside the root was written too: %v", err)
	}
	r, err := ledger.OpenReader(dirs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if rep, err := r.Verify(context.Background(), ledger.NewFileChainAnchor(anchor)); err != nil || !rep.Anchored {
		t.Fatalf("verify against the named anchor: %+v %v", rep, err)
	}
}
