// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestAForkRefusedBeforeTheWatcherStartsStillEndsTheRunAsPids is R11 against the order of a real run.
// watchCgroup starts after the ack, so the agent is already running when it does, and a shell that
// forks past pids.max does so within milliseconds. When the watcher read its baseline at that point,
// the refused fork was already inside it, no later poll ever saw the counter rise, and the run ended
// with the shell's own exit status 2 instead of reason=pids and 137 (seen as root in the KVM guest,
// where the agent reliably won that race). The baseline is now what the cgroup read when it was new.
func TestAForkRefusedBeforeTheWatcherStartsStillEndsTheRunAsPids(t *testing.T) {
	cgroups := &fakeCgroups{root: t.TempDir()}
	r := &runner{
		log:     slog.New(slog.DiscardHandler),
		rt:      &agent.RuleTable{Contract: &agent.Contract{Name: "pidsbase"}},
		deps:    Deps{Cgroups: cgroups},
		agentID: identity.AgentID("pidsbase"),
		id:      identity.RunID("r-00000000-000000000000a-aaaaaa"),
	}
	// The fake manager hands back a path; give it the two event files a fresh cgroup has.
	dir := filepath.Join(cgroups.root, "pidsbase", "r-00000000-000000000000a-aaaaaa")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEvents := func(pidsMax string) {
		t.Helper()
		writeFile(t, filepath.Join(dir, "memory.events"), []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"))
		writeFile(t, filepath.Join(dir, "pids.events"), []byte("max "+pidsMax+"\n"))
	}
	writeEvents("0")
	if err := r.createCgroup(); err != nil {
		t.Fatalf("createCgroup: %v", err)
	}

	// The agent runs and a fork is refused, all before the watcher's first read.
	writeEvents("1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.watchCgroup(ctx); err != nil {
		t.Fatalf("watchCgroup: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the watcher never saw the refused fork: it was counted in its baseline")
	}
	if r.terminal != identity.ReasonPids || cgroups.killed != 1 {
		t.Fatalf("terminal %q after %d kills, want pids and one cgroup.kill", r.terminal, cgroups.killed)
	}
}
