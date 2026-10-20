// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestIntegrationStopRearmsABuildWhoseTimerDied is ADR 0022 (4) and (8) through the real binary, as root: a build
// left lingering past its linger whose timer died stays attached host-wide until a reaper, `tego stop` or gc acts
// for it. A root `tego stop` of another run (here one that is not running) starts the build's timer again, and the
// timer removes the build within 3 s; stop itself removes nothing, so its latency stays an exec rather than a
// removal's 1.7 to 3.7 s (limits-check-doctor-cli.md R29).
func TestIntegrationStopRearmsABuildWhoseTimerDied(t *testing.T) {
	requireRealPrepare(t)
	base, err := os.MkdirTemp("", "tego-stop-rearm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := buildTegoWithTags(t, base, "tegobpf,tegotesthooks")
	ledger := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledger)), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewRunID([32]byte{}, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(ledger, string(id)), 0o700); err != nil {
		t.Fatal(err)
	}

	// The build lingers in the host's state directory, where stop's pass looks, and its timer dies at once.
	hash := fmt.Sprintf("stop-rearm-%d", os.Getpid())
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })
	b := New(Options{Machine: machineLinger(time.Hour), Hash: hash, Events: &sink{},
		startTimer: func(string) error { return nil }})
	rel, cid := runCgroup(t, "stop-rearm")
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}
	h, err := b.Prepare(context.Background(), table, Run{ID: "stop-rearm", Agent: "a", CgroupID: cid, CgroupPath: rel})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(pins.Links); err != nil {
		t.Fatalf("the build did not linger: %v", err)
	}
	// Idle past any linger: the machine's is the default 5 minutes here, bpf.linger being read from /etc only.
	lock := filepath.Join(hoststate.Path, "bpf-"+hash+".lock")
	at := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, at, at); err != nil {
		t.Fatal(err)
	}

	stop := exec.Command(bin, "stop", string(id))
	stop.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "TEGO_TEST_OWN_LOG_HOME="+filepath.Join(base, "home"),
		"TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(base, "chain.log"))
	start := time.Now()
	out, err := stop.CombinedOutput()
	stopped := time.Now()
	if err != nil || !strings.Contains(string(out), string(id)+": not running") {
		t.Fatalf("tego stop: %v\n%s", err, out)
	}
	_, there := os.Stat(pins.Root)
	t.Logf("tego stop took %v; the build was there when it returned: %v", stopped.Sub(start).Round(time.Millisecond), there == nil)
	for {
		if _, err := os.Stat(pins.Root); os.IsNotExist(err) {
			t.Logf("the timer stop started removed the build %v after stop returned", time.Since(stopped).Round(time.Millisecond))
			return
		}
		if time.Since(stopped) > 3*time.Second {
			t.Fatalf("the build whose timer died is still pinned at %s 3 s after tego stop:\n%s", pins.Root, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
