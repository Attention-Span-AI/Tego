// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// mainExitAgent starts one process in a session of its own and one its shell child disowns, waits for neither, and
// exits 7: internal/runtime's leaverAgent, the shape of a crashed agent that left a dev server behind.
const mainExitAgent = "#!/bin/sh\nsetsid sleep 300 &\nsh -c 'sleep 300 &'\nexit 7\n"

const mainExitContract = `version: 0
name: mainexit
command: ["sh", "./leaver.sh"]
fs:
  write: ["./out/"]
exec:
  allow: ["sh", "sleep", "setsid"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: summary
`

// TestTierRunEndsWithItsMainProcess is TestIntegrationARunEndsWithItsMainProcess (internal/runtime, tier landlock)
// at the root tiers, through the real binary: at tier cgroup (the plane the machine selects, and the fanotify
// listener) and at tier bpflsm, the agent's exit 7 with a `setsid` child and a disowned grandchild still running
// ends `tego run` with 7 stop_grace (2 s) after it, not when the sleeps would end (300 s), and run_end keeps exit 7,
// reason exit, and names the two processes the kill ended.
func TestTierRunEndsWithItsMainProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tiers cgroup and bpflsm need root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	bin := buildPlaneTego(t, t.TempDir())
	requireTier(t, bin, "cgroup")
	for _, c := range []struct{ name, tier, pin string }{
		{"cgroup", "cgroup", "auto"},
		{"cgroup-fanotify", "cgroup", PlaneFanotify},
		{"bpflsm", "bpflsm", "lsm"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.tier == "bpflsm" {
				requireTier(t, bin, "bpflsm")
			}
			p := newPlaneProject(t, uid, gid, map[string]string{"leaver.sh": mainExitAgent, "agent.yaml": mainExitContract},
				[]string{"out"}, nil)
			cfg, err := os.ReadFile(p.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.cfg, append(cfg, "stop_grace: 2s\n"...), 0o644); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			var out bytes.Buffer
			cmd := p.runAt(ctx, bin, c.tier, "agent.yaml", c.pin, &out)
			start := time.Now()
			err = cmd.Run()
			took := time.Since(start)
			t.Logf("tego run --tier %s (plane %s): %v after %s\n%s", c.tier, c.pin, err, took.Round(time.Millisecond), out.String())
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 7 {
				t.Fatalf("tego run = %v, want the agent's exit 7", err)
			}
			if took > 90*time.Second {
				t.Errorf("the run took %s: it waited for what the agent left running", took)
			}
			var end map[string]any
			for _, e := range runEvents(t, p.ledger) {
				if e["kind"] == "run_start" && e["tier"] != c.tier {
					t.Errorf("run_start tier %v, want %s", e["tier"], c.tier)
				}
				if e["kind"] == "run_end" {
					end = e
				}
			}
			if end == nil {
				t.Fatal("no run_end")
			}
			detail, _ := end["detail"].(string)
			if code, _ := end["exit_code"].(float64); code != 7 || end["reason"] != "exit" {
				t.Errorf("run_end %v, want exit_code 7 and reason exit", end)
			}
			if !strings.Contains(detail, "the main process exited") || !strings.Contains(detail, "2 processes:") ||
				strings.Count(detail, " sleep") != 2 {
				t.Errorf("run_end detail %q, want the two sleeps the kill ended named", detail)
			}
		})
	}
}
