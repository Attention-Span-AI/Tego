// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// limits R4's kernel half end to end, as root through the whole of `tego run`: under record: off an
// allowed open, file operation or connect makes no kernel sample, so before the activity stamp a tier-2 or tier-3
// agent that only read files, or wrote files a plane mode decides (they leave the seccomp notify set), had no line,
// no sample and no supervisor answer for the stall check to see, and stall_after ended it while it worked. Each such
// action of a stall-bounded run now stamps the run's slot of tego_activity, which the watcher pulls once a tick. The
// cells run in every plane mode this machine passes, on the fanotify listener, and at tier bpflsm where LSM mode
// passes (the guest's lsm=...,bpf boot); an idle agent still stalls in each.

// activityReaderContract is a python3 agent under record: off with a 2 s stall_after and nothing else to count.
const activityReaderContract = `version: 0
name: t2-activity
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
env:
  pass: ["PATH", "HOME"]
limits:
  stall_after: 2s
record: off
`

// activityReaderAgent reads the files under data/ in a loop for 6 s, three times the stall_after: read-only opens
// and reads, no exec, no write, no connect, nothing the supervisor is notified of under record: off.
const activityReaderAgent = `import os, time
files = [os.path.join("data", n) for n in sorted(os.listdir("data"))]
end, n = time.monotonic() + 6, 0
while time.monotonic() < end:
    for p in files:
        with open(p, "rb") as f:
            f.read()
        n += 1
    time.sleep(0.05)
print("RESULT reads", n, flush=True)
`

// activityWriterAgent changes files under out/ in a loop for 6 s: renames and a directory made and removed, which a
// plane mode decides in the kernel and leaves out of the seccomp notify set (planeSkips).
const activityWriterAgent = `import os, time
open("out/a", "w").close()
end, n = time.monotonic() + 6, 0
while time.monotonic() < end:
    os.rename("out/a", "out/b")
    os.rename("out/b", "out/a")
    os.mkdir("out/d")
    os.rmdir("out/d")
    n += 1
    time.sleep(0.05)
print("RESULT changes", n, flush=True)
`

// activityIdleAgent does nothing after its start.
const activityIdleAgent = `import time
time.sleep(30)
print("RESULT woke", flush=True)
`

// activityPreconditions is planePreconditions without its skip for a machine with no plane mode: the fanotify cells
// run wherever tier cgroup does.
func activityPreconditions(t *testing.T) (string, int, int, []string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Fatalf("a tegobpf test binary carries no BPF objects: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	bin := buildPlaneTego(t, t.TempDir())
	requireTier(t, bin, "cgroup")
	return bin, uid, gid, planeModesHere(t, bin)
}

// activityCell is one tier and plane: the agent's run, its exit code, its ledger and how long it took.
func activityCell(t *testing.T, bin string, uid, gid int, tier, mode, agent string) (int, []map[string]any, time.Duration, string) {
	t.Helper()
	data := map[string]string{"agent.py": agent, "agent.yaml": activityReaderContract}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		data["data/"+n+".txt"] = strings.Repeat(n, 4096)
	}
	p := newPlaneProject(t, uid, gid, data, []string{"out", "data"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	cmd.Env = append(cmd.Env, "TEGO_TEST_PHASE_TIMING=1") // the start phases' times, on stderr, for a slow run's log
	start := time.Now()
	err := cmd.Run()
	took := time.Since(start)
	t.Logf("tego run --tier %s (%s) from %s, after %s: %v\n%s", tier, mode, start.UTC().Format(time.RFC3339Nano), took, err,
		out.String())
	code := 0
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		t.Fatalf("tego run --tier %s (%s): %v", tier, mode, err)
	}
	return code, runEvents(t, p.ledger), took, out.String()
}

// sinceRunStart is how long after run_start the ledger's first line of kind was written, by the lines' mono_ns.
func sinceRunStart(events []map[string]any, kind string) (time.Duration, bool) {
	var start float64
	for _, e := range events {
		mono, _ := e["mono_ns"].(float64)
		switch {
		case e["kind"] == "run_start":
			start = mono
		case e["kind"] == kind && start > 0:
			return time.Duration(mono - start), true
		}
	}
	return 0, false
}

// timeline is a ledger's lines as kind@+ms from run_start's mono_ns, for a failure's message.
func timeline(events []map[string]any) string {
	var start float64
	var b strings.Builder
	for _, e := range events {
		mono, _ := e["mono_ns"].(float64)
		if e["kind"] == "run_start" {
			start = mono
		}
		fmt.Fprintf(&b, " %v@%+.0fms", e["kind"], (mono-start)/1e6)
		if e["kind"] == "run_start" || e["kind"] == "run_end" {
			fmt.Fprintf(&b, "(%v)", e["ts"])
		}
	}
	return b.String()
}

// activityCells are the tiers and planes the cells run at here: tier cgroup in each plane mode and on the listener,
// and tier bpflsm where LSM mode passes.
func activityCells(modes []string) [][2]string {
	var cells [][2]string
	for _, m := range append(slices.Clone(modes), PlaneFanotify) {
		cells = append(cells, [2]string{"cgroup", m})
	}
	if slices.Contains(modes, "lsm") {
		cells = append(cells, [2]string{"bpflsm", "lsm"})
	}
	return cells
}

func TestAReadingAgentUnderRecordOffIsNotAStall(t *testing.T) {
	bin, uid, gid, modes := activityPreconditions(t)
	for _, cell := range activityCells(modes) {
		for _, tc := range []struct{ name, agent, result string }{
			{"reader", activityReaderAgent, "reads"},
			{"writer", activityWriterAgent, "changes"},
		} {
			t.Run(cell[0]+"/"+cell[1]+"/"+tc.name, func(t *testing.T) {
				code, events, took, out := activityCell(t, bin, uid, gid, cell[0], cell[1], tc.agent)
				if code != 0 {
					t.Fatalf("an agent busy for 6 s under record: off with stall_after 2s exited %d after %s, want 0", code, took)
				}
				if !strings.Contains(out, "RESULT "+tc.result+" ") {
					t.Fatalf("the agent did not finish its loop")
				}
				// Nothing is unseen at a root tier under off now, so `tego run` warns nothing of it.
				if strings.Contains(out, "[stall-reads-unseen]") {
					t.Errorf("tego run warned that the run's reads are unseen:\n%s", out)
				}
				if took < 5*time.Second {
					t.Fatalf("the run took %s, under the agent's 6 s loop", took)
				}
				for _, e := range events {
					if e["kind"] == "limit" {
						t.Errorf("a busy agent got a limit line: %v", e)
					}
				}
				end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
				if end == nil || end["reason"] != "exit" {
					t.Errorf("run_end %v, want reason exit", end)
				}
				start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" })
				if start == nil || start["tier"] != cell[0] {
					t.Errorf("run_start %v, want tier %s", start, cell[0])
				}
			})
		}
	}
}

func TestAnIdleAgentUnderRecordOffStallsAtTier2(t *testing.T) {
	bin, uid, gid, modes := activityPreconditions(t)
	for _, cell := range activityCells(modes) {
		t.Run(cell[0]+"/"+cell[1], func(t *testing.T) {
			code, events, took, out := activityCell(t, bin, uid, gid, cell[0], cell[1], activityIdleAgent)
			if code != 124 {
				t.Fatalf("an idle agent under record: off exited %d after %s, want 124 (stall)", code, took)
			}
			if strings.Contains(out, "RESULT woke") {
				t.Fatal("the idle agent ran to its end")
			}
			// From run_start, not from the process's start: a test function's first run of a mode pays the build's and
			// the run probe's cold start before run_start, which is no part of the stall.
			if at, ok := sinceRunStart(events, "limit"); !ok || at > 5*time.Second {
				t.Errorf("the stall's limit line came %s after run_start (found %v), want within stall_after 2s and a tick "+
					"or two; the ledger: %s", at, ok, timeline(events))
			}
			var limits []map[string]any
			for _, e := range events {
				if e["kind"] == "limit" {
					limits = append(limits, e)
				}
			}
			if len(limits) != 1 || limits[0]["which"] != "stall_after" {
				t.Errorf("limit lines %v, want exactly one, stall_after", limits)
			}
		})
	}
}
