// SPDX-License-Identifier: Apache-2.0

//go:build integration

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

	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
)

// TestPlaneCapBoundaryNeverEMFILE is enforce-plane §2.4 condition 7 as root (TIER3-PLAN's P4 capacity): a contract
// of N deny_read files in one directory, each held at a descriptor with every sibling, run at N = the launcher's
// descriptor cap less one, the cap and one more, either runs or is refused before run_start naming the cap, and is
// never an EMFILE; half the cap runs. The cap is this test process's budget, which the root launcher it starts
// inherits (the same RLIMIT_NOFILE, a few descriptors fewer in use). Each N runs auto (tier bpflsm where LSM mode
// passes, else tier cgroup) and, where LSM mode passes, pinned to bpflsm.
func TestPlaneCapBoundaryNeverEMFILE(t *testing.T) {
	bin, uid, gid, _ := capPreconditions(t)
	b, err := landlock.ReadFDBudget()
	if err != nil {
		t.Fatal(err)
	}
	limit := b.Cap()
	t.Logf("descriptor budget %+v: cap %d", b, limit)
	if limit < 16 || limit > 20000 {
		t.Skipf("a cap of %d is out of this test's range (RLIMIT_NOFILE %d)", limit, b.Limit)
	}
	tiers := []string{""}
	if slices.Contains(planeModesHere(t, bin), "lsm") {
		tiers = append(tiers, "bpflsm")
	}
	for _, n := range []int{limit / 2, limit - 1, limit, limit + 1} {
		for _, tier := range tiers {
			name := fmt.Sprintf("%d/%s", n, map[string]string{"": "auto", "bpflsm": "bpflsm"}[tier])
			t.Run(name, func(t *testing.T) { capBoundaryCell(t, bin, uid, gid, n, tier, n == limit/2) })
		}
	}
}

// capPreconditions skips where a root run cannot be made and returns the binary and the sudo caller.
func capPreconditions(t *testing.T) (string, int, int, bool) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("a run at a root tier needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	bin := buildPlaneTego(t, t.TempDir())
	requireTier(t, bin, "cgroup")
	return bin, uid, gid, true
}

// capBoundaryCell runs one N: exit 0 with the agent's line, or exit 125 naming the cap; never EMFILE. mustRun holds
// the control, which fits.
func capBoundaryCell(t *testing.T, bin string, uid, gid, n int, tier string, mustRun bool) {
	files := map[string]string{"agent.py": "print('RESULT ran', flush=True)\n"}
	deny := make([]string, n)
	for i := range n {
		deny[i] = fmt.Sprintf("\"./out/many/f%05d\"", i)
		files[fmt.Sprintf("out/many/f%05d", i)] = "s\n"
	}
	files["agent.yaml"] = fmt.Sprintf(`version: 0
name: plane-cap
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  deny_read: [%s]
exec:
  allow: ["python3"]
env:
  pass: ["PATH", "HOME"]
`, strings.Join(deny, ", "))
	p := newPlaneProject(t, uid, gid, files, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var out bytes.Buffer
	start := time.Now()
	err := p.runAt(ctx, bin, tier, "agent.yaml", "", &out).Run()
	msg := out.String()
	t.Logf("N=%d tier=%q: %v in %s\n%s", n, tier, err, time.Since(start).Round(time.Millisecond), capTail(msg, 1500))
	if strings.Contains(msg, "too many open files") || strings.Contains(msg, "EMFILE") {
		t.Fatalf("N=%d: the run met EMFILE instead of the cap", n)
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		if !strings.Contains(msg, "RESULT ran") {
			t.Errorf("N=%d: exit 0 without the agent's line", n)
		}
	case errors.As(err, &exit) && exit.ExitCode() == 125:
		if mustRun {
			t.Errorf("N=%d, half the cap, was refused", n)
		}
		if !strings.Contains(msg, "its cap on this launcher") && !strings.Contains(msg, "descriptor cap is") &&
			!strings.Contains(msg, "at most 4096") {
			t.Errorf("N=%d: the refusal names no cap", n)
		}
		if strings.Contains(msg, "RESULT") {
			t.Errorf("N=%d: refused, yet the agent ran", n)
		}
	default:
		t.Errorf("N=%d: tego run = %v, want exit 0 or 125", n, err)
	}
}

// capTail is the last n bytes of s.
func capTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
