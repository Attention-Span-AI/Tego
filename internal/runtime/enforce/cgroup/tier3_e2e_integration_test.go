// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestTierBPFLSMRunEndToEnd is TIER3-PLAN T7's acceptance (enforce-plane R19, §6 case 12): on a boot where LSM mode
// passes doctor's probe (the guest's lsm=...,bpf boot), `tego run --tier bpflsm` runs, decided by the plane in LSM
// mode exactly as TestPlaneRunEndToEnd's lsm cell is at tier cgroup, and its run_start names tier bpflsm; an auto run
// as root gets tier bpflsm too (auto prefers it). On a boot where it does not (bpf not in the LSM list), `--tier
// bpflsm` is refused before run_start, exit 125 [tier-unavailable], with doctor's GRUB line, and never runs at tier
// cgroup instead; an auto run there gets tier cgroup.
func TestTierBPFLSMRunEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier bpflsm needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
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
	modes := planeModesHere(t, bin)
	if slices.Contains(modes, "lsm") {
		t.Run("pinned", func(t *testing.T) { planeRunCellAt(t, bin, uid, gid, "lsm", "bpflsm", "bpflsm") })
		t.Run("auto", func(t *testing.T) { planeRunCellAt(t, bin, uid, gid, "lsm", "", "bpflsm") })
		return
	}
	t.Run("pinned refused", func(t *testing.T) { tier3RefusedCell(t, bin, uid, gid) })
	cgroupMode := PlaneFanotify
	if slices.Contains(modes, "fmod_ret") {
		cgroupMode = "fmod_ret"
	}
	t.Run("auto", func(t *testing.T) { planeRunCellAt(t, bin, uid, gid, cgroupMode, "", "cgroup") })
}

// tier3RefusedCell is `tego run --tier bpflsm` where LSM mode does not pass: exit 125 before run_start, the refusal
// naming tier bpflsm, why and the GRUB line when bpf is not an active LSM, and the agent never started.
func tier3RefusedCell(t *testing.T, bin string, uid, gid int) {
	files, dirs, links := planeFiles(t)
	p := newPlaneProject(t, uid, gid, files, dirs, links)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, "bpflsm", "agent.yaml", "auto", &out)
	err := cmd.Run()
	t.Logf("tego run --tier bpflsm: %v\n%s", err, out.String())
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 125 {
		t.Fatalf("tego run --tier bpflsm = %v, want exit 125", err)
	}
	msg := out.String()
	for _, want := range []string{"tier bpflsm pinned but not available", "[tier-unavailable]"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q", want)
		}
	}
	lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
	if !slices.Contains(strings.Split(strings.TrimSpace(string(lsm)), ","), "bpf") {
		if !strings.Contains(msg, "bpf is not in the active LSM list") || !strings.Contains(msg, ",bpf to the kernel command line") {
			t.Errorf("bpf is not an active LSM here (%s), and the refusal gives no GRUB line", strings.TrimSpace(string(lsm)))
		}
	}
	if strings.Contains(msg, "RESULT") {
		t.Error("the agent ran")
	}
	if runs, _ := filepath.Glob(filepath.Join(p.ledger, "*", "events.jsonl")); len(runs) != 0 {
		for _, e := range runEvents(t, p.ledger) {
			if e["kind"] == "run_start" {
				t.Errorf("the refused run wrote run_start: %v", e)
			}
		}
	}
}
