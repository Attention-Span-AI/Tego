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
	"strings"
	"testing"
	"time"
)

// TestPlaneRunFillMismatchFailsPrepare is enforce-plane §7's "the fill disagreeing with fdinfo fails Prepare before
// arming; nothing runs" in a real `tego run`, not only in fillPlane's unit (TestPlaneFillFailsOnAReusedDescriptor):
// a binary built with the test hooks reuses one of the plan's descriptor numbers between the plan and the fill
// (TEGO_TEST_PLANE_FILL_REUSE: another file dup3'd over it), in each plane mode this machine passes. The run exits 125
// naming the reuse, writes no run_start, and the agent never starts; the slot's rows are gone after it.
func TestPlaneRunFillMismatchFailsPrepare(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the plane needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
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
	if len(modes) == 0 {
		t.Skip("no plane mode passes doctor's probe here")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			files, dirs, links := planeFiles(t)
			p := newPlaneProject(t, uid, gid, files, dirs, links)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var out bytes.Buffer
			cmd := p.run(ctx, bin, "agent.yaml", mode, &out)
			cmd.Env = append(cmd.Env, "TEGO_TEST_PLANE_FILL_REUSE=1") // plane_testhook.go (that file builds under tegotesthooks only)
			err := cmd.Run()
			t.Logf("tego run: %v\n%s", err, out.String())
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 125 {
				t.Fatalf("tego run with a reused descriptor number = %v, want exit 125", err)
			}
			if !strings.Contains(out.String(), "the number was reused") {
				t.Errorf("the refusal does not name the reuse")
			}
			if strings.Contains(out.String(), "RESULT") {
				t.Error("the agent ran")
			}
			if runs, _ := filepath.Glob(filepath.Join(p.ledger, "*", "events.jsonl")); len(runs) != 0 {
				for _, e := range runEvents(t, p.ledger) {
					if e["kind"] == "run_start" {
						t.Errorf("the refused run wrote run_start: %v", e)
					}
				}
			}
			if rows, _ := planeRowCount(t, mode); rows != 0 {
				t.Errorf("the plane's maps hold %d rows after the refused run", rows)
			}
		})
	}
}
