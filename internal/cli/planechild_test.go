// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
)

// planeChildCheckEnv marks the child TestTestBinaryIsThePlaneProbesChild starts: a test binary that runs its suite
// there instead of the probe's child reaches that test again and says so.
const planeChildCheckEnv = "TEGO_TEST_PLANE_CHILD_CHECK"

// TestTestBinaryIsThePlaneProbesChild: doctor's decision-plane probe (D7, enforce-plane R21), which `doctor` and a
// run's tier check (probeMachine) run in this process as root with the plane's objects, starts
// /proc/self/exe __doctor-plane-probe as its child and waits for it to say ready; it also execs a copy of the
// binary with __doctor-plane-probe noop. cmd/tego answers that argument first, and so must this package's test
// binary: it ran its whole suite instead, so the child never said ready within planeProbeTimeout, doctor.Run's
// fresh probe answered LSM mode "the probe child did not start", and TestProbeMachineIsDoctorsProbe compared that
// with a run's answer adopted from a build an earlier test left pinned (KVM root suites of integration/wave-a,
// internal_cli.tegobpf, 2026-10-16).
func TestTestBinaryIsThePlaneProbesChild(t *testing.T) {
	if os.Getenv(planeChildCheckEnv) != "" {
		_, _ = os.Stdout.WriteString("the test binary ran its suite as the plane probe's child\n")
		os.Exit(3)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{doctor.PlaneProbeCommand, "noop"}, 0},
		// An argument the probe does not know is its usage, exit 2, never the suite.
		{[]string{doctor.PlaneProbeCommand, "bogus"}, 2},
	} {
		cmd := exec.CommandContext(ctx, exe, c.args...)
		cmd.Env = append(os.Environ(), planeChildCheckEnv+"=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		if code != c.code || stdout.Len() != 0 {
			t.Errorf("%v: exit %d (%v), stdout %q, stderr %q; want exit %d and no output", c.args, code, err,
				stdout.String(), stderr.String(), c.code)
		}
	}
}
