// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Caller-only refusals precede machine capability refusals. In particular a bad
// parent must neither wait for the probe nor disappear behind an unavailable tier.
func TestRunChecksTheCallerBeforeProbing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		probeErr error
	}{{"available machine", nil}, {"unavailable machine", errors.New("machine tier unavailable")}} {
		t.Run(tc.name, func(t *testing.T) {
			summaryHarness(t)
			t.Setenv(identity.EnvRunID, "invalid-parent")
			probes, starts := 0, 0
			probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
				probes++
				return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, tc.probeErr
			}
			startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
				starts++
				return tegoruntime.Result{}, nil
			}
			code, stdout, stderr := run(t, "run", "testdata/minimal.yaml", "--offline", "--no-summary")
			if code != identity.ExitLauncher || stdout != "" || !strings.Contains(stderr, "is not a run id") || strings.Contains(stderr, "invalid-parent") {
				t.Fatalf("caller refusal: exit=%d stdout=%q stderr=%s", code, stdout, stderr)
			}
			if probes != 0 || starts != 0 {
				t.Fatalf("caller refusal reached probe=%d runtime=%d", probes, starts)
			}
		})
	}
}

// An unusable caller-owned anchor is also independent of kernel capability.
// Keep this before the expensive probe even when both would refuse the launch.
func TestRunChecksTheAnchorBeforeProbing(t *testing.T) {
	summaryHarness(t)
	anchorPath = func(*config.Machine) (string, error) { return "", errors.New("anchor is unavailable") }
	probes, starts := 0, 0
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		probes++
		return nil, errors.New("machine tier unavailable")
	}
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		starts++
		return tegoruntime.Result{}, nil
	}
	code, stdout, stderr := run(t, "run", "testdata/minimal.yaml", "--offline", "--no-summary")
	if code != identity.ExitLauncher || stdout != "" || !strings.Contains(stderr, "chain anchor: anchor is unavailable") || probes != 0 || starts != 0 {
		t.Fatalf("anchor refusal: exit=%d probes=%d starts=%d stdout=%q stderr=%s", code, probes, starts, stdout, stderr)
	}
}

func TestRunChecksTheSocketRequestBeforeProbing(t *testing.T) {
	summaryHarness(t)
	path := t.TempDir() + "/agent.yaml"
	writeTestFile(t, path, "version: 0\nname: preflight\nharness: generic\ncommand: [true]\nenv:\n  set: {XDG_RUNTIME_DIR: \"%R\"}\n")
	probes, starts := 0, 0
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		probes++
		return nil, errors.New("machine tier unavailable")
	}
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		starts++
		return tegoruntime.Result{}, nil
	}
	code, stdout, stderr := run(t, "run", path, "--offline", "--no-summary")
	if code != identity.ExitLauncher || stdout != "" || !strings.Contains(stderr, "requires a provisioned claude-code harness") || probes != 0 || starts != 0 {
		t.Fatalf("socket refusal: exit=%d probes=%d starts=%d stdout=%q stderr=%s", code, probes, starts, stdout, stderr)
	}
}
