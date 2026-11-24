// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// A contract the root-only approval floor cannot admit (setuid) is refused from the configuration alone: exit 125
// with the floor's words before any kernel probe (the cold-probe finding: a bpf teardown behind the probe took
// 20 to 38 s, so a refusal that waited for it outran the guest row's ten seconds), and before any run starts.
func TestLocalRolesSetuidFloorRefusesBeforeProbing(t *testing.T) {
	summaryHarness(t)
	prev := machineTestHook
	machineTestHook = config.SetOwnerOnlyForTest
	t.Cleanup(func() { machineTestHook = prev })
	path := t.TempDir() + "/agent.yaml"
	writeTestFile(t, path, "version: 0\nname: roles-setuid\ncommand: [true]\nsetuid: true\nrecord: summary\nenv:\n  pass: [PATH]\n")
	probes, starts := 0, 0
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		probes++
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		starts++
		return tegoruntime.Result{}, nil
	}
	code, stdout, stderr := run(t, "run", path, "--offline", "--no-summary")
	if code != identity.ExitLauncher || stdout != "" || !strings.Contains(stderr, "local root-only approvals require") || !strings.Contains(stderr, "setuid disabled") {
		t.Fatalf("setuid floor: exit=%d stdout=%q stderr=%s", code, stdout, stderr)
	}
	if probes != 0 || starts != 0 {
		t.Fatalf("the floor refusal reached the probe %d times and the runtime %d times", probes, starts)
	}
}
