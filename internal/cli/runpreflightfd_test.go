// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

// Early status validation must not increase the descriptor requirement of a
// capability probe. Its real writer is opened and validated again afterward.
func TestRunClosesTheStatusPrecheckBeforeProbing(t *testing.T) {
	summaryHarness(t)
	dir := statusTestDir(t)
	probes := 0
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		probes++
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", file.Name()))
			if err == nil && target == dir {
				t.Errorf("status precheck retained directory FD %s during the probe", file.Name())
			}
		}
		return nil, errors.New("machine tier unavailable")
	}
	code, stdout, stderr := run(t, "run", "testdata/minimal.yaml", "--offline", "--no-summary", "--status-file", filepath.Join(dir, "run.json"))
	if code != identity.ExitLauncher || probes != 1 || stdout != "" || !strings.Contains(stderr, "machine tier unavailable") {
		t.Fatalf("probe refusal: exit=%d probes=%d stdout=%q stderr=%s", code, probes, stdout, stderr)
	}
}

func TestRunReopensTheValidatedStatusWriterAfterProbing(t *testing.T) {
	summaryHarness(t)
	path := filepath.Join(statusTestDir(t), "run.json")
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	starts := 0
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		starts++
		if d.RunStatus == nil {
			t.Fatal("missing status writer")
		}
		if err := d.RunStatus(cliStatus()); err != nil {
			t.Fatal(err)
		}
		return tegoruntime.Result{ExitCode: 0}, nil
	}
	code, _, stderr := run(t, "run", "testdata/minimal.yaml", "--offline", "--no-summary", "--status-file", path)
	if code != 0 || starts != 1 {
		t.Fatalf("run: exit=%d starts=%d stderr=%s", code, starts, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runstatus.Decode(data)
	if err != nil || got.Run != cliStatus().Run {
		t.Fatalf("runtime status=%+v err=%v", got, err)
	}
}
