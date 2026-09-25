// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRunRefusesABudgetWhoseCaptureCannotStart: the runtime's refusal of a budgeted run whose capture could not
// start (runtime.ErrCaptureUnavailable, limits-check-doctor-cli.md R32) is exit 125 [capture-unavailable] with
// the runtime's cause and fix, and it keeps the cached probe answer, which it says nothing against.
func TestRunRefusesABudgetWhoseCaptureCannotStart(t *testing.T) {
	code, out, dropped := runRefusedBy(t, fmt.Errorf("%w: the tokens budget cannot be metered: the uprobe capture did "+
		"not start (cause). Fix: the fix", tegoruntime.ErrCaptureUnavailable))
	if code != identity.ExitLauncher || !strings.Contains(out, "[capture-unavailable]") ||
		!strings.Contains(out, "the uprobe capture did not start (cause)") || !strings.Contains(out, "Fix: the fix") {
		t.Fatalf("exit %d, want 125 [capture-unavailable] with the cause and the fix:\n%s", code, out)
	}
	if dropped != 0 {
		t.Errorf("the cached probe answer was dropped %d times; a capture refusal says nothing against it", dropped)
	}
}

// TestRunRefusesADeclaredBudgetNothingCounts: the runtime's refusal of a budget the contract declares and nothing
// counts (runtime.ErrBudgetUnmetered: no capture runs, or no price table that prices a model for cost_usd) is exit 125
// [budget-unmetered] with the runtime's cause and fix, where the run used to go ahead with a limit that never
// tripped. The cached probe answer is kept: the cause is the contract or the machine config, not the machine.
func TestRunRefusesADeclaredBudgetNothingCounts(t *testing.T) {
	code, out, dropped := runRefusedBy(t, fmt.Errorf("%w: the tokens budget cannot be counted, so the run is refused "+
		"rather than run with a limit that never trips: the cause. Fix: the fix, or remove the budget", tegoruntime.ErrBudgetUnmetered))
	if code != identity.ExitLauncher || !strings.Contains(out, "[budget-unmetered]") ||
		!strings.Contains(out, "the tokens budget cannot be counted") || !strings.Contains(out, "Fix: the fix") {
		t.Fatalf("exit %d, want 125 [budget-unmetered] with the cause and the fix:\n%s", code, out)
	}
	if dropped != 0 {
		t.Errorf("the cached probe answer was dropped %d times; an uncounted budget says nothing against it", dropped)
	}
}

// runRefusedBy runs testdata/minimal.yaml through runRun with the runtime's start stubbed to fail with err, and
// returns the exit code, stderr and how many times the cached probe answer was dropped.
func runRefusedBy(t *testing.T, err error) (int, string, int) {
	t.Helper()
	requireLandlockABI(t)
	prevProbe := probeMachine
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevAnchor, prevRun, prevCapture, prevRecorder, prevFailed := anchorPath, startRun, captureFor, recorderFor, startFailed
	t.Cleanup(func() {
		probeMachine, anchorPath, startRun, captureFor, recorderFor, startFailed = prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder, prevFailed
	})
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	dropped := 0
	startFailed = func(*doctor.Report) { dropped++ }
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		return tegoruntime.Result{}, err
	}
	var stderr bytes.Buffer
	code := runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"),
		command: []string{"true"}, offline: true}, &stderr)
	return code, stderr.String(), dropped
}
