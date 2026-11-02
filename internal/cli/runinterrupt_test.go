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

// TestRunInterruptedBeforeStartLaunchesNothing: a SIGINT or SIGTERM that lands after the contract compiled but
// before the runtime subscribes to signals of its own cancelled a context nothing read again, so the agent
// started regardless; and a probe the interrupt cut short was reported as [tier-unavailable]. Both are now
// refused as an interrupt, exit 125 [run], with nothing launched (R29).
func TestRunInterruptedBeforeStartLaunchesNothing(t *testing.T) {
	requireLandlockABI(t)
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
	prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder := probeMachine, anchorPath, startRun, captureFor, recorderFor
	t.Cleanup(func() {
		probeMachine, anchorPath, startRun, captureFor, recorderFor = prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder
	})
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	started := 0
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		started++
		return tegoruntime.Result{}, nil
	}

	for _, probeFails := range []bool{false, true} {
		started = 0
		ctx, cancel := context.WithCancel(context.Background())
		probeMachine = func(pctx context.Context, _ *config.Machine, _ backend.Tier) (*doctor.Report, error) {
			// The signal lands while the machine is probed.
			cancel()
			if probeFails {
				return nil, fmt.Errorf("doctor: %w", pctx.Err())
			}
			return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
		}
		var stderr bytes.Buffer
		code := runRun(ctx, runOptions{contract: filepath.Join("testdata", "minimal.yaml"),
			command: []string{"true"}, offline: true}, &stderr)
		cancel()
		out := stderr.String()
		if started != 0 || code != identity.ExitLauncher || !strings.Contains(out, "interrupted before the agent started") ||
			strings.Contains(out, backend.CodeTierUnavailable) {
			t.Errorf("probe fails %v: started %d times, exit %d, stderr:\n%s\nwant no start, 125, interrupted, no [%s]",
				probeFails, started, code, out, backend.CodeTierUnavailable)
		}
	}
}

// TestInterruptedBeforeStartNamesTheCommand: the interrupt's line names the command interrupted, and an adoption's says
// nothing was adopted: its agent was running before tego was, so run's "before the agent started; nothing was run",
// under tego run's name, was not so.
func TestInterruptedBeforeStartNamesTheCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var quiet bytes.Buffer
	if interruptedBeforeStart(ctx, runOptions{}, &quiet) || quiet.Len() != 0 {
		t.Fatalf("a context not cancelled read as an interrupt: %q", quiet.String())
	}
	cancel()
	for _, c := range []struct {
		o    runOptions
		want string
	}{
		{runOptions{}, "tego run: interrupted before the agent started; nothing was run [run]\n"},
		{runOptions{cmd: "tego watch", watched: true}, "tego watch: interrupted before the agent started; nothing was run [run]\n"},
		{runOptions{cmd: "tego adopt", adopted: true}, "tego adopt: interrupted before the adoption; nothing was adopted [run]\n"},
	} {
		var b bytes.Buffer
		if !interruptedBeforeStart(ctx, c.o, &b) || b.String() != c.want {
			t.Errorf("%s: %q, want %q", c.o.cmdName(), b.String(), c.want)
		}
	}
}
