// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return 0, nil }

// TestSuccessfulCommandsRequireOutput covers the formerly unchecked success branches
// and short writes whose writer neglected to return io.ErrShortWrite (R25).
func TestSuccessfulCommandsRequireOutput(t *testing.T) {
	id, _ := verifiedRun(t)
	for _, args := range [][]string{
		{"help"}, {"status", "--all"}, {"stop", id},
		{"events", id, "--verify"}, {"init", t.TempDir()},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var errs bytes.Buffer
			code := Main(append([]string{"tego"}, args...), shortOutput{}, &errs)
			if code != identity.ExitError || !strings.Contains(errs.String(), "short write") {
				t.Fatalf("exit=%d stderr=%q, want output I/O failure", code, errs.String())
			}
		})
	}
	// Empty status has its own success branch.
	gcRoot(t)
	if code := Main([]string{"tego", "status", "--all"}, shortOutput{}, io.Discard); code != identity.ExitError {
		t.Fatalf("empty status exit=%d, want %d", code, identity.ExitError)
	}
	if code := Main([]string{"tego", "compile", "-h"}, io.Discard, shortOutput{}); code != identity.ExitError {
		t.Fatalf("subcommand help exit=%d, want %d", code, identity.ExitError)
	}
}

func TestOutputFailurePreservesNonzeroExit(t *testing.T) {
	cmd := Command{Name: "finding", Run: func(_ context.Context, _ *flag.FlagSet, out, _ io.Writer) int {
		fmt.Fprintln(out, "finding")
		return identity.ExitFinding
	}}
	code := mainWith(t.Context(), []string{"tego", "finding"}, shortOutput{}, io.Discard, []Command{cmd})
	if code != identity.ExitFinding {
		t.Fatalf("exit=%d, want the command's finding exit", code)
	}
}

// fullOutput fails every write the way a full disk or exhausted quota does (`2>/dev/full`).
type fullOutput struct{}

func (fullOutput) Write([]byte) (int, error) { return 0, syscall.ENOSPC }

// TestRunExitIgnoresTegosStderrFailure: run's exit is the agent's (RUN-IDENTITY.md "passthrough", "Warnings
// never change the code"), and its stderr carries tego's warnings, not a result. A stderr tego could not write
// turned an agent's exit 0 into 125, which CI reads as a launcher failure before exec. `run -h` still
// requires its usage text.
func TestRunExitIgnoresTegosStderrFailure(t *testing.T) {
	requireLandlockABI(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	// A price table of a version this binary does not know: the one warning a run always prints (a table nobody
	// installed is quiet), so there are warnings to lose.
	prices := filepath.Join(base, "prices.yaml")
	if err := os.WriteFile(prices, []byte("version: 99\nmodels: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\nprices: "+prices+"\n"), 0o600); err != nil {
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
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	started := 0
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		started++
		return tegoruntime.Result{}, nil // the agent exited 0
	}
	argv := []string{"tego", "run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--", "true"}
	var healthy bytes.Buffer
	if code := mainWith(t.Context(), argv, io.Discard, &healthy, []Command{cmdRun()}); code != identity.ExitOK || healthy.Len() == 0 {
		t.Fatalf("healthy stderr: exit %d, %d bytes of warnings; want 0 with warnings to lose:\n%s", code, healthy.Len(), healthy.String())
	}
	if code := mainWith(t.Context(), argv, io.Discard, fullOutput{}, []Command{cmdRun()}); code != identity.ExitOK || started != 2 {
		t.Errorf("stderr full: exit %d, agent started %d times; want the agent's 0", code, started)
	}
	if code := mainWith(t.Context(), []string{"tego", "run", "-h"}, io.Discard, fullOutput{}, []Command{cmdRun()}); code != identity.ExitError {
		t.Errorf("run -h with stderr full: exit %d, want %d", code, identity.ExitError)
	}
}
