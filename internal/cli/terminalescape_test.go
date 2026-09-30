// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestVerifiedLineEscapesTheAnchor: the anchor path verifiedLine names is escaped like the run id beside it
// (limits-check-doctor-cli.md: every human-readable view escapes ledger text with record.Printable).
func TestVerifiedLineEscapesTheAnchor(t *testing.T) {
	const evil = "R\x1b[2J\x1b]0;pwned\a\r"
	line := verifiedLine(ledger.VerifyReport{Run: "r", Lines: 2, Anchored: true}, "/x/"+evil)
	if strings.ContainsAny(line, "\x1b\a\r\n") {
		t.Errorf("verifiedLine wrote control bytes: %q", line)
	}
}

// TestRunHandsTheRuntimeItsSignalSubscription: the CLI's handler releases itself on the first signal, so one
// landing between the last interrupt check and the runtime's own subscription reached neither; the run
// passes a subscription made before that check, which queues it (R29).
func TestRunHandsTheRuntimeItsSignalSubscription(t *testing.T) {
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
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	got := false
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		if deps.Signals == nil {
			return tegoruntime.Result{}, nil
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		select {
		case <-deps.Signals:
			got = true
		case <-time.After(5 * time.Second):
		}
		return tegoruntime.Result{}, nil
	}
	var stderr bytes.Buffer
	runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"),
		command: []string{"true"}, offline: true}, &stderr)
	if !got {
		t.Errorf("the runtime was not handed a subscribed signal channel; stderr:\n%s", stderr.String())
	}
}
