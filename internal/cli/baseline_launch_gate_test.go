// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func appendLaunchBaseline(t *testing.T, text string) {
	t.Helper()
	f, err := os.OpenFile(os.Getenv(config.EnvConfigVar), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(text)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("baseline fixture: write=%v close=%v", err, closeErr)
	}
}

func TestBaselineRunGatePrecedesResources(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"ordinary command", ""},
		{"forwarder", "capture: forwarder\nmodels: [{provider: openai, host: 127.0.0.1, port: 9511}]\n"},
		{"forwarder and MCP", "capture: forwarder\nmodels: [{provider: openai, host: 127.0.0.1, port: 9511}]\nmcp: [{name: local, command: [/bin/true], tools: {}}]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gcRoot(t)
			appendLaunchBaseline(t, "baseline: {env: {deny: [TOKEN]}}\n")
			buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
			path := filepath.Join(t.TempDir(), "contract.yaml")
			if err := os.WriteFile(path, []byte("version: 0\nname: early-gate\ncommand: [/bin/true]\n"+tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			oldProbe, oldCapture, oldRun := probeMachine, captureFor, startRun
			t.Cleanup(func() { probeMachine, captureFor, startRun = oldProbe, oldCapture, oldRun })
			probes, captures, starts := 0, 0, 0
			probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
				probes++
				return nil, errors.New("unexpected backend probe")
			}
			captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
				captures++
				return nil, nil
			}
			startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
				starts++
				return tegoruntime.Result{}, errors.New("unexpected runtime start")
			}
			var diagnostics bytes.Buffer
			code := runRun(t.Context(), runOptions{contract: path, offline: true}, &diagnostics)
			if code != identity.ExitLauncher || !strings.Contains(diagnostics.String(), tegoruntime.ErrBaselineRecordUnavailable.Error()) || probes != 0 || captures != 0 || starts != 0 {
				t.Fatalf("baseline reached launch resources: exit=%d probes=%d capture=%d start=%d\n%s", code, probes, captures, starts, diagnostics.String())
			}
		})
	}
}

func TestBaselineAdoptionGatePrecedesResources(t *testing.T) {
	gcRoot(t)
	target := filepath.Join(t.TempDir(), "protected")
	if err := os.WriteFile(target, []byte("baseline target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	appendLaunchBaseline(t, "baseline: {fs: {deny_write: ["+target+"]}}\n")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	boundary := ceilingBoundary(t)
	m, ds, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatalf("machine: %v %v", err, ds)
	}
	oldProbe := probeMachine
	t.Cleanup(func() { probeMachine = oldProbe })
	probes := 0
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		probes++
		return nil, errors.New("unexpected adoption backend probe")
	}
	var diagnostics bytes.Buffer
	a, code := prepareAdoption(t.Context(), m, adoptOptions{boundary: boundary}, adopt.Process{}, 1000, &diagnostics)
	if a != nil || code != identity.ExitLauncher || probes != 0 || !strings.Contains(diagnostics.String(), tegoruntime.ErrBaselineRecordUnavailable.Error()) {
		t.Fatalf("baseline reached adoption resources: table=%t exit=%d probes=%d\n%s", a != nil, code, probes, diagnostics.String())
	}
}

func TestBaselineObservePassesEarlyGate(t *testing.T) {
	gcRoot(t)
	appendLaunchBaseline(t, "baseline: {env: {deny: [TOKEN]}}\n")
	path := filepath.Join(t.TempDir(), "observe.yaml")
	if err := os.WriteFile(path, []byte("version: 0\nname: observe-gate\ncommand: [/bin/true]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldProbe, oldCapture, oldRun, oldFailed := probeMachine, captureFor, startRun, startFailed
	t.Cleanup(func() { probeMachine, captureFor, startRun, startFailed = oldProbe, oldCapture, oldRun, oldFailed })
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		t.Fatal("observe selected an enforcing backend probe")
		return nil, nil
	}
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	startFailed = func(*doctor.Report) {}
	starts := 0
	startRun = func(_ context.Context, rt *agent.RuleTable, _ []string, _ tegoruntime.Deps) (tegoruntime.Result, error) {
		starts++
		if rt.Baseline == nil || rt.Baseline.Applied || len(rt.Baseline.Entries) != 1 {
			t.Error("observe lost its not-applied baseline snapshot")
		}
		return tegoruntime.Result{}, tegoruntime.ErrDeps
	}
	var diagnostics bytes.Buffer
	code := runRun(t.Context(), runOptions{contract: path, observe: true, offline: true}, &diagnostics)
	if starts != 1 || code != identity.ExitLauncher || strings.Contains(diagnostics.String(), tegoruntime.ErrBaselineRecordUnavailable.Error()) {
		t.Fatalf("record-only path acquired an applied-baseline gate: starts=%d exit=%d\n%s", starts, code, diagnostics.String())
	}
}
