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

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// firstUseHome starts with the same absent user layer as an ordinary first use:
// home exists, but neither ~/.tego nor its optional config layer does.
func firstUseHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	prevSources, prevLogHome := machineSources, ownLogHomeOf
	machineSources = func(int, bool) (config.Sources, string, []config.Diagnostic) {
		return config.Sources{User: filepath.Join(home, config.UserRelPath)}, home, nil
	}
	ownLogHomeOf = func(int) string { return home }
	useAnchor(t, filepath.Join(home, ".tego", ledger.ChainLogFile))
	t.Cleanup(func() { machineSources, ownLogHomeOf = prevSources, prevLogHome })
	return home
}

func TestAdoptionFirstUseAdmission(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("configuration_changed_during_wait=%t", changed), func(t *testing.T) {
			sandboxAdopt(t, terminalProcs(), true)
			home := firstUseHome(t)
			if _, err := os.Stat(ownRecords(home)); !os.IsNotExist(err) {
				t.Fatalf("first-use fixture already has own records: %v", err)
			}
			// Keep CLI initialization and the strict reload real. Model only the
			// migration wait, then apply the runtime's unchanged snapshot comparison.
			moved := 0
			adoptRun = func(_ context.Context, _ *agent.RuleTable, _ tegoruntime.AdoptSpec, deps tegoruntime.AdoptDeps) (tegoruntime.Result, error) {
				if _, err := os.Stat(ownRecords(home)); err != nil {
					t.Fatalf("own directory was not initialized: %v", err)
				}
				if changed {
					if err := os.WriteFile(filepath.Join(home, config.UserRelPath), []byte("version: 0\nlog:\n  level: debug\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				current, err := deps.ReloadConfig()
				if err == nil {
					err = deps.Config.CheckAdmissionSnapshot(current)
				}
				if err != nil {
					return tegoruntime.Result{}, err
				}
				moved++
				return tegoruntime.Result{}, nil
			}
			code, _, stderr := runAdoptCmd(t, context.Background(), "--pid", "500")
			if changed {
				if code != identity.ExitLauncher || moved != 0 || !strings.Contains(stderr, "configuration changed") {
					t.Fatalf("changed configuration: exit %d, moved %d, stderr:\n%s", code, moved, stderr)
				}
			} else if code != identity.ExitOK || moved != 1 {
				t.Fatalf("unchanged first use: exit %d, moved %d, stderr:\n%s", code, moved, stderr)
			}
		})
	}
}

func TestRunFirstUseConfigurationSnapshot(t *testing.T) {
	home := firstUseHome(t)
	prevRun, prevCapture, prevRecorder := startRun, captureFor, recorderFor
	t.Cleanup(func() { startRun, captureFor, recorderFor = prevRun, prevCapture, prevRecorder })
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	started := false
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		started = true
		if _, err := os.Stat(ownRecords(home)); err != nil {
			t.Fatalf("own directory was not initialized: %v", err)
		}
		current, _, err := loadMachine(config.TrustAbort)
		if err == nil {
			err = deps.Config.CheckAdmissionSnapshot(current)
		}
		if err != nil {
			t.Fatalf("run compiled with a stale first-use snapshot: %v", err)
		}
		return tegoruntime.Result{}, nil
	}
	var stderr bytes.Buffer
	code := runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"), observe: true, offline: true, noSummary: true}, &stderr)
	if code != identity.ExitOK || !started {
		t.Fatalf("first-use run: exit %d, started %t, stderr:\n%s", code, started, stderr.String())
	}
}
