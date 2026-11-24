// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Removing the delayed note leaves an otherwise silent root probe unexplained;
// printing it unconditionally adds output to every ordinary fast start.
func TestRunExplainsOnlyAStartupThatWaits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		delay    time.Duration
		probeErr error
		wantCode int
		wantNote bool
	}{
		{"fast cached probe", 0, nil, identity.ExitOK, false},
		{"slow probe", 1100 * time.Millisecond, nil, identity.ExitOK, true},
		{"slow failing probe", 1100 * time.Millisecond, errors.New("probe refused"), identity.ExitLauncher, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summaryHarness(t)
			probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
				time.Sleep(tc.delay)
				if tc.probeErr != nil {
					return nil, tc.probeErr
				}
				return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
			}
			startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
				return tegoruntime.Result{ExitCode: identity.ExitOK, Reason: record.RunEndExit}, nil
			}
			code, stdout, stderr := run(t, "run", "testdata/minimal.yaml", "--offline", "--no-summary")
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d: %s", code, tc.wantCode, stderr)
			}
			if stdout != "" {
				t.Fatalf("startup diagnostic reached stdout: %q", stdout)
			}
			count := strings.Count(stderr, "[startup-wait]")
			if tc.wantNote && count != 1 || !tc.wantNote && count != 0 {
				t.Fatalf("wait notes=%d, wantNote=%v: %s", count, tc.wantNote, stderr)
			}
			if tc.probeErr != nil && !strings.Contains(stderr, "probe refused") {
				t.Fatalf("probe refusal lost: %s", stderr)
			}
		})
	}
}

// A cached probe can still be followed by expensive runtime program loads.
func TestRunExplainsWaitingForPrepareAfterACachedProbe(t *testing.T) {
	_, anchor := summaryHarness(t)
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		time.Sleep(1100 * time.Millisecond)
		if err := deps.Started(tegoruntime.StartedRun{ID: "r-00000000-000000000000a-outer0", Dir: anchor + ".run"}); err != nil {
			return tegoruntime.Result{}, err
		}
		return tegoruntime.Result{Reason: record.RunEndExit}, nil
	}
	code, stdout, stderr := run(t, "run", "testdata/minimal.yaml", "--offline", "--no-summary")
	if code != identity.ExitOK || stdout != "" || strings.Count(stderr, "[startup-wait]") != 1 {
		t.Fatalf("slow prepare: exit=%d stdout=%q stderr=%s", code, stdout, stderr)
	}
}

// A start callback is the boundary before the agent is released. Omitting the
// timer's stop there would put an unrelated startup note into a long agent run.
func TestRunWaitNoteEndsBeforeTheAgentStarts(t *testing.T) {
	_, anchor := summaryHarness(t)
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
		if deps.Started != nil {
			if err := deps.Started(tegoruntime.StartedRun{ID: "r-00000000-000000000000a-outer0", Dir: anchor + ".run"}); err != nil {
				return tegoruntime.Result{}, err
			}
		}
		time.Sleep(1100 * time.Millisecond)
		return tegoruntime.Result{Reason: record.RunEndExit}, nil
	}
	code, stdout, stderr := run(t, "run", "testdata/minimal.yaml", "--offline", "--no-summary")
	if code != identity.ExitOK || stdout != "" || strings.Contains(stderr, "[startup-wait]") {
		t.Fatalf("startup note after agent release: exit=%d stdout=%q stderr=%s", code, stdout, stderr)
	}
}

func TestRunCancelledWhileProbingPrintsNoWaitNote(t *testing.T) {
	summaryHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		cancel()
		time.Sleep(1100 * time.Millisecond)
		return nil, ctx.Err()
	}
	var stdout, stderr strings.Builder
	code := mainWith(ctx, []string{"tego", "run", "testdata/minimal.yaml", "--offline", "--no-summary"}, &stdout, &stderr, []Command{cmdRun()})
	if code != identity.ExitLauncher || stdout.Len() != 0 || strings.Contains(stderr.String(), "[startup-wait]") || !strings.Contains(stderr.String(), "interrupted before the agent started") {
		t.Fatalf("cancelled start: exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
}
