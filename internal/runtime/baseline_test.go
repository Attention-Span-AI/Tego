// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestBaselineReplayCannotLaunchOrAdopt(t *testing.T) {
	machine, _, root := startupFixture(t)
	c, ds, err := agent.LoadBytes(filepath.Join(root, "source.yaml"), []byte("version: 0\nname: historical\ncommand: [/bin/true]\n"), nil)
	if err != nil {
		t.Fatalf("load historical source: %v %v", err, ds)
	}
	rt, ds, err := agent.UnknownBaselineReplay().Compile(c, machine, agent.WithHome(root), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("reconstruct historical source: %v %v", err, ds)
	}
	if _, err := newRunner(rt, []string{"/bin/true"}, Deps{Config: machine, Enforce: &fakeBackend{}}); !errors.Is(err, ErrBaselineLaunch) {
		t.Fatalf("sealed historical table authorized a runner: %v", err)
	}
	f := newAdoptFixture(t)
	if _, err := newAdoption(rt, f.spec(t), f.deps); !errors.Is(err, ErrBaselineLaunch) || !strings.Contains(err.Error(), `admission check "compiled runtime eligibility" during preparation`) {
		t.Fatalf("sealed historical table authorized adoption: %v", err)
	}
	if len(f.host.moves) != 0 || f.cgroups.created != 0 {
		t.Fatalf("historical replay refusal happened after moves=%d or scopes=%d", len(f.host.moves), f.cgroups.created)
	}
}

// The baseline refusals that need no backend are checked before a launch probes the machine;
// the one that needs the selected tier stays with the runner.
func TestPreflightRefusesBaselineFactsWithoutABackend(t *testing.T) {
	machine, _, root := startupFixture(t)
	c, ds, err := agent.LoadBytes(filepath.Join(root, "source.yaml"), []byte("version: 0\nname: historical\ncommand: [/bin/true]\n"), nil)
	if err != nil {
		t.Fatalf("load historical source: %v %v", err, ds)
	}
	replay, ds, err := agent.UnknownBaselineReplay().Compile(c, machine, agent.WithHome(root), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("reconstruct historical source: %v %v", err, ds)
	}
	if err := Preflight(replay, []string{"/bin/true"}, Deps{Config: machine}); !errors.Is(err, ErrBaselineLaunch) {
		t.Fatalf("a sealed historical table passed the preflight: %v", err)
	}
	// An applied or recording-only baseline is the backend's fact: the preflight cannot see it, the runner does.
	rec := childBaselineTable("TOKEN", false)
	if err := Preflight(rec, []string{"/bin/true"}, Deps{Config: machine}); err != nil {
		t.Fatalf("preflight refused a backend-dependent baseline fact: %v", err)
	}
}

func TestBaselineLaunchWaitsForRecordAndGuestSlices(t *testing.T) {
	machine, _, _ := startupFixture(t)
	if _, err := newRunner(childBaselineTable("TOKEN", true), []string{"/bin/true"}, Deps{Config: machine, Enforce: &fakeBackend{}}); !errors.Is(err, ErrBaselineRecordUnavailable) {
		t.Fatalf("baseline launch escaped the unimplemented record boundary: %v", err)
	}
	f := newAdoptFixture(t)
	f.rt.Baseline = childBaselineTable("TOKEN", true).Baseline
	spec := f.spec(t)
	spec.Boundary = true
	if _, err := newAdoption(f.rt, spec, f.deps); !errors.Is(err, ErrBaselineRecordUnavailable) {
		t.Fatalf("baseline adoption escaped the unimplemented record boundary: %v", err)
	}
	if len(f.host.moves) != 0 || f.cgroups.created != 0 {
		t.Fatalf("record-support refusal happened after moves=%d or scopes=%d", len(f.host.moves), f.cgroups.created)
	}
	for _, rt := range []*agent.RuleTable{nil, {}, childBaselineTable("TOKEN", false)} {
		if err := baselineLaunchRecord(rt); err != nil {
			t.Fatalf("empty/not-applied baseline acquired a record-support refusal: %v", err)
		}
	}
}

func TestBaselineLaunchUsesEffectiveRecordOnlyMode(t *testing.T) {
	for _, tc := range []struct {
		name                string
		applied, recordOnly bool
		wantError           bool
	}{
		{"enforcing", true, false, false},
		{"recording", false, true, false},
		{"recording snapshot cannot enforce", false, false, true},
		{"enforcing snapshot cannot claim not applied", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBaselineLaunch(childBaselineTable("TOKEN", tc.applied), config.Builtin(), tc.recordOnly)
			if errors.Is(err, ErrBaselineLaunch) != tc.wantError {
				t.Fatalf("applied=%t recording-only=%t: %v", tc.applied, tc.recordOnly, err)
			}
		})
	}
	for _, recordOnly := range []bool{false, true} {
		if err := validateBaselineLaunch(&agent.RuleTable{}, config.Builtin(), recordOnly); err != nil {
			t.Fatalf("empty baseline changed existing mode behavior: %v", err)
		}
	}
}

func TestRunnerRefusesUnappliedBaselineBeforeResources(t *testing.T) {
	machine, _, _ := startupFixture(t)
	for _, tc := range []struct {
		name    string
		applied bool
		observe bool
	}{
		{"recording snapshot to enforcing backend", false, false},
		{"enforcing snapshot to recording backend", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var backend enforce.Backend = &fakeBackend{}
			if tc.observe {
				backend = enforce.Observe()
			}
			if _, err := newRunner(childBaselineTable("TOKEN", tc.applied), []string{"/bin/true"}, Deps{Config: machine, Enforce: backend}); !errors.Is(err, ErrBaselineLaunch) {
				t.Fatalf("mismatched table authorized a runner: %v", err)
			}
		})
	}
}

func TestAdoptionRefusesAppliedBaselineInRecordingMode(t *testing.T) {
	f := newAdoptFixture(t)
	f.rt.Baseline = childBaselineTable("TOKEN", true).Baseline
	if _, err := newAdoption(f.rt, f.spec(t), f.deps); !errors.Is(err, ErrBaselineLaunch) {
		t.Fatalf("record-only adoption accepted applied rules: %v", err)
	}
	if len(f.host.moves) != 0 || f.cgroups.created != 0 {
		t.Fatalf("baseline refusal happened after moves=%d or scopes=%d", len(f.host.moves), f.cgroups.created)
	}
}
