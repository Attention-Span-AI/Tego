// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// ErrBaselineLaunch is an attempted launch with a historical or differently
// applied baseline table. A launch must compile its own current snapshot.
var ErrBaselineLaunch = errors.New("runtime: machine baseline cannot authorize this launch")

// ErrBaselineRecordUnavailable holds launch support until ADR 0144's recorder
// and guest proof can state the exact effective rules and per-entry mechanism.
var ErrBaselineRecordUnavailable = errors.New("runtime: baseline record support is not installed; ADR 0144 slices 6 and 9 remain required")

// CheckBaselineLaunchRecord checks the release boundary before a caller creates
// capture sources or probes a backend. Runtime constructors repeat the check.
func CheckBaselineLaunchRecord(rt *agent.RuleTable) error {
	return baselineLaunchRecord(rt)
}

// baselineLaunchRecord is the recorder seam for slice 6. Removing this guard
// requires its effective.yaml, run_start and receipt facts, plus slice 9 proof.
// There is deliberately no flag or configuration that bypasses this boundary.
func baselineLaunchRecord(rt *agent.RuleTable) error {
	if rt != nil && rt.Baseline != nil && rt.Baseline.Applied && len(rt.Baseline.Entries) > 0 {
		return ErrBaselineRecordUnavailable
	}
	return nil
}

func validateBaselineLaunch(rt *agent.RuleTable, machine *config.Machine, recordOnly bool) error {
	if err := validateBaselineTable(rt, machine); err != nil {
		return err
	}
	if rt.Baseline != nil && len(rt.Baseline.Entries) > 0 && rt.Baseline.Applied == recordOnly {
		return fmt.Errorf("%w: compiled baseline applied=%t contradicts actual recording-only=%t; recompile for the selected mechanism", ErrBaselineLaunch, rt.Baseline.Applied, recordOnly)
	}
	return nil
}

// validateBaselineTable is the part of validateBaselineLaunch that needs no backend: a replayed table, an
// unknown or uncompiled machine baseline. Preflight runs it before any probe.
func validateBaselineTable(rt *agent.RuleTable, machine *config.Machine) error {
	if rt.Replayed() {
		return fmt.Errorf("%w: a sealed recorded reconstruction cannot start or adopt a process", ErrBaselineLaunch)
	}
	if machine != nil && !machine.BaselineKnown() {
		return fmt.Errorf("%w: the machine baseline is UNKNOWN; repair and reload the failed configuration layers", ErrBaselineLaunch)
	}
	if rt.Baseline == nil {
		baseline, _ := machine.BaselineSnapshot()
		if machine != nil && !baseline.Empty() {
			return fmt.Errorf("%w: the configured machine baseline was not compiled into this table", ErrBaselineLaunch)
		}
		return nil
	}
	return nil
}
