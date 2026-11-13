// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// These are check-time inputs, separate from the run-probe cache. Tests supply modeled mount layouts and a passwd
// home without requiring mounts, reading the real home or running the privileged probes.
var (
	doctorMountInfo  = agent.DefaultMountInfo
	doctorPasswdHome = config.PasswdHome
)

// addMountWarnings enriches doctor's existing D8 detail without changing capability selection or report shape.
// ForRun does not call this: Prepare acquires and checks the run's own snapshot against its compiled entries.
func (r *Report) addMountWarnings(uid int) {
	mt, _, err := agent.ReadMountSnapshot(doctorMountInfo)
	var warnings []string
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("mount alias check unavailable: %v; a run checks again before start", err))
	} else {
		warnings = append(warnings, mt.NetworkMountWarnings()...)
		home, err := doctorPasswdHome(uid)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("home alias check unavailable: %v", err))
		} else if home, err = filepath.EvalSymlinks(home); err != nil {
			warnings = append(warnings, fmt.Sprintf("home alias check unavailable: %v", err))
		} else {
			warnings = append(warnings, protectedMountWarnings(mt, home)...)
		}
	}
	if len(warnings) == 0 {
		return
	}
	// A mount table may contain many repeated sources or home views. Name representative entries and keep the
	// diagnostic readable; this has no effect on Prepare's full check.
	const maxWarnings = 8
	if extra := len(warnings) - maxWarnings; extra > 0 {
		warnings = append(warnings[:maxWarnings], fmt.Sprintf("and %d more mount warnings", extra))
	}
	for i := range r.Results {
		if r.Results[i].ID == CheckFanotify {
			r.Results[i].Detail += "; WARNING: " + strings.Join(warnings, "; WARNING: ")
			return
		}
	}
}

func protectedMountWarnings(mt *agent.MountTable, home string) []string {
	var warnings []string
	const wholeTree = "; for compiled deny_read entries covering this content, tier cgroup without a decision plane refuses " +
		"to start; tiers cgroup and bpflsm with a decision plane can hold whole-tree aliases when the remaining contract can be held"
	homeAliases := mt.Of(home).Aliases
	_, _, homeUncertainty := mt.AliasDetails(home)
	if homeUncertainty != "" {
		warnings = append(warnings, uncertainMountWarning(home, homeUncertainty))
	}
	homeConsequence := wholeTree
	if homeUncertainty != "" {
		homeConsequence = "; a run checks again before start"
	}
	for _, alias := range homeAliases {
		warnings = append(warnings, fmt.Sprintf("this host shows your home %q at a second place %q", home, alias)+homeConsequence)
	}
	// A target may itself be a link outside the home or contain a detached mount copy, even where the home has no
	// whole-tree alias. Inspect the actual built-in inventory, not a second hand-maintained list of names.
	for _, rel := range append(agent.BuiltInDenyRead(), ".tego") {
		target, err := filepath.EvalSymlinks(filepath.Join(home, rel))
		if err != nil {
			continue // an absent target contributes no compiled path entry
		}
		if _, err := os.Stat(target); err != nil {
			continue
		}
		aliases, parts, uncertainty := mt.AliasDetails(target)
		if uncertainty != "" {
			warnings = append(warnings, uncertainMountWarning(target, uncertainty))
		}
		if len(parts) != 0 {
			for _, part := range parts {
				warnings = append(warnings, fmt.Sprintf("this host shows a detached part of built-in protected target %q at %q; "+
					"tiers cgroup and bpflsm refuse to start a run with this compiled deny_read target because the decision plane "+
					"cannot hold the detached part", target, part))
			}
			continue
		}
		if len(homeAliases) != 0 && agent.Covers(home, target) {
			continue // the home warning already names this whole-tree view
		}
		consequence := wholeTree
		if uncertainty != "" {
			consequence = "; a run checks again before start"
		}
		for _, alias := range aliases {
			warnings = append(warnings, fmt.Sprintf("this host shows built-in protected target %q at a second place %q", target, alias)+consequence)
		}
	}
	return warnings
}

func uncertainMountWarning(target, reason string) string {
	return fmt.Sprintf("cannot tell whether folder %q is visible under another name because %s; a run checks again before start", target, reason)
}
