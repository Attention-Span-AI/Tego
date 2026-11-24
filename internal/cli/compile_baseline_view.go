// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/attention-span-ai/tego/pkg/spec/agent"

// TableBaseline presents compile-time predictions. Actual recorded mechanism
// facts belong to ADR 0144 slice 6 and have a separate versioned schema.
type TableBaseline struct {
	Applied bool                 `json:"applied"`
	UID     int                  `json:"owner_uid"`
	Home    string               `json:"owner_home"`
	Entries []TableBaselineEntry `json:"entries"`
}

// TableBaselineEntry retains many-source membership independently of rule origin.
type TableBaselineEntry struct {
	Key      string                  `json:"key"`
	Value    string                  `json:"value"`
	Expanded string                  `json:"expanded"`
	Target   string                  `json:"target,omitempty"`
	Sources  []TableBaselineSource   `json:"sources"`
	Rules    []string                `json:"rules"`
	Coverage []TableBaselineCoverage `json:"modeled_coverage"`
}

// TableBaselineSource is one contributing machine layer position.
type TableBaselineSource struct {
	Layer string `json:"layer"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// TableBaselineCoverage states the operations, conditions and limits for a mechanism.
type TableBaselineCoverage struct {
	Tier       string   `json:"tier"`
	Plane      string   `json:"plane,omitempty"`
	Held       string   `json:"held"`
	ImageMode  string   `json:"image_mode,omitempty"`
	Operations []string `json:"operations"`
	Conditions []string `json:"conditions"`
	Limits     []string `json:"limits"`
}

func tableBaseline(rt *agent.RuleTable) *TableBaseline {
	b := rt.Baseline
	if b == nil || len(b.Entries) == 0 {
		return nil
	}
	out := &TableBaseline{Applied: b.Applied, UID: b.Owner.UID, Home: b.Owner.Home}
	for _, e := range b.Entries {
		row := TableBaselineEntry{Key: string(e.Key), Value: e.Value, Expanded: e.Expanded, Target: e.Target, Rules: e.Rules}
		for _, s := range e.Sources {
			row.Sources = append(row.Sources, TableBaselineSource{Layer: s.Layer.String(), File: s.File, Line: s.Line})
		}
		for _, c := range e.Coverage {
			row.Coverage = append(row.Coverage, TableBaselineCoverage{Tier: string(c.Tier), Plane: c.Plane, Held: c.Held, ImageMode: c.ImageMode, Operations: c.Operations, Conditions: c.Conditions, Limits: c.Limits})
		}
		out.Entries = append(out.Entries, row)
	}
	return out
}
