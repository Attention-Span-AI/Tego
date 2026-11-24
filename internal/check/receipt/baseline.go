// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"fmt"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func baselineSummary(p record.RunStartPayload) *BaselineSummary {
	if !p.BaselineRecorded() {
		return nil
	}
	return &BaselineSummary{Evidence: p.Baseline, ContractHash: p.ContractHash, EffectiveHash: p.EffectiveHash, Refusals: []BaselineRefusals{}}
}
func (rc *Receipt) finishBaseline() {
	if rc.Baseline == nil {
		return
	}
	for _, entry := range rc.Baseline.Evidence.Rules {
		n := 0
		for _, count := range rc.Refusals.ByRule {
			if slices.Contains(entry.Rule, count.Rule) {
				n += count.Count
			}
		}
		rc.Baseline.Refusals = append(rc.Baseline.Refusals, BaselineRefusals{ID: entry.ID, Count: n})
	}
}
func (rc *Receipt) writeBaseline(out *strings.Builder) {
	if rc.Baseline == nil {
		return
	}
	b := rc.Baseline.Evidence
	p := record.Printable
	out.WriteString("\nMachine baseline\n")
	if b.Mode == "not-applied" {
		out.WriteString("  A machine baseline was configured. Recording alone held nothing; every entry was not applied.\n")
	} else {
		out.WriteString("  A machine baseline was in force for this run.\n")
		counts := map[string]int{}
		for _, r := range b.Rules {
			counts[r.Held]++
		}
		fmt.Fprintf(out, "  Baseline evaluated: %d held by the kernel, %d conditional, %d best effort.\n", counts["kernel"], counts["conditional"], counts["best-effort"])
	}
	fmt.Fprintf(out, "  Baseline SHA-256: %s\n  Contract SHA-256: %s\n  Effective SHA-256: %s\n", p(b.SHA256), p(rc.Baseline.ContractHash), p(rc.Baseline.EffectiveHash))
	fmt.Fprintf(out, "  Owner uid %d, home %q, owner context known: %t.\n", b.OwnerUID, p(b.Home), b.OwnerKnown)
	for i, r := range b.Rules {
		count := 0
		if i < len(rc.Baseline.Refusals) {
			count = rc.Baseline.Refusals[i].Count
		}
		fmt.Fprintf(out, "  %s %q: %s at %s/%s; %d recorded refusals.\n", p(r.Key), p(r.Value), p(r.Held), p(r.Tier), p(r.Plane), count)
		for _, s := range r.Sources {
			fmt.Fprintf(out, "    Source %s %q:%d.\n", p(s.Layer), p(s.File), s.Line)
		}
		fmt.Fprintf(out, "    Operations: %s. Conditions: %s. Limits: %s. Image mode: %s.\n", p(strings.Join(r.Operations, "; ")), p(strings.Join(r.Conditions, "; ")), p(strings.Join(r.Limits, "; ")), p(r.ImageMode))
		if r.EmptyReason != "" {
			fmt.Fprintf(out, "    No separate action rule: %s.\n", p(r.EmptyReason))
		}
	}
	for _, s := range b.Sources {
		digest := "none"
		if s.SHA256 != nil {
			digest = *s.SHA256
		}
		fmt.Fprintf(out, "  Consulted layer %s %q: %s; SHA-256 %s.\n", p(s.Layer), p(s.File), p(s.State), p(digest))
	}
	if b.ProtectedOwnerLayer != "" {
		fmt.Fprintf(out, "  Extra protected owner layer: %q.\n", p(b.ProtectedOwnerLayer))
	}
	out.WriteString("  Counts include only recorded refusals. Shared contract membership does not prove unique causation.\n  This record does not authenticate the administrator's mount namespace. Later config edits affect later launches.\n")
}

// BaselineText is shared by the terminal and dashboard, with identical coverage words.
func (rc *Receipt) BaselineText() string {
	var out strings.Builder
	rc.writeBaseline(&out)
	return out.String()
}
