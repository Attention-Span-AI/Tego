// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"iter"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Count adds the hits of a run's ledger lines to the view: rules yields the rule field of each line, "" for a line
// with none. A line counts once for every rule whose RuleKey or Covers names it, so two rules that one compiled rule
// stands for (an exec.allow entry and the command it repeats) each show it; a line no rule names and whose rule is
// "unmatched" counts in Unmatched. Count adds to what an earlier call counted.
func (v *View) Count(rules iter.Seq[string]) {
	index := map[string][]*Rule{}
	for gi := range v.Groups {
		g := &v.Groups[gi]
		for ri := range g.Rules {
			r := &g.Rules[ri]
			if r.RuleKey != "" {
				index[r.RuleKey] = append(index[r.RuleKey], r)
			}
			for _, k := range r.Covers {
				index[k] = append(index[k], r)
			}
		}
	}
	for rule := range rules {
		if rule == "" {
			continue
		}
		if rs, ok := index[rule]; ok {
			for _, r := range rs {
				r.Hits++
			}
			continue
		}
		if rule == "unmatched" {
			v.Unmatched++
		}
	}
}

// CountEvents is Count over decoded ledger events.
func (v *View) CountEvents(events []record.Event) {
	v.Count(func(yield func(string) bool) {
		for i := range events {
			if !yield(events[i].Rule) {
				return
			}
		}
	})
}
