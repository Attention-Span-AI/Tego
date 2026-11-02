// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"iter"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Count adds the hits of a run's ledger lines to the view: rules yields the rule field of each line, "" for a line
// with none. A line counts once for every rule whose RuleKey or Covers names it, so every program entry that
// resolved to one file (cat and its path, python3 and the python3.13 it links to, "git status" and "git diff")
// shows it, every entry of a tool shows the lines of the helper images compile granted it (git's exec-path git,
// which an allowed git commit re-runs), and a script command's row the lines of the interpreter its #! line was
// granted; a line no rule names and whose rule is "unmatched" counts in Unmatched. A constrained tool's unlisted
// invocation (exec.args[git]) names no entry and counts nowhere. Count adds to what an earlier call counted.
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
		if rule == unmatched {
			v.Unmatched++
		}
	}
}

// unmatched is the rule of a ledger line no rule named (spec/record/v1: "the declared entry or unmatched").
const unmatched = "unmatched"

// CountDefault adds n ledger lines of kind whose rule is "unmatched" to the default of the group whose DefaultKind is
// kind: Count counts each such line in Unmatched, and this says which group's default decided it. A kind no group's
// default speaks for (a file line, a refusal line, a model tool's) stays in Unmatched alone. CountDefault adds to what
// an earlier call counted.
func (v *View) CountDefault(kind string, n int) {
	for i := range v.Groups {
		if g := &v.Groups[i]; kind != "" && g.DefaultKind == kind {
			g.DefaultHits += n
		}
	}
}

// CountEvents is Count over decoded ledger events, with each unmatched line's kind given to CountDefault.
func (v *View) CountEvents(events []record.Event) {
	v.Count(func(yield func(string) bool) {
		for i := range events {
			if !yield(events[i].Rule) {
				return
			}
		}
	})
	for i := range events {
		if events[i].Rule == unmatched {
			v.CountDefault(string(events[i].Kind), 1)
		}
	}
}
