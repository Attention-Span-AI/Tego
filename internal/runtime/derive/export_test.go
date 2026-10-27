// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// AttributeByTime is Steps.byTime's rule (whose doc is the contract) over a snapshot of the per-thread states:
// the tests' oracle for the counts byTime keeps.
func AttributeByTime(states map[string]StepState, ev *record.Event) record.Attribution {
	unattributed := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	if ev != nil && ev.Attr != nil && richerThanTime(ev.Attr.Method) {
		return *ev.Attr
	}
	if len(states) == 0 {
		return unattributed
	}
	var inflight, withStep []string
	for thread, st := range states {
		if st.Step == 0 {
			continue
		}
		withStep = append(withStep, thread)
		if st.InFlight {
			inflight = append(inflight, thread)
		}
	}
	slices.Sort(inflight)
	slices.Sort(withStep)
	switch {
	case len(inflight) == 1:
		return *record.AttributedByTime(inflight[0], states[inflight[0]].Step)
	case len(inflight) > 1:
		return unattributed
	case len(withStep) == 1:
		return *record.AttributedByTime(withStep[0], states[withStep[0]].Step)
	default:
		return unattributed
	}
}

// MaxRetired and MaxTouched are the bounds of the retired threads Steps remembers and of the threads one epoch keeps
// rule (1)'s earlier answer for, which the bound tests reach past.
const (
	MaxRetired = maxRetired
	MaxTouched = maxTouched
)
