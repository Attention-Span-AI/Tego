// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Model-step groups on a run's timeline. The record ties an action to a model step by the writer's own counting of
// model turns (record.Event.ModelStep); this file only says that in words and starts a new group where the step of
// consecutive rows changes. It never joins a step number to one ssl_request line and never says a step caused an
// action: retries and side traffic break that count, and the method says how sure the tie is.

// Words of a group's header.
const (
	stepFolded  = "Repeated lines, folded (steps may differ)"
	stepNotTied = "Not tied to a model step"
)

// StepKeyOf is the group a line belongs to and the words of its header. A line that carries no attribution at all
// (a kind that never does: ask, answer, gap, a standalone refusal, run_start, run_end ...) is tied to no step, which
// is what ModelStep says of it, so it belongs to the group "none": it never sits under the header of a step it has no
// tie to. Every header on a tied line says "likely": the record writes that confidence for every method.
func StepKeyOf(e *Event) (key, words string) {
	if e.StepMethod == "" {
		return "none", stepNotTied
	}
	step, tied := e.ModelStep()
	if !tied {
		return "none", stepNotTied
	}
	n := strconv.Itoa(step)
	key = n + "/" + e.StepMethod
	switch {
	case e.StepMethod == record.MethodTime && step > 0:
		return key, "After model request " + n + ", matched by time (likely)"
	case e.StepMethod == record.MethodTime:
		// The spec's {likely, time, step 0}: said as the record says it, with no claim about what came before.
		return key, "Step 0, matched by time (likely)"
	}
	return key, "Model step " + n + " (likely)"
}

// GroupSteps sets StepKey on every row of rows (a page of a timeline, newest first) and StepHead on the first row of
// each run of consecutive rows of one group, so the work is one pass over the page and never over the ledger. It sets
// nothing when the run has no line the record ties to a step (a run with no model capture): there the headers would
// all say "not tied" and carry no information. A line the record ties to no step is in the group "none" and closes
// the group around it. A row that stands for several folded lines (Count above 1) can span steps, so it is in the
// group "folded", with no step to link to, and closes the group around it too.
func GroupSteps(rows []Row, run *Run) {
	if run == nil || run.StepLines == 0 {
		return
	}
	open := ""
	for i := range rows {
		r := &rows[i]
		key, words := StepFolded, stepFolded
		if r.Count <= 1 {
			key, words = StepKeyOf(&r.Event)
		}
		r.StepKey = key
		if key != open {
			r.StepHead, open = words, key
		}
	}
}

// StepFolded is the StepKey of a folded row.
const StepFolded = "folded"
