// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"slices"
)

// validateDecisionLost checks an exec line's decision_lost (ExecPayload.DecisionLost), raw. It is added at revision 41
// (MinorEveryLaunch), so a ledger below it is refused [below-minor]. The field says the line is the exec's own result and
// nothing more: the call failed with EACCES, its verdict is observed, and no decision record of it was read, so the line
// is refused [decision-lost] when it is anything else (a refused or allowed line, another errno, a mechanism or a
// plane_reason a decision gives, or an argv_facts but the gate's own copied_syscall), or when its list is empty, names a gap outside DecisionLostWhys, is not sorted or
// repeats a gap.
func (e *Event) validateDecisionLost(minor int, raw []byte) error {
	const f = "exec.decision_lost"
	if err := belowMinor(f, true, minor, MinorEveryLaunch); err != nil {
		return err
	}
	var whys []string
	if err := decodeField(f, raw, &whys); err != nil {
		return err
	}
	if len(whys) == 0 {
		return fieldErr("decision-lost", f, "an empty list")
	}
	for i, w := range whys {
		if !slices.Contains(DecisionLostWhys[:], w) {
			return fieldErr("decision-lost", f, "%q is no gap that loses a decision record", w)
		}
		if i > 0 && whys[i-1] >= w {
			return fieldErr("decision-lost", f, "the list is not sorted, or repeats %q", w)
		}
	}
	// The payload is read as a map: the schema refuses a key by its presence, and so does this, so "errno":0 and
	// "mechanism":"" are refused as the schema refuses them (a zero value is no absence).
	var p map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return fieldErr("decision-lost", f, "the payload is not readable: %v", err)
	}
	var ret int64
	if err := json.Unmarshal(p["syscall_ret"], &ret); err != nil || ret != -13 {
		return fieldErr("decision-lost", f, "syscall_ret is not -13 (EACCES)")
	}
	if e.Verdict != VerdictObserved || e.Reason != "" || e.Rule != "unmatched" || e.Source == SourceSeccomp {
		return fieldErr("decision-lost", f, "the line's verdict is %q, rule %q, source %q: a decision was read, or none was lost", e.Verdict, e.Rule, e.Source)
	}
	// An exec a command rule admitted names the rule and, as the gate's own fact, that its decision read the supervisor's
	// copy of argv (ArgvFactsCopied): that is no plane decision, so the line may carry it, and the command_* fields (the
	// rule's name, list and match) beside it. kernel_pinned and unproven are the plane's: a line with them is a decision.
	// The other keys are a decision's or a kill's or the pin step's (spec: none of them is written beside the field).
	for _, k := range []string{"mechanism", "plane_reason", "decision_plane", "signal", "errno", "by",
		"detected_bypass", "kill_failed", "argv_decided", "pin_unavailable"} {
		if _, ok := p[k]; ok {
			return fieldErr("decision-lost", f, "the line carries %s, a decision's own field", k)
		}
	}
	if raw, ok := p["argv_facts"]; ok {
		var facts string
		if err := json.Unmarshal(raw, &facts); err != nil || facts != ArgvFactsCopied {
			return fieldErr("decision-lost", f, "the line carries argv_facts other than %s", ArgvFactsCopied)
		}
	}
	return nil
}
