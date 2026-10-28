// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Schema names the --json object's version. A field is only ever added within it (docs/user/self-check.md).
const Schema = "tego.selftest/v1"

// The results an Outcome carries.
const (
	// ResultSucceeded is a baseline action that took effect: this machine lets it happen without Tego.
	ResultSucceeded = "succeeded"
	// ResultFailed is a baseline action that did not take effect, so its refusal under Tego would prove nothing.
	ResultFailed = "failed"
	// ResultRefused is an action under Tego that did not take effect and whose run recorded the refusal.
	ResultRefused = "refused"
	// ResultAllowed is an action under Tego that took effect: what the self-check exists to catch.
	ResultAllowed = "allowed"
	// ResultUnrecorded is an action under Tego that did not take effect but whose run recorded no refusal of it.
	ResultUnrecorded = "unrecorded"
	// ResultError is a half tego test could not run or read.
	ResultError = "error"
)

// The verdicts a Report carries, each with its exit code.
const (
	// VerdictPass: every action succeeded directly and was refused, and recorded, under Tego (exit 0).
	VerdictPass = "pass"
	// VerdictFail: at least one action took effect under Tego, or was stopped without a record of it (exit 1).
	VerdictFail = "fail"
	// VerdictInconclusive: no action got through, but at least one could not be judged (exit 125).
	VerdictInconclusive = "inconclusive"
)

// Report is one tego test: the --json object.
type Report struct {
	Schema string `json:"schema"`
	// Tier is the enforcement tier the runs had, from the first run's run_start.
	Tier string `json:"tier"`
	// Actions and Refused count the rows and the rows refused under Tego.
	Actions int    `json:"actions"`
	Refused int    `json:"refused"`
	Verdict string `json:"verdict"`
	// Dir is the temporary tree the checks ran in; it is removed when tego test ends.
	Dir    string `json:"dir"`
	Checks []Row  `json:"checks"`
}

// Row is one action, run directly and under Tego.
type Row struct {
	Name      string  `json:"name"`
	Action    string  `json:"action"`
	Baseline  Outcome `json:"baseline"`
	UnderTego Outcome `json:"under_tego"`
}

// Outcome is one half of a row.
type Outcome struct {
	Result string `json:"result"`
	// Run, Rule, Reason and Target are the run's and its ledger's refusal, under Tego.
	Run    string `json:"run,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
	Target string `json:"target,omitempty"`
	// Match says how the refusal was tied to the check: MatchTarget (it names the check's own target) or MatchReason
	// (no refusal named the target, and this one carries the check's reason). Set on a refused row only.
	Match  string `json:"match,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// The ways a refusal is tied to its check (Outcome.Match).
const (
	// MatchTarget is a refusal whose target is the check's own.
	MatchTarget = "target"
	// MatchReason is a refusal that only carries the check's reason: weaker evidence, which the report says.
	MatchReason = "reason"
)

// judge is the under-Tego half of check c: allowed when the action took effect (the check said so, or its effect is
// there), refused when it did not and the ledger holds the refusal of its target (or, failing an exact target, the
// one refusal with c's reason), unrecorded otherwise.
func judge(c check, t layout, res checkResult, ev runEvents, took bool) Outcome {
	o := Outcome{Run: res.Run, Detail: res.Detail}
	if took {
		o.Result = ResultAllowed
		return o
	}
	target := c.target(t)
	var found *refusal
	match := MatchTarget
	for i := range ev.refused {
		if r := &ev.refused[i]; r.Target == target && target != "" {
			found = r
			break
		}
	}
	if found == nil {
		match = MatchReason
		for i := range ev.refused {
			if r := &ev.refused[i]; r.Reason == c.reason {
				found = r
				break
			}
		}
	}
	if found == nil {
		o.Result = ResultUnrecorded
		return o
	}
	o.Result, o.Rule, o.Reason, o.Target, o.Match = ResultRefused, found.Rule, found.Reason, found.Target, match
	return o
}

// finish counts the rows and sets the verdict.
func (r *Report) finish() {
	r.Actions, r.Refused = len(r.Checks), 0
	fail, unsure := false, false
	for _, row := range r.Checks {
		switch row.UnderTego.Result {
		case ResultRefused:
			r.Refused++
		case ResultAllowed, ResultUnrecorded:
			fail = true
		default:
			unsure = true
		}
		if row.Baseline.Result != ResultSucceeded {
			unsure = true
		}
	}
	switch {
	case fail:
		r.Verdict = VerdictFail
	case unsure:
		r.Verdict = VerdictInconclusive
	default:
		r.Verdict = VerdictPass
	}
}

// ExitCode is the report's exit status (R25): 0 pass, 1 an action got through or went unrecorded, 125 a check that
// could not be judged.
func (r Report) ExitCode() int {
	switch r.Verdict {
	case VerdictPass:
		return identity.ExitOK
	case VerdictFail:
		return identity.ExitFinding
	}
	return identity.ExitError
}

// WriteJSON prints the report as one indented JSON object.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText prints the one-screen report: a headline, a row per action, and what the verdict means.
func (r Report) WriteText(w io.Writer) error {
	var b strings.Builder
	tier := r.Tier
	if tier == "" {
		tier = "unknown"
	}
	fmt.Fprintf(&b, "Tego self-check: %d actions, %d refused at tier %s\n\n", r.Actions, r.Refused, tier)
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ACTION\tWITHOUT TEGO\tUNDER TEGO\tREFUSAL")
	for _, row := range r.Checks {
		rule := ""
		if row.UnderTego.Result == ResultRefused {
			rule = row.UnderTego.Reason + ": " + r.short(row.UnderTego.Rule)
			if row.UnderTego.Rule == "unmatched" {
				rule = row.UnderTego.Reason + ": no entry of the contract allows it"
			}
			if row.UnderTego.Match == MatchReason {
				rule += " (by reason: the record names " + r.short(row.UnderTego.Target) + ")"
			}
		} else if row.UnderTego.Detail != "" {
			rule = r.short(row.UnderTego.Detail)
		}
		base := row.Baseline.Result
		if base != ResultSucceeded && row.Baseline.Detail != "" {
			base += ": " + r.short(row.Baseline.Detail)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", row.Action, base, row.UnderTego.Result, rule)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	b.WriteString("\n")
	switch r.Verdict {
	case VerdictPass:
		b.WriteString("Each action works on this machine without Tego, and Tego refused and recorded every one.\n")
	case VerdictFail:
		b.WriteString("Tego did not refuse every action: a row marked allowed took effect under Tego, and one marked\n" +
			"unrecorded was stopped without a record. Run tego doctor and report it.\n")
	default:
		b.WriteString("Some actions could not be judged (see the rows): a refusal proves nothing when the action\n" +
			"fails without Tego too. Nothing got through.\n")
	}
	b.WriteString("The actions ran on decoys in a temporary folder, removed now, and the four runs' records went there too.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// short is s with the temporary tree's path written <tmp>, so a row fits the screen.
func (r Report) short(s string) string {
	if r.Dir == "" {
		return s
	}
	return strings.ReplaceAll(s, r.Dir, "<tmp>")
}
