// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
)

// A change's direction is the compiled comparison's: both texts are compiled and agentdiff orders each family of the
// two tables. The edit core's lexical model (internal/check/rule direction.go) words the change ("Asks you before it
// reads X") but does not decide which way it moves what the next run may do: it follows no profile, glob or link, and
// it must never show a looser rule as tighter. Only a test compiler (Service.Compile, Service.Check), which returns
// no table, leaves the lexical direction in place.

// keyFamilies are the compiled families an edited list's words are about, for the direction of one sentence.
var keyFamilies = map[string][]string{
	"fs.write":      {"filesystem", "filesystem approvals", "filesystem protection"},
	"fs.deny_read":  {"filesystem", "filesystem approvals", "filesystem protection"},
	"fs.ask_read":   {"filesystem", "filesystem approvals", "filesystem protection", "approval configuration"},
	"fs.ask":        {"filesystem", "filesystem approvals", "filesystem protection", "approval configuration"},
	"fs.deny_write": {"filesystem", "filesystem approvals", "filesystem protection"},
	// An exec.allow entry with words ("git status") is a command rule: it changes the program arguments' family too.
	"exec.allow": {"programs", "program arguments"},
	"net.allow":  {"destinations"},
	"net.ask":    {"destination approvals", "approval configuration"},
}

// compiledDirection is rows' one direction as the editor's word, and the sentence that says what decided it: the
// families that changed, each with the way it moved.
func compiledDirection(rows []agentdiff.Result) (rule.Direction, string) {
	d, _ := agentdiff.Fold(rows)
	var parts []string
	for _, r := range rows {
		switch r.Direction {
		case agentdiff.Narrowed:
			parts = append(parts, r.Family+" narrowed")
		case agentdiff.Widened:
			parts = append(parts, r.Family+" widened")
		case agentdiff.CannotClassify:
			parts = append(parts, r.Family+" changed and cannot be ordered")
		case agentdiff.Unchanged:
		}
	}
	why := "the compiled contract before and after: "
	if len(parts) == 0 {
		why += "nothing it allows changed"
	} else {
		why += strings.Join(parts, ", ")
	}
	return rule.Direction(d), why
}

// sentenceDirection is the direction of one sentence about the list key: the compiled families that list's words are
// about, folded alone, and never narrowing while any family of the change cannot be ordered: a sentence agrees with the
// overall direction, so the sentence naming an entry never says "narrows" beside a change the comparison calls mixed.
// A key no family is known for is mixed: it is never called narrowing without a comparison.
func sentenceDirection(rows []agentdiff.Result, key string) rule.Direction {
	fams, ok := keyFamilies[key]
	if !ok {
		return rule.Mixed
	}
	var own []agentdiff.Result
	for _, r := range rows {
		if slices.Contains(fams, r.Family) {
			own = append(own, r)
		}
	}
	d, _ := agentdiff.Fold(own)
	if d == agentdiff.OverallNarrows && hasUnordered(rows) {
		return rule.Mixed
	}
	return rule.Direction(d)
}

// hasUnordered says some family changed that the comparison cannot order.
func hasUnordered(rows []agentdiff.Result) bool {
	return slices.ContainsFunc(rows, func(r agentdiff.Result) bool { return r.Direction == agentdiff.CannotClassify })
}

// noChangeWords is a sentence whose change compiled to the same tables: the entry the text names went, and what it
// granted or refused is still granted or refused by another entry, such as one in a profile the contract extends.
const noChangeWords = "No change: the compiled contract allows the same, because another entry (for example one in a profile it extends) still covers it. If that entry goes, this access goes with it, and this contract no longer says it"

// sentenceUnchanged says every compiled family the list's words are about came out equal.
func sentenceUnchanged(rows []agentdiff.Result, key string) bool {
	fams, ok := keyFamilies[key]
	if !ok || hasUnordered(rows) {
		return false
	}
	seen := false
	for _, r := range rows {
		if slices.Contains(fams, r.Family) {
			seen = true
			if r.Direction != agentdiff.Unchanged {
				return false
			}
		}
	}
	return seen
}
