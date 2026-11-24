// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
)

// FamilyChange is one compiled family the contract's change moved, said in words: the preview's projection of the
// compared families (agentdiff.Compare). A change is worded from the whole comparison, so a rule family the edit
// form has no sentence for (a limit, an approval setting, a program's arguments) and every family a whole-text edit
// touches are named, each with the direction the comparison ordered it in.
type FamilyChange struct {
	// Family is the comparison's name for it; Words says what happens to what the agent can do.
	Family, Words string
	// Direction is narrows, widens or mixed: mixed is a family the comparison cannot order, never narrowing.
	Direction string
}

// maxNamedGrants bounds how many newly allowed names one family's words list.
const maxNamedGrants = 4

// familyLabels say what each compared family is about, in the words the rest of the page uses.
var familyLabels = map[string]string{
	"filesystem":              "Files it may change",
	"filesystem approvals":    "Files it asks you before changing",
	"filesystem protection":   "Files it may not read or change",
	"programs":                "Programs it may run",
	"program arguments":       "The arguments a program may run with",
	"destinations":            "Places it may connect to",
	"destination approvals":   "Places it asks you before connecting to",
	"environment":             "Environment variables it receives",
	"environment assignments": "Environment values set for it",
	"run limits":              "Limits on a run",
	"network limits":          "Limits on its network use",
	"approval configuration":  "How Tego asks you",
	"credentials":             "Credentials Tego adds to its requests",
	"read recording":          "Recording of the reads it is refused",
	"process privileges":      "Special permissions of the agent's processes",
	"business rules":          "Business rules",
}

// familyLabel is the words for a family, its own name capitalised for a family not listed above.
func familyLabel(family string) string {
	if l, ok := familyLabels[family]; ok {
		return l
	}
	if family == "" {
		return "Another setting"
	}
	return strings.ToUpper(family[:1]) + family[1:]
}

// familyChanges is every family of rows that changed, in the comparison's order. A family the comparison cannot order
// says so and is mixed; one it narrowed says the next run may do less, and one it widened says the next run may do
// more and, where the comparison names them, what it may now do.
func familyChanges(rows []agentdiff.Result) []FamilyChange {
	var out []FamilyChange
	for _, r := range rows {
		label := familyLabel(r.Family)
		switch r.Direction {
		case agentdiff.Narrowed:
			out = append(out, FamilyChange{Family: r.Family, Direction: string(rule.Narrows),
				Words: label + ": the next run may do less than before"})
		case agentdiff.Widened:
			w := label + ": the next run may do more than before"
			if n := len(r.NewlyAllowed); n > 0 {
				shown := r.NewlyAllowed
				if n > maxNamedGrants {
					shown = shown[:maxNamedGrants]
				}
				w += " (" + joinWords(shown, "; ")
				if n > maxNamedGrants {
					w += "; and more, listed under This will newly allow"
				}
				w += ")"
			}
			out = append(out, FamilyChange{Family: r.Family, Direction: string(rule.Widens), Words: w})
		case agentdiff.CannotClassify:
			out = append(out, FamilyChange{Family: r.Family, Direction: string(rule.Mixed),
				Words: label + ": changed, and Tego cannot tell whether the next run may do more"})
		case agentdiff.Unchanged:
		}
	}
	return out
}

// familySummary is the changed families in one line for a journal: "filesystem narrowed, destinations widened". No change in any compared family says so.
func familySummary(fs []FamilyChange) string {
	if len(fs) == 0 {
		return "nothing the compiled contract allows changed"
	}
	parts := make([]string, len(fs))
	for i, f := range fs {
		switch f.Direction {
		case string(rule.Narrows):
			parts[i] = f.Family + " narrowed"
		case string(rule.Widens):
			parts[i] = f.Family + " widened"
		default:
			parts[i] = f.Family + " changed (cannot be ordered)"
		}
	}
	return joinWords(parts, ", ")
}

// joinWords is items one after another with sep between them; it is words, never a path.
func joinWords(items []string, sep string) string {
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(it)
	}
	return b.String()
}
