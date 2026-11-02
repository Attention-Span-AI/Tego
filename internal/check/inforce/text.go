// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"fmt"
	"strings"
)

// Text is the view as plain text, the form `tego rules` prints: each group's title and lede, one line per rule (its
// sentence, then how it is enforced, where it came from and its hits), and the group's default with the hits it
// decided. A group with no rule and no default is left out.
func (v *View) Text() string {
	var b strings.Builder
	name := v.Agent
	if name == "" {
		name = "this agent"
	}
	fmt.Fprintf(&b, "Rules in force for %s\n", name)
	if v.ContractPath != "" {
		fmt.Fprintf(&b, "File: %s\n", v.ContractPath)
	}
	if v.Tier != "" {
		fmt.Fprintf(&b, "Tier: %s\n", v.Tier)
	}
	for _, n := range v.Notes {
		fmt.Fprintf(&b, "Note: %s\n", n)
	}
	for _, g := range v.Groups {
		if len(g.Rules) == 0 && g.Default == "" {
			continue
		}
		fmt.Fprintf(&b, "\n%s: %s\n", g.Title, g.Lede)
		for _, r := range g.Rules {
			meta := []string{}
			if r.EnforcedText != "" {
				meta = append(meta, r.EnforcedText)
			}
			meta = append(meta, where(r.Source))
			if r.Editable {
				meta = append(meta, "editable")
			}
			if r.Hits > 0 {
				meta = append(meta, fmt.Sprintf("%d hits", r.Hits))
			}
			fmt.Fprintf(&b, "  - %s  [%s]\n", r.Sentence, strings.Join(meta, "; "))
		}
		switch {
		case g.Default != "" && g.DefaultHits > 0:
			fmt.Fprintf(&b, "  %s  [%d hits]\n", g.Default, g.DefaultHits)
		case g.Default != "":
			fmt.Fprintf(&b, "  %s\n", g.Default)
		}
	}
	if v.Unmatched > 0 {
		fmt.Fprintf(&b, "\n%d lines were decided by the defaults.\n", v.Unmatched)
	}
	return b.String()
}

// where says a rule's source: "line 12", "profile <file> line 3", "built in".
func where(s Source) string {
	switch s.Origin {
	case OriginContract:
		if s.Line > 0 {
			return fmt.Sprintf("line %d", s.Line)
		}
		return "contract"
	case OriginProfile:
		if s.Line > 0 {
			return fmt.Sprintf("profile %s line %d", s.File, s.Line)
		}
		return "profile " + s.File
	}
	return s.Origin
}
