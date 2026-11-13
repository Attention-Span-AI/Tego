// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

import (
	"reflect"
	"slices"
	"sort"
	"strings"

	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

// AllowInvocation is one constrained ordinary interpretation of the same exec.
// The caller must also retain every formerly unlisted released interpretation.
type AllowInvocation struct {
	Tool     string
	Tokens   []string
	Readings any
	Entries  []string
}

// AllowMarkerBindings restricts certificates to invocation separator spellings.
// Every constrained authority must remain independently admitted.
func AllowMarkerBindings(primaryEntry, primaryTool string, complete, final bool, invs []AllowInvocation) string {
	return allowBindings(primaryEntry, primaryTool, complete, final, invs, true)
}

// AllowBindings certifies every constrained interpretation, including those of
// other tools reached through argv0, loaders or interpreters. A valid reading
// cannot hide an unlisted reading of the same exec. Every new admission uses the
// identical entry in the released parser or an independently specified binding.
// An incomplete value-binding change is certified only while the proposed result
// remains nonfinal; it has a separate class and cannot authorize execution.
func AllowBindings(primaryEntry, primaryTool string, complete, final bool, invs []AllowInvocation) string {
	return allowBindings(primaryEntry, primaryTool, complete, final, invs, false)
}

func allowBindings(primaryEntry, primaryTool string, complete, final bool, invs []AllowInvocation, markerOnly bool) string {
	if len(invs) == 0 {
		return ""
	}
	primary := false
	classes := map[string]bool{}
	for _, inv := range invs {
		class := ""
		for _, entry := range inv.Entries {
			candidate := allowBinding(entry, inv.Tool, complete, final, inv.Tokens, inv.Readings)
			if markerOnly && candidate != "" && candidate != "unchanged" {
				candidate = ""
				if class := AllowSpellingClass(entry, inv.Tool, inv.Tokens, inv.Readings); class != "" {
					candidate = "allow-spelling/" + inv.Tool + "/" + class
				}
			}
			if candidate == "" {
				continue
			}
			if inv.Tool == primaryTool && entry == primaryEntry {
				primary = true
			}
			if class == "" {
				class = candidate
			}
		}
		if class == "" {
			return ""
		}
		if class != "unchanged" {
			classes[class] = true
		}
	}
	if !primary {
		return ""
	}
	if len(classes) == 0 {
		return "unchanged"
	}
	names := make([]string, 0, len(classes))
	for class := range classes {
		names = append(names, class)
	}
	sort.Strings(names)
	return strings.Join(names, "+")
}

func allowBinding(entry, tool string, complete, final bool, tokens []string, readings any) string {
	rs := oldrows.Builtin()
	p, err := old.Parse(entry, old.ListAllow, rs)
	if err != nil || p.Tool != tool {
		return ""
	}
	// Semantic signatures omit parse-state flags. A proposed allow must still
	// satisfy the current reading's refusal conditions independently of them.
	if !complete && final && p.NamesArgs() {
		return ""
	}
	v := reflect.ValueOf(readings)
	if v.IsValid() {
		for i := 0; i < v.Len(); i++ {
			r := v.Index(i)
			if final && r.FieldByName("Pending").Bool() {
				return ""
			}
			if !p.Bare && (r.FieldByName("Unlocatable").Bool() || r.FieldByName("UnknownBefore").Bool() || p.NamesArgs() && r.FieldByName("Unknown").Bool()) {
				return ""
			}
		}
	}
	row := rs.Lookup(tool)
	var expected []old.Reading
	if row != nil {
		expected = old.NewNormalizer(row, nil).Normalize(tokens)
	}
	inv := old.Invocation{Tool: tool, Row: row, Tokens: tokens, Readings: expected}
	if (row == nil || sameReadings(reflect.ValueOf(readings), expected)) && p.Match(&inv) == old.MatchDefinite {
		return "unchanged"
	}
	if (complete || !final) && tool == "npm" {
		if class := NpmValueClass(entry, tokens, readings); class != "" {
			if !complete {
				return "held-allow-value/" + class
			}
			return "allow-value/" + class
		}
	}
	if class := PatternSeparatorClass(entry, tool, tokens, readings); class != "" {
		return "pattern-separator/" + class
	}
	if class := AllowSpellingClass(entry, tool, tokens, readings); class != "" {
		return "allow-spelling/" + tool + "/" + class
	}
	return ""
}

// SameInvocation identifies the authority and token vector that supplied a
// released reading. Dispatch routes must not disappear to pass the comparison.
func SameInvocation(tool string, tokens []string, btool string, btokens []string) bool {
	return tool == btool && slices.Equal(tokens, btokens)
}
