// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

// SeparatorPatternDoesNotMatch certifies that a separator entry cannot match
// this complete invocation. It independently translates pattern predicates from
// frozen grammar and the established separator rules; it never reads a current
// Pattern. Callers must check every relevant invocation and the entire index.
func SeparatorPatternDoesNotMatch(entry, tool string, tokens []string, readings any) bool {
	if hasUnlocatable(readings) {
		return false
	}
	words, _, err := old.SplitWords(entry)
	if err != nil || len(words) < 2 || filepath.Base(words[0]) != tool {
		return false
	}
	pattern := words[1:]
	if !slices.Contains(pattern, "--") {
		return false
	}
	row := oldrows.Builtin().Lookup(tool)
	if row == nil {
		return genericSeparatorDoesNotMatch(tool, pattern, tokens)
	}
	if pattern[len(pattern)-1] == "*" {
		pattern = pattern[:len(pattern)-1]
	}
	meanings, ok := separatorReadings(tool, pattern)
	if !ok || len(meanings) == 0 {
		return false
	}
	expected, ok := separatorReadings(tool, tokens)
	if !ok || !sameReadings(reflect.ValueOf(readings), expected) {
		return false
	}
	inv := old.Invocation{Tool: tool, Row: row, Tokens: tokens, Readings: expected}
	for _, r := range meanings {
		if r.Unlocatable || r.Unknown || r.UnknownBefore {
			return false
		}
		p := old.Pattern{Tool: tool, Row: row, List: old.ListDeny, Path: r.Path, Operands: r.Operands}
		for _, name := range r.Path {
			if strings.ContainsAny(name, "*?[") {
				return false
			}
		}
		for _, h := range r.Hits {
			if h.Opt == nil {
				return false
			}
			p.Opts = append(p.Opts, old.PatOpt{Opt: h.Opt, Raw: h.Raw, Value: h.Value, HasValue: h.HasValue, Neg: h.Neg, Depth: h.Depth})
		}
		for _, actual := range expected {
			if actual.Unlocatable {
				return false
			}
			if !r.Located && len(actual.Path) != len(r.Path) {
				continue // This entry ends dispatch at this exact parser level.
			}
			inv.Readings = []old.Reading{actual}
			if p.Match(&inv) != old.MatchNone {
				return false
			}
		}
	}
	return true
}

func separatorReadings(tool string, tokens []string) ([]old.Reading, bool) {
	row := oldrows.Builtin().Lookup(tool)
	if row == nil {
		return nil, false
	}
	work := slices.Clone(tokens)
	var empty npmRestore
	switch tool {
	case "npm":
		work, empty, _ = npmCanonical(work)
	case "go", "pip", "systemctl", "aws":
		work = canonicalMarkers(tool, work, row)
	case "git":
		// Git dispatch stops at --. At a defaulting group, insert that
		// group's declared default first; git stash -- means stash push.
		for at, tok := range work {
			if tok != "--" {
				continue
			}
			prefix := old.NewNormalizer(row, nil).NormalizeOpen(work[:at], true)
			if len(prefix) != 1 || prefix[0].Unlocatable || prefix[0].UnknownBefore {
				return nil, false
			}
			lv := row.Root
			for _, name := range prefix[0].Path {
				if lv == nil {
					break
				}
				lv = lv.Subs[name]
			}
			if lv != nil && lv.Default != "" {
				if len(prefix[0].Path) != 1 || !slices.Contains([]string{"stash", "reflog", "notes"}, prefix[0].Path[0]) {
					return nil, false
				}
				work = append(append(slices.Clone(work[:at]), lv.Default), work[at:]...)
			}
			break
		}
	case "gh": // Cobra's established root -- ends command dispatch, no default.
		if at := slices.Index(tokens, "--"); at >= 0 && !rootMarker(tokens, at, row) {
			return nil, false
		}
	default:
		return nil, false
	}
	if tool == "aws" {
		if at := rootSeparator(tokens, row); at >= 0 {
			root := cloneLevel(row.Root)
			for i := range root.Opts {
				root.Opts[i].Persistent = false
			}
			row = &old.Row{Tool: tool, Root: root}
		}
	}
	out := old.NewNormalizer(row, nil).Normalize(work)
	restoreNpmEmpty(out, empty)
	return out, true
}

// E104 uses the explicit marker's two regions. Without a marker, preconditions
// and post-separator operands independently search the complete token vector.
func genericSeparatorDoesNotMatch(tool string, pattern, tokens []string) bool {
	at := slices.Index(pattern, "--")
	if at < 0 {
		return false
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == "*" {
		pattern = pattern[:len(pattern)-1]
	}
	before, operands := tokens, tokens
	if marker := slices.Index(tokens, "--"); marker >= 0 {
		before, operands = tokens[:marker], tokens[marker+1:]
	}
	entry := tool
	if at > 0 {
		quoted := quotedWords(pattern[:at])
		if quoted == "" {
			return false
		}
		entry += " " + quoted
	}
	p, err := old.Parse(entry, old.ListDeny, oldrows.Builtin())
	if err != nil {
		return false
	}
	inv := old.Invocation{Tool: tool, Tokens: before}
	if p.Match(&inv) == old.MatchNone {
		return true
	}
	wanted := pattern[at+1:]
	j := 0
	for _, tok := range operands {
		if j < len(wanted) && old.Glob(wanted[j], tok) {
			j++
		}
	}
	return j < len(wanted)
}
