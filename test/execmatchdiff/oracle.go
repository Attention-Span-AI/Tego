// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"

	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

// Signature compares semantic bindings, without pointer identity or token offsets.
// The two matcher packages deliberately have distinct Go types.
func Signature(reading any) string {
	v := reflect.ValueOf(reading)
	var hits []any
	for i := 0; i < v.FieldByName("Hits").Len(); i++ {
		h := v.FieldByName("Hits").Index(i)
		name := ""
		if o := h.FieldByName("Opt"); !o.IsNil() {
			name = o.Elem().FieldByName("Name").String()
		}
		hits = append(hits, []any{name, h.FieldByName("Raw").String(), h.FieldByName("Value").String(), h.FieldByName("HasValue").Bool(), h.FieldByName("Neg").Bool(), h.FieldByName("Depth").Int()})
	}
	data, err := json.Marshal([]any{v.FieldByName("Path").Interface(), hits, v.FieldByName("Operands").Interface()})
	if err != nil {
		panic(err) // The signature consists only of strings, bools, integers and slices.
	}
	return string(data)
}

// AllowSpelling is the independent exception oracle. Deleting a marker must name
// the identical allow entry in the released matcher, and preserve all semantic
// bindings. AWS additionally loses the main parser's globals below a root marker;
// a second, frozen reading prevents a shared wrong binding from blessing itself.
func AllowSpelling(entry, tool string, tokens []string, readings any) bool {
	return AllowSpellingClass(entry, tool, tokens, readings) != ""
}

// AllowSpellingClass distinguishes identical bindings from a verified parser
// which has ended option processing. Both must pass the stripped released allow.
func AllowSpellingClass(entry, tool string, tokens []string, readings any) string {
	switch tool {
	case "systemctl", "npm", "go", "pip", "aws":
	default:
		return ""
	}
	var markers []int
	for i, tok := range tokens {
		if tok == "--" || tool == "npm" && len(tok) > 2 && strings.Trim(tok, "-") == "" {
			markers = append(markers, i)
		}
	}
	if len(markers) == 0 || len(markers) > 8 {
		return ""
	}
	rs := oldrows.Builtin()
	p, err := old.Parse(entry, old.ListAllow, rs)
	if err != nil {
		return ""
	}
	ix := old.NewIndex(rs, []*old.Pattern{p}, old.IndexOptions{})
	v := reflect.ValueOf(readings)
	rootAt := -1
	for _, at := range markers {
		if rootMarker(tokens, at, rs.Lookup(tool)) {
			rootAt = at
			break
		}
	}
	for mask := 1; mask < 1<<len(markers); mask++ {
		var plain []string
		for i, tok := range tokens {
			if at := slices.Index(markers, i); at >= 0 && mask&(1<<at) != 0 {
				continue
			}
			plain = append(plain, tok)
		}
		f := old.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: append([]string{tool}, plain...), ArgvComplete: true}
		b := ix.Decide(&f)
		if b.Outcome != old.OutcomeAllowed || b.Pattern == nil || b.Pattern.Entry != entry {
			continue
		}
		br := old.NewNormalizer(rs.Lookup(tool), nil).Normalize(plain)
		all := sameReadings(v, br)
		if tool == "aws" && rootAt >= 0 {
			root := cloneLevel(rs.Lookup(tool).Root)
			for i := range root.Opts {
				root.Opts[i].Persistent = false
			}
			// The service parser never owns main-parser globals. A fresh frozen
			// grammar must admit this same entry with every binding preserved.
			rr := &old.Row{Tool: tool, Root: root}
			independent := old.NewNormalizer(rr, nil).Normalize(plain)
			// Keep original pattern semantics: it may name a main-parser
			// global after the verb, but the actual hit must remain before --.
			inv := old.Invocation{Tool: tool, Row: p.Row, Tokens: plain, Readings: independent}
			if !sameReadings(v, independent) || p.Match(&inv) != old.MatchDefinite {
				all = false
			} else if !all {
				return "child-vocabulary"
			}
		}
		if all {
			return "identical-binding"
		}
		// nopt and getopt stop reading options at their root marker; pip retains
		// its marker in the child argv after removing the command word. Reinsert
		// the marker after the selected verb for the released parser, whose
		// command-position handling predates this fix. This independent reading
		// must agree on every path, option hit and operand, not just the verb.
		if (tool == "npm" || tool == "systemctl" || tool == "pip") && rootAt >= 0 {
			at := rootAt
			if at+1 >= len(tokens) || strings.HasPrefix(tokens[at+1], "-") {
				continue
			}
			independent := append([]string(nil), tokens[:at]...)
			independent = append(independent, tokens[at+1], "--")
			independent = append(independent, tokens[at+2:]...)
			if sameReadings(v, old.NewNormalizer(rs.Lookup(tool), nil).Normalize(independent)) {
				return "ended-options"
			}
		}
	}
	return ""
}

func sameReadings(v reflect.Value, expected []old.Reading) bool {
	if v.Len() == 0 {
		return false
	}
	for i := 0; i < v.Len(); i++ {
		if !slices.ContainsFunc(expected, func(r old.Reading) bool { return Signature(r) == Signature(v.Index(i).Interface()) }) {
			return false
		}
	}
	for _, r := range expected {
		found := false
		for i := 0; i < v.Len(); i++ {
			if Signature(r) == Signature(v.Index(i).Interface()) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// PatternSeparatorClass checks the separately specified pattern-side separator
// correction. Generic words use an independent literal-prefix check. Established
// command parsers use an equivalent pattern in the released grammar, and every
// invocation binding must agree with that frozen reading.
func PatternSeparatorClass(entry, tool string, tokens []string, readings any) string {
	words, _, err := old.SplitWords(entry)
	if err != nil || len(words) < 2 {
		return ""
	}
	pattern := words[1:]
	at := slices.Index(pattern, "--")
	if at < 0 {
		return ""
	}
	row := oldrows.Builtin().Lookup(tool)
	if row == nil {
		// An invocation may omit the marker at precisely the pattern boundary.
		// Later markers and dash words are literal operands.
		plain := append([]string(nil), tokens...)
		if at < len(plain) && plain[at] == "--" {
			plain = append(plain[:at], plain[at+1:]...)
		}
		wanted := append(append([]string(nil), pattern[:at]...), pattern[at+1:]...)
		if len(wanted) > 0 && wanted[len(wanted)-1] == "*" {
			wanted = wanted[:len(wanted)-1]
		}
		if len(plain) < len(wanted) {
			return ""
		}
		for i, w := range wanted {
			if !old.Glob(w, plain[i]) {
				return ""
			}
		}
		return "generic"
	}
	switch tool {
	case "systemctl", "npm", "go", "pip", "aws":
	default:
		return ""
	}
	if tool == "npm" {
		if class := NpmPatternValueClass(entry, tokens, readings); class != "" {
			return class
		}
	}
	equivalent := canonicalMarkers(tool, pattern, row)
	if slices.Equal(equivalent, pattern) {
		return ""
	}
	if tool == "aws" && rootSeparator(pattern, row) >= 0 {
		br := old.NewNormalizer(row, nil).Normalize(equivalent)
		if len(br) == 0 || !awsGlobalsSafe(row, equivalent, br) {
			return ""
		}
	}
	quoted := quotedWords(equivalent)
	if quoted == "" && len(equivalent) > 0 {
		return ""
	}
	plainEntry := words[0] + " " + quoted
	p, err := old.Parse(plainEntry, old.ListAllow, oldrows.Builtin())
	if err != nil {
		return ""
	}
	plainTokens := canonicalMarkers(tool, tokens, row)
	ix := old.NewIndex(oldrows.Builtin(), []*old.Pattern{p}, old.IndexOptions{})
	f := old.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: append([]string{tool}, plainTokens...), ArgvComplete: true}
	if got := ix.Decide(&f); got.Outcome != old.OutcomeAllowed || got.Pattern == nil || got.Pattern.Entry != plainEntry {
		return ""
	}
	if sameReadings(reflect.ValueOf(readings), old.NewNormalizer(row, nil).Normalize(plainTokens)) {
		return tool
	}
	return ""
}

func quotedWords(words []string) string {
	// JSON's quotes are also the pattern grammar's literal double quotes for
	// these generated tokens. Reject quotes/backslashes rather than reinterpret.
	for _, w := range words {
		if strings.ContainsAny(w, "\"'\\\n\r\t ") {
			return ""
		}
	}
	return strings.Join(words, " ")
}

func canonicalMarkers(tool string, tokens []string, row *old.Row) []string {
	at := rootSeparator(tokens, row)
	if at < 0 || at+1 >= len(tokens) {
		return tokens
	}
	if strings.HasPrefix(tokens[at+1], "-") {
		return tokens
	}
	plain := append([]string(nil), tokens[:at]...)
	plain = append(plain, tokens[at+1])
	if tool == "npm" || tool == "systemctl" || tool == "pip" {
		plain = append(plain, "--")
	}
	plain = append(plain, tokens[at+2:]...)
	return plain
}

func awsGlobalsSafe(row *old.Row, tokens []string, expected []old.Reading) bool {
	root := cloneLevel(row.Root)
	for i := range root.Opts {
		root.Opts[i].Persistent = false
	}
	independent := old.NewNormalizer(&old.Row{Tool: row.Tool, Root: root}, nil).Normalize(tokens)
	for _, r := range independent {
		if r.Unlocatable {
			return false
		}
	}
	return len(independent) > 0 && sameReadings(reflect.ValueOf(expected), independent)
}

// rootSeparator skips literal markers consumed as known option values. This
// distinction matters when a later marker actually ends the root parser.
func rootSeparator(tokens []string, row *old.Row) int {
	for at, tok := range tokens {
		if tok == "--" && rootMarker(tokens, at, row) {
			return at
		}
	}
	return -1
}

func rootMarker(tokens []string, at int, row *old.Row) bool {
	nz := old.NewNormalizer(row, nil)
	before := nz.NormalizeOpen(tokens[:at], true)
	probe := append(slices.Clone(tokens[:at]), "--")
	after := nz.NormalizeOpen(probe, true)
	for _, r := range before {
		if len(r.Path) != 0 || r.Unlocatable {
			continue
		}
		for _, ended := range after {
			// A real root separator preserves bindings; a required value
			// instead changes the preceding option's value/presence.
			if !ended.Unlocatable && Signature(r) == Signature(ended) {
				return true
			}
		}
	}
	return false
}

func cloneLevel(lv *old.Level) *old.Level {
	if lv == nil {
		return nil
	}
	x := &old.Level{Opts: append([]old.Opt(nil), lv.Opts...), Alias: lv.Alias, Skip: lv.Skip, SkipPrefix: lv.SkipPrefix, Fold: lv.Fold, SubPrefix: lv.SubPrefix, Syntax: lv.Syntax, Default: lv.Default}
	if lv.Subs != nil {
		x.Subs = make(map[string]*old.Level, len(lv.Subs))
		for n, child := range lv.Subs {
			x.Subs[n] = cloneLevel(child)
		}
	}
	x.Wild = cloneLevel(lv.Wild)
	return x
}

// hasUnlocatable keeps refusal-state flags out of spelling certificates. Binding
// signatures alone cannot prove a current unresolved reading may be admitted.
func hasUnlocatable(readings any) bool {
	v := reflect.ValueOf(readings)
	if !v.IsValid() {
		return false
	}
	for i := 0; i < v.Len(); i++ {
		if v.Index(i).FieldByName("Unlocatable").Bool() {
			return true
		}
	}
	return false
}
