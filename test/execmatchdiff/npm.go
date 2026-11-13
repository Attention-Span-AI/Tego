// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

// NpmValueClass independently ports nopt 5.0.0's token splice and type guard,
// using the released option inventory. It does not read the new Syntax/Opt
// fields or call the current normalizer. The transformed released matcher must
// admit the exact same entry, and every semantic binding must agree both ways.
func NpmValueClass(entry string, tokens []string, readings any) string {
	if words, _, err := old.SplitWords(entry); err != nil || len(words) < 2 || slices.Contains(words[1:], "--") {
		return ""
	}
	variants, changed := npmVariants(tokens)
	if !changed {
		return ""
	}
	if len(variants) == 1 {
		v := variants[0]
		if v.restore.markerOnly {
			return "" // Marker-only allows still need the stripped same-entry certificate.
		}
		if !frozenValueCheck(entry, "npm", v.tokens, v.restore, readings) {
			return ""
		}
	} else {
		if !sameReadings(reflect.ValueOf(readings), npmVariantReadings(variants)) {
			return ""
		}
		for _, v := range variants {
			if !frozenValueCheck(entry, "npm", v.tokens, v.restore, npmVariantReadings([]npmVariant{v})) {
				return ""
			}
		}
		return "npm-optional-value-binding"
	}
	empty := variants[0].restore
	if empty.shorthand {
		return "npm-shorthand-binding"
	}
	if len(empty.raw) > 0 {
		return "npm-leading-dash-binding"
	}
	return "npm-value-binding"
}

// NpmTransform returns a certified frozen-parser token vector. It is also used
// by the complete-facts observer to re-evaluate its entire original rule index.
func NpmTransform(tokens []string, readings any) ([]string, bool) {
	if hasUnlocatable(readings) {
		return nil, false
	}
	canonical, empty, changed := npmCanonical(tokens)
	if !changed {
		return nil, false
	}
	expected := old.NewNormalizer(oldrows.Builtin().Lookup("npm"), nil).Normalize(canonical)
	restoreNpmEmpty(expected, empty)
	return canonical, sameReadings(reflect.ValueOf(readings), expected)
}

type npmRestore struct {
	empty      map[string]string
	raw        map[string]string
	shorthand  bool
	markerOnly bool
}

func npmCanonical(tokens []string) ([]string, npmRestore, bool) {
	row := oldrows.Builtin().Lookup("npm")
	work := slices.Clone(tokens)
	var canonical []string
	empty := npmRestore{empty: map[string]string{}, raw: map[string]string{}}
	changed := false
	expansions := 0
	for i := 0; i < len(work); i++ {
		tok := work[i]
		if len(tok) >= 2 && strings.Trim(tok, "-") == "" {
			canonical = append(canonical, work[i:]...)
			break
		}
		name, value, equals := strings.Cut(tok, "=")
		shortName := strings.TrimLeft(name, "-")
		if len(name) > 1 && name[0] == '-' && npmExactLong(row.Root, shortName) == nil && len(shortName) > 1 {
			var expansion []string
			allSimple := true
			for _, ch := range shortName {
				long, ok := npmSimpleShort(string(ch))
				if !ok {
					allSimple = false
					break
				}
				expansion = append(expansion, "--"+long)
			}
			if allSimple && len(expansion) > 0 {
				expansions += len(expansion)
				if expansions > old.MaxReadings {
					return nil, npmRestore{}, false
				}
				if equals {
					expansion = append(expansion, value)
				}
				work = append(work[:i], append(expansion, work[i+1:]...)...)
				i--
				empty.shorthand = true
				changed = true
				continue
			}
		}
		o := npmOpt(row.Root, name)
		if o == nil {
			canonical = append(canonical, tok)
			continue
		}
		originalRaw := name
		canonicalRaw := name
		if len(name) > 1 && name[0] == '-' && npmExactLong(row.Root, shortName) == nil {
			if long, ok := npmSimpleShort(shortName); ok && len(shortName) == 1 && len(name) > 2 {
				canonicalRaw = "--" + long
				empty.shorthand = true
			}
		}
		if canonicalRaw == name && strings.HasPrefix(name, "---") {
			canonicalRaw = "--" + shortName
		}
		if canonicalRaw != name {
			if previous, ok := empty.raw[canonicalRaw]; ok && previous != originalRaw {
				return nil, npmRestore{}, false
			}
			empty.raw[canonicalRaw] = originalRaw
			name, tok = canonicalRaw, canonicalRaw
			changed = true
		}
		if equals {
			expansions++
			if expansions > old.MaxReadings {
				return nil, npmRestore{}, false
			}
			// Nopt inserts the right-hand token before it applies the option's
			// type rule. A preceding option can already have consumed it whole.
			work = append(work[:i+1], append([]string{value}, work[i+1:]...)...)
			tok = name
			changed = true
		}
		if o.Name == "browser" && i+1 < len(work) && len(work[i+1]) > 1 && work[i+1][0] == '-' {
			next := work[i+1]
			// nopt 5.0.0's Boolean/String branch uses /^-[^-]/, before
			// the exact-String/all-dash guard. Double dashes are consumed.
			if next[1] == '-' {
				canonical = append(canonical, tok+"="+next)
				i++
				changed = true
				continue
			}
			marker := fmt.Sprintf("__execmatch_nopt_empty_%d", len(empty.empty))
			for slices.ContainsFunc(tokens, func(word string) bool { return strings.Contains(word, marker) }) {
				marker += "_"
			}
			empty.empty[marker] = originalRaw
			canonical = append(canonical, "--browser="+marker)
			changed = true
			continue
		}
		if o.Arg == old.ArgRequired && i+1 < len(work) {
			next := work[i+1]
			allDash := len(next) >= 2 && strings.Trim(next, "-") == ""
			optionName := strings.HasPrefix(next, "-") && len(next) > 1 && next[1] != '-' || strings.HasPrefix(next, "--") && len(next) > 2 && next[2] != '-'
			if allDash || o.Arg == old.ArgRequired && npmStringType(o.Name) && optionName {
				marker := fmt.Sprintf("__execmatch_nopt_empty_%d", len(empty.empty))
				for slices.ContainsFunc(tokens, func(tok string) bool { return strings.Contains(tok, marker) }) {
					marker += "_"
				}
				empty.empty[marker] = originalRaw
				canonical = append(canonical, "--"+o.Long[0]+"="+marker)
				changed = true
				continue
			}
			if o.Arg == old.ArgRequired {
				canonical = append(canonical, tok, next)
				i++
				continue
			}
		}
		canonical = append(canonical, tok)
		if o.Arg == old.ArgNone && i+1 < len(work) && (work[i+1] == "true" || work[i+1] == "false") {
			canonical = append(canonical, work[i+1])
			i++
		}
	}
	otherChange := changed
	for i, tok := range canonical {
		if len(tok) >= 2 && strings.Trim(tok, "-") == "" {
			canonical[i] = "--"
			changed = changed || tok != "--"
			break
		}
	}
	empty.markerOnly = changed && !otherChange
	canonical = canonicalMarkers("npm", canonical, row)
	return canonical, empty, changed
}

// NpmRefusalCorrectionClass certifies removal of a released deny/ask false positive.
// The original entry must actually refuse this verb, and the corrected frozen
// reading must produce the requested non-refusal with every binding preserved.
func NpmRefusalCorrectionClass(entry, list string, tokens []string, readings any, outcome, rule string) string {
	if words, _, err := old.SplitWords(entry); err != nil || len(words) < 2 || slices.Contains(words[1:], "--") {
		return ""
	}
	var which old.List
	switch list {
	case "deny":
		which = old.ListDeny
	case "ask":
		which = old.ListAsk
	default:
		return ""
	}
	canonical, ok := NpmTransform(tokens, readings)
	if !ok || outcome == "refused" {
		return ""
	}
	p, err := old.Parse(entry, which, oldrows.Builtin())
	if err != nil {
		return ""
	}
	ix := old.NewIndex(oldrows.Builtin(), []*old.Pattern{p}, old.IndexOptions{})
	f := old.Facts{Requested: "npm", Image: "npm", Argv0: "npm", Argv: append([]string{"npm"}, tokens...), ArgvComplete: true}
	original := ix.Decide(&f)
	if original.Outcome != old.OutcomeRefused || original.Pattern == nil || original.Pattern.Entry != entry {
		return ""
	}
	f.Argv = append([]string{"npm"}, canonical...)
	corrected := ix.Decide(&f)
	if corrected.Outcome.String() == outcome && corrected.Rule() == rule {
		_, restored, _ := npmCanonical(tokens)
		if restored.shorthand {
			return "npm-shorthand-binding"
		}
		if slices.ContainsFunc(tokens, func(tok string) bool { return strings.HasPrefix(tok, "---") && strings.Trim(tok, "-") != "" }) {
			return "npm-leading-dash-binding"
		}
		if slices.Contains(canonical, "--") {
			return "npm-ended-options"
		}
		for _, tok := range canonical {
			if strings.HasPrefix(tok, "--browser=") {
				return "npm-browser-value"
			}
		}
		return "npm-token-splice"
	}
	return ""
}

// ReplaceSuffix replaces only an exact original invocation suffix. The observer
// uses this to retain loader/interpreter facts and all rules in its full index.
func ReplaceSuffix(argv, tokens, replacement []string) ([]string, bool) {
	if len(tokens) == 0 || len(tokens) > len(argv) || !slices.Equal(argv[len(argv)-len(tokens):], tokens) {
		return nil, false
	}
	return append(append([]string(nil), argv[:len(argv)-len(tokens)]...), replacement...), true
}

func restoreNpmEmpty(expected []old.Reading, empty npmRestore) {
	for i := range expected {
		for j := range expected[i].Hits {
			h := &expected[i].Hits[j]
			if raw, ok := empty.empty[h.Value]; ok {
				h.Raw = raw
				h.Value = ""
				h.HasValue = false
			} else if raw, ok := empty.raw[h.Raw]; ok {
				h.Raw = raw
			}
		}
	}
}

func npmExactLong(lv *old.Level, name string) *old.Opt {
	for i := range lv.Opts {
		if slices.Contains(lv.Opts[i].Long, name) {
			return &lv.Opts[i]
		}
	}
	return nil
}

func npmOpt(lv *old.Level, raw string) *old.Opt {
	if !strings.HasPrefix(raw, "-") {
		return nil
	}
	name := strings.TrimLeft(raw, "-")
	if o := npmExactLong(lv, name); o != nil {
		return o
	}
	if long, ok := npmSimpleShort(name); ok {
		return npmExactLong(lv, long)
	}
	if len(raw) == 2 {
		for i := range lv.Opts {
			if strings.Contains(lv.Opts[i].Short, raw[1:]) {
				return &lv.Opts[i]
			}
		}
	}

	var match *old.Opt
	for i := range lv.Opts {
		o := &lv.Opts[i]
		for _, n := range o.Long {
			if strings.HasPrefix(n, name) {
				if match != nil && match != o {
					return nil
				}
				match = o
			}
		}
	}
	return match
}

// NpmStringOption reports the exact String types in the independently frozen
// npm source inventory, for generated spelling coverage.
func NpmStringOption(name string) bool { return npmStringType(name) }

func npmStringType(name string) bool {
	// Exact String (including singleton [String]), read from npm 9.2.0's
	// definitions.js. Nullable unions and numeric/path types are not String.
	return slices.Contains(strings.Fields(`call diff-dst-prefix diff-src-prefix editor git heading init-author-email init-author-name init-license init.author.email init.author.name init.license message pack-destination preid save-prefix scope searchexclude searchopts shell tag tag-version-prefix user-agent viewer`), name)
}

// NpmPatternValueClass independently reads a separator after a value option.
// Its pattern predicates come from frozen nopt bindings, never the new pattern
// compiler; each possible pattern reading must admit every invocation reading.
func NpmPatternValueClass(entry string, tokens []string, readings any) string {
	words, _, err := old.SplitWords(entry)
	if err != nil || len(words) < 2 || !slices.Contains(words[1:], "--") {
		return ""
	}
	pattern := words[1:]
	rest := len(pattern) > 0 && pattern[len(pattern)-1] == "*"
	if rest {
		pattern = pattern[:len(pattern)-1]
	}
	canonical, empty, changed := npmCanonical(pattern)
	if !changed || len(empty.empty) == 0 {
		return ""
	}
	row := oldrows.Builtin().Lookup("npm")
	meanings := old.NewNormalizer(row, nil).Normalize(canonical)
	restoreNpmEmpty(meanings, empty)
	canonical, empty, _ = npmCanonical(tokens)
	expected := old.NewNormalizer(row, nil).Normalize(canonical)
	restoreNpmEmpty(expected, empty)
	if !sameReadings(reflect.ValueOf(readings), expected) {
		return ""
	}
	inv := old.Invocation{Tool: "npm", Row: row, Tokens: tokens, Readings: expected}
	for _, r := range meanings {
		if r.Unlocatable || len(r.Path) == 0 {
			return ""
		}
		p := old.Pattern{Tool: "npm", Row: row, List: old.ListAllow, Path: r.Path, Operands: r.Operands, Rest: rest}
		for _, name := range r.Path {
			if strings.ContainsAny(name, "*?[") {
				return ""
			}
		}
		for _, h := range r.Hits {
			if h.Opt == nil {
				return ""
			}
			p.Opts = append(p.Opts, old.PatOpt{Opt: h.Opt, Raw: h.Raw, Value: h.Value, HasValue: h.HasValue, Neg: h.Neg, Depth: h.Depth})
		}
		if p.Match(&inv) != old.MatchDefinite {
			return ""
		}
	}
	if len(meanings) == 0 {
		return ""
	}
	return "npm-pattern-value"
}

// NpmEndedRootDoesNotMatch independently represents nopt's root marker when its
// first remaining word starts with a dash. The old normalizer cannot spell that
// dispatch, so retain its independently parsed prefix hits and set the literal
// command and opaque operands from nopt's documented argv.remain contract.
func NpmEndedRootDoesNotMatch(entry string, tokens []string, readings any) bool {
	words, _, err := old.SplitWords(entry)
	if err != nil || len(words) < 2 || slices.Contains(words[1:], "--") {
		return false
	}
	canonical, empty, _ := npmCanonical(tokens)
	at := slices.Index(canonical, "--")
	if at < 0 || at+1 >= len(canonical) || !strings.HasPrefix(canonical[at+1], "-") {
		return false
	}
	row := oldrows.Builtin().Lookup("npm")
	expected := old.NewNormalizer(row, nil).Normalize(canonical[:at])
	restoreNpmEmpty(expected, empty)
	for i := range expected {
		r := &expected[i]
		if r.Unlocatable || len(r.Path) != 0 || len(r.Operands) != 0 {
			return false
		}
		r.Path = []string{canonical[at+1]}
		r.Located = true
		r.Operands = slices.Clone(canonical[at+2:])
	}
	if !sameReadings(reflect.ValueOf(readings), expected) {
		return false
	}
	v := reflect.ValueOf(readings)
	for i := 0; i < v.Len(); i++ {
		if v.Index(i).FieldByName("Unlocatable").Bool() {
			return false
		}
	}
	p, err := old.Parse(entry, old.ListDeny, oldrows.Builtin())
	if err != nil || p.Tool != "npm" {
		return false
	}
	inv := old.Invocation{Tool: "npm", Row: row, Tokens: tokens, Readings: expected}
	return p.Match(&inv) == old.MatchNone
}
