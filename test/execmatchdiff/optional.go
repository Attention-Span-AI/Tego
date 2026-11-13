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

type npmVariant struct {
	tokens  []string
	restore npmRestore
}

// npmVariants keeps the actual Boolean/String arm and the conservative valueless
// arm for ordinary browser values after command selection. The released parser
// forks that optional value only before selection, so explicit attached forms
// represent the two alternatives without modifying the frozen parser.
func npmVariants(tokens []string) ([]npmVariant, bool) {
	canonical, restore, changed := npmCanonical(tokens)
	row := oldrows.Builtin().Lookup("npm")
	variants := []npmVariant{{canonical, restore}}
	for i := 0; i < len(canonical); i++ {
		tok := canonical[i]
		if tok == "--" {
			break
		}
		name, _, equals := strings.Cut(tok, "=")
		o := npmOpt(row.Root, name)
		if o == nil || equals {
			continue
		}
		if o.Arg == old.ArgRequired {
			i++ // Canonical required options already have their type boundary encoded.
			continue
		}
		if o.Name != "browser" || i+1 >= len(canonical) || len(canonical[i+1]) > 1 && canonical[i+1][0] == '-' {
			if o.Arg == old.ArgNone && i+1 < len(canonical) && (canonical[i+1] == "true" || canonical[i+1] == "false") {
				i++
			}
			continue
		}
		prefix := old.NewNormalizer(row, nil).NormalizeOpen(canonical[:i], true)
		if len(prefix) != 1 || !prefix[0].Located || prefix[0].UnknownBefore || prefix[0].Unlocatable {
			continue // The frozen parser already keeps both arities before a command.
		}
		if len(variants)*2 > old.MaxReadings {
			return nil, false
		}
		// Stable suffixes identify positions after earlier consuming variants.
		marker := fmt.Sprintf("__execmatch_browser_empty_%d", i)
		for slices.ContainsFunc(canonical, func(word string) bool { return strings.Contains(word, marker) }) {
			marker += "_"
		}
		var next []npmVariant
		for _, v := range variants {
			// Previous expansions are confined to the prefix. Find this browser
			// by the stable remaining suffix, never by a coincidental option value.
			at := len(v.tokens) - (len(canonical) - i)
			if at < 0 || !slices.Equal(v.tokens[at:], canonical[i:]) {
				return nil, false
			}
			flag := npmVariant{tokens: slices.Clone(v.tokens), restore: cloneNpmRestore(v.restore)}
			flag.tokens[at] = name + "=" + marker
			raw := name
			if source, ok := flag.restore.raw[name]; ok {
				raw = source
			}
			flag.restore.empty[marker] = raw
			value := npmVariant{tokens: append(slices.Clone(v.tokens[:at]), name+"="+canonical[i+1]), restore: cloneNpmRestore(v.restore)}
			value.tokens = append(value.tokens, v.tokens[at+2:]...)
			next = append(next, flag, value)
		}
		variants = next
		changed = true
		i++
	}
	return variants, changed
}

func cloneNpmRestore(r npmRestore) npmRestore {
	out := npmRestore{empty: map[string]string{}, raw: map[string]string{}, shorthand: r.shorthand, markerOnly: r.markerOnly}
	for k, v := range r.empty {
		out.empty[k] = v
	}
	for k, v := range r.raw {
		out.raw[k] = v
	}
	return out
}

func npmVariantReadings(variants []npmVariant) []old.Reading {
	var expected []old.Reading
	for _, v := range variants {
		r := old.NewNormalizer(oldrows.Builtin().Lookup("npm"), nil).Normalize(v.tokens)
		restoreNpmEmpty(r, v.restore)
		expected = append(expected, r...)
	}
	return expected
}

// NpmOptionalDoesNotMatch certifies a false command/option predicate against
// every independently derived conservative browser reading. Callers must check
// every old matching authority and preserve the entire remaining released index.
func NpmOptionalDoesNotMatch(entry, list string, tokens []string, readings any) bool {
	which := old.ListDeny
	if list == "ask" {
		which = old.ListAsk
	} else if list != "deny" {
		return false
	}
	variants, changed := npmVariants(tokens)
	if !changed || len(variants) < 2 {
		return false
	}
	expected := npmVariantReadings(variants)
	v := reflect.ValueOf(readings)
	for i := 0; i < v.Len(); i++ {
		if v.Index(i).FieldByName("Unlocatable").Bool() {
			return false
		}
	}
	if !sameReadings(v, expected) {
		return false
	}
	for _, r := range expected {
		if r.Unlocatable {
			return false
		}
	}
	words, _, err := old.SplitWords(entry)
	if err != nil || len(words) < 2 || slices.Contains(words[1:], "--") {
		return false
	}
	p, err := old.Parse(entry, which, oldrows.Builtin())
	if err != nil || p.Tool != "npm" || p.Bare {
		return false
	}
	inv := old.Invocation{Tool: "npm", Row: oldrows.Builtin().Lookup("npm"), Tokens: tokens, Readings: expected}
	return p.Match(&inv) == old.MatchNone
}
