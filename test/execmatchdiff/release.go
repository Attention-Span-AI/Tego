// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

import (
	"fmt"
	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
	"reflect"
	"slices"
)

// ReleasedRefuses evaluates a single entry using the byte-verified released
// matcher, for conservative compatibility controls in the package tests.
func ReleasedRefuses(entry, list string, argv []string) bool {
	kind := old.ListAllow
	switch list {
	case "deny":
		kind = old.ListDeny
	case "ask":
		kind = old.ListAsk
	}
	rs := oldrows.Builtin()
	p, err := old.Parse(entry, kind, rs)
	if err != nil {
		return true
	}
	f := old.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: true}
	return old.NewIndex(rs, []*old.Pattern{p}, old.IndexOptions{}).Decide(&f).Outcome == old.OutcomeRefused
}

// CheckSourceCase compares one original contract input, including compile
// refusals. It preserves the eight explicitly named invalid-entry exceptions.
// Facts and current results use public fields copied across the frozen types.
func CheckSourceCase(entry string, list uint8, facts any, identity string, candidates, exact []string, valid bool, outcome uint8, final bool, decidingList uint8) (string, error) {
	var f old.Facts
	copyReleaseValue(reflect.ValueOf(&f).Elem(), reflect.ValueOf(facts))
	rs := oldrows.Builtin()
	var p *old.Pattern
	var err error
	if exact != nil {
		p = old.ExactPattern("hook", entry, exact)
	} else {
		p, err = old.Parse(entry, old.List(list), rs)
	}
	if !valid {
		return "compile-refusal", nil
	}
	if err != nil {
		if entry == "git add --no-f" && list == uint8(old.ListAllow) && outcome == uint8(old.OutcomeAllowed) && len(f.Argv) == 3 && f.Argv[0] == "git" && f.Argv[1] == "add" && slices.Contains([]string{"--no-f", "--no-force", "--no-f=true", "--no-force=true"}, f.Argv[2]) {
			return "named-invalid-allow-key", nil
		}
		if outcome != uint8(old.OutcomeRefused) {
			return "", fmt.Errorf("unapproved admission from released-invalid entry %q", entry)
		}
		return "retained-refusal", nil
	}
	opts := old.IndexOptions{}
	if identity != "" {
		opts.Identities = map[old.ID]string{{Dev: 1, Ino: 2}: identity}
	}
	if candidates != nil {
		opts.Candidates = old.NewCandidates(candidates, rs.Lookup("git").Common)
	}
	b := old.NewIndex(rs, []*old.Pattern{p}, opts).Decide(&f)
	before := DecisionState{Outcome: b.Outcome.String(), List: b.List.String(), Final: b.Final}
	after := DecisionState{Outcome: old.Outcome(outcome).String(), List: old.List(decidingList).String(), Final: final}
	if PotentialLoosening(before, after) {
		return "", fmt.Errorf("source contract %q lost released refusal/finality: before=%+v after=%+v", entry, b, after)
	}
	return "retained-or-tighter", nil
}

func copyReleaseValue(dst, src reflect.Value) {
	switch dst.Kind() {
	case reflect.Pointer:
		if !src.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
			copyReleaseValue(dst.Elem(), src.Elem())
		}
	case reflect.Struct:
		for i := 0; i < dst.NumField(); i++ {
			if dst.Type().Field(i).IsExported() {
				v := src.FieldByName(dst.Type().Field(i).Name)
				if v.IsValid() {
					copyReleaseValue(dst.Field(i), v)
				}
			}
		}
	case reflect.Slice:
		if !src.IsNil() {
			dst.Set(reflect.MakeSlice(dst.Type(), src.Len(), src.Len()))
			for i := 0; i < src.Len(); i++ {
				copyReleaseValue(dst.Index(i), src.Index(i))
			}
		}
	case reflect.Map:
		if !src.IsNil() {
			dst.Set(reflect.MakeMap(dst.Type()))
			it := src.MapRange()
			for it.Next() {
				k, v := reflect.New(dst.Type().Key()).Elem(), reflect.New(dst.Type().Elem()).Elem()
				copyReleaseValue(k, it.Key())
				copyReleaseValue(v, it.Value())
				dst.SetMapIndex(k, v)
			}
		}

	default:
		dst.Set(src.Convert(dst.Type()))
	}
}

// ReleasedRowRefuses checks a caller-supplied row using only the frozen matcher.
// New parser metadata is absent from the released row type.
func ReleasedRowRefuses(row any, entry string, argv []string) bool {
	var r old.Row
	copyReleaseValue(reflect.ValueOf(&r).Elem(), reflect.ValueOf(row).Elem())
	rs := old.NewRows(&r)
	p, err := old.Parse(entry, old.ListAllow, rs)
	if err != nil {
		return true
	}
	f := old.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: true}
	return old.NewIndex(rs, []*old.Pattern{p}, old.IndexOptions{}).Decide(&f).Outcome == old.OutcomeRefused
}
