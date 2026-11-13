// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

import (
	"reflect"

	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

func frozenValueCheck(entry, tool string, canonical []string, empty npmRestore, readings any) bool {
	row := oldrows.Builtin().Lookup(tool)
	p, err := old.Parse(entry, old.ListAllow, oldrows.Builtin())
	if err != nil {
		return false
	}
	ix := old.NewIndex(oldrows.Builtin(), []*old.Pattern{p}, old.IndexOptions{})
	f := old.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: append([]string{tool}, canonical...), ArgvComplete: true}
	b := ix.Decide(&f)
	if b.Outcome != old.OutcomeAllowed || b.Pattern == nil || b.Pattern.Entry != entry {
		return false
	}
	expected := old.NewNormalizer(row, nil).Normalize(canonical)
	restoreNpmEmpty(expected, empty)
	inv := old.Invocation{Tool: tool, Row: row, Tokens: canonical, Readings: expected}
	return p.Match(&inv) == old.MatchDefinite && sameReadings(reflect.ValueOf(readings), expected)
}
