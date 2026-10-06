// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// rules builds an index from entries written "deny: git push", "allow: git status", "ask: npm install".
func rules(t testing.TB, entries ...string) *execmatch.Index {
	t.Helper()
	var ps []*execmatch.Pattern
	for _, e := range entries {
		list, body, ok := strings.Cut(e, ": ")
		if !ok {
			t.Fatalf("entry %q: want <list>: <pattern>", e)
		}
		l := map[string]execmatch.List{"allow": execmatch.ListAllow, "deny": execmatch.ListDeny, "ask": execmatch.ListAsk}[list]
		p, err := execmatch.Parse(body, l, Builtin())
		if err != nil {
			t.Fatalf("Parse(%q): %v", body, err)
		}
		ps = append(ps, p)
	}
	return execmatch.NewIndex(Builtin(), ps, execmatch.IndexOptions{})
}

// run decides an exec of argv by name (requested, image and argv[0] all argv[0]'s basename unless the facts say
// otherwise).
func run(ix *execmatch.Index, argv ...string) execmatch.Result {
	f := execmatch.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: true}
	return ix.Decide(&f)
}

// decided is a result in one string: "refused exec.deny[git push] (definite, via name)", "allowed exec.allow[git
// status]", "none".
func decided(r execmatch.Result) string {
	switch r.Outcome {
	case execmatch.OutcomeNone:
		return "none"
	case execmatch.OutcomeAllowed:
		return "allowed " + r.Rule()
	case execmatch.OutcomeRefused:
		return "refused " + r.Rule()
	}
	return "?"
}

// words splits a command line on spaces for table tests.
func words(s string) []string { return strings.Fields(s) }
