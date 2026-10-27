// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// hookArgv is a harness hook's exact argv (ADR 0064): the tego binary and every argument, the reason path included.
var hookArgv = []string{"/opt/tego/bin/tego", "hook", "claude-code", "--reason", "/run/user/1000/tego/R/last-refusal.json", "--mode", "json"}

// hookFacts is a direct exec of /opt/tego/bin/tego with argv, read whole.
func hookFacts(argv []string) *execmatch.Facts {
	f := &execmatch.Facts{Requested: "tego", Path: "/opt/tego/bin/tego", Image: "tego", Argv: argv, ArgvComplete: true}
	if len(argv) > 0 {
		f.Argv0 = argv[0]
	}
	return f
}

// TestExactPatternAdmitsOnlyTheWholeVector is ADR 0064's grant in the matcher: the runtime pattern admits exactly the
// hook's argv, argv[0] included, and refuses every other vector of the tool under its own rule, exec.harness-hook[...]:
// a trailing argument (a contract allow entry's generic reading would admit it as a token prefix), one missing, a
// changed argument or argv[0], a word that is a glob in a contract entry, and no argument at all.
func TestExactPatternAdmitsOnlyTheWholeVector(t *testing.T) {
	p := execmatch.ExactPattern("harness-hook", "tego", hookArgv)
	ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
	const rule = "exec.harness-hook[/opt/tego/bin/tego]"
	if !ix.Constrained("tego") || p.Rule() != rule {
		t.Fatalf("constrained %v, rule %q", ix.Constrained("tego"), p.Rule())
	}
	got := ix.Decide(hookFacts(hookArgv))
	if got.Outcome != execmatch.OutcomeAllowed || got.Rule() != rule || got.K != len(hookArgv) || !got.Final {
		t.Fatalf("the hook's argv: %+v (rule %q)", got, got.Rule())
	}
	other := func(edit func([]string) []string) []string { return edit(slices.Clone(hookArgv)) }
	refused := map[string][]string{
		"a trailing argument": other(func(a []string) []string { return append(a, "--extra") }),
		"one argument fewer":  other(func(a []string) []string { return a[:len(a)-1] }),
		"another reason path": other(func(a []string) []string { a[4] = "/tmp/other.json"; return a }),
		"another argv[0]":     other(func(a []string) []string { a[0] = "tego"; return a }),
		"tego run":            {hookArgv[0], "run", "c.yaml"},
		"tego approve":        {hookArgv[0], "approve", "01J0000000000000000000000A", "a1"},
		"tego __probe":        {hookArgv[0], "__probe"},
		"tego hook other":     {hookArgv[0], "hook", "other"},
		"no argument":         {hookArgv[0]},
	}
	for name, argv := range refused {
		res := ix.Decide(hookFacts(argv))
		if res.Outcome != execmatch.OutcomeRefused || !res.Unlisted || res.Rule() != rule || res.ListName() != "unlisted" || !res.Final {
			t.Errorf("%s %q: %+v (rule %q); want refused unlisted under %s", name, argv, res, res.Rule(), rule)
		}
	}
	// A word is literal: "*" in the grant's argv admits "*", never any token.
	star := execmatch.ExactPattern("harness-hook", "tego", []string{hookArgv[0], "hook", "*"})
	six := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{star}, execmatch.IndexOptions{})
	if res := six.Decide(hookFacts([]string{hookArgv[0], "hook", "claude-code"})); res.Outcome != execmatch.OutcomeRefused {
		t.Errorf("a * word matched another token: %+v", res)
	}
	if res := six.Decide(hookFacts([]string{hookArgv[0], "hook", "*"})); res.Outcome != execmatch.OutcomeAllowed {
		t.Errorf("a * word did not match itself: %+v", res)
	}
}

// TestExactPatternNeedsTheWholeVectorRead: a staged read that stopped inside the vector decides nothing yet while what
// it read is a prefix of the grant's argv (the supervisor reads on), and is final once it cannot be.
func TestExactPatternNeedsTheWholeVectorRead(t *testing.T) {
	ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{execmatch.ExactPattern("harness-hook", "tego", hookArgv)}, execmatch.IndexOptions{})
	f := hookFacts(hookArgv[:3])
	f.ArgvComplete = false
	if res := ix.Decide(f); res.Outcome == execmatch.OutcomeAllowed || res.Final {
		t.Fatalf("an open prefix of the hook's argv: %+v; want undecided", res)
	}
	f = hookFacts(slices.Clone(hookArgv))
	f.ArgvComplete = false // the whole grant read, and more to come: never exact
	if res := ix.Decide(f); res.Outcome != execmatch.OutcomeRefused || !res.Final {
		t.Fatalf("the hook's argv with more after it: %+v; want a final refusal", res)
	}
}

// TestExactPatternIsReadOnTheImageItself: the grant admits the exec of the tool's own image (by name, image, argv[0]
// or identity), never the same vector reached through a #! chain or a loader's program.
func TestExactPatternIsReadOnTheImageItself(t *testing.T) {
	id := execmatch.ID{Dev: 8, Ino: 99}
	ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{execmatch.ExactPattern("harness-hook", "tego", hookArgv)},
		execmatch.IndexOptions{Identities: map[execmatch.ID]string{id: "tego"}})
	byID := hookFacts(hookArgv)
	byID.Requested, byID.Image, byID.ID, byID.HasID = "t", "t", id, true // a link of another name, its identity tego's
	if res := ix.Decide(byID); res.Outcome != execmatch.OutcomeAllowed {
		t.Errorf("by identity: %+v", res)
	}
	script := &execmatch.Facts{
		Requested: "claude-code", Path: "claude-code", Image: "claude-code", Argv0: "claude-code",
		Argv: []string{"claude-code", "--reason", hookArgv[4], "--mode", "json"}, ArgvComplete: true,
		Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: hookArgv[0], Arg: "hook", Image: "tego"}},
	}
	if res := ix.Decide(script); res.Outcome != execmatch.OutcomeRefused {
		t.Errorf("the hook's vector through a #! chain: %+v; want refused", res)
	}
}

// TestExactPatternBesideAContractEntry: a contract's own allow entry for the tool keeps admitting its invocations
// beside the grant, and an unlisted refusal then names the tool's arguments rule, exec.args[tego], as it does
// without a grant.
func TestExactPatternBesideAContractEntry(t *testing.T) {
	own, err := execmatch.Parse("tego compile", execmatch.ListAllow, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{own, execmatch.ExactPattern("harness-hook", "tego", hookArgv)}, execmatch.IndexOptions{})
	for _, argv := range [][]string{hookArgv, {hookArgv[0], "compile", "c.yaml"}} {
		if res := ix.Decide(hookFacts(argv)); res.Outcome != execmatch.OutcomeAllowed {
			t.Errorf("%q: %+v", argv, res)
		}
	}
	if res := ix.Decide(hookFacts([]string{hookArgv[0], "run"})); res.Outcome != execmatch.OutcomeRefused || res.Rule() != "exec.args[tego]" {
		t.Errorf("tego run: %+v (rule %q)", res, res.Rule())
	}
}
