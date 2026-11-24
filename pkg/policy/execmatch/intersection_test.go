// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

func TestBaselineCommandIntersection(t *testing.T) {
	tests := []struct {
		name, deny, allow string
		want              execmatch.IntersectionKind
	}{
		{"subcommand extension", "git push", "git push --dry-run", execmatch.IntersectionOverlap},
		{"different verb", "git push", "git status", execmatch.IntersectionDisjoint},
		{"helper closure", "git gc", "git fetch", execmatch.IntersectionOverlap},
		{"transitive helper", "git worktree prune", "git pull", execmatch.IntersectionOverlap},
		{"different second verb", "git remote remove", "git remote show", execmatch.IntersectionDisjoint},
		{"canonical alias", "git remote remove", "git remote rm origin", execmatch.IntersectionOverlap},
		{"directory word is not prefix", "git push", "git pushback", execmatch.IntersectionDisjoint},
		{"operand mismatch", "git push production", "git push staging", execmatch.IntersectionDisjoint},
		{"operand subsequence", "git push production", "git push origin production", execmatch.IntersectionOverlap},
		{"operand count", "git push origin production", "git push production", execmatch.IntersectionDisjoint},
		{"trailing rest", "git push production", "git push staging *", execmatch.IntersectionOverlap},
		{"operand glob overlap", "git push prod*", "git push *duction", execmatch.IntersectionOverlap},
		{"operand glob disjoint", "git push prod[0-9]", "git push prod[a-z]", execmatch.IntersectionDisjoint},
		{"negated class", "git push prod[!0-9]", "git push prod[0-9]", execmatch.IntersectionDisjoint},
		{"clustered options", "rm -rf", "rm --recursive --force x", execmatch.IntersectionOverlap},
		{"extra denied option", "git push --force", "git push --dry-run", execmatch.IntersectionOverlap},
		{"repeated option values", "git push --repo=production", "git push --repo=staging", execmatch.IntersectionOverlap},
		{"generic prefix extends", "custom delete", "custom inspect", execmatch.IntersectionOverlap},
		{"interpreter dispatch", "pip install", "python -m pip install", execmatch.IntersectionOverlap},
		{"entry script dispatch", "npm publish", "node npm-cli.js publish", execmatch.IntersectionOverlap},
		{"multicall dispatch", "rm -r", "busybox rm -r", execmatch.IntersectionOverlap},
		{"loader dispatch", "git push", "ld-linux-x86-64.so.2 /usr/bin/git push", execmatch.IntersectionOverlap},
		{"fixed script disjoint", "git push", "python custom.py", execmatch.IntersectionDisjoint},
		{"fixed script arguments", "git push", "python custom.py inspect", execmatch.IntersectionDisjoint},
		{"tool identities", "git push", "rm -r x", execmatch.IntersectionDisjoint},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, a := intersectionPatterns(t, tt.deny, tt.allow)
			got := execmatch.Intersect(rows.Builtin(), d, a, execmatch.IntersectionOptions{})
			if got.Kind != tt.want {
				t.Fatalf("Intersect(%q, %q) = %v (%s), want %v", tt.deny, tt.allow, got.Kind, got.Reason, tt.want)
			}
			if got.Kind == execmatch.IntersectionOverlap {
				checkIntersectionWitness(t, d, a, got.Witness, execmatch.IndexOptions{})
			}
		})
	}
}

func TestBaselineIntersectionKnownImage(t *testing.T) {
	d, a := intersectionPatterns(t, "git push", "renamed push")
	image := execmatch.Facts{Requested: "/opt/renamed", Image: "git", ID: execmatch.ID{Dev: 2, Ino: 3}, HasID: true}
	opts := execmatch.IntersectionOptions{
		IndexOptions: execmatch.IndexOptions{Identities: map[execmatch.ID]string{image.ID: "git"}},
		AllowImage:   &image,
	}
	got := execmatch.Intersect(rows.Builtin(), d, a, opts)
	if got.Kind != execmatch.IntersectionOverlap {
		t.Fatalf("known image identity was lost: %+v", got)
	}
	checkIntersectionWitness(t, d, a, got.Witness, opts.IndexOptions)
}

func TestBaselineIntersectionPreservesUnknownImageVersion(t *testing.T) {
	d, a := intersectionPatterns(t, "npm publish", "node npm-cli.js publish")
	image := execmatch.Facts{Requested: "node", Image: "node", Argv0: "node"}
	got := execmatch.Intersect(rows.Builtin(), d, a, execmatch.IntersectionOptions{AllowImage: &image})
	if got.Kind != execmatch.IntersectionOverlap || got.Witness == nil || got.Witness.NodeVersion != "" {
		t.Fatalf("unknown runtime version was replaced by an inventoried version: %+v", got)
	}
	checkIntersectionWitness(t, d, a, got.Witness, execmatch.IndexOptions{})
}

func TestBaselineIntersectionUnresolved(t *testing.T) {
	d, a := intersectionPatterns(t, "git push", "python custom.py *")
	got := execmatch.Intersect(rows.Builtin(), d, a, execmatch.IntersectionOptions{})
	if got.Kind != execmatch.IntersectionUnknown || got.Reason == "" {
		t.Fatalf("unresolved interpreter language must not be disjoint: %+v", got)
	}
	got = execmatch.Intersect(rows.Builtin(), nil, a, execmatch.IntersectionOptions{})
	if got.Kind != execmatch.IntersectionUnknown || got.Reason == "" {
		t.Fatalf("missing input must not be disjoint: %+v", got)
	}
	got = execmatch.Intersect(rows.Builtin(), d, a, execmatch.IntersectionOptions{MaxStates: 1})
	if got.Kind != execmatch.IntersectionUnknown {
		t.Fatalf("exhausted solver bound must not be disjoint: %+v", got)
	}
}

// The oracle is the actual index, including helper closures and dispatcher readings.
// This is deliberately an implication: conservative UNKNOWN results remain refusals
// at compile, and an always-UNKNOWN implementation cannot satisfy the unit table.
func FuzzBaselineCommandIntersection(f *testing.F) {
	for _, seed := range [][3]string{
		{"git push", "git status", "status"},
		{"git push", "git push --dry-run", "push --dry-run"},
		{"git gc", "git fetch", "gc --auto"},
		{"git push production", "git push staging *", "push staging production"},
		{"rm -r", "busybox rm -r", "rm -r x"},
		{"pip install", "python -m pip install", "-m pip install x"},
		{"npm publish", "node npm-cli.js publish", "npm-cli.js publish"},
		{"custom delete", "custom inspect", "inspect delete"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, denyText, allowText, argvText string) {
		d, err := execmatch.Parse(denyText, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			return
		}
		a, err := execmatch.Parse(allowText, execmatch.ListAllow, rows.Builtin())
		if err != nil || a.Bare {
			return
		}
		tokens, _, err := execmatch.SplitWords(argvText)
		if err != nil || len(tokens) > execmatch.MaxWords {
			return
		}
		facts := execmatch.Facts{Requested: a.Command, Image: a.Command, Argv0: a.Command,
			Argv: append([]string{a.Command}, tokens...), ArgvComplete: true}
		if a.Row != nil && a.Row.Interp != nil && len(a.Row.Interp.Versions) > 0 {
			facts.NodeVersion = a.Row.Interp.Versions[0]
		}
		ai := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{a}, execmatch.IndexOptions{})
		di := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{d}, execmatch.IndexOptions{})
		if ar, dr := ai.Decide(&facts), di.Decide(&facts); ar.Outcome != execmatch.OutcomeAllowed || dr.Pattern != d {
			return
		}
		got := execmatch.Intersect(rows.Builtin(), d, a, execmatch.IntersectionOptions{})
		if got.Kind == execmatch.IntersectionDisjoint {
			t.Fatalf("false disjoint for deny=%q allow=%q argv=%q: %s", denyText, allowText, facts.Argv, got.Reason)
		}
		if got.Kind == execmatch.IntersectionOverlap {
			checkIntersectionWitness(t, d, a, got.Witness, execmatch.IndexOptions{})
		}
	})
}

func intersectionPatterns(t *testing.T, deny, allow string) (*execmatch.Pattern, *execmatch.Pattern) {
	t.Helper()
	d, err := execmatch.Parse(deny, execmatch.ListDeny, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	a, err := execmatch.Parse(allow, execmatch.ListAllow, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	return d, a
}

func checkIntersectionWitness(t *testing.T, d, a *execmatch.Pattern, facts *execmatch.Facts, opts execmatch.IndexOptions) {
	t.Helper()
	if facts == nil {
		t.Fatal("overlap has no witness")
	}
	ai := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{a}, opts)
	di := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{d}, opts)
	if ar, dr := ai.Decide(facts), di.Decide(facts); ar.Outcome != execmatch.OutcomeAllowed || dr.Pattern != d {
		t.Fatalf("witness does not satisfy matcher: argv=%q allow=%+v deny=%+v", facts.Argv, ar, dr)
	}
}
