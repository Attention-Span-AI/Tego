// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// TestMotivatingExamples holds what ADR 0048 set out to do: deny a whole command, deny specific
// subcommands wherever the tool's own options put them, and allow only some subcommands.
func TestMotivatingExamples(t *testing.T) {
	t.Run("deny a whole command", func(t *testing.T) {
		ix := rules(t, "deny: npm")
		for _, line := range []string{"npm", "npm publish", "npm --version", "npm i left-pad"} {
			if got := decided(run(ix, words(line)...)); got != "refused exec.deny[npm]" {
				t.Errorf("%s: %s", line, got)
			}
		}
		if got := decided(run(ix, "git", "status")); got != "none" {
			t.Errorf("git status under deny npm: %s", got)
		}
	})
	t.Run("deny subcommands", func(t *testing.T) {
		ix := rules(t, "deny: git push", "deny: rm -r", "deny: git push --force")
		refused := map[string]string{
			"git push":                                 "exec.deny[git push]",
			"git push origin main":                     "exec.deny[git push]",
			"git -C . push":                            "exec.deny[git push]",
			"git -c push.default=current push":         "exec.deny[git push]",
			"git --git-dir=.git push":                  "exec.deny[git push]",
			"git --git-dir .git --work-tree . push -f": "exec.deny[git push]",
			"git --no-pager push":                      "exec.deny[git push]",
			"rm -r x":                                  "exec.deny[rm -r]",
			"rm -rf x":                                 "exec.deny[rm -r]",
			"rm -fr x":                                 "exec.deny[rm -r]",
			"rm -R x":                                  "exec.deny[rm -r]",
			"rm -r -f x":                               "exec.deny[rm -r]",
			"rm x --recursive --force":                 "exec.deny[rm -r]",
			"rm x --rec --forc":                        "exec.deny[rm -r]",
			"rm -dRv x":                                "exec.deny[rm -r]",
		}
		for line, rule := range refused {
			r := run(ix, words(line)...)
			if r.Outcome != execmatch.OutcomeRefused || r.Rule() != rule {
				t.Errorf("%s: %s, want refused %s", line, decided(r), rule)
			}
		}
		for _, line := range []string{"git status", "git stash push", "git log --oneline", "rm x", "rm -f x", "rm -- -r", "rm -i x", "git -C push status"} {
			if got := decided(run(ix, words(line)...)); got != "none" {
				t.Errorf("%s: %s, want none", line, got)
			}
		}
	})
	t.Run("deny git subcommand alias rm/remove", func(t *testing.T) {
		// git-remote(1): "remove, rm". A deny or allow entry for git remote remove must cover git remote rm, its
		// alias, which git 2.51 runs. rename is a distinct subcommand, not covered.
		ix := rules(t, "deny: git remote remove")
		for _, line := range []string{"git remote remove origin", "git remote rm origin", "git -C . remote rm x"} {
			r := run(ix, words(line)...)
			if r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[git remote remove]" {
				t.Errorf("%s: %s, want refused exec.deny[git remote remove]", line, decided(r))
			}
		}
		for _, line := range []string{"git remote rename a b", "git remote add o url", "git remote -v", "git rm x"} {
			if got := decided(run(ix, words(line)...)); got != "none" {
				t.Errorf("%s: %s, want none", line, got)
			}
		}
	})
	t.Run("git bisect next and the removed --super-prefix", func(t *testing.T) {
		// git bisect next is a verb (git bisect -h lists it): a rule can name it, and an allow list of other bisect
		// verbs does not admit it. git 2.49 removed --super-prefix; the row listed it as taking a value, so `git
		// --super-prefix push` read push as that value and no subcommand at all. Now the word is unknown and read
		// both ways, so a deny on git push refuses it (2026-10-16, TestGitRowFresh holds both to the installed git).
		if _, err := execmatch.Parse("git bisect next", execmatch.ListDeny, Builtin()); err != nil {
			t.Fatalf("deny: git bisect next: %v", err)
		}
		ix := rules(t, "deny: git bisect next")
		if got := decided(run(ix, words("git bisect next")...)); got != "refused exec.deny[git bisect next]" {
			t.Errorf("git bisect next: %s", got)
		}
		if got := decided(run(rules(t, "allow: git bisect good"), words("git bisect next")...)); got != "refused exec.args[git]" {
			t.Errorf("git bisect next under allow: git bisect good: %s", got)
		}
		push := rules(t, "deny: git push")
		for _, line := range []string{"git --super-prefix push", "git --super-prefix x push", "git --super-prefix=x push"} {
			if r := run(push, words(line)...); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[git push]" {
				t.Errorf("%s under deny: git push: %s, want refused exec.deny[git push]", line, decided(r))
			}
		}
	})
	t.Run("allow only some subcommands", func(t *testing.T) {
		ix := rules(t, "allow: git status", "allow: git diff", "allow: git log")
		for _, line := range []string{"git status", "git status -s", "git -C /repo status", "git diff --cached", "git log --oneline -n 5", "git log --any-new-option"} {
			r := run(ix, words(line)...)
			if r.Outcome != execmatch.OutcomeAllowed {
				t.Errorf("%s: %s, want allowed", line, decided(r))
			}
		}
		for _, line := range []string{"git push", "git commit -m x", "git", "git --frobnicate status", "git stauts"} {
			r := run(ix, words(line)...)
			if r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.args[git]" {
				t.Errorf("%s: %s, want refused exec.args[git]", line, decided(r))
			}
		}
		if got := decided(run(ix, "rm", "x")); got != "none" {
			t.Errorf("rm under a git allow list: %s", got)
		}
	})
}

// TestAdversarialChecks are ADR 0048's "Adversarial checks" for the rows of this package.
func TestAdversarialChecks(t *testing.T) {
	ix := rules(t, "deny: git push", "deny: rm -r", "deny: pip install", "deny: npm publish")
	cases := []struct {
		name  string
		facts execmatch.Facts
		want  string // "" for none
		via   execmatch.Via
		match execmatch.Match
	}{
		{"dashed path", facts("/usr/lib/git-core/git-push", "git", "git-push", "origin"), "exec.deny[git push]", execmatch.ViaDashed, execmatch.MatchDefinite},
		{"argv0 dashed", facts("/usr/bin/git", "git", "git-push", "origin"), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchDefinite},
		{"argv0 dispatch on a renamed file", facts("/tmp/x", "x", "git-push"), "exec.deny[git push]", execmatch.ViaDashed, execmatch.MatchDefinite},
		{"autocorrect psuh", facts("/usr/bin/git", "git", "git", "psuh"), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchAmbiguous},
		{"autocorrect psh", facts("/usr/bin/git", "git", "git", "psh"), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchAmbiguous},
		{"autocorrect Push", facts("/usr/bin/git", "git", "git", "Push"), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchAmbiguous},
		{"autocorrect pusg", facts("/usr/bin/git", "git", "git", "pusg"), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchAmbiguous},
		{"autocorrect push with a trailing space", facts("/usr/bin/git", "git", "git", "push "), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchAmbiguous},
		{"autocorrect pυsh", facts("/usr/bin/git", "git", "git", "pυsh"), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchAmbiguous},
		{"pus ties push and pull", facts("/usr/bin/git", "git", "git", "pus"), "", 0, 0},
		{"git lfs", facts("/usr/bin/git", "git", "git", "lfs", "push"), "", 0, 0},
		{"git gui", facts("/usr/bin/git", "git", "git", "gui"), "", 0, 0},
		{"git ls", facts("/usr/bin/git", "git", "git", "ls"), "", 0, 0},
		{"git sh", facts("/usr/bin/git", "git", "git", "sh"), "", 0, 0},
		{"stash push", facts("/usr/bin/git", "git", "git", "stash", "push"), "", 0, 0},
		{"unknown global option", facts("/usr/bin/git", "git", "git", "--newopt", "push", "status"), "exec.deny[git push]", execmatch.ViaName, execmatch.MatchAmbiguous},
		{"busybox rm", facts("/usr/bin/busybox", "busybox", "busybox", "rm", "-rf", "x"), "exec.deny[rm -r]", execmatch.ViaMulticall, execmatch.MatchDefinite},
		{"busybox as rm", facts("/bin/rm", "busybox", "rm", "-rf", "x"), "exec.deny[rm -r]", execmatch.ViaName, execmatch.MatchDefinite},
		{"gnurm", facts("/usr/bin/gnurm", "gnurm", "gnurm", "-rf", "x"), "exec.deny[rm -r]", execmatch.ViaName, execmatch.MatchDefinite},
		{"python -m pip", facts("/usr/bin/python3", "python3.13", "python3", "-m", "pip", "install", "x"), "exec.deny[pip install]", execmatch.ViaInterpreter, execmatch.MatchDefinite},
		{"python -Im pip", facts("/usr/bin/python3", "python3.13", "python3", "-Im", "pip", "install", "x"), "exec.deny[pip install]", execmatch.ViaInterpreter, execmatch.MatchDefinite},
		{"python -c is opaque", facts("/usr/bin/python3", "python3.13", "python3", "-c", "import pip", "install"), "", 0, 0},
		{"rm -- -rf", facts("/bin/rm", "gnurm", "rm", "--", "-rf"), "", 0, 0},
	}
	for _, c := range cases {
		r := ix.Decide(&c.facts)
		if c.want == "" {
			if r.Outcome != execmatch.OutcomeNone {
				t.Errorf("%s: %s, want none", c.name, decided(r))
			}
			continue
		}
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want {
			t.Errorf("%s: %s, want refused %s", c.name, decided(r), c.want)
			continue
		}
		if r.Via != c.via || r.Match != c.match {
			t.Errorf("%s: via %s, match %s; want via %s, match %s", c.name, r.Via, r.Match, c.via, c.match)
		}
	}
}

// facts builds exec facts: requested pathname, image basename, then argv.
func facts(requested, image string, argv ...string) execmatch.Facts {
	return execmatch.Facts{Requested: requested, Path: requested, Image: image, Argv0: argv[0], Argv: argv, ArgvComplete: true}
}
