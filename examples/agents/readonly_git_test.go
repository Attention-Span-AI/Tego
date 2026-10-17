// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// TestReadOnlyGitProfile holds examples/profiles/base/read-only-git.yaml to what it says (ADR 0048 C7): every
// reading command an agent runs is admitted, wherever git's global options put the subcommand, and every
// writing form is refused, by a deny entry or as unlisted.
func TestReadOnlyGitProfile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "profiles", "base", "read-only-git.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var prof struct {
		Exec struct {
			Allow, Deny []string
		}
	}
	if err := yaml.Unmarshal(data, &prof); err != nil {
		t.Fatal(err)
	}
	var ps []*execmatch.Pattern
	for _, e := range prof.Exec.Allow {
		p, err := execmatch.Parse(e, execmatch.ListAllow, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	for _, e := range prof.Exec.Deny {
		p, err := execmatch.Parse(e, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	ix := execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})
	decide := func(line string) execmatch.Outcome {
		argv := strings.Fields(line)
		f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: argv, ArgvComplete: true}
		return ix.Decide(&f).Outcome
	}
	for _, line := range []string{
		"git status --porcelain", "git -C sub status", "git diff --cached --stat", "git log --oneline -n 20",
		"git show HEAD:README.md", "git rev-parse --show-toplevel", "git ls-files -z", "git branch",
		"git branch --show-current", "git branch --list", "git remote -v", "git remote get-url origin",
		"git config --get user.email", "git config get user.email", "git blame -L 1,5 x.go", "git grep -n TODO",
		"git --no-pager log -1", "git merge-base HEAD main",
	} {
		if got := decide(line); got != execmatch.OutcomeAllowed {
			t.Errorf("%s: %s, want allowed", line, got)
		}
	}
	for _, line := range []string{
		"git push", "git commit -m x", "git reset --hard", "git checkout -b x", "git branch -D x",
		"git branch --delete x", "git branch -m x y", "git remote add o url", "git remote set-url o url",
		"git config set user.email x", "git config --unset user.email", "git stash", "git clean -fdx",
		"git fetch", "git -C sub push", "git psuh", "git tag v1",
		"git remote remove origin", "git remote rm origin", // rm is remove's alias
	} {
		if got := decide(line); got != execmatch.OutcomeRefused {
			t.Errorf("%s: %s, want refused", line, got)
		}
	}
}
