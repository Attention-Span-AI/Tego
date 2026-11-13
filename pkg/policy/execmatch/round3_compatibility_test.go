// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

func TestRound3ExtraDashRefusalUnion(t *testing.T) {
	for _, entry := range []string{"git push ---force", "git push ----force", "git push ---force=true", "git push ---for", "go test ---v"} {
		for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
			p, err := execmatch.Parse(entry, list, rows.Builtin())
			if err != nil {
				t.Fatal(err)
			}
			tool, sub := "git", "push"
			spellings := []string{"--force", strings.Fields(entry)[2], "--for", "--f", "-force"}
			if strings.HasPrefix(entry, "go ") {
				tool, sub, spellings = "go", "test", []string{"-v", "--v", "---v"}
			}
			if strings.HasSuffix(entry, "=true") {
				spellings = []string{"--force=true", "---force=true", "--for=true"}
			}
			if strings.HasSuffix(entry, "---for") {
				spellings = []string{"---for", "--for", "--f"}
			}
			ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
			for _, spelling := range spellings {
				f := execmatch.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: []string{tool, sub, spelling}, ArgvComplete: true}
				if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
					t.Errorf("%s %s vs %s: %+v", list, entry, spelling, r)
				}
			}
		}
	}
}

// Required values may consume a word that the literal parse treats as a path.
// Preserve the whole released pattern, not just its individual option names.
func TestRound3ExtraDashValueBinding(t *testing.T) {
	for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
		p, err := execmatch.Parse("git ---git-dir repo status", list, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
		for _, args := range [][]string{{"git", "--git-dir", "repo", "status"}, {"git", "---git-dir", "repo", "status"}} {
			f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: args, ArgvComplete: true}
			if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%s %v: %+v", list, args, r)
			}
		}
		p, err = execmatch.Parse("git ---git-dir repo push --force", list, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ix = execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
		prefix := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", "--git-dir", "repo", "push"}}
		if r := ix.Decide(&prefix); r.Final {
			t.Errorf("%s: prefix settled before compatibility option: %+v", list, r)
		}
		prefix.Argv, prefix.ArgvComplete = append(prefix.Argv, "--force"), true
		if r := ix.Decide(&prefix); r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s: tail did not complete refusal: %+v", list, r)
		}
		prefix = execmatch.Facts{Requested: "coreutils", Image: "coreutils", Argv0: "xgit", Argv: []string{"xgit", "--git-dir", "repo", "push"}}
		if r := ix.Decide(&prefix); r.Final {
			t.Errorf("%s: multicall prefix settled before compatibility option: %+v", list, r)
		}
		prefix.Argv, prefix.ArgvComplete = append(prefix.Argv, "--force"), true
		if r := ix.Decide(&prefix); r.Outcome != execmatch.OutcomeRefused || r.Via != execmatch.ViaMulticall {
			t.Errorf("%s: multicall tail did not complete refusal: %+v", list, r)
		}
	}
	if _, err := execmatch.Parse("git push ---force", execmatch.ListAllow, rows.Builtin()); err == nil {
		t.Fatal("extra-dash allow gained ordinary option")
	}
}

func TestRound3CompatibilityReading(t *testing.T) {
	p, err := execmatch.Parse("git ---git-dir repo push --force", execmatch.ListDeny, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"subcommand repo", "also retains released reading: subcommand push", "--git-dir=repo", "--force"} {
		if got := p.Reading(); !strings.Contains(got, want) {
			t.Errorf("reading %q omits %q", got, want)
		}
	}
	p, err = execmatch.Parse("git push ---force", execmatch.ListDeny, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	if note := p.Coverage(rows.Builtin()); !strings.Contains(note, "force-with-lease") {
		t.Errorf("lost released reading's coverage note: %q", note)
	}
}

func TestRound3OptionSpellingWarnings(t *testing.T) {
	for _, c := range []struct{ entry, ordinary string }{
		{"git push ---force", "--force"}, {"git push -force", "--force"},
		{"rm -forc", "--forc"}, {"go test ---v", "--v"},
		{"git push -no-force", "--no-force"}, {"git add -no-f", "--no-f"},
		{"unknown ---option", "--option"},
	} {
		p, err := execmatch.Parse(c.entry, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(p.Warnings, " "), `"`+c.ordinary+`"`) {
			t.Errorf("%s lacks ordinary-spelling warning for %s: %v", c.entry, c.ordinary, p.Warnings)
		}
	}
	for _, entry := range []string{"git push --force", "git -C repo status", "git push -- ---operand", "unknown -- ---operand"} {
		p, err := execmatch.Parse(entry, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Warnings) != 0 {
			t.Errorf("%s: false warning %v", entry, p.Warnings)
		}
	}
}

// Tool-defined single-dash words must not receive typo migration advice.
func TestRound4OrdinaryOptionSpellings(t *testing.T) {
	for _, entry := range []string{
		"go build -race", "go test -run Test", "go test -run=Test",
		"npm install -workspace app", "npx -package tool tool",
		"find -name file", "java -jar app.jar",
	} {
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			t.Run(list.String()+"/"+entry, func(t *testing.T) {
				p, err := execmatch.Parse(entry, list, rows.Builtin())
				if err != nil {
					t.Fatal(err)
				}
				if len(p.Warnings) != 0 {
					t.Errorf("ordinary tool spelling: %v", p.Warnings)
				}
			})
		}
	}
}
