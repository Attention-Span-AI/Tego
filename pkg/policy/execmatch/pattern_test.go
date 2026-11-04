// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// TestParseErrors are ADR 0048 (1)'s exec-rule errors: each names the word and carries the fix.
func TestParseErrors(t *testing.T) {
	cases := []struct {
		entry string
		list  execmatch.List
		want  string // a substring of the error
		fix   string // a substring of the fix
	}{
		{"/usr/bin/git push", execmatch.ListDeny, "path in its command word", `"git push"`},
		{"/usr/bin/git", execmatch.ListAsk, "path in its command word", `"git"`},
		{"git push && git tag", execmatch.ListDeny, `"&&" is shell syntax`, "own entry"},
		{"git push | cat", execmatch.ListDeny, `"|" is shell syntax`, "own entry"},
		{"Bash(git push:*)", execmatch.ListDeny, "Bash(...:*)", `"git push"`},
		{"git push:*", execmatch.ListDeny, "Bash(...:*)", `"git push"`},
		{"gi* push", execmatch.ListDeny, "holds a glob", ""},
		{"git * push", execmatch.ListDeny, "lone * is allowed only as the last word", ""},
		{"git 'push", execmatch.ListDeny, "unterminated", "close the quote"},
		{"git log --frobnicate", execmatch.ListAllow, "does not list the option", "deny entry"},
		{"git " + strings.Repeat("x ", 33), execmatch.ListDeny, "at most 32 words", ""},
		{"git " + strings.Repeat("x", 300), execmatch.ListDeny, "more than 256 bytes", ""},
		{"git push\x00", execmatch.ListDeny, "no NUL", ""},
	}
	for _, c := range cases {
		_, err := execmatch.Parse(c.entry, c.list, rows.Builtin())
		var se *execmatch.SyntaxError
		if !errors.As(err, &se) {
			t.Errorf("Parse(%q): %v, want a SyntaxError", c.entry, err)
			continue
		}
		if !strings.Contains(se.Msg, c.want) || !strings.Contains(se.Fix, c.fix) {
			t.Errorf("Parse(%q): %q / fix %q; want %q / %q", c.entry, se.Msg, se.Fix, c.want, c.fix)
		}
	}
}

// TestParseReadings: a pattern is read with the same row as an invocation, so every spelling of one option is one
// option word, and words land as subcommands, options or operands as the tool reads them.
func TestParseReadings(t *testing.T) {
	p, err := execmatch.Parse("git -C /repo push --force origin", execmatch.ListDeny, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "git" || strings.Join(p.Path, " ") != "push" || strings.Join(p.Operands, " ") != "origin" || len(p.Opts) != 2 {
		t.Fatalf("parsed %+v", p)
	}
	if p.Opts[0].Opt == nil || p.Opts[0].Opt.Name != "C" || p.Opts[0].Value != "/repo" || p.Opts[0].Depth != 0 {
		t.Errorf("global -C: %+v", p.Opts[0])
	}
	if p.Opts[1].Opt == nil || p.Opts[1].Opt.Name != "force" || p.Opts[1].Depth != 1 {
		t.Errorf("push --force: %+v", p.Opts[1])
	}
	for _, spelling := range []string{"rm -rf", "rm -fr", "rm -r -f", "rm --recursive --force", "rm -R --forc"} {
		p, err := execmatch.Parse(spelling, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, o := range p.Opts {
			names = append(names, o.Opt.Name)
		}
		if got := strings.Join(names, ","); got != "recursive,force" && got != "force,recursive" {
			t.Errorf("%s: options %s", spelling, got)
		}
	}
	if !execmatch.IsPattern("git push") || execmatch.IsPattern("git") || execmatch.IsPattern("'/opt/My Tools/run'") {
		t.Error("IsPattern classifies by unquoted spaces")
	}
	if execmatch.Word("'/opt/My Tools/run'") != "/opt/My Tools/run" {
		t.Error("Word unquotes one quoted word")
	}
	// An exec.allow entry with no space or tab is one word as written, quote characters included, as before ADR
	// 0048: an unbalanced quote is no syntax error, and a balanced one is not removed (which granted another file).
	for _, e := range []string{"/home/me/O'Brien/bin/tool", "/opt/a'b'c/tool", `/opt/say"hi"/run`, "o'brien-tool"} {
		if execmatch.IsPattern(e) || execmatch.Word(e) != e {
			t.Errorf("%s: IsPattern %v, Word %q; want one word as written", e, execmatch.IsPattern(e), execmatch.Word(e))
		}
		p, err := execmatch.Parse(e, execmatch.ListAllow, rows.Builtin())
		if err != nil || !p.Bare || p.Command != e {
			t.Errorf("Parse(%s) = %+v, %v; want a bare entry of that command", e, p, err)
		}
	}
	// With a space, quotes still delimit: an unbalanced one is the pattern's syntax error.
	if !execmatch.IsPattern("/home/me/O'Brien/My Tools/run") {
		t.Error("an entry with a space and an unbalanced quote is a pattern, refused by its grammar")
	}
	if execmatch.Word(`"/home/me/O'Brien/My Tools/run"`) != "/home/me/O'Brien/My Tools/run" {
		t.Error("double quotes hold a single quote")
	}
	q, err := execmatch.Parse(`mytool "a b" c`, execmatch.ListDeny, rows.Builtin())
	if err != nil || len(q.Words) != 2 || q.Words[0] != "a b" {
		t.Errorf("quoted word: %+v %v", q, err)
	}
	w, err := execmatch.Parse("mytool $HOME", execmatch.ListDeny, rows.Builtin())
	if err != nil || len(w.Warnings) != 1 {
		t.Errorf("$ in a word warns: %+v %v", w, err)
	}
}

// TestGlob covers the one-token glob: no special slash.
func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"feature/*", "feature/x/y", true},
		{"prod*", "production", true},
		{"prod*", "dev", false},
		{"?", "a", true},
		{"?", "", false},
		{"[abc]x", "bx", true},
		{"[!abc]x", "bx", false},
		{"[a-c]", "b", true},
		{"[", "[", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
		{"*", "", true},
	}
	for _, c := range cases {
		if got := execmatch.Glob(c.p, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

// TestGenericFallback: a tool with no row. An allow entry is an exact token prefix; a deny entry is a subsequence of
// words and options present anywhere before `--`, over-matching by design.
func TestGenericFallback(t *testing.T) {
	ix := index(t, "deny: mytool deploy --force", "deny: other -r", "allow: kubectl2 get pods")
	cases := map[string]string{
		"mytool deploy --force":     "refused exec.deny[mytool deploy --force]",
		"mytool --force x deploy":   "refused exec.deny[mytool deploy --force]",
		"mytool deploy --forc":      "refused exec.deny[mytool deploy --force]",
		"mytool deploy --force=yes": "refused exec.deny[mytool deploy --force]",
		"mytool deploy":             "none",
		"mytool deploy -- --force":  "none",
		"other -prefix":             "refused exec.deny[other -r]",
		"other -xr":                 "refused exec.deny[other -r]",
		"other -x":                  "none",
		"kubectl2 get pods":         "allowed exec.allow[kubectl2 get pods]",
		"kubectl2 get pods -o yaml": "allowed exec.allow[kubectl2 get pods]",
		"kubectl2 -n x get pods":    "refused exec.args[kubectl2]",
		"kubectl2 delete pods":      "refused exec.args[kubectl2]",
	}
	for line, want := range cases {
		if got := decide(ix, strings.Fields(line)...); got != want {
			t.Errorf("%s: %s, want %s", line, got, want)
		}
	}
}

// index builds an index from "list: pattern" entries.
func index(t testing.TB, entries ...string) *execmatch.Index {
	t.Helper()
	var ps []*execmatch.Pattern
	for _, e := range entries {
		list, body, _ := strings.Cut(e, ": ")
		l := map[string]execmatch.List{"allow": execmatch.ListAllow, "deny": execmatch.ListDeny, "ask": execmatch.ListAsk}[list]
		p, err := execmatch.Parse(body, l, rows.Builtin())
		if err != nil {
			t.Fatalf("Parse(%q): %v", body, err)
		}
		ps = append(ps, p)
	}
	return execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})
}

// decide is one exec by name, as "refused <rule>", "allowed <rule>" or "none".
func decide(ix *execmatch.Index, argv ...string) string {
	f := execmatch.Facts{NodeVersion: "20.19.4", Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: true}
	r := ix.Decide(&f)
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
