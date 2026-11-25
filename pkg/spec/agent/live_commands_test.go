// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// liveFacts is the facts of a direct exec of tool (image and argv[0] the same) with argv.
func liveFacts(tool string, argv ...string) *execmatch.Facts {
	return &execmatch.Facts{Requested: tool, Image: tool, Argv0: tool, Form: execmatch.FormDirect,
		Argv: append([]string{tool}, argv...), ArgvComplete: true}
}

// TestLiveCommandsRefuseWhatExecDenyRefuses: a block's text decides as the same entry in a contract's exec.deny, which
// compile builds from the same parser: the same program with other words is not touched; options, the long spelling of
// an option and a wrapper do not hide the command; a different program is not touched.
func TestLiveCommandsRefuseWhatExecDenyRefuses(t *testing.T) {
	l, err := NewLiveCommands(nil, "", []string{"git push", "npm install --global *"})
	if err != nil {
		t.Fatal(err)
	}
	denyOnly := execmatch.NewIndex(rows.Builtin(), mustPatterns(t, execmatch.ListDeny, "git push", "npm install --global *"), execmatch.IndexOptions{})
	for _, c := range []struct {
		name string
		f    *execmatch.Facts
		want bool
		rule string
	}{
		{"the command", liveFacts("git", "push"), true, "exec.deny[git push]"},
		{"with arguments after", liveFacts("git", "push", "origin", "main"), true, "exec.deny[git push]"},
		{"an option before the subcommand", liveFacts("git", "-C", ".", "push"), true, "exec.deny[git push]"},
		{"a config option before it", liveFacts("git", "-c", "x=y", "push", "--force"), true, "exec.deny[git push]"},
		{"the same program, other words", liveFacts("git", "status"), false, ""},
		{"the same program, no words", liveFacts("git"), false, ""},
		{"another program", liveFacts("hg", "push"), false, ""},
		{"a glob word", liveFacts("npm", "install", "--global", "left-pad"), true, "exec.deny[npm install --global *]"},
		{"a glob word not met", liveFacts("npm", "install", "left-pad"), false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := l.Index.Decide(c.f)
			refused := res.Outcome == execmatch.OutcomeRefused && res.List == execmatch.ListDeny
			if refused != c.want {
				t.Fatalf("Decide = %+v, want refused %v", res, c.want)
			}
			if refused {
				if v, ok := l.ValueOf(res.Pattern); !ok || res.Rule() != c.rule || !strings.HasPrefix(c.rule, "exec.deny["+v) {
					t.Errorf("rule %q, value %q (%v), want %q", res.Rule(), v, ok, c.rule)
				}
			}
			// The contract's own exec.deny decides it the same way.
			if got := denyOnly.Decide(c.f); got.Outcome != res.Outcome || got.Rule() != res.Rule() {
				t.Errorf("a contract's exec.deny answers %v %q, the live block %v %q", got.Outcome, got.Rule(), res.Outcome, res.Rule())
			}
		})
	}
	if _, ok := l.ValueOf(nil); ok {
		t.Error("ValueOf(nil) names a block")
	}
}

func liveIdentityOf(t *testing.T, fi os.FileInfo) execmatch.ID {
	t.Helper()
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no inode numbers here")
	}
	return execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino} //nolint:unconvert // Dev's type differs by platform
}

func mustPatterns(t *testing.T, list execmatch.List, entries ...string) []*execmatch.Pattern {
	t.Helper()
	var out []*execmatch.Pattern
	for _, e := range entries {
		p, err := execmatch.Parse(e, list, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// TestLiveCommandsRefuseWhatIsNotACommand: a value the parser refuses, or one with no words, builds nothing.
func TestLiveCommandsRefuseWhatIsNotACommand(t *testing.T) {
	for _, v := range []string{"git", "/usr/bin/git push", "git push && ls", "git commit -m 'x"} {
		if l, err := NewLiveCommands(nil, "", []string{v}); err == nil || l != nil {
			t.Errorf("NewLiveCommands(%q) = %v, %v; want an error", v, l, err)
		}
	}
	if l, err := NewLiveCommands(nil, "", nil); l != nil || err != nil {
		t.Errorf("no blocks: %v, %v", l, err)
	}
}

// TestLiveCommandsKnowTheProgramsFileOnPath: the program's file of one link on the run's PATH is the tool's identity, so
// a copy of it under another name (a hard link has two links and is no identity, as compile reads it) is not
// matched by name but the file itself is, by its identity, under any name; a multi-link file is not.
func TestLiveCommandsKnowTheProgramsFileOnPath(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "mytool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	rt := &RuleTable{PATH: dir}
	l, err := NewLiveCommands(rt, "", []string{"mytool run"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(tool)
	if err != nil {
		t.Fatal(err)
	}
	id := liveIdentityOf(t, st)
	// Run as "other": by name nothing says mytool; by identity the file is.
	f := &execmatch.Facts{Requested: "other", Image: "other", Argv0: "other", Form: execmatch.FormDirect,
		Argv: []string{"other", "run"}, ArgvComplete: true, ID: id, HasID: true, Links: 1}
	if res := l.Index.Decide(f); res.Outcome != execmatch.OutcomeRefused || res.List != execmatch.ListDeny {
		t.Fatalf("the program's file under another name: %+v, want refused by its identity", res)
	}
	f.HasID = false
	if res := l.Index.Decide(f); res.Outcome == execmatch.OutcomeRefused {
		t.Fatalf("another name and no identity: %+v, want left alone", res)
	}
	// A program nowhere on PATH has no identity.
	none, err := NewLiveCommands(&RuleTable{PATH: t.TempDir()}, "", []string{"mytool run"})
	if err != nil {
		t.Fatal(err)
	}
	f.HasID = true
	if res := none.Index.Decide(f); res.Outcome == execmatch.OutcomeRefused {
		t.Fatalf("no file of that name on PATH, yet an identity matched: %+v", res)
	}
}
