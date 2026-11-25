// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestBlockOfCommandWords (ADR 0171): the removal of an exec.allow entry that names a command with words, and the
// addition of such an exec.deny entry, have a live block that refuses what that text in exec.deny refuses, offered only
// where it refuses nothing the new contract allows: every other exec.allow entry of the same program must be provably
// disjoint from it, none may admit the program bare, the command must name its program by its bare name, and the
// contract's other entries must be known.
func TestBlockOfCommandWords(t *testing.T) {
	allow := func(es ...string) map[string][]string { return map[string][]string{"exec.allow": es} }
	// withImplicit is allow's view with the tools the run's own commands run (restOf's implicitKey).
	withImplicit := func(m map[string][]string, tools ...string) map[string][]string {
		m[implicitKey] = tools
		return m
	}
	cases := []struct {
		name       string
		remove     bool
		key, entry string
		rest       map[string][]string
		want       string // kind:value, or "!" plus a word of the reason
	}{
		{"removed, no other entry", true, "exec.allow", "git push", allow(), "exec:git push"},
		{"removed, another program's entries", true, "exec.allow", "git push", allow("curl", "npm install"), "exec:git push"},
		{"removed, a disjoint command of the same program", true, "exec.allow", "git push", allow("git status", "git log"), "exec:git push"},
		{"removed, spelled with extra spaces", true, "exec.allow", "  git   push ", allow("git status"), "exec:git push"},
		{"removed, a glob word", true, "exec.allow", "npm install --global *", allow("npm run build"), "exec:npm install --global *"},
		{"added to exec.deny", false, "exec.deny", "git push --force", allow("git status"), "exec:git push --force"},
		{"added to exec.deny, no allow list", false, "exec.deny", "rm -rf", map[string][]string{}, "exec:rm -rf"},
		{"added to exec.deny, though an entry allows the program bare (deny comes first)", false, "exec.deny", "git push", allow("git"), "exec:git push"},
		{"added to exec.deny, though an entry allows part of it (deny comes first)", false, "exec.deny", "git push origin", allow("git push *"), "exec:git push origin"},
		{"added to exec.deny, other entries not known", false, "exec.deny", "git push", nil, "exec:git push"},
		{"another entry allows a superset", true, "exec.allow", "git push", allow("git push origin"), "!may still allow"},
		{"another entry allows every push", true, "exec.allow", "git push --force", allow("git push *"), "!may still allow"},
		{"another entry allows the program bare", true, "exec.allow", "git push", allow("git"), "!allows every command"},
		{"a path entry grants the image and constrains nothing", true, "exec.allow", "git push", allow("/usr/bin/git", "git status"), "exec:git push"},
		{"the image is granted by path and no entry with words is left", true, "exec.allow", "git push", allow("/usr/bin/git"), "!by its file or folder"},
		{"the image is granted by a relative path and no entry with words is left", true, "exec.allow", "git push", allow("./bin/git", "npm install"), "!by its file or folder"},
		{"a folder is granted and no entry with words is left", true, "exec.allow", "git push", allow("/usr/bin/"), "!by its file or folder"},
		{"a folder is granted, another entry with words of the program is left", true, "exec.allow", "git push", allow("/usr/bin/", "git status"), "exec:git push"},
		{"the run's own command is the program (implicit grant)", true, "exec.allow", "git push", withImplicit(allow(), "git"), "!own command"},
		{"the run's own command is the program, another entry with words is left", true, "exec.allow", "git push", withImplicit(allow("git status"), "git"), "!own command"},
		{"an MCP server's command or a script's interpreter is the program", true, "exec.allow", "npx -y serve", withImplicit(allow("npx -y other"), "node", "npx"), "!own command"},
		{"the run's own command is another program", true, "exec.allow", "git push", withImplicit(allow(), "node", "python3"), "exec:git push"},
		{"added to exec.deny, though the run's own command is the program (deny comes first)", false, "exec.deny", "git push", withImplicit(allow(), "git"), "exec:git push"},
		{"the contract's other entries are not known", true, "exec.allow", "git push", nil, "!not known"},
		{"the command names its program with its folder", true, "exec.allow", "/usr/bin/git push", allow(), "!written with its folder"},
		{"a command that is not one", true, "exec.allow", "git push && ls", allow(), "!cannot be blocked live"},
		{"an entry that cannot be read", true, "exec.allow", "git push", allow("git 'status"), "!could not be read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, v, why := blockOf(rule.Change{Remove: c.remove, Key: c.key, Entry: c.entry}, "/p/proj", "/h", c.rest)
			if strings.HasPrefix(c.want, "!") {
				if k != "" || !strings.Contains(why, c.want[1:]) {
					t.Fatalf("%s:%s (%q), want no block, a reason with %q", k, v, why, c.want[1:])
				}
				return
			}
			if string(k)+":"+v != c.want || why != "" {
				t.Fatalf("%s:%s (%q), want %s", k, v, why, c.want)
			}
		})
	}
}

// TestNowOptionsCommandWordsNeedTheLaunchersMark: the offer for a command's words is held back, in words, on a run whose
// launcher has not made the mark that it reads one, and not for a program's block; a run with the mark gets the block.
func TestNowOptionsCommandWordsNeedTheLaunchersMark(t *testing.T) {
	marked := map[string]bool{"r-new": true}
	s := &Service{Home: "/h",
		facts:     func(string) livestatus.Facts { return livestatus.Facts{RecordMinor: record.Minor} },
		wordsMark: func(run string) bool { return marked[run] },
	}
	words := []rule.Change{{Remove: true, Key: "exec.allow", Entry: "git push"}}
	program := []rule.Change{{Remove: true, Key: "exec.allow", Entry: "curl"}}
	rest := map[string][]string{"exec.allow": {"git status"}}
	opts := s.nowOptions(context.Background(), []string{"r-new", "r-old"}, words, "/p", rest)
	if len(opts) != 2 {
		t.Fatalf("options %+v", opts)
	}
	for _, o := range opts {
		switch o.Run {
		case "r-new":
			if !o.OK || o.Block != "exec:git push" || o.Kind != "exec" || o.Value != "git push" {
				t.Errorf("a run that reads commands: %+v", o)
			}
		case "r-old":
			if o.OK || o.Block != "" || o.Why != whyOldWords {
				t.Errorf("a run whose launcher has no mark: %+v", o)
			}
		}
	}
	for _, o := range s.nowOptions(context.Background(), []string{"r-old"}, program, "/p", rest) {
		if !o.OK || o.Block != "exec:curl" {
			t.Errorf("a program's block on an older launcher: %+v", o)
		}
	}
}

// TestImplicitToolsOfTheContract: the tools a contract's own commands run with any arguments are its command's program,
// each MCP server's, the interpreter a script's #! line names and env's program argument; a program that is nowhere on
// the machine has only its own name.
func TestImplicitToolsOfTheContract(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "run.sh"), "#!/usr/bin/env node\nconsole.log(1)\n")
	write(filepath.Join(bin, "serve"), "#!/bin/bash\nexit 0\n")
	s := &Service{PATH: bin}
	cases := []struct {
		name, text string
		want       []string
	}{
		{"a bare command", "command: [git, status]\n", []string{"git"}},
		{"a path command", "command: [/opt/agent/run]\n", []string{"run"}},
		{"a script run by path: its interpreter and env's argument", "command: [./run.sh]\n", []string{"run.sh", "env", "node"}},
		{"an MCP server on the PATH is a script", "command: [git]\nmcp:\n  - name: s\n    command: [serve, --port, \"1\"]\n", []string{"git", "serve", "bash"}},
		{"an MCP server's program", "command: [python3, a.py]\nmcp:\n  - {name: s, command: [npx, -y, srv]}\n", []string{"python", "npx"}},
		{"no command", "version: 0\nexec:\n  allow: [git]\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.implicitTools([]byte(c.text), dir); !reflect.DeepEqual(got, c.want) {
				t.Errorf("implicit tools = %q, want %q", got, c.want)
			}
		})
	}
	m := s.restOf([]byte("command: [git]\nexec:\n  allow: [\"git status\"]\n"), dir)
	if !reflect.DeepEqual(m[implicitKey], []string{"git"}) || !reflect.DeepEqual(m["exec.allow"], []string{"git status"}) {
		t.Errorf("restOf = %v", m)
	}
	if s.restOf([]byte("- not a mapping\n"), dir) != nil {
		t.Error("restOf of text that does not parse is not nil")
	}
}

// TestNowOptionsCommandWordsHoldBackForTheRunsCommand: a run started with `tego run -- git ...` runs git with any
// arguments (run_start's run_command_grant), so removing the contract's last "git push" entry offers no block on that
// run; another run of the same contract, started without that command, is offered the block.
func TestNowOptionsCommandWordsHoldBackForTheRunsCommand(t *testing.T) {
	s := &Service{Home: "/h",
		facts: func(run string) livestatus.Facts {
			f := livestatus.Facts{RecordMinor: record.Minor}
			if run == "r-git" {
				f.RunCommandGrant = "/usr/bin/git"
			}
			return f
		},
		wordsMark: func(string) bool { return true },
	}
	words := []rule.Change{{Remove: true, Key: "exec.allow", Entry: "git push"}}
	rest := map[string][]string{"exec.allow": {"git status"}, implicitKey: nil}
	for _, o := range s.nowOptions(context.Background(), []string{"r-git", "r-plain"}, words, "/p", rest) {
		switch o.Run {
		case "r-git":
			if o.OK || o.Block != "" || !strings.Contains(o.Why, "own command") {
				t.Errorf("a run started with git as its command: %+v", o)
			}
		case "r-plain":
			if !o.OK || o.Block != "exec:git push" {
				t.Errorf("a run with another command: %+v", o)
			}
		}
	}
	if len(rest[implicitKey]) != 0 {
		t.Errorf("the contract's view was changed by a run's command: %v", rest)
	}
}
