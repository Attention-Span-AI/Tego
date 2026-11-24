// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

func baselineCommandTable(t *testing.T, deny string) (*fixture, *RuleTable, string) {
	t.Helper()
	// Two absolute interpreter paths must fit binfmt_script's 256-byte header.
	// Test-named temporary roots can exceed it even with a private on-disk TMPDIR.
	dir, err := os.MkdirTemp("", "bf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	f := fillCommandFixture(t, newFixtureIn(t, dir))
	loader := filepath.Join(f.bin, "ld-linux-x86-64.so.2")
	f.file(loader, string(elf64("", 2)), 0o755)
	c := f.load("version: 0\nname: command-facts\ncommand: [static-tool]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['"+deny+"']}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("compile baseline command fixture: %v %s", err, render(ds))
	}
	return f, rt, loader
}

func TestBaselineCommandFactsLoaderPrograms(t *testing.T) {
	f, rt, loader := baselineCommandTable(t, "git push")
	git := filepath.Join(f.bin, "git")
	alias := filepath.Join(f.project, "program")
	if err := os.Symlink(git, alias); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"direct", []string{loader, git, "push"}},
		{"argv0 does not hide image", []string{loader, "--argv0", "ls", git, "push"}},
		{"equals argv0", []string{loader, "--argv0=ls", git, "push"}},
		{"program alias", []string{loader, alias, "push"}},
		{"relative program", []string{loader, "../bin/git", "push"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts, err := rt.baselineCommandFacts(tc.argv)
			if err != nil || facts.Loaded == nil || !facts.Loaded.HasID || facts.Loaded.Image != "git" {
				t.Fatalf("loaded image facts lost: %v %+v", err, facts.Loaded)
			}
			if got := rt.ExecCommands.Index.Decide(&facts); got.Outcome != execmatch.OutcomeRefused || got.Via != execmatch.ViaLoader {
				t.Fatalf("real matcher allowed a denied loader program: %+v", got)
			}
			if err := rt.ValidateBaselineCommand(tc.argv); err == nil {
				t.Fatal("required loader command bypassed baseline")
			}
		})
	}
	for _, argv := range [][]string{{loader, "--help"}, {loader, "--version"}, {loader}, {loader, git, "status"}} {
		if err := rt.ValidateBaselineCommand(argv); err != nil {
			t.Fatalf("ordinary disjoint/exiting loader refused: %q: %v", argv, err)
		}
	}
}

func TestBaselineCommandFactsLoaderUnknownRefuses(t *testing.T) {
	f, rt, loader := baselineCommandTable(t, "git push")
	broken := filepath.Join(f.project, "unsupported")
	f.file(broken, "not an executable ELF header\n", 0o755)
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"unknown option", []string{loader, "--future-option", filepath.Join(f.bin, "git"), "push"}},
		{"search-path operand", []string{loader, "git", "push"}},
		{"missing program", []string{loader, filepath.Join(f.project, "missing"), "push"}},
		{"unsupported header", []string{loader, broken, "push"}},
		{"nested loader", []string{loader, loader, filepath.Join(f.bin, "git"), "push"}},
		{"process-relative program", []string{loader, "/proc/self/exe", "push"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts, err := rt.baselineCommandFacts(tc.argv)
			if err == nil || facts.Form != execmatch.FormUnknown {
				t.Fatalf("unknown loaded interpretation was treated as direct: %v %+v", err, facts)
			}
			if err := rt.ValidateBaselineCommand(tc.argv); err == nil || !strings.Contains(err.Error(), "baseline-conflict") {
				t.Fatalf("unsupported mandatory command did not refuse launch: %v", err)
			}
		})
	}
}

func TestBaselineCommandFactsScriptInterpreters(t *testing.T) {
	f, rt, loader := baselineCommandTable(t, "git")
	git := filepath.Join(f.bin, "git")
	for _, tc := range []struct {
		name, header string
		emptyArg     bool
		loaded       bool
	}{
		{"absolute", "#!" + git + "\n", false, false},
		{"relative", "#!../bin/git\n", false, false},
		{"explicit empty argument", "#!" + git + " \x00\n", true, false},
		{"loader interpreter", "#!" + loader + " " + git + "\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := filepath.Join(f.project, strings.ReplaceAll(tc.name, " ", "-"))
			f.file(script, tc.header, 0o755)
			facts, err := rt.baselineCommandFacts([]string{script, "push"})
			if err != nil || facts.Form != execmatch.FormScript || len(facts.Interp) != 1 || facts.Interp[0].EmptyArg != tc.emptyArg || (facts.Loaded != nil) != tc.loaded {
				t.Fatalf("script facts differ from binfmt_script: %v %+v", err, facts)
			}
			if got := rt.ExecCommands.Index.Decide(&facts); got.Outcome != execmatch.OutcomeRefused {
				t.Fatalf("script interpreter bypassed real matcher: %+v", got)
			}
		})
	}
	inner := filepath.Join(f.project, "inner")
	outer := filepath.Join(f.project, "outer")
	f.file(inner, "#!"+git+"\n", 0o755)
	f.file(outer, "#!"+inner+" --flag\n", 0o755)
	facts, err := rt.baselineCommandFacts([]string{outer})
	if err != nil || len(facts.Interp) != 2 || rt.ExecCommands.Index.Decide(&facts).Outcome != execmatch.OutcomeRefused {
		t.Fatalf("nested interpreter facts lost: %v %+v", err, facts)
	}
	alias := filepath.Join(f.project, "outer-alias")
	if err := os.Symlink(outer, alias); err != nil {
		t.Fatal(err)
	}
	facts, err = rt.baselineCommandFacts([]string{alias})
	if err != nil || facts.Path != alias {
		t.Fatalf("script's kernel argument was replaced by resolved image: %v %+v", err, facts)
	}
}

func TestBaselineCommandLoaderCLIConflict(t *testing.T) {
	f, _, loader := baselineCommandTable(t, "git push")
	c := f.load("version: 0\nname: cli-loader\ncommand: [static-tool]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
	argv := []string{loader, "--argv0", "ls", filepath.Join(f.bin, "git"), "push"}
	rt, ds, err := Compile(c, m, f.opts(WithRunArgv(argv))...)
	if rt != nil || err == nil || !strings.Contains(render(ds), CodeBaselineConflict) || !strings.Contains(render(ds), "run command after --") {
		t.Fatalf("compile missed the required loader command: %v %s", err, render(ds))
	}
}
