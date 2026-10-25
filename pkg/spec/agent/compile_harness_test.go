// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// TestCompileHarness: harness: resolves auto from the contract's own command, keeps a named harness, keeps auto for a
// table whose contract has no command (the launcher resolves it), and prints the result (agent-contract.md R27, ADR 0062).
func TestCompileHarness(t *testing.T) {
	cases := []struct {
		yaml  string
		want  harness.Name
		print string
	}{
		{"command: [claude, -p]\n", harness.ClaudeCode, "harness   claude-code (auto, from the contract's command)"},
		{"command: [BIN/codex]\nharness: auto\n", harness.Codex, "harness   codex (auto, from the contract's command)"},
		{"command: [python]\n", harness.Generic, "harness   generic (auto, from the contract's command)"},
		{"command: [claude]\nharness: none\n", harness.None, "harness   none"},
		{"command: [python]\nharness: claude-code\n", harness.ClaudeCode, "harness   claude-code"},
	}
	for _, c := range cases {
		f := newFixture(t)
		for _, n := range []string{"claude", "codex"} {
			f.file(filepath.Join(f.bin, n), string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)
		}
		rt, _ := f.compile(f.load("version: 0\nname: t\n" + strings.ReplaceAll(c.yaml, "BIN", f.bin)))
		if rt.Harness != c.want {
			t.Errorf("%q: Harness = %q, want %q", c.yaml, rt.Harness, c.want)
		}
		var b bytes.Buffer
		if err := PrintRuleTable(&b, rt); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "\n"+c.print+"\n") {
			t.Errorf("%q: the table does not print %q:\n%s", c.yaml, c.print, b.String())
		}
	}
	// auto is the harness of the command the run executes: the one `tego run` was given after the contract
	// (WithRunCommand) when there is one, not the contract's own.
	f := newFixture(t)
	f.file(filepath.Join(f.bin, "claude"), string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)
	for _, run := range []string{"claude", filepath.Join(f.bin, "claude")} {
		if rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [python]\n"), WithRunCommand(run)); rt.Harness != harness.ClaudeCode {
			t.Errorf("command [python] run as %s: Harness = %q, want claude-code", run, rt.Harness)
		}
	}
	if rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [claude]\n"), WithRunCommand("python")); rt.Harness != harness.Generic {
		t.Errorf("command [claude] run as python: Harness = %q, want generic", rt.Harness)
	}
	// A table built for a contract with no command (a generated one) keeps auto, and says so.
	var b bytes.Buffer
	if err := PrintRuleTable(&b, &RuleTable{Harness: harness.Auto}); err != nil {
		t.Fatal(err)
	}
	if want := "harness   auto (detected when the run starts, from its command's name)\n"; !strings.Contains(b.String(), want) {
		t.Errorf("an auto table does not print %q:\n%s", want, b.String())
	}
}

// TestHarnessSchemaRefusesOtherValues: the key takes the five names and nothing else.
func TestHarnessSchemaRefusesOtherValues(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.project, "agent.yaml")
	for _, v := range []string{"claude", "Auto", "[none]", "{}"} {
		f.file(path, "version: 0\nname: t\ncommand: [python]\nharness: "+v+"\n", 0o644)
		if _, ds, err := Load(path, f.profiles()); err == nil {
			t.Errorf("harness: %s loaded:\n%s", v, render(ds))
		}
	}
}

// TestHarnessMergeContractWins: harness: is contract-wins (ADR 0065): the contract's value when it writes the key,
// else the profile's.
func TestHarnessMergeContractWins(t *testing.T) {
	f := newFixture(t)
	src := f.profiles()
	dir := filepath.Join(f.root, "profiles")
	if err := os.WriteFile(filepath.Join(dir, "hp.yaml"), []byte("harness: none\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.project, "agent.yaml")
	for body, want := range map[string]harness.Name{
		"":                     harness.None,
		"harness: generic\n":   harness.Generic,
		"harness: auto\n":      harness.Auto,
		"harness: codex\n":     harness.Codex,
		"harness: none\n":      harness.None,
		"harness: claude-code": harness.ClaudeCode,
	} {
		f.file(path, "version: 0\nname: t\nextends: hp\ncommand: [python]\n"+body, 0o644)
		c, ds, err := Load(path, src)
		if err != nil {
			t.Fatalf("%q: %v\n%s", body, err, render(ds))
		}
		if c.Harness != want {
			t.Errorf("%q over a profile's none: Harness = %q, want %q", body, c.Harness, want)
		}
	}
}
