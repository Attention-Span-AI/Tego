// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestInteractiveAgentRules: an interactive Claude Code starts `claude` with its own default settings and reaches its
// model directly; the rules compile, and the option combinations that make no sense are refused.
func TestInteractiveAgentRules(t *testing.T) {
	dir := project(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	m := config.Builtin()
	m.Home = home
	env := CheckEnv{Machine: m, Options: []agent.CompileOption{agent.WithPATH(bin + ":/usr/bin:/bin"), agent.WithHome(home)}}
	base := Options{Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Writes: []string{"src/"}, Name: "p", Dir: dir,
		Agent: "claude-code", Interactive: true}

	r, err := Compose(base)
	if err != nil {
		t.Fatal(err)
	}
	text := string(r.Contract)
	for _, want := range []string{`command: ["claude"]`, `"tcp://api.anthropic.com:443"`, "capture: off", "harness: claude-code"} {
		if !strings.Contains(text, want) {
			t.Errorf("rules lack %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `"claude", "-p"`) || strings.Contains(text, "forwarder") || strings.Contains(text, "dangerously") {
		t.Errorf("rules start print mode, the forwarder, or change Claude's own settings:\n%s", text)
	}
	if _, err := Create(r, dir); err != nil {
		t.Fatal(err)
	}
	// Checked as the guide saves it: a registry file outside the project, run from the project.
	if ds, ok := CheckFile(r.Contract, filepath.Join(t.TempDir(), "p.yaml"), dir, env); !ok {
		t.Fatalf("rules do not compile: %v\n%s", ds, text)
	}

	for _, bad := range []Options{
		{Presets: base.Presets, Name: "p", Dir: dir, Command: "sh", Interactive: true},
		{Presets: base.Presets, Name: "p", Dir: dir, Agent: "claude-code", Interactive: true, Prompt: "x"},
	} {
		if _, err := Compose(bad); err == nil || !IsUsage(err) {
			t.Errorf("Compose(%+v) = %v, want a usage error", bad, err)
		}
	}
}
