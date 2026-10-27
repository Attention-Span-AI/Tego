// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeProvisioner returns its provision, or calls fn with the run it was told.
type fakeProvisioner struct {
	p    harness.Provision
	err  error
	fn   func(harness.Run) harness.Provision
	runs []harness.Run
}

func (f *fakeProvisioner) Provision(run harness.Run) (harness.Provision, error) {
	f.runs = append(f.runs, run)
	if f.fn != nil {
		return f.fn(run), f.err
	}
	return f.p, f.err
}

// harnessContract is a contract whose exec: section is given (nil for none) and whose harness is h.
func harnessContract(h harness.Name, exec *agent.ExecSection) *agent.Contract {
	return &agent.Contract{Version: 0, Name: "h", Command: []string{"/bin/sh"}, Harness: h, Exec: exec}
}

// harnessRunner is a runner with a runtime directory under a private XDG_RUNTIME_DIR, its reason file named as
// createRuntimeDir names it (the writer is a run's, absent here), and p as the provisioner for every harness.
func harnessRunner(t *testing.T, rt *agent.RuleTable, cmd []string, p Provisioner) *runner {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory")
	}
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
	r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: rt, cmd: cmd, log: slog.New(slog.DiscardHandler),
		deps: Deps{Environ: []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin"}}}
	if p != nil {
		r.deps.Harness = func(harness.Name) Provisioner { return p }
	}
	if err := r.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	r.reasonFile = filepath.Join(r.runtimeDir, ledger.LastRefusalFile)
	if err := os.WriteFile(r.reasonFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return r
}

func tableFor(c *agent.Contract) *agent.RuleTable {
	h := c.Harness
	if h == "" {
		h = harness.Auto
	}
	return &agent.RuleTable{Contract: c, Harness: h}
}

// TestHarnessNoneIsTheRunWithoutTheKey is ADR 0062's acceptance (1): harness: none provisions nothing and records
// nothing, and an auto harness with no provisioner (every name, in this package) changes only run_start: the same
// argv, environment and rule table (the filter is built from the table) as a run with no provisioning point at all.
func TestHarnessNoneIsTheRunWithoutTheKey(t *testing.T) {
	for _, h := range []harness.Name{harness.None, harness.Auto, harness.Generic, harness.ClaudeCode, harness.Codex} {
		rt := tableFor(harnessContract(h, nil))
		var p Provisioner
		if h == harness.None {
			p = &fakeProvisioner{p: harness.Provision{Argv: []string{"/bin/sh", "x"}}}
		}
		r := harnessRunner(t, rt, []string{"/bin/sh", "-c", "true"}, p)
		// The run as it was before the provisioning point: the same runner, never provisioned.
		want := struct {
			argv []string
			env  []string
			rt   *agent.RuleTable
		}{resolveCommand(r.rt, r.cmd), r.agentEnv(), r.rt}
		if err := r.provisionHarness(); err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if got := resolveCommand(r.rt, r.cmd); !slices.Equal(got, want.argv) {
			t.Errorf("%s: argv %q, want %q", h, got, want.argv)
		}
		if got := r.harnessEnv(r.agentEnv()); !slices.Equal(got, want.env) {
			t.Errorf("%s: env %q, want %q", h, got, want.env)
		}
		if r.rt != want.rt || !reflect.DeepEqual(*r.rt, *want.rt) {
			t.Errorf("%s: the rule table changed", h)
		}
		if _, err := os.Stat(filepath.Join(r.runtimeDir, hookStateName)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: hook-state exists (%v) for a run provisioned nothing", h, err)
		}
		switch {
		case h == harness.None && r.harness.start != nil:
			t.Errorf("none: run_start.harness %+v, want none", r.harness.start)
		case h != harness.None:
			name := string(h.Resolve("/bin/sh"))
			if s := r.harness.start; s == nil || s.Name != name || s.Provisioned || s.Why != record.HarnessWhyNoProvisioner ||
				s.ReasonFile != r.reasonFile || len(s.Files) != 0 || s.StateDir != "" {
				t.Errorf("%s: run_start.harness %+v, want {%s, false, no-provisioner}", h, s, name)
			}
		}
	}
}

// TestHarnessAutoResolvesFromTheResolvedCommand: auto (and a table built with no harness) is the resolved command's
// basename's harness, the one the provisioner is asked for and run_start names.
func TestHarnessAutoResolvesFromTheResolvedCommand(t *testing.T) {
	bin := t.TempDir()
	for _, n := range []string{"claude", "codex", "aider"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for cmd, want := range map[string]harness.Name{"claude": harness.ClaudeCode, "codex": harness.Codex, "aider": harness.Generic,
		filepath.Join(bin, "claude"): harness.ClaudeCode} {
		rt := tableFor(harnessContract(harness.Auto, nil))
		rt.PATH = bin
		var asked []harness.Name
		r := harnessRunner(t, rt, []string{cmd}, nil)
		r.deps.Harness = func(n harness.Name) Provisioner { asked = append(asked, n); return nil }
		if err := r.provisionHarness(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(asked, []harness.Name{want}) || r.harness.start.Name != string(want) {
			t.Errorf("%s: asked %v, run_start %q; want %s", cmd, asked, r.harness.start.Name, want)
		}
	}
}

// TestHarnessAutoFollowsTheCommandTheRunExecutes: a compiled table's auto harness is the harness of the command the
// run executes, not of the contract's own command, which `tego run c.yaml -- <command>` replaces; a named harness is
// itself whatever runs.
func TestHarnessAutoFollowsTheCommandTheRunExecutes(t *testing.T) {
	bin := t.TempDir()
	claude := filepath.Join(bin, "claude")
	if err := os.WriteFile(claude, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		contract []string
		h        harness.Name
		run      []string
		want     harness.Name
	}{
		{[]string{claude}, harness.Auto, []string{"/bin/sh", "-c", "true"}, harness.Generic},
		{[]string{"/bin/sh"}, harness.Auto, []string{claude}, harness.ClaudeCode},
		{[]string{"/bin/sh"}, "", []string{claude}, harness.ClaudeCode},
		{[]string{claude}, harness.Codex, []string{"/bin/sh"}, harness.Codex},
	}
	for _, c := range cases {
		ct := harnessContract(c.h, nil)
		ct.Command = c.contract
		rt := compileTable(t, ct)
		var asked []harness.Name
		r := harnessRunner(t, rt, c.run, nil)
		r.deps.Harness = func(n harness.Name) Provisioner { asked = append(asked, n); return nil }
		if err := r.provisionHarness(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(asked, []harness.Name{c.want}) || r.harness.start.Name != string(c.want) {
			t.Errorf("contract %q (harness %q) run as %q: asked %v, run_start %q; want %s", c.contract, c.h, c.run, asked,
				r.harness.start.Name, c.want)
		}
	}
}

// claudeLike is a provision as the claude-code provisioner makes: a settings file, a new argv, an environment entry and a
// hook running the tego binary.
func claudeLike(run harness.Run) harness.Provision {
	settings := filepath.Join(run.RuntimeDir, "claude-settings.json")
	return harness.Provision{
		Argv:  append([]string{run.Argv[0], "--settings", settings}, run.Argv[1:]...),
		Env:   []string{"TEGO_CLAUDE_SETTINGS=" + settings},
		Files: []harness.File{{Dir: harness.Runtime, Name: "claude-settings.json", Bytes: []byte(`{"hooks":{}}`)}},
		Hook:  &harness.Hook{Argv: []string{run.TegoExe, "hook", "claude-code", "--reason", run.ReasonFile}},
	}
}

// TestHarnessProvisionIsMadeByTheLauncher is acceptance (3) and (4): the files are made 0444 in the runtime directory,
// hook-state/ 0700 beside last-refusal.json, granted fs.harness-state with its identity; the argv replaces the
// command and the environment entry is added; run_start says what was made.
func TestHarnessProvisionIsMadeByTheLauncher(t *testing.T) {
	compiled := tableFor(harnessContract(harness.ClaudeCode, nil))
	p := &fakeProvisioner{fn: claudeLike}
	r := harnessRunner(t, compiled, []string{"/bin/sh", "-p"}, p)
	if err := r.provisionHarness(); err != nil {
		t.Fatal(err)
	}
	run := p.runs[0]
	if run.RuntimeDir != r.runtimeDir || run.ReasonFile != r.reasonFile || run.StateDir != filepath.Join(r.runtimeDir, "hook-state") ||
		!filepath.IsAbs(run.TegoExe) || run.AllowList || run.Root || !slices.Equal(run.Argv, []string{"/bin/sh", "-p"}) ||
		!envHas(run.Env, "TEGO_REASON") || run.ReadUserFile == nil {
		t.Fatalf("the provisioner was told %+v", run)
	}
	settings := filepath.Join(r.runtimeDir, "claude-settings.json")
	if fi, err := os.Lstat(settings); err != nil || fi.Mode() != 0o444 {
		t.Fatalf("settings file %v %v, want a 0444 file", fi, err)
	}
	state := filepath.Join(r.runtimeDir, "hook-state")
	fi, err := os.Lstat(state)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("hook-state %v %v, want a 0700 directory", fi, err)
	}
	if filepath.Dir(state) != filepath.Dir(r.reasonFile) {
		t.Fatalf("hook-state %s is not a sibling of %s", state, r.reasonFile)
	}
	st := fi.Sys().(*syscall.Stat_t)
	g := r.rt.FS[len(r.rt.FS)-1]
	if g.Runtime != agent.HarnessStateGrant || g.Path != state || g.Kind != agent.FSWrite || g.RuntimeDev != uint64(st.Dev) || g.RuntimeIno != st.Ino {
		t.Fatalf("grant %+v, want fs.harness-state on %s with its identity", g, state)
	}
	if len(compiled.FS) != 0 {
		t.Fatalf("the compiled table was mutated")
	}
	if got := runtimeGrants(r.rt); !slices.Equal(got, []string{"fs.harness-state[" + state + "]"}) {
		t.Fatalf("runtime_grants %v", got)
	}
	if !slices.Equal(r.cmd, []string{"/bin/sh", "--settings", settings, "-p"}) {
		t.Fatalf("argv %q", r.cmd)
	}
	env := r.harnessEnv(r.agentEnv())
	if env[len(env)-1] != "TEGO_CLAUDE_SETTINGS="+settings {
		t.Fatalf("env %q lacks the provision's entry", env)
	}
	// No exec: section: the hook is admitted as it is, and the launcher grants nothing (ADR 0064).
	hook := &record.HarnessHook{Argv: []string{run.TegoExe, "hook", "claude-code", "--reason", r.reasonFile}}
	want := &record.HarnessStart{Name: "claude-code", Provisioned: true, Files: []string{settings}, ReasonFile: r.reasonFile, StateDir: state, Hook: hook}
	if !reflect.DeepEqual(r.harness.start, want) {
		t.Fatalf("run_start.harness %+v, want %+v", r.harness.start, want)
	}
}

// TestHarnessCodexHomeFiles: a CodexHome file is made 0600 in the CODEX_HOME writeCodexHome made, and refused for a run
// with none.
func TestHarnessCodexHomeFiles(t *testing.T) {
	rt := tableFor(harnessContract(harness.Codex, nil))
	p := &fakeProvisioner{p: harness.Provision{Files: []harness.File{{Dir: harness.CodexHome, Name: "hooks.json", Bytes: []byte("{}")}}}}
	r := harnessRunner(t, rt, []string{"/bin/sh"}, p)
	if err := r.provisionHarness(); !errors.Is(err, ErrHarnessProvision) {
		t.Fatalf("a CodexHome file with no CODEX_HOME: %v, want ErrHarnessProvision", err)
	}
	c := codexRunner(rt)
	c.cmd = []string{"/bin/sh"}
	c.deps.Harness = func(harness.Name) Provisioner { return p }
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
	if err := c.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	c.reasonFile = filepath.Join(c.runtimeDir, ledger.LastRefusalFile)
	if err := c.provisionHarness(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(c.codexHome, "hooks.json"))
	if err != nil || fi.Mode() != 0o600 {
		t.Fatalf("CODEX_HOME file %v %v, want 0600", fi, err)
	}
}

// TestHarnessProvisionRefusals is acceptance (3)'s refusals, one each, all before run_start (prepare's error is exit
// 125): a name with '/', '..' or a NUL, a name that exists, an environment name without TEGO_, one the agent's
// environment holds by the contract's env.set, an argv not starting with the resolved command, and a provisioner's
// own error.
func TestHarnessProvisionRefusals(t *testing.T) {
	file := func(name string) func(harness.Run) harness.Provision {
		return func(harness.Run) harness.Provision {
			return harness.Provision{Files: []harness.File{{Dir: harness.Runtime, Name: name, Bytes: []byte("x")}}}
		}
	}
	for name, fn := range map[string]func(harness.Run) harness.Provision{
		"slash":                 file("a/b"),
		"dotdot":                file(".."),
		"nul":                   file("a\x00b"),
		"exists: the reason":    file(ledger.LastRefusalFile),
		"exists: the lock":      file(runtimeLockFile),
		"exists: hook-state":    file(hookStateName),
		"env without TEGO_":     func(harness.Run) harness.Provision { return harness.Provision{Env: []string{"CLAUDE_X=1"}} },
		"env tego sets":         func(harness.Run) harness.Provision { return harness.Provision{Env: []string{"TEGO_REASON=/x"}} },
		"env the contract sets": func(harness.Run) harness.Provision { return harness.Provision{Env: []string{"TEGO_MINE=1"}} },
		"argv[0]":               func(harness.Run) harness.Provision { return harness.Provision{Argv: []string{"/bin/bash", "-p"}} },
		"bare argv[0]":          func(harness.Run) harness.Provision { return harness.Provision{Argv: []string{"sh"}} },
	} {
		rt := tableFor(harnessContract(harness.Generic, nil))
		rt.Set = map[string]string{"TEGO_MINE": "0"}
		r := harnessRunner(t, rt, []string{"/bin/sh"}, &fakeProvisioner{fn: fn})
		if err := r.provisionHarness(); !errors.Is(err, ErrHarnessProvision) {
			t.Errorf("%s: %v, want ErrHarnessProvision", name, err)
		}
		if fi, err := os.Lstat(r.reasonFile); err != nil || fi.Size() != 2 {
			t.Errorf("%s: the reason file was written through (%v)", name, err)
		}
	}
	r := harnessRunner(t, tableFor(harnessContract(harness.Generic, nil)), []string{"/bin/sh"}, &fakeProvisioner{err: errors.New("boom")})
	if err := r.provisionHarness(); !errors.Is(err, ErrHarnessProvision) || !strings.Contains(err.Error(), "boom") {
		t.Errorf("a provisioner's error: %v, want ErrHarnessProvision naming it", err)
	}
}

// TestHarnessNestedRunReplacesTheParentsVariables: a run started inside a provisioned run inherits the parent
// provision's TEGO_ variables (no env.pass list); its own provision replaces them, one entry each, as the identity set
// replaces TEGO_RUN_ID, where it used to refuse the nested run with exit 125.
func TestHarnessNestedRunReplacesTheParentsVariables(t *testing.T) {
	p := &fakeProvisioner{p: harness.Provision{Env: []string{"TEGO_T_SETTINGS=/child"}}}
	r := harnessRunner(t, tableFor(harnessContract(harness.Generic, nil)), []string{"/bin/sh"}, p)
	r.deps.Environ = append(r.deps.Environ, "TEGO_T_SETTINGS=/parent", "TEGO_PARENT_RUN=r-parent")
	if err := r.provisionHarness(); err != nil {
		t.Fatalf("a nested run: %v", err)
	}
	var got []string
	for _, kv := range r.harnessEnv(r.agentEnv()) {
		if strings.HasPrefix(kv, "TEGO_T_SETTINGS=") {
			got = append(got, kv)
		}
	}
	if !slices.Equal(got, []string{"TEGO_T_SETTINGS=/child"}) {
		t.Fatalf("the agent's TEGO_T_SETTINGS entries %q, want the child's alone", got)
	}
}

// TestHarnessReservedNames: the engine's own names are refused whether or not they exist yet: last-refusal.json (the
// file TEGO_REASON names, which the ledger first writes at the first refusal), its writer's temporary names, the lock,
// hook-state and codex, and the environment names the launcher sets or strips itself (the identity set, the DNS
// broker's pair), reads as its own configuration (TEGO_CONFIG) or as a test hook (TEGO_TEST_*), absent from the
// agent's environment or not.
func TestHarnessReservedNames(t *testing.T) {
	file := func(name string) harness.Provision {
		return harness.Provision{Files: []harness.File{{Dir: harness.Runtime, Name: name, Bytes: []byte(`{"forged":true}`)}}}
	}
	env := func(kv string) harness.Provision { return harness.Provision{Env: []string{kv}} }
	for name, p := range map[string]harness.Provision{
		"the reason file":        file(ledger.LastRefusalFile),
		"the reason's temporary": file("." + ledger.LastRefusalFile + ".123"),
		"the lock":               file(runtimeLockFile),
		"codex":                  file(codexHomeName),
		"hook-state":             file(hookStateName),
		"the DNS broker's dir":   env("TEGO_DNS_BROKER_DIR=/elsewhere"),
		"the DNS broker's pid":   env("TEGO_DNS_BROKER_PID=1"),
		"the run id":             env("TEGO_RUN_ID=r-forged"),
		"the parent run":         env("TEGO_PARENT_RUN=r-forged"),
		"the machine config":     env("TEGO_CONFIG=/elsewhere"),
		"a test hook":            env("TEGO_TEST_CHAIN_ANCHOR=/elsewhere"),
	} {
		r := harnessRunner(t, tableFor(harnessContract(harness.Generic, nil)), []string{"/bin/sh"}, &fakeProvisioner{p: p})
		if err := os.Remove(r.reasonFile); err != nil { // as a run has it before its first refusal
			t.Fatal(err)
		}
		if err := r.provisionHarness(); !errors.Is(err, ErrHarnessProvision) {
			t.Errorf("%s: %v, want ErrHarnessProvision", name, err)
		}
		if _, err := os.Lstat(r.reasonFile); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: the reason file was made (%v)", name, err)
		}
	}
}

// TestHarnessHookAdmission is acceptance (5): the provision is made only when the run admits the hook's exact argv;
// otherwise it is dropped whole (no file, no hook-state, no argv or environment change) and run_start says why, with
// a warning naming the rule. An allow-list contract whose own rules do not admit the hook is admitted by the launcher's
// grant of its exact argv (ADR 0064), recorded in harness.hook and runtime_grants; one whose rules admit it already
// (the binary named by path) needs none, and neither does a deny-list.
func TestHarnessHookAdmission(t *testing.T) {
	cases := []struct {
		name    string
		exec    *agent.ExecSection
		why     string
		granted bool
	}{
		{"no exec section", nil, "", false},
		{"a deny-list that denies another program", &agent.ExecSection{Deny: []string{"id"}}, "", false},
		{"a deny-list that denies tego", &agent.ExecSection{Deny: []string{"TEGO"}}, record.HarnessWhyHookRefused, false},
		{"an allow-list", &agent.ExecSection{Allow: []string{"/bin/sh"}}, "", true},
		{"an allow-list that names tego's binary", &agent.ExecSection{Allow: []string{"/bin/sh", "EXE"}}, "", false},
		{"an allow-list that denies tego", &agent.ExecSection{Allow: []string{"/bin/sh"}, Deny: []string{"TEGO"}}, record.HarnessWhyHookRefused, false},
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		ct := harnessContract(harness.ClaudeCode, c.exec)
		if c.exec != nil {
			for i, d := range c.exec.Deny {
				c.exec.Deny[i] = strings.ReplaceAll(d, "TEGO", filepath.Base(exe))
			}
			for i, a := range c.exec.Allow {
				c.exec.Allow[i] = strings.ReplaceAll(a, "EXE", exe)
			}
		}
		rt := compileTable(t, ct)
		var warned []string
		r := harnessRunner(t, rt, []string{"/bin/sh"}, &fakeProvisioner{fn: claudeLike})
		r.deps.Warn = func(code, what string) { warned = append(warned, code+": "+what) }
		before := r.rt
		if err := r.provisionHarness(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		s := r.harness.start
		hook := []string{exe, "hook", "claude-code", "--reason", r.reasonFile}
		if s.Hook == nil || !slices.Equal(s.Hook.Argv, hook) || s.Hook.Granted != c.granted {
			t.Errorf("%s: run_start.harness.hook %+v, want argv %q, granted %v", c.name, s.Hook, hook, c.granted)
		}
		grant := "exec." + agent.HarnessHookGrant + "[" + exe + "]"
		if got := slices.Contains(runtimeGrants(r.rt), grant); got != c.granted || slices.Equal(r.rt.HarnessHook, hook) != c.granted {
			t.Errorf("%s: runtime_grants %q, table hook %q; want the grant %s: %v", c.name, runtimeGrants(r.rt), r.rt.HarnessHook, grant, c.granted)
		}
		if c.why == "" {
			if !s.Provisioned || len(warned) != 0 {
				t.Errorf("%s: run_start.harness %+v, warnings %q; want provisioned", c.name, s, warned)
			}
			continue
		}
		if s.Provisioned || s.Why != c.why || len(s.Files) != 0 || s.StateDir != "" {
			t.Errorf("%s: run_start.harness %+v, want unprovisioned, why %s", c.name, s, c.why)
		}
		if len(warned) != 1 || !strings.HasPrefix(warned[0], WarnHarnessHookRefused+": ") || !strings.Contains(warned[0], "rule ") {
			t.Errorf("%s: warnings %q, want one %s naming the rule", c.name, warned, WarnHarnessHookRefused)
		}
		if r.rt != before || !slices.Equal(r.cmd, []string{"/bin/sh"}) || len(r.harness.env) != 0 {
			t.Errorf("%s: a dropped provision changed the run", c.name)
		}
		if _, err := os.Lstat(filepath.Join(r.runtimeDir, "claude-settings.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a dropped provision wrote its file", c.name)
		}
		if _, err := os.Lstat(filepath.Join(r.runtimeDir, hookStateName)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a dropped provision made hook-state", c.name)
		}
	}
}

// TestHarnessHookUnderTheGate: the hook is judged as compile --test and the supervisor judge an exec, the gate
// after the floor: a gate exec rule scoring the hook into the refused band or the ask band (an exec's ask is refused,
// exec-gate) drops the provision naming the gate rule; one below allow's threshold leaves it.
func TestHarnessHookUnderTheGate(t *testing.T) {
	for _, c := range []struct {
		score int
		why   string
	}{{90, record.HarnessWhyHookRefused}, {60, record.HarnessWhyHookRefused}, {10, ""}} {
		ct := harnessContract(harness.ClaudeCode, nil)
		var n yaml.Node
		if err := yaml.Unmarshal(fmt.Appendf(nil, "rules:\n  - 'exec matches *': %d\n", c.score), &n); err != nil {
			t.Fatal(err)
		}
		ct.Gate = *n.Content[0]
		rt := compileTable(t, ct)
		var warned []string
		r := harnessRunner(t, rt, []string{"/bin/sh"}, &fakeProvisioner{fn: claudeLike})
		r.deps.Warn = func(code, what string) { warned = append(warned, code+": "+what) }
		if err := r.provisionHarness(); err != nil {
			t.Fatalf("score %d: %v", c.score, err)
		}
		s := r.harness.start
		if c.why == "" {
			if !s.Provisioned || len(warned) != 0 {
				t.Errorf("score %d: run_start.harness %+v, warnings %q; want provisioned", c.score, s, warned)
			}
			continue
		}
		if s.Provisioned || s.Why != c.why {
			t.Errorf("score %d: run_start.harness %+v, want unprovisioned, why %s", c.score, s, c.why)
		}
		if len(warned) != 1 || !strings.Contains(warned[0], "rule gate.rules[0]") {
			t.Errorf("score %d: warnings %q, want one naming gate.rules[0]", c.score, warned)
		}
	}
}

// TestHookAdmittedAtBPFLSM: at bpflsm the hook is judged on the plane's own rows, as compile --test's bpflsm column
// is, not on the policy model's. A deny-list that denies tego refuses it at every tier, naming the entry; a table the
// plane cannot hold (an exec entry whose verdict is ask, built by hand as decide's TestPlaneEvaluatorUnbuildable builds
// it: an exec row carries no verdict) refuses every exec in that column, the hook's too, naming plane-unbuildable,
// while the policy model, which the other tiers use and which would admit it at bpflsm too, admits it.
func TestHookAdmittedAtBPFLSM(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hook := &harness.Hook{Argv: []string{exe, "hook", "claude-code", "--reason", "/run/r/last-refusal.json"}}
	tiers := []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}

	denied := compileTable(t, harnessContract(harness.ClaudeCode, &agent.ExecSection{Deny: []string{filepath.Base(exe)}}))
	for _, tier := range tiers {
		if d := AdmitHook(denied, tier, exe, hook); d.Why != record.HarnessWhyHookRefused || !strings.HasPrefix(d.Rule, "exec.deny[") {
			t.Errorf("deny tego at %s: %q %q, want %s naming exec.deny", tier, d.Why, d.Rule, record.HarnessWhyHookRefused)
		}
	}

	unbuildable := compileTable(t, harnessContract(harness.ClaudeCode, nil))
	unbuildable.Exec = append(unbuildable.Exec, agent.ExecRule{Path: "/b/x", Resolved: "/b/x", Verdict: agent.VerdictAsk})
	if decide.NewPlaneEvaluator(unbuildable).Err() == nil {
		t.Fatal("an ask exec entry compiles for the plane")
	}
	if got := decide.NewEvaluator(unbuildable).EvaluateIn(agent.Action{Kind: agent.ActionExec, Path: exe, Argv: hook.Argv},
		backend.TierBPFLSM, decide.Env{}); got.Verdict != agent.VerdictAllow {
		t.Fatalf("the policy model at bpflsm refuses the hook (%+v): the case no longer tells the two columns apart", got)
	}
	for _, tier := range tiers {
		d := AdmitHook(unbuildable, tier, exe, hook)
		why, rule := d.Why, d.Rule
		if tier == backend.TierBPFLSM {
			if why != record.HarnessWhyHookRefused || rule != decide.PlaneUnbuildableRule {
				t.Errorf("unbuildable plane at %s: %q %q, want %s naming %s", tier, why, rule, record.HarnessWhyHookRefused, decide.PlaneUnbuildableRule)
			}
		} else if why != "" {
			t.Errorf("ask entry for another program at %s: %q %q, want admitted", tier, why, rule)
		}
	}
}

// TestHookStateUnderAnExecDirectoryIsRefused:hook-state inside an exec directory entry would make every file the agent
// writes there executable, so the run is refused (execOverGrant, as the CODEX_HOME is).
func TestHookStateUnderAnExecDirectoryIsRefused(t *testing.T) {
	xdg := privateTempDir(t)
	rt := tableFor(harnessContract(harness.ClaudeCode, nil))
	rt.Exec = []agent.ExecRule{{Path: xdg, IsDir: true, Verdict: agent.VerdictAllow, Source: "exec.allow", Raw: xdg}}
	r := harnessRunner(t, rt, []string{"/bin/sh"}, &fakeProvisioner{fn: claudeLike})
	r.rt.Exec[0].Path = filepath.Dir(r.runtimeDir)
	if err := r.provisionHarness(); !errors.Is(err, ErrHookStateExecutable) {
		t.Fatalf("hook-state under an exec directory: %v, want ErrHookStateExecutable", err)
	}
}

// TestHarnessWithNoRuntimeDirectory is acceptance (7): no reason file, no provision, and the reason-unavailable gap.
func TestHarnessWithNoRuntimeDirectory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	p := &fakeProvisioner{fn: claudeLike}
	r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: tableFor(harnessContract(harness.ClaudeCode, nil)), cmd: []string{"/bin/sh"},
		log: slog.New(slog.DiscardHandler), deps: Deps{Harness: func(harness.Name) Provisioner { return p }}}
	if err := r.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	if err := r.provisionHarness(); err != nil {
		t.Fatal(err)
	}
	if s := r.harness.start; len(p.runs) != 0 || s == nil || s.Provisioned || s.Why != record.HarnessWhyReasonUnavailable {
		t.Fatalf("run_start.harness %+v after %d provisions, want reason-unavailable and none", s, len(p.runs))
	}
	r.queue = NewQueue(4)
	r.emitReasonUnavailableGap()
	select {
	case ev := <-r.queue.C():
		var g record.GapPayload
		if ev.Kind != record.KindGap || ev.DecodePayload(&g) != nil || g.What != record.GapRecord || g.Why != GapReasonUnavailable {
			t.Fatalf("gap %+v", g)
		}
	default:
		t.Fatal("no reason-unavailable gap")
	}
	// harness: none says nothing of a reason file it never asked for.
	none := &runner{rt: tableFor(harnessContract(harness.None, nil)), cmd: []string{"/bin/sh"}, queue: NewQueue(4)}
	if err := none.provisionHarness(); err != nil {
		t.Fatal(err)
	}
	none.emitReasonUnavailableGap()
	select {
	case ev := <-none.queue.C():
		t.Fatalf("harness: none wrote %s", ev.Kind)
	default:
	}
}

// TestReadUserFile is acceptance (6): the run's deny_read is honoured as writeCodexHome honours it, at most 2 MiB,
// regular files only (a link is not followed, a FIFO not waited on), an absolute path only, and nothing at euid 0.
func TestReadUserFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write("ok.json", harness.MaxUserFile)
	big := write("big.json", harness.MaxUserFile+1)
	secret := write("secret.json", 10)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	r := &runner{rt: &agent.RuleTable{FS: []agent.FSRule{{Path: secret, Kind: agent.FSDenyRead, Raw: secret}}}}
	defer func(f func() int) { launcherEUID = f }(launcherEUID)
	launcherEUID = func() int { return 1000 } // an unprivileged launcher, whoever runs the test
	if b, err := r.readUserFile(ok); err != nil || len(b) != harness.MaxUserFile {
		t.Fatalf("a 2 MiB file: %d bytes, %v", len(b), err)
	}
	for name, p := range map[string]string{"over 2 MiB": big, "deny_read": secret, "a link": link, "a FIFO": fifo,
		"a directory": dir, "relative": "ok.json", "missing": filepath.Join(dir, "none")} {
		if _, err := r.readUserFile(p); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	launcherEUID = func() int { return 0 }
	if _, err := r.readUserFile(ok); err == nil {
		t.Error("a root launcher read the user's file")
	}
}

// compileTable compiles c as the run would, offline, in a scratch project.
func compileTable(t *testing.T, c *agent.Contract) *agent.RuleTable {
	t.Helper()
	dir := t.TempDir()
	y, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ds, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), y, nil)
	if err != nil {
		t.Fatalf("load: %v %v\n%s", err, ds, y)
	}
	rt, ds, err := agent.Compile(loaded, config.Builtin(), agent.WithCwd(dir), agent.WithHome(dir), agent.WithMountInfo(""),
		agent.WithPATH("/usr/bin:/bin"), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	return rt
}
