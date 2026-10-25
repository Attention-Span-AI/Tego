// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// goldenProvisioner is a fixed stand-in shaped like claudecode.Provisioner's provision, for the compile golden.
type goldenProvisioner struct{}

func (goldenProvisioner) Provision(run harness.Run) (harness.Provision, error) {
	settings := run.RuntimeDir + "/claude-settings.json"
	return harness.Provision{
		Argv:    append([]string{run.Argv[0], "--settings", settings}, run.Argv[1:]...),
		Env:     []string{"TEGO_CLAUDE_SETTINGS=" + settings},
		Files:   []harness.File{{Dir: harness.Runtime, Name: "claude-settings.json", Bytes: []byte(`{"hooks":{}}`)}},
		Hook:    &harness.Hook{Argv: []string{run.TegoExe, "hook", "claude-code", "--reason", run.ReasonFile}},
		Summary: "a settings file holding the reason hook",
	}, nil
}

// reservedProvisioner provisions a file in the name of the run's reason file, which the launcher reserves.
type reservedProvisioner struct{}

func (reservedProvisioner) Provision(harness.Run) (harness.Provision, error) {
	return harness.Provision{Files: []harness.File{{Dir: harness.Runtime, Name: "last-refusal.json", Bytes: []byte("{}")}}}, nil
}

// codexHomeProvisioner provisions a file in the run's CODEX_HOME when the run has one, as a Codex provisioner would.
type codexHomeProvisioner struct{}

func (codexHomeProvisioner) Provision(run harness.Run) (harness.Provision, error) {
	if run.CodexHome == "" {
		return harness.Provision{}, nil
	}
	return harness.Provision{Files: []harness.File{{Dir: harness.CodexHome, Name: "hooks.json", Bytes: []byte("{}")}}}, nil
}

// TestCompilePrintsTheHarness is ADR 0062's acceptance (2): compile prints the harness, auto resolved from the
// contract's command, and, when a provisioner exists, what it provisions (golden); with the hook refused by the exec
// rules it warns harness-hook-refused naming the rule. In this build no harness has a provisioner, and compile then
// prints the harness line alone.
func TestCompilePrintsTheHarness(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "agent.yaml")
		if err := os.WriteFile(p, []byte("version: 0\nname: h\ncommand: [sh, -c, \"true\"]\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// This build's own provisioner (internal/adapters): the contract's command is sh, a wrapper, so the settings file
	// is named in TEGO_CLAUDE_SETTINGS and the argv is kept.
	code, out, errs := run(t, "compile", "--offline", write("harness: claude-code\n"))
	if code != identity.ExitOK || !strings.Contains(out, "\nharness   claude-code provisions: claude-settings.json with the hook on ") ||
		!strings.Contains(out, "\nharness   env TEGO_CLAUDE_SETTINGS\n") || strings.Contains(out, "harness   argv") {
		t.Fatalf("claude-code's provisioner: exit %d\n%s\n%s", code, out, errs)
	}
	// A claude command naming its own --settings path: compile reads none of the user's files, so it makes the run's
	// checks of the path, prints the provision made with an empty file in its place and says a run merges the file,
	// unless the run's deny_read covers it, which a run refuses too.
	userSettings := filepath.Join(dir, "my-settings.json")
	if err := os.WriteFile(userSettings, []byte(`{"model":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A claude of the test's own, so compile resolves the command on a host without Claude Code.
	claude := filepath.Join(dir, "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(claude), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claude, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeClaude := func(settings, body string) string {
		p := filepath.Join(dir, "claude.yaml")
		c := fmt.Sprintf("version: 0\nname: h\nharness: claude-code\ncommand: [%q, --settings, %q, -p, hi]\n%s", claude, settings, body)
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	code, out, errs = run(t, "compile", "--offline", writeClaude(userSettings, ""))
	if code != identity.ExitOK || strings.Contains(out, "(a run is refused)") ||
		!strings.Contains(out, "\nharness   claude-code provisions: claude-settings.json with the hook on ") ||
		!strings.Contains(out, "\nharness   argv ") || !strings.Contains(out, "\n"+compileInheritedNote+"\n") ||
		!strings.Contains(out, "\nharness   claude-code merges "+userSettings+" into the file at run time") {
		t.Fatalf("a readable --settings path: exit %d\n%s\n%s", code, out, errs)
	}
	// The provision of a path is checked as a run checks it once the file is read: the exec rules' verdict on the hook
	// (an allow-list's run grants the hook's exact argv, ADR 0064, and drops the provision when the agent could
	// rewrite the tego binary) and the refusal of an env.set that gives a variable the provision sets.
	allow := "exec:\n  allow: [sh, " + strconv.Quote(claude) + "]\n"
	code, out, errs = run(t, "compile", "--offline", writeClaude(userSettings, allow))
	if code != identity.ExitOK || strings.Contains(errs, tegoruntime.WarnHarnessHookRefused) || !strings.Contains(out, "\nharness hook: exact argv; ") ||
		!strings.Contains(out, "merges "+userSettings) {
		t.Fatalf("a --settings path under an allow-list: exit %d\n%s\n%s", code, out, errs)
	}
	tego, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "compile", "--offline", writeClaude(userSettings, allow+"fs:\n  write: ["+strconv.Quote(filepath.Dir(tego))+"]\n"))
	if code != identity.ExitOK || !strings.Contains(errs, "["+tegoruntime.WarnHarnessHookRefused+"]") || !strings.Contains(errs, "harness-hook-writable") ||
		strings.Contains(out, "harness hook: exact argv") || !strings.Contains(out, "merges "+userSettings) {
		t.Fatalf("a --settings path under an allow-list whose write entry holds the tego binary: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run(t, "compile", "--offline", writeClaude(userSettings, "env:\n  set: {TEGO_CLAUDE_SETTINGS: /mine}\n"))
	if code != identity.ExitOK || !strings.Contains(out, "harness   claude-code provisions nothing: ") ||
		!strings.Contains(out, "TEGO_CLAUDE_SETTINGS") || !strings.Contains(out, "(a run is refused)") || strings.Contains(out, "merges "+userSettings) {
		t.Fatalf("a --settings path and env.set TEGO_CLAUDE_SETTINGS: exit %d\n%s\n%s", code, out, errs)
	}
	// The refusal and the merge line echo the contract's own --settings value: escaped for the terminal, so a cloned
	// contract cannot put a control sequence on it.
	code, out, errs = run(t, "compile", "--offline", writeClaude("rel\x1b[2J.json", ""))
	if code != identity.ExitOK || strings.ContainsRune(out, 0x1b) || !strings.Contains(out, "is a relative path") || !strings.Contains(out, "[2J.json") {
		t.Fatalf("a relative --settings path holding ESC: exit %d\n%q\n%s", code, out, errs)
	}
	code, out, errs = run(t, "compile", "--offline", writeClaude(filepath.Join(dir, "s\x1b[2J\n.json"), ""))
	if code != identity.ExitOK || strings.ContainsRune(out, 0x1b) || strings.Contains(out, "[2J\n") || !strings.Contains(out, "harness   claude-code merges ") {
		t.Fatalf("a --settings path holding ESC and a newline: exit %d\n%q\n%s", code, out, errs)
	}
	code, out, errs = run(t, "compile", "--offline", writeClaude(userSettings, "fs:\n  deny_read: ["+strconv.Quote(dir+"/")+"]\n"))
	if code != identity.ExitOK || !strings.Contains(out, "harness   claude-code provisions nothing: ") ||
		!strings.Contains(out, "deny_read covers it") || !strings.Contains(out, "(a run is refused)") {
		t.Fatalf("a --settings path deny_read covers: exit %d\n%s\n%s", code, out, errs)
	}
	// env.set reaches the provisioner as a run's agent environment does: CLAUDE_CODE_SIMPLE (bare mode, which runs no
	// hook) and CLAUDE_CODE_SAFE_MODE are refusals; compile says an inherited variable can still change what a run makes.
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\nenv:\n  set: {CLAUDE_CODE_SIMPLE: \"1\"}\n"))
	if code != identity.ExitOK || !strings.Contains(out, "harness   claude-code provisions nothing: ") || !strings.Contains(out, "CLAUDE_CODE_SIMPLE") ||
		!strings.Contains(out, "(a run is refused)") {
		t.Fatalf("env.set CLAUDE_CODE_SIMPLE: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\nenv:\n  set: {CLAUDE_CODE_SIMPLE: \"0\"}\n"))
	if code != identity.ExitOK || !strings.Contains(out, "(--mode json)") || !strings.Contains(out, "\n"+compileInheritedNote+"\n") {
		t.Fatalf("env.set CLAUDE_CODE_SIMPLE 0: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\nenv:\n  set: {CLAUDE_CODE_SAFE_MODE: \"1\"}\n"))
	if code != identity.ExitOK || !strings.Contains(out, "harness   claude-code provisions nothing: ") || !strings.Contains(out, "CLAUDE_CODE_SAFE_MODE") {
		t.Fatalf("env.set CLAUDE_CODE_SAFE_MODE: exit %d\n%s\n%s", code, out, errs)
	}
	// A pass-list that names nothing inherits nothing, so there is no note.
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\nenv:\n  pass: []\n  set: {PATH: /usr/bin:/bin}\n"))
	if code != identity.ExitOK || strings.Contains(out, compileInheritedNote) {
		t.Fatalf("an empty env.pass: exit %d\n%s\n%s", code, out, errs)
	}
	prevProvisioner := harnessProvisioner
	harnessProvisioner = func(harness.Name) tegoruntime.Provisioner { return nil }
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\n"))
	harnessProvisioner = prevProvisioner
	if code != identity.ExitOK || !strings.Contains(out, "\nharness   claude-code\n") || strings.Contains(out, "provisions") {
		t.Fatalf("no provisioner: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = run(t, "compile", "--offline", write(""))
	if code != identity.ExitOK || !strings.Contains(out, "\nharness   generic (auto, from the contract's command)\n") {
		t.Fatalf("auto: exit %d\n%s", code, out)
	}
	code, out, _ = run(t, "compile", "--offline", "--json", write(""))
	if code != identity.ExitOK || !strings.Contains(out, `"harness":"generic"`) {
		t.Fatalf("--json: exit %d\n%s", code, out)
	}

	defer func(f func(harness.Name) tegoruntime.Provisioner) { harnessProvisioner = f }(harnessProvisioner)
	harnessProvisioner = func(harness.Name) tegoruntime.Provisioner { return goldenProvisioner{} }
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\n"))
	if code != identity.ExitOK || strings.Contains(errs, tegoruntime.WarnHarnessHookRefused) {
		t.Fatalf("a provisioner: exit %d\n%s\n%s", code, out, errs)
	}
	var got []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "harness ") {
			got = append(got, strings.ReplaceAll(l, exe, "<tego>"))
		}
	}
	golden := filepath.Join("testdata", "compile-harness.golden")
	if os.Getenv("TEGO_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(strings.Join(got, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "\n")+"\n" != string(want) {
		t.Errorf("the harness lines drifted from %s:\ngot:\n%s\nwant:\n%s", golden, strings.Join(got, "\n"), want)
	}

	// A deny-list that denies the hook's program: the run would drop the provision, and compile says why.
	code, _, errs = run(t, "compile", "--offline", write("harness: claude-code\nexec:\n  deny: ["+filepath.Base(exe)+"]\n"))
	if code != identity.ExitOK || !strings.Contains(errs, "["+tegoruntime.WarnHarnessHookRefused+"]") || !strings.Contains(errs, "rule exec.deny[") {
		t.Fatalf("a denied hook: exit %d\n%s", code, errs)
	}
	// A gate exec rule scoring the hook into the ask band: compile --test's exec row and the supervisor refuse it.
	code, _, errs = run(t, "compile", "--offline", write("harness: claude-code\ngate:\n  rules:\n    - 'exec matches *': 60\n"))
	if code != identity.ExitOK || !strings.Contains(errs, "["+tegoruntime.WarnHarnessHookRefused+"]") || !strings.Contains(errs, "rule gate.rules[0]") {
		t.Fatalf("a gated hook: exit %d\n%s", code, errs)
	}
	// An allow-list: the run grants the hook's exact argv (ADR 0064), and compile says what holds the grant.
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\nexec:\n  allow: [sh]\n"))
	if code != identity.ExitOK || strings.Contains(errs, tegoruntime.WarnHarnessHookRefused) || !strings.Contains(out, "\nharness hook: exact argv; ") ||
		!strings.Contains(out, "(ADR 0048 R5)\n") {
		t.Fatalf("an allow-list: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = run(t, "compile", "--offline", write("tier: landlock\nharness: claude-code\nexec:\n  allow: [sh]\n"))
	if code != identity.ExitOK || !strings.Contains(out, "\nharness hook: exact argv; best effort against a racing thread at tier landlock (ADR 0048 R5)\n") {
		t.Fatalf("an allow-list at tier landlock: exit %d\n%s", code, out)
	}
	// An allow-list whose write entry holds the tego binary: the agent could rewrite what a grant admits, so a run
	// drops the provision, and compile says why.
	code, out, errs = run(t, "compile", "--offline", write("harness: claude-code\nexec:\n  allow: [sh]\nfs:\n  write: ["+filepath.Dir(exe)+"]\n"))
	if code != identity.ExitOK || !strings.Contains(errs, "harness-hook-writable") || !strings.Contains(errs, "rule fs.write[") ||
		strings.Contains(out, "harness hook: exact argv") {
		t.Fatalf("a writable hook binary: exit %d\n%s\n%s", code, out, errs)
	}
	// A contract whose env.set gives a variable the provision sets: every run of it is refused, and compile says so.
	code, out, _ = run(t, "compile", "--offline", write("harness: claude-code\nenv:\n  set: {TEGO_CLAUDE_SETTINGS: /mine}\n"))
	if code != identity.ExitOK || !strings.Contains(out, "harness   claude-code provisions nothing: ") ||
		!strings.Contains(out, "TEGO_CLAUDE_SETTINGS") || !strings.Contains(out, "(a run is refused)") || strings.Contains(out, "harness   env ") {
		t.Fatalf("env.set gives a provision variable: exit %d\n%s", code, out)
	}
	// A provision naming a file the launcher reserves: a run refuses it, and compile says so.
	harnessProvisioner = func(harness.Name) tegoruntime.Provisioner { return reservedProvisioner{} }
	code, out, _ = run(t, "compile", "--offline", write("harness: claude-code\n"))
	if code != identity.ExitOK || !strings.Contains(out, "harness   claude-code provisions nothing: ") || !strings.Contains(out, "(a run is refused)") {
		t.Fatalf("a reserved name: exit %d\n%s", code, out)
	}
	// A CODEX_HOME file: a run has a CODEX_HOME only when it routes codex through the forwarder, which compile cannot
	// know, so compile shows the file and says when a run makes it, rather than a refusal every routed run contradicts.
	harnessProvisioner = func(harness.Name) tegoruntime.Provisioner { return codexHomeProvisioner{} }
	code, out, _ = run(t, "compile", "--offline", write("harness: codex\n"))
	if code != identity.ExitOK || strings.Contains(out, "provisions nothing") ||
		!strings.Contains(out, "harness   file codex_home/hooks.json (2 bytes, 0600; only in a run that routes codex through the forwarder") {
		t.Fatalf("a CODEX_HOME file: exit %d\n%s", code, out)
	}
}

// TestRunConnectsTheHarnessProvisioners: tego run hands the launcher the adapters' registry as Deps.Harness, nil for every
// harness in this build.
func TestRunConnectsTheHarnessProvisioners(t *testing.T) {
	requireLandlockABI(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevProbe, prevAnchor, prevRun, prevCapture := probeMachine, anchorPath, startRun, captureFor
	t.Cleanup(func() { probeMachine, anchorPath, startRun, captureFor = prevProbe, prevAnchor, prevRun, prevCapture })
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	var got tegoruntime.Deps
	var gotRT *agent.RuleTable
	startRun = func(_ context.Context, rt *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		got, gotRT = d, rt
		return tegoruntime.Result{}, nil
	}
	var stderr bytes.Buffer
	runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"), command: []string{"true"}, offline: true}, &stderr)
	if got.Harness == nil {
		t.Fatalf("Deps.Harness is nil: the run cannot reach a provisioner\n%s", stderr.String())
	}
	for _, n := range harness.Names() {
		if p := got.Harness(n); (p != nil) != (n == harness.ClaudeCode) {
			t.Errorf("Deps.Harness(%s) = %T, want a provisioner for claude-code only in this build", n, p)
		}
	}
	// auto is the harness of the command the run executes: `tego run c.yaml -- claude` for a contract whose own
	// command is sh is a claude-code run, and the contract's own command a generic one (agent-contract.md R27).
	claude := filepath.Join(base, "claude")
	if err := os.WriteFile(claude, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(base, "c.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: c\ncommand: [/bin/sh]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		command []string
		want    harness.Name
	}{{[]string{claude}, harness.ClaudeCode}, {nil, harness.Generic}} {
		gotRT = nil
		stderr.Reset()
		runRun(context.Background(), runOptions{contract: contract, command: c.command, offline: true}, &stderr)
		if gotRT == nil {
			t.Fatalf("tego run c.yaml -- %q: no run\n%s", c.command, stderr.String())
		}
		if gotRT.Harness != c.want {
			t.Errorf("tego run c.yaml -- %q: the table's harness is %s, want %s", c.command, gotRT.Harness, c.want)
		}
	}
}
