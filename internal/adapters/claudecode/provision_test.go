// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

const (
	provExe     = "/opt/tego/bin/tego"
	provRunDir  = "/run/user/1000/tego/" + testRun
	provReason  = provRunDir + "/last-refusal.json"
	provSetting = provRunDir + "/" + SettingsFile
)

// userInline is a user's own settings: keys tego leaves alone, and hooks of theirs on an event tego registers too
// (PostToolUse) and on one it does not (PreToolUse).
const userInline = `{"model":"claude-x","permissions":{"allow":["Read","Bash(ls:*)"]},"env":{"A":"<b>&"},` +
	`"hooks":{"PostToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"/usr/bin/true"}]}],` +
	`"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo pre"}]}]}}`

// provRun is a run of argv with the given agent environment; ReadUserFile serves files from user.
func provRun(argv []string, env []string, user map[string]string) harness.Run {
	return harness.Run{
		RunID: testRun, Tier: "landlock", RuntimeDir: provRunDir, ReasonFile: provReason, StateDir: provRunDir + "/hook-state",
		TegoExe: provExe, Argv: argv, Env: env,
		ReadUserFile: func(p string) ([]byte, error) {
			if b, ok := user[p]; ok {
				return []byte(b), nil
			}
			return nil, errors.New(p + ": the run's deny_read covers it [contradiction]")
		},
	}
}

// render is a provision as the goldens hold it: the settings file's content spelled out.
func render(t *testing.T, p harness.Provision) string {
	t.Helper()
	type file struct {
		Dir, Name string
		Content   json.RawMessage
	}
	out := struct {
		Argv    []string
		Env     []string
		Hook    []string
		Summary string
		Files   []file
	}{Argv: p.Argv, Env: p.Env, Summary: p.Summary}
	if p.Hook != nil {
		out.Hook = p.Hook.Argv
	}
	for _, f := range p.Files {
		out.Files = append(out.Files, file{f.Dir.String(), f.Name, f.Bytes})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// provision provisions run and checks what every provision must be: accepted by harness.Provision.Check, one file
// and only in the runtime directory, TEGO_CLAUDE_SETTINGS naming it, and every hook entry in it the hook's exact argv.
func provision(t *testing.T, run harness.Run) harness.Provision {
	t.Helper()
	p, err := Provisioner{}.Provision(run)
	if err != nil {
		t.Fatalf("Provision(%q): %v", run.Argv, err)
	}
	if err := p.Check(run); err != nil {
		t.Fatalf("Provision(%q) is refused by Check: %v", run.Argv, err)
	}
	if len(p.Files) != 1 || p.Files[0].Dir != harness.Runtime || p.Files[0].Name != SettingsFile {
		t.Fatalf("files %+v, want one, %s in the runtime directory", p.Files, SettingsFile)
	}
	if !slices.Equal(p.Env, []string{envClaudeSettings + "=" + provSetting}) {
		t.Errorf("env %q", p.Env)
	}
	if p.Hook == nil || p.Hook.Argv[0] != provExe {
		t.Fatalf("hook %+v", p.Hook)
	}
	var s struct {
		Hooks           map[string][]hookGroup `json:"hooks"`
		DisableAllHooks *bool                  `json:"disableAllHooks"`
	}
	if err := json.Unmarshal(p.Files[0].Bytes, &s); err != nil {
		t.Fatal(err)
	}
	// The flag level outranks user, project and local settings, so its false keeps a true there (a cloned repo's, or
	// one the agent writes mid-run) from turning the hook off.
	if s.DisableAllHooks == nil || *s.DisableAllHooks {
		t.Errorf("disableAllHooks %v, want false set at the top level", s.DisableAllHooks)
	}
	isHook := func(g hookGroup) bool {
		return len(g.Hooks) == 1 && slices.Equal(append([]string{g.Hooks[0].Command}, g.Hooks[0].Args...), p.Hook.Argv)
	}
	events := hookEvents
	for ev, groups := range s.Hooks {
		if !slices.Contains(events, ev) {
			if slices.ContainsFunc(groups, isHook) {
				t.Errorf("%s holds the hook, which is registered for %q only", ev, events)
			}
			continue
		}
		if g := groups[len(groups)-1]; !isHook(g) { // tego's entry is appended after the user's
			t.Errorf("%s: tego's entry %+v is not the hook argv %q", ev, g, p.Hook.Argv)
		}
	}
	for _, ev := range events {
		if _, ok := s.Hooks[ev]; !ok {
			t.Errorf("no %s entry", ev)
		}
	}
	return p
}

// TestProvisionGoldens is acceptance (1), (2), (3) and (4): the argv, the settings file and the hook for a claude
// command, one whose own --settings is merged (inline or by path, which give the same file), and a wrapper (whose
// argv is kept, a --bare in it too: tego does not read a wrapper's arguments). -update rewrites testdata/golden/provision-*.
func TestProvisionGoldens(t *testing.T) {
	claude := "/usr/local/bin/claude"
	userPath := "/home/u/my-settings.json"
	cases := []struct {
		name string
		run  harness.Run
	}{
		{"provision-claude", provRun([]string{claude, "-p", "--permission-mode", "acceptEdits", "do the task"}, []string{"PATH=/usr/bin"}, nil)},
		{"provision-inline", provRun([]string{claude, "-p", "--settings", userInline, "do the task"}, nil, nil)},
		{"provision-path", provRun([]string{claude, "--settings=" + userPath, "-p", "do the task"}, nil, map[string]string{userPath: userInline})},
		{"provision-wrapper", provRun([]string{"/opt/bin/run-claude.sh", "--settings", "ignored", "--bare"}, nil, nil)},
	}
	got := map[string]harness.Provision{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := provision(t, tc.run)
			got[tc.name] = p
			golden(t, tc.name, render(t, p))
		})
	}
	// The same user settings give the same file, inline or read from a path.
	if a, b := got["provision-inline"], got["provision-path"]; len(a.Files) == 1 && len(b.Files) == 1 && string(a.Files[0].Bytes) != string(b.Files[0].Bytes) {
		t.Errorf("inline and path settings differ:\n%s\n%s", a.Files[0].Bytes, b.Files[0].Bytes)
	}
}

// TestProvisionArgv: the flag is inserted at index 1 so that neither a trailing "--" nor a positional prompt takes
// it; only whole elements are read, so a prompt that mentions --settings or --bare is an argument. The hook is always
// in json mode.
func TestProvisionArgv(t *testing.T) {
	claude := "/usr/bin/claude"
	for _, tc := range []struct {
		name string
		argv []string
		want []string
	}{
		{"no arguments", []string{claude}, []string{claude, flagSettings, provSetting}},
		{"a trailing --", []string{claude, "-p", "--", "x"}, []string{claude, flagSettings, provSetting, "-p", "--", "x"}},
		{"a prompt after -- naming the flags", []string{claude, "--", "use --settings=x, --safe-mode"}, []string{claude, flagSettings, provSetting, "--", "use --settings=x, --safe-mode"}},
		{"a prompt naming the flags", []string{claude, "-p", "use --settings=x and --bare"}, []string{claude, flagSettings, provSetting, "-p", "use --settings=x and --bare"}},
		{"their --settings taken out", []string{claude, "-p", "--settings", "{}", "hi"}, []string{claude, flagSettings, provSetting, "-p", "hi"}},
		{"their --settings= taken out", []string{claude, "--settings={}", "hi"}, []string{claude, flagSettings, provSetting, "hi"}},
		{"a name ending in claude", []string{"/usr/bin/notclaude", "x"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := provision(t, provRun(tc.argv, nil, nil))
			if !slices.Equal(p.Argv, tc.want) {
				t.Errorf("argv %q, want %q", p.Argv, tc.want)
			}
			if mode := p.Hook.Argv[len(p.Hook.Argv)-1]; mode != ModeJSON {
				t.Errorf("hook mode %s, want %s", mode, ModeJSON)
			}
		})
	}
}

// TestProvisionRefuses is acceptance (3)'s refusals and the merge's: each refuses the run (the launcher makes that
// exit 125), naming what to do. A path is refused for a root launcher and when the run's ReadUserFile refuses it
// (deny_read covers it, it is no regular file or too large), with 'pass it inline or set harness: none'.
func TestProvisionRefuses(t *testing.T) {
	claude := "/usr/bin/claude"
	root := provRun([]string{claude, "--settings", "/home/u/s.json"}, nil, map[string]string{"/home/u/s.json": "{}"})
	root.Root = true
	noExe := provRun([]string{claude}, nil, nil)
	noExe.TegoExe = "tego"
	noReason := provRun([]string{claude}, nil, nil)
	noReason.ReasonFile = ""
	for _, tc := range []struct {
		name string
		run  harness.Run
		want string
	}{
		{"a path under a root launcher", root, fixPath},
		{"a path deny_read covers", provRun([]string{claude, "--settings", "/home/u/secret.json"}, nil, nil), fixPath},
		{"a relative path", provRun([]string{claude, "--settings", "s.json"}, nil, map[string]string{"s.json": "{}"}), fixPath},
		{"--settings twice", provRun([]string{claude, "--settings", "{}", "--settings={}"}, nil, nil), "given twice"},
		{"--settings with no value", provRun([]string{claude, "-p", "--settings"}, nil, nil), "no value"},
		{"--settings empty", provRun([]string{claude, "--settings="}, nil, nil), "empty value"},
		{"not JSON", provRun([]string{claude, "--settings", "{not json"}, nil, nil), "not one JSON object"},
		{"trailing data", provRun([]string{claude, "--settings", "{} {}"}, nil, nil), "not one JSON object"},
		{"an array", provRun([]string{claude, "--settings", "/home/u/a.json"}, nil, map[string]string{"/home/u/a.json": "[]"}), "not one JSON object"},
		{"null", provRun([]string{claude, "--settings", "/home/u/n.json"}, nil, map[string]string{"/home/u/n.json": "null"}), "null"},
		{"hooks not an object", provRun([]string{claude, "--settings", `{"hooks":[]}`}, nil, nil), "hooks is not an object"},
		{"an event not an array", provRun([]string{claude, "--settings", `{"hooks":{"Stop":{}}}`}, nil, nil), "hooks.Stop is not an array"},
		{"disableAllHooks", provRun([]string{claude, "--settings", `{"disableAllHooks":true}`}, nil, nil), "disableAllHooks"},
		{"disableAllHooks not a boolean", provRun([]string{claude, "--settings", `{"disableAllHooks":"no"}`}, nil, nil), "disableAllHooks"},
		{"an event entry not an object", provRun([]string{claude, "--settings", `{"hooks":{"Stop":[1]}}`}, nil, nil), "hooks.Stop[0] is not an object"},
		{"an entry of an event tego leaves alone", provRun([]string{claude, "--settings", `{"hooks":{"PreToolUse":["x"]}}`}, nil, nil), "hooks.PreToolUse[0] is not an object"},
		{"an event tego leaves alone not an array", provRun([]string{claude, "--settings", `{"hooks":{"PreToolUse":{}}}`}, nil, nil), "hooks.PreToolUse is not an array"},
		{"--safe-mode", provRun([]string{claude, "--safe-mode", "-p", "hi"}, nil, nil), fixSafeMode},
		// Bare mode runs no hook at all (measured with Claude Code 2.1.310): refused as safe mode is.
		{"--bare", provRun([]string{claude, "--bare", "-p", "hi"}, nil, nil), fixBare},
		{"CLAUDE_CODE_SIMPLE", provRun([]string{claude, "-p", "hi"}, []string{"CLAUDE_CODE_SIMPLE=1"}, nil), fixBare},
		{"CLAUDE_CODE_SIMPLE under a wrapper", provRun([]string{"/opt/bin/run-claude.sh"}, []string{"CLAUDE_CODE_SIMPLE=yes"}, nil), fixBare},
		{"CLAUDE_CODE_SIMPLE in their env block", provRun([]string{claude, "--settings", `{"env":{"CLAUDE_CODE_SIMPLE":"1"}}`}, nil, nil), fixBare},
		// Claude Code's option parser takes "--" as the value of an option that takes one (--model --), so a flag
		// after "--" may be a flag: --safe-mode, --settings and --settings= there are refused, never read as a prompt.
		{"--safe-mode after an option's --", provRun([]string{claude, "--model", "--", "--safe-mode", "-p", "hi"}, nil, nil), `after "--"`},
		{"--safe-mode after --", provRun([]string{claude, "-p", "--", "--safe-mode"}, nil, nil), `after "--"`},
		{"--bare after an option's --", provRun([]string{claude, "--model", "--", "--bare"}, nil, nil), `after "--"`},
		{"--bare after --", provRun([]string{claude, "-p", "--", "--bare"}, nil, nil), `after "--"`},
		{"--settings after an option's --", provRun([]string{claude, "--model", "--", "--settings", "/home/u/mine.json"}, nil, nil), `after "--"`},
		{"--settings= after --", provRun([]string{claude, "--", "--settings={}"}, nil, nil), `after "--"`},
		{"--settings after -- and their own", provRun([]string{claude, "--settings", "{}", "--model", "--", "--settings", "{}"}, nil, nil), `after "--"`},
		// The settings file's env block is read by Claude Code as the shell's is: safe mode there is safe mode.
		{"CLAUDE_CODE_SAFE_MODE in their env block", provRun([]string{claude, "--settings", `{"env":{"CLAUDE_CODE_SAFE_MODE":"1"}}`}, nil, nil), fixSafeMode},
		{"env not an object", provRun([]string{claude, "--settings", `{"env":[]}`}, nil, nil), "env is not an object of strings"},
		{"an env value not a string", provRun([]string{claude, "--settings", `{"env":{"A":1}}`}, nil, nil), "env is not an object of strings"},
		// A matcher group must hold a hooks array of objects with a string type, and a string matcher when it has one.
		{"a group with no hooks", provRun([]string{claude, "--settings", `{"hooks":{"Stop":[{}]}}`}, nil, nil), "hooks.Stop[0].hooks is not an array"},
		{"a group whose hooks is a string", provRun([]string{claude, "--settings", `{"hooks":{"Stop":[{"hooks":"x"}]}}`}, nil, nil), "hooks.Stop[0].hooks is not an array"},
		{"a hook not an object", provRun([]string{claude, "--settings", `{"hooks":{"Stop":[{"hooks":[1]}]}}`}, nil, nil), "hooks.Stop[0].hooks[0] is not an object"},
		{"a hook with no type", provRun([]string{claude, "--settings", `{"hooks":{"PreToolUse":[{"hooks":[{"command":"x"}]}]}}`}, nil, nil), "hooks.PreToolUse[0].hooks[0].type is not a string"},
		{"a matcher not a string", provRun([]string{claude, "--settings", `{"hooks":{"PostToolUse":[{"matcher":1,"hooks":[]}]}}`}, nil, nil), "hooks.PostToolUse[0].matcher is not a string"},
		{"CLAUDE_CODE_SAFE_MODE", provRun([]string{claude, "-p", "hi"}, []string{"CLAUDE_CODE_SAFE_MODE=1"}, nil), fixSafeMode},
		{"CLAUDE_CODE_SAFE_MODE under a wrapper", provRun([]string{"/opt/bin/run-claude.sh"}, []string{"CLAUDE_CODE_SAFE_MODE=true"}, nil), fixSafeMode},
		{"a tego that is not absolute", noExe, "not an absolute path"},
		{"no reason file", noReason, "no reason file"},
		{"no command", provRun(nil, nil, nil), "no command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Provisioner{}.Provision(tc.run)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Provision = %q, %v; want an error naming %q", p.Argv, err, tc.want)
			}
		})
	}
	// disableAllHooks: false is what tego writes anyway, and a falsy CLAUDE_CODE_SAFE_MODE or CLAUDE_CODE_SIMPLE (the
	// agent's, or their env block's) is neither safe nor bare mode.
	for _, run := range []harness.Run{
		provRun([]string{claude, "--settings", `{"disableAllHooks":false}`}, nil, nil),
		provRun([]string{claude, "-p", "hi"}, []string{"CLAUDE_CODE_SAFE_MODE=0"}, nil),
		provRun([]string{claude, "--settings", `{"env":{"CLAUDE_CODE_SAFE_MODE":"false"}}`}, nil, nil),
		provRun([]string{claude, "-p", "hi"}, []string{"CLAUDE_CODE_SIMPLE=0"}, nil),
		provRun([]string{claude, "--settings", `{"env":{"CLAUDE_CODE_SIMPLE":"off"}}`}, nil, nil),
	} {
		provision(t, run)
	}
}

// TestProvisionPinsTheModeVariables: the settings file's env block, which Claude Code reads as it reads the shell's,
// sets CLAUDE_CODE_SAFE_MODE and CLAUDE_CODE_SIMPLE "0", so a lower level's env block (a project's
// .claude/settings.json) cannot turn on a mode, safe or bare, in which no hook runs; the user's other entries are kept.
func TestProvisionPinsTheModeVariables(t *testing.T) {
	claude := "/usr/bin/claude"
	for _, tc := range []struct {
		name string
		run  harness.Run
		env  map[string]string
	}{
		{"no env of theirs", provRun([]string{claude, "-p", "hi"}, nil, nil), map[string]string{envSafeMode: "0", envSimple: "0"}},
		{"their env kept", provRun([]string{claude, "--settings", `{"env":{"A":"b","CLAUDE_CODE_SIMPLE":"false"}}`}, nil, nil),
			map[string]string{"A": "b", envSafeMode: "0", envSimple: "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := provision(t, tc.run)
			var f struct {
				Env map[string]string `json:"env"`
			}
			if err := json.Unmarshal(p.Files[0].Bytes, &f); err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(f.Env, tc.env) {
				t.Errorf("env %v, want %v", f.Env, tc.env)
			}
		})
	}
}

// TestProvisionSizeLimit: the merged file stays within Claude Code's 2 MiB limit for a settings file, or the run is
// refused; a user file at the limit leaves no room for the hook.
func TestProvisionSizeLimit(t *testing.T) {
	big := `{"x":"` + strings.Repeat("a", harness.MaxUserFile-8) + `"}`
	run := provRun([]string{"/usr/bin/claude", "--settings", "/home/u/big.json"}, nil, map[string]string{"/home/u/big.json": big})
	if _, err := (Provisioner{}).Provision(run); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("a settings file past 2 MiB: %v", err)
	}
}
