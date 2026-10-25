// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// SettingsFile is the settings file the provisioner has the launcher make in the run's runtime directory (0444, so
// the agent reads it and cannot change it): the hook, and the user's own --settings merged in.
const SettingsFile = "claude-settings.json"

// envClaudeSettings names the settings file in the agent's environment, for a wrapper and the Agent SDK to pass on
// (pkg/spec/identity EnvClaudeSettings; the adapter may not import identity, and TestNamesMatchTheEngines keeps the
// two equal).
const envClaudeSettings = "TEGO_CLAUDE_SETTINGS"

// claudeName is the basename of the Claude Code CLI: a command with another name is a wrapper, whose argv is left
// as it is.
const claudeName = "claude"

// fixPath is what a refused --settings path asks the user to do instead.
const fixPath = "pass it inline or set harness: none"

// fixSafeMode is what a refused safe-mode session asks the user to do instead.
const fixSafeMode = "drop --safe-mode and CLAUDE_CODE_SAFE_MODE, or set harness: none"

// fixBare is what a refused bare session asks the user to do instead.
const fixBare = "drop --bare and CLAUDE_CODE_SIMPLE, or set harness: none"

// errProvision is a run the provisioner cannot provision.
var errProvision = errors.New("claude-code provision")

// Provisioner is the Claude Code harness's provisioner (agent-contract.md R27, ADR 0062, ADR 0063): it installs
// `tego hook claude-code` in the run through a per-run settings file and nothing else. Claude Code's own files
// (~/.claude, CLAUDE_CONFIG_DIR, a project's .claude/) are never written: a hook there would outlive the run and be
// loaded by every later session, governed or not.
type Provisioner struct{}

// Provision is the run's provision. The hook argv is the tego executable, then hook claude-code --reason <the
// reason file> --mode json. The settings file lists that argv, in exec form, for each event hookEvents names, after the user's
// own --settings entries. For a resolved claude command the argv becomes claude --settings <runtime dir>/
// claude-settings.json and then the user's arguments, their own --settings taken out and merged into the file
// (inline JSON as given; a path read through run.ReadUserFile, refused for a root launcher and for a path the run's
// deny_read covers). Any other command (harness: claude-code set on a wrapper) keeps its argv. Either way the agent's
// environment gains TEGO_CLAUDE_SETTINGS, the file's path. A safe-mode session (--safe-mode in a claude argv, or
// CLAUDE_CODE_SAFE_MODE truthy in the agent's environment or in the user's --settings env block) loads no hook from
// --settings and a bare one (--bare, or CLAUDE_CODE_SIMPLE truthy in the same places) runs no hook at all, so each is
// refused rather than recorded provisioned, and so is a --settings, --safe-mode or --bare after a "--" (parseArgs).
// Nothing is written here: the launcher makes the file.
func (Provisioner) Provision(run harness.Run) (harness.Provision, error) {
	switch {
	case len(run.Argv) == 0:
		return harness.Provision{}, fmt.Errorf("%w: the run has no command", errProvision)
	case run.ReasonFile == "" || run.RuntimeDir == "":
		return harness.Provision{}, fmt.Errorf("%w: the run has no reason file for the hook to read", errProvision)
	case !filepath.IsAbs(run.TegoExe):
		return harness.Provision{}, fmt.Errorf("%w: the tego executable %q is not an absolute path", errProvision, run.TegoExe)
	case envOn(run.Env, envSafeMode):
		return harness.Provision{}, fmt.Errorf("%w: the agent's environment sets %s, under which Claude Code loads no hook but a managed "+
			"policy's, so the agent would never hear of a refusal; %s", errProvision, envSafeMode, fixSafeMode)
	case envOn(run.Env, envSimple):
		return harness.Provision{}, fmt.Errorf("%w: the agent's environment sets %s, under which Claude Code runs no hook, so the agent "+
			"would never hear of a refusal; %s", errProvision, envSimple, fixBare)
	}
	direct := filepath.Base(run.Argv[0]) == claudeName
	var args claudeArgs
	if direct {
		var err error
		if args, err = parseArgs(run.Argv[1:]); err != nil {
			return harness.Provision{}, err
		}
	}
	raw, err := userSettings(run, args)
	if err != nil {
		return harness.Provision{}, err
	}
	user, err := parseUser(raw)
	if err != nil {
		return harness.Provision{}, err
	}
	if truthy(user.env[envSafeMode]) {
		return harness.Provision{}, fmt.Errorf("%w: the user's --settings env sets %s, under which Claude Code loads no hook but a managed "+
			"policy's, so the agent would never hear of a refusal; %s", errProvision, envSafeMode, fixSafeMode)
	}
	if truthy(user.env[envSimple]) {
		return harness.Provision{}, fmt.Errorf("%w: the user's --settings env sets %s, under which Claude Code runs no hook, so the agent "+
			"would never hear of a refusal; %s", errProvision, envSimple, fixBare)
	}
	hook := []string{run.TegoExe, Verb, Harness, "--reason", run.ReasonFile, "--mode", ModeJSON}
	b, err := buildSettings(user, tegoGroups(hook))
	if err != nil {
		return harness.Provision{}, err
	}
	path := filepath.Join(run.RuntimeDir, SettingsFile)
	p := harness.Provision{
		Env:   []string{envClaudeSettings + "=" + path},
		Files: []harness.File{{Dir: harness.Runtime, Name: SettingsFile, Bytes: b}},
		Hook:  &harness.Hook{Argv: hook},
	}
	what := fmt.Sprintf("%s with the hook on %s (--mode %s)", SettingsFile, strings.Join(hookEvents, ", "), ModeJSON)
	if args.hasSettings {
		what += ", the command's own --settings merged in"
	}
	if direct {
		p.Argv = withSettings(run.Argv[0], args.rest, path)
		p.Summary = what + "; claude is given --settings " + path
		// A run with servers behind Tego's MCP relay has its client config in the runtime directory (ADR 0126 §4,
		// TEGO_MCP_CONFIG): claude is pointed at it, in the one-value form, since --mcp-config takes several.
		if cfg := filepath.Join(run.RuntimeDir, mcpConfigFile); regularFile(cfg) {
			p.Argv = append(p.Argv[:1:1], append([]string{"--mcp-config=" + cfg}, p.Argv[1:]...)...)
			p.Summary += " and --mcp-config " + cfg + " (Tego's MCP relay)"
		}
	} else {
		p.Summary = what + "; the command is not claude, so its argv is kept: a wrapper passes --settings \"$" + envClaudeSettings + "\""
	}
	return p, nil
}

// mcpConfigFile is the MCP relay's client config in the run's runtime directory (internal/runtime/mcprelay
// ConfigName, which an adapter may not import).
const mcpConfigFile = "tego-mcp.json"

// regularFile reports whether p is a regular file, no link followed.
func regularFile(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// userSettings is the user's own --settings value as JSON bytes, nil when they gave none. A value that starts with
// "{" (after blanks) is inline JSON, as Claude Code reads it; anything else is a path, which must be absolute and is
// read through run.ReadUserFile: never at euid 0 (a root launcher reads no path a user names), never under the run's
// deny_read (the copy would sit where the agent reads it), and only a regular file of at most 2 MiB.
func userSettings(run harness.Run, args claudeArgs) ([]byte, error) {
	if !args.hasSettings {
		return nil, nil
	}
	v := args.settings
	if strings.HasPrefix(strings.TrimSpace(v), "{") {
		return []byte(v), nil
	}
	switch {
	case run.Root:
		return nil, fmt.Errorf("%w: --settings %s: a root launcher reads none of the user's files; %s", errProvision, v, fixPath)
	case !filepath.IsAbs(v):
		return nil, fmt.Errorf("%w: --settings %s is a relative path; give it absolute, %s", errProvision, v, fixPath)
	}
	b, err := run.ReadUserFile(v)
	if err != nil {
		return nil, fmt.Errorf("%w: --settings %s: %w; %s", errProvision, v, err, fixPath)
	}
	return b, nil
}
