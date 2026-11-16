// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdAdd) }

// presetChoices are the rules tego add agent --preset names, the same tego start offers.
var presetChoices = map[string]rulesChoice{
	"base-development": {label: "Base development", presets: []string{"no-secrets", "no-prod", "repo-only-writes"}, writeProject: true},
	"read-only-review": {label: "Read-only review", presets: []string{"no-secrets", "no-prod", "repo-only-writes"}},
}

// cmdAdd is `tego add agent [<name>] --project <folder> [--program …] [--preset …] [--allow-host <host>]…`: tego
// start's agent step by flags, for scripts and for people who know what they want. It writes the agent's rules file
// through the same code as the guide (guideSaveRules) and never replaces an agent of the same name.
func cmdAdd() Command {
	var program, project, preset string
	var hosts []string
	return Command{
		Name:    "add",
		Summary: "add an agent for Tego to supervise: its program, project and rules",
		Usage:   "agent [<name>] --project <folder> [--program claude-code|codex|<command>] [--preset base-development|read-only-review] [--allow-host <host>]...",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&project, "project", "", "the folder the agent works in")
			fs.StringVar(&program, "program", "claude-code", "claude-code, codex, or the command that starts another program")
			fs.StringVar(&preset, "preset", "base-development", "base-development or read-only-review")
			fs.Func("allow-host", "another host the agent may reach (repeatable)", func(v string) error { hosts = append(hosts, v); return nil })
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			return runCreate(ctx, fs.Args(), program, project, preset, hosts, stdout, stderr)
		},
	}
}

func runCreate(ctx context.Context, args []string, program, project, preset string, hosts []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "agent" || len(args) > 2 {
		message(stderr, "", 0, 0, "tego add: use tego add agent [<name>] --project <folder>", codeUsage)
		return identity.ExitUsage
	}
	if project == "" {
		message(stderr, "", 0, 0, "tego add agent: --project names the folder the agent works in", codeUsage)
		return identity.ExitUsage
	}
	rc, ok := presetChoices[preset]
	if !ok {
		message(stderr, "", 0, 0, fmt.Sprintf("tego add agent: --preset %q is not base-development or read-only-review", preset), codeUsage)
		return identity.ExitUsage
	}
	rc.hosts = hosts
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego add agent: machine config: "+err.Error(), config.CodeUntrusted)
		return identity.ExitError
	}
	abs, err := projectPath(project, m.Home, false)
	if err != nil {
		message(stderr, "", 0, 0, "tego add agent: "+err.Error(), codeUsage)
		return identity.ExitUsage
	}
	a, command := guideAgent{}, program
	for _, g := range guideAgents {
		if g.harness != "" && g.harness == program {
			a, command = g, g.command
		}
	}
	if _, err := guideLookPath(strings.Fields(command)[0]); err != nil {
		message(stderr, "", 0, 0, "tego add agent: "+strings.Fields(command)[0]+" isn't installed; tego start can install Claude Code or Codex", codeUsage)
		return identity.ExitUsage
	}
	name := agentNameFor(abs)
	if len(args) == 2 {
		name = args[1]
		if _, err := identity.ParseAgentID(name); err != nil {
			message(stderr, "", 0, 0, fmt.Sprintf("tego add agent: %q is not an agent name ([a-z0-9-]{1,40})", name), codeUsage)
			return identity.ExitUsage
		}
	}
	if file, err := agentFile(m, name); err == nil {
		if _, err := os.Stat(file); err == nil {
			fmt.Fprintf(stdout, "✗ Agent %s already exists: %s\n  Change it: tego edit agent %s\n", name, tildeHome(file, m.Home), name)
			return identity.ExitFinding
		}
	}
	path, code := guideSaveRules(ctx, m, a, command, name, abs, rc, false, false, stderr)
	if code != identity.ExitOK {
		return code
	}
	fmt.Fprintf(stdout, "✓ Agent %s added: %s\n  Start a session: cd %s && tego run %s\n", name, tildeHome(path, m.Home),
		tildeHome(filepath.Clean(abs), m.Home), name)
	return identity.ExitOK
}
