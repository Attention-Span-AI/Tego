// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/adapters"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// harnessProvisioner connects Layer 3's provisioners (internal/adapters) to the launcher (Deps.Harness) and to compile's
// harness lines (agent-contract.md R27, ADR 0062): nil for a harness this build cannot provision. A variable so a test
// can stand a provisioner in.
var harnessProvisioner = func(name harness.Name) tegoruntime.Provisioner {
	if p := adapters.For(name); p != nil {
		return p
	}
	return nil
}

// compileRunDir is how compile spells the runtime directory a run will make: its path holds the run id.
const compileRunDir = "$XDG_RUNTIME_DIR/tego/<run id>"

// compileCodexHome is how compile spells the run's own CODEX_HOME. A run has one only when it routes codex through
// the forwarder (writeCodexHome), which compile cannot know, so compile asks the provisioner as for a run that has one,
// and its CODEX_HOME files' lines say when a run makes them.
const compileCodexHome = compileRunDir + "/codex"

// compileUserFile is compile's answer to a provisioner's Run.ReadUserFile for a path the run's checks admit: compile
// reads none of the user's files, so the provisioner merges an empty settings object, and compile says that a run
// merges the file (a run is refused if it cannot read or merge it).
const compileUserFile = "{}"

// compileInheritedNote is the line compile adds to a provision when the contract inherits any of the launcher's
// environment: compile gives the provisioner the contract's env.set alone, and a provisioner may read the agent's
// environment (claude-code refuses a run whose agent sets CLAUDE_CODE_SIMPLE or CLAUDE_CODE_SAFE_MODE).
const compileInheritedNote = "harness   from env.set alone: a variable the run inherits can change what a run provisions"

// compileAgentEnv is the agent environment compile gives the provisioner: the contract's env.set, in name order,
// without the names env.deny drops, as a run's agent environment holds them (buildEnv). What a run inherits from the
// launcher is not known at compile time (compileInheritedNote).
func compileAgentEnv(rt *agent.RuleTable) []string {
	var env []string
	for _, name := range slices.Sorted(maps.Keys(rt.Set)) {
		if !slices.Contains(rt.Deny, name) {
			env = append(env, name+"="+rt.Set[name])
		}
	}
	return env
}

// printHarnessProvision prints, after the rule table, what the harness's provisioner would make for a run of the
// contract's own command, and warns harness-hook-refused, naming the rule, when the table's exec rules would not admit
// its hook (the run then provisions nothing). It prints nothing for none, for auto (a contract with no command), or for
// a harness with no provisioner. A provisioner's error, or a provision CheckProvision refuses, is printed, never the
// compile's: the run would refuse it.
func printHarnessProvision(stdout, stderr io.Writer, label string, rt *agent.RuleTable) error {
	name := rt.Harness
	if name == harness.Auto || name == harness.None || name == "" || rt.Contract == nil || len(rt.Contract.Command) == 0 {
		return nil
	}
	p := harnessProvisioner(name)
	if p == nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// unread is the user's files the provisioner asked for: compile reads none of them, so it makes the run's checks of
	// each path (tegoruntime.CheckUserFile) and, when they pass, answers compileUserFile. The provision is then checked
	// as a run checks it (CheckProvision, HookAdmitted) and printed with a line naming each file a run merges in.
	var unread []string
	run := harness.Run{
		RunID: "<run id>", Tier: string(rt.Tier), RuntimeDir: compileRunDir,
		ReasonFile: compileRunDir + "/last-refusal.json", StateDir: compileRunDir + "/hook-state", CodexHome: compileCodexHome, TegoExe: exe,
		Argv: rt.Contract.Command, Env: compileAgentEnv(rt), AllowList: !rt.ExecUnrestricted(),
		ReadUserFile: func(path string) ([]byte, error) {
			if err := tegoruntime.CheckUserFile(rt, path); err != nil {
				return nil, err
			}
			unread = append(unread, path)
			return []byte(compileUserFile), nil
		},
	}
	prov, err := p.Provision(run)
	if err == nil {
		err = tegoruntime.CheckProvision(rt, run, prov)
	}
	if err != nil {
		_, werr := fmt.Fprintln(stdout, record.Printable(fmt.Sprintf("harness   %s provisions nothing: %v (a run is refused)", name, err)))
		return werr
	}
	var b strings.Builder
	if prov.Summary != "" {
		fmt.Fprintf(&b, "harness   %s provisions: %s\n", name, prov.Summary)
	}
	for _, path := range unread {
		// The path is the contract's, escaped here: a newline in it would otherwise split the line before the
		// per-line escaping below, and forge one.
		fmt.Fprintf(&b, "harness   %s merges %s into the file at run time (compile reads none of the user's files, so the sizes "+
			"below are without it; a run is refused if it cannot read or merge it)\n", name, record.Printable(path))
	}
	for _, f := range prov.Files {
		mode := "0444"
		if f.Dir == harness.CodexHome {
			mode = "0600; only in a run that routes codex through the forwarder, which a run without one refuses"
		}
		fmt.Fprintf(&b, "harness   file %s/%s (%d bytes, %s)\n", f.Dir, filepath.Base(f.Name), len(f.Bytes), mode)
	}
	if prov.Argv != nil {
		fmt.Fprintf(&b, "harness   argv %q\n", prov.Argv)
	}
	for _, kv := range prov.Env {
		k, _, _ := strings.Cut(kv, "=")
		fmt.Fprintf(&b, "harness   env %s\n", k)
	}
	d := tegoruntime.AdmitHook(rt, rt.Tier, exe, prov.Hook)
	if prov.Hook != nil {
		fmt.Fprintf(&b, "harness   hook %q\n", prov.Hook.Argv)
		if d.Granted {
			b.WriteString(rt.HarnessHookNote() + "\n")
		}
		b.WriteString("harness   hook-state " + run.StateDir + " (the one place in the runtime directory the agent may write)\n")
	}
	if rt.Env == nil || len(rt.Env) > 0 {
		b.WriteString(compileInheritedNote + "\n")
	}
	for _, line := range strings.SplitAfter(b.String(), "\n") {
		if line == "" {
			continue
		}
		// Each line escaped for the terminal: a provision's argv and names come from the user's command and files.
		if _, err := io.WriteString(stdout, record.Printable(strings.TrimSuffix(line, "\n"))+"\n"); err != nil {
			return err
		}
	}
	if d.Why != "" {
		detail := ""
		if d.Detail != "" {
			detail = ": " + d.Detail
		}
		message(stderr, label, 0, 0, fmt.Sprintf("warning: harness %s is not provisioned: its hook is not admitted by the exec rules (%s, rule %s%s); "+
			"a run gives the agent TEGO_REASON only", name, d.Why, d.Rule, detail), tegoruntime.WarnHarnessHookRefused)
	}
	return nil
}
