// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdRule) }

// cmdRule is `tego rule <run> <seq> --block|--ask|--allow [--folder|--level N|--command|--host] [--dry-run]`: make
// what line #seq of a run shows a rule of the contract that run compiled, so the next run blocks it, asks first, or
// allows it. The scope is the event's file, program or destination, or with --folder the file's folder, --level N
// the folder N-1 levels above that (up to the run's working directory or home), --command the program's command
// ("git push", an exec command rule) and --host the destination's whole host. It prints the
// diff, writes the contract (the old one kept as <file>.bak) unless --dry-run, and says what the next run does
// differently. The write goes through internal/rulefile, as the dashboard's does: the contract must pass its guards,
// and the change is journaled under the run's ledger root (.rule-changes/), where history and undo read it. The new contract is compiled first, as tego compile would, and never written when it does not.
func cmdRule() Command {
	var block, ask, allow, folder, dry, command, host bool
	var level int
	return Command{
		Name:    "rule",
		Summary: "make what a run did a rule of its contract: block, ask or allow it next time",
		Usage:   "<run> <seq> --block|--ask|--allow [--folder|--level N|--command|--host] [--dry-run]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&block, "block", false, "refuse it next time")
			fs.BoolVar(&ask, "ask", false, "hold it next time until you answer")
			fs.BoolVar(&allow, "allow", false, "allow it next time")
			fs.BoolVar(&folder, "folder", false, "name the file's folder, not the file (a read or a write)")
			fs.IntVar(&level, "level", 0, "name an ancestor folder of the file: 1 its folder (as --folder), N the folder N-1 levels above it, up to the run's working directory or home")
			fs.BoolVar(&command, "command", false, "name the program's command (\"git push\": program and subcommand), not the whole program (a run of a program)")
			fs.BoolVar(&host, "host", false, "name the destination's whole host, every port (a connection)")
			fs.BoolVar(&dry, "dry-run", false, "print the diff, write nothing")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			var actions []rule.Action
			for a, on := range map[rule.Action]bool{rule.Block: block, rule.Ask: ask, rule.Allow: allow} {
				if on {
					actions = append(actions, a)
				}
			}
			if fs.NArg() != 2 || len(actions) != 1 {
				message(stderr, "", 0, 0, "tego rule: a run id, a line number and exactly one of --block, --ask, --allow", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			seq, err := strconv.ParseUint(strings.TrimPrefix(fs.Arg(1), "#"), 10, 64)
			if err != nil {
				message(stderr, "", 0, 0, "tego rule: "+fs.Arg(1)+" is not a line number", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			scopes := 0
			for _, on := range []bool{folder, level > 0, command, host} {
				if on {
					scopes++
				}
			}
			if scopes > 1 || level < 0 {
				message(stderr, "", 0, 0, "tego rule: at most one of --folder, --level N (N >= 1), --command, --host", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if folder {
				level = 1
			}
			return runRule(ctx, fs.Arg(0), seq, actions[0], ruleScope{level, command, host}, dry, stdout, stderr)
		},
	}
}

// ruleScope is the rule's scope beyond the event's own target: a folder level, the command, the whole host.
type ruleScope struct {
	level         int
	command, host bool
}

func runRule(ctx context.Context, ref string, seq uint64, a rule.Action, sc ruleScope, dry bool, stdout, stderr io.Writer) int {
	mc := &machineOnce{stderr: stderr}
	dir, err := resolveRunDir(ref, true, mc)
	if err != nil {
		return runRefFailed(stderr, "rule", err)
	}
	m, err := mc.get()
	if err != nil {
		return identity.ExitError
	}
	found, err := rulefile.FindIn(dir, seq, ruleGuard(dir, m))
	if errors.Is(err, rulefile.ErrNoContract) {
		// A watched run has no file to change; the next step is to write one from what it did.
		run := filepath.Base(dir)
		message(stderr, "", 0, 0, fmt.Sprintf("tego rule: %v; once the run has ended, write a contract from what it did "+
			"with tego learn %s --out agent.yaml, then run the agent with tego run agent.yaml", err, run), codeUsage)
		return identity.ExitFinding
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego rule: "+err.Error(), codeIO)
		return identity.ExitError
	}
	check := func(text []byte) error { return compileRule(ctx, m, dir, found, text) }
	req := found.Request(a, false, m.Home, time.Now().Format(time.DateOnly), check)
	req.Level, req.Command, req.HostOnly = sc.level, sc.command, sc.host
	res, err := rule.Apply(req)
	if err != nil {
		what := "tego rule: " + err.Error()
		if strings.Contains(what, agent.CodeExecNotOnPath) {
			// The compile ran on this terminal's PATH (ruleContext), which is what "the run's PATH" there means here.
			what += "; tego rule compiles the change on this terminal's PATH, so run it where the program is on PATH"
		}
		message(stderr, found.Contract, 0, 0, what, codeUsage)
		if errors.Is(err, rule.ErrNothing) || errors.Is(err, rule.ErrRefused) || errors.Is(err, rule.ErrUnsupported) {
			return identity.ExitFinding
		}
		return identity.ExitError
	}
	if _, err := io.WriteString(stdout, res.Diff); err != nil {
		return identity.ExitError
	}
	if dry {
		fmt.Fprintf(stdout, "dry run: nothing written. Without --dry-run the next run of %s will %s.\n", found.Contract, res.Effect)
		return identity.ExitOK
	}
	if res.Direction != rule.Narrows && refuseGoverned("rule", stderr) {
		return identity.ExitFinding
	}
	found.Via, found.Summary = "cli", res.Summary
	bak, err := found.Write(res.Text)
	if err != nil {
		message(stderr, found.Contract, 0, 0, "tego rule: "+err.Error(), codeIO)
		return identity.ExitError
	}
	fmt.Fprintf(stdout, "wrote %s (the old file is %s)\n%s\nThe next run of %s will %s.\n", found.Contract, bak, res.Summary,
		found.Contract, res.Effect)
	return identity.ExitOK
}

// ruleGuard is where tego rule refuses a contract and journals its change: the run directory's parent is the run's
// ledger root (the journal goes there, where the dashboard serving that root reads it), and the machine's ledger root
// and tego's home under m.Home are refused too.
func ruleGuard(dir string, m *config.Machine) rulefile.Guard {
	g := rulefile.DefaultGuard(filepath.Dir(dir))
	if root, err := ledgerRootOf(m); err == nil && root != "" {
		g.Refuse = append(g.Refuse, root)
	}
	if m.Home != "" {
		g.Refuse = append(g.Refuse, filepath.Join(m.Home, ".tego"))
	}
	return g
}

// compileRule compiles text as the contract the run in dir found ran, as tego compiles the next run of it
// (internal/nextrun, the compile the dashboard's rule service calls too): the run's tier, run command grant and
// working directory, offline, on this PATH and then the run's exec directories. The error carries the diagnostics.
func compileRule(ctx context.Context, m *config.Machine, dir string, found *rulefile.Found, text []byte) error {
	_, err := nextrun.Compile(ctx, m, ruleContext(m, dir, found), text)
	return err
}

// ruleContext is the run's compile context as tego rule fills it: this build's tiers for an auto contract whose run
// recorded none, and the launcher's chain anchor and runtime directories.
func ruleContext(m *config.Machine, dir string, found *rulefile.Found) nextrun.Context {
	cc := nextrun.Context{Contract: found.Contract, Cwd: found.Cwd, Tier: found.Tier, Tiers: builtTiers(),
		RunCommandGrant: found.RunCommandGrant, PATH: os.Getenv("PATH"), RunDir: dir, Home: m.Home,
		RuntimeDirs: config.RuntimeDirBases(), Exe: runningBinary()}
	if p, err := anchorPath(m); err == nil {
		cc.Anchor = p
	}
	return cc
}
