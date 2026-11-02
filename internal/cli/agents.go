// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

// codePrivilege is the diagnostic code of a command that needs a privilege it was not given.
const codePrivilege = "privilege"

// Variables so a test can take the privileged path without privilege: the root check, the proc-connector open and
// the /proc root (a directory tree standing in for it).
var (
	agentsPrivileged = config.InitNSRoot
	agentsOpen       = func() (watcher.Source, error) { return procconn.Open() }
	agentsProcRoot   = "/proc"
)

func init() { register(cmdAgents) }

// cmdAgents is `tego agents [--signature <rule>]... [--follow] [--children] [--json]` (docs/poc/agent-watcher.md,
// M2, detection only). It names the agent processes on this machine, the ones a signature recognises, and says for
// each whether it is running inside a tego run. With --follow it goes on listening to the kernel's process events
// (the proc connector) and reports each agent as it starts and as it exits.
//
// It only observes. It never signals, moves, blocks, traces or changes a process, and it writes nothing but its
// report. It needs root: the proc connector needs CAP_NET_ADMIN, and /proc/<pid>/environ and /proc/<pid>/exe of
// other users' processes are root's to read. Without it the command says so and exits 125 [privilege].
//
// With --follow --adopt it is the guard (ADR 0055): each agent it reports outside every governed run
// whose real, effective and saved uid are one --uid is adopted (tego adopt), its tree moved into a run and recorded
// from the kernel; any other is reported and left alone. --uid is required: any local user can name a program claude.
func cmdAgents() Command {
	var (
		specs      []string
		follow     bool
		children   bool
		asJSON     bool
		noDefaults bool
		adoptAll   bool
		uids       []int
		boundary   string
		recordMode string
	)
	return Command{
		Name:    "agents",
		Summary: "(root) list the agent processes running here, and report new ones (observes only, unless --adopt)",
		Usage: "[--signature <rule>]... [--follow [--adopt --uid <uid>... [--boundary <agent.yaml | name>] [--record <mode>]]] " +
			"[--children] [--json] [--no-default-signatures]",
		Flags: func(fs *flag.FlagSet) {
			fs.Func("signature", "a rule naming an agent, added to the list (repeatable): a program name (claude), an absolute path "+
				"(/opt/a/agent), or name=<argv pattern> (web=node .../web/cli.js), or name=file:<dev>:<inode>; "+
				"the same name as a shipped rule replaces it, name= alone removes it", func(s string) error {
				specs = append(specs, s)
				return nil
			})
			fs.BoolVar(&noDefaults, "no-default-signatures", false, "start from an empty list instead of the shipped one (claude, codex, opencode, gemini)")
			fs.BoolVar(&follow, "follow", false, "keep running and report each agent as it starts and exits, until interrupted (observation only: no process is signaled, moved, blocked or changed)")
			fs.BoolVar(&children, "children", false, "with --follow, also report each process an agent starts: its forks, programs and exits")
			fs.BoolVar(&asJSON, "json", false, "one JSON object per line")
			fs.BoolVar(&adoptAll, "adopt", false, "with --follow, adopt each agent found outside a governed run whose uid is a --uid: "+
				"its process tree moves into a run that records it from the kernel (tego adopt); it is released, never killed, when this stops")
			fs.Func("uid", "with --adopt, a uid whose agents are adopted (repeatable; required): real, effective and saved uid must all be it; "+
				"root's processes only with --uid 0", func(v string) error {
				n, err := strconv.ParseUint(v, 10, 32)
				if err != nil {
					return fmt.Errorf("%q is not a uid", v)
				}
				uids = append(uids, int(n))
				return nil
			})
			fs.StringVar(&boundary, "boundary", "", "with --adopt, hold every adopted agent to this contract's file rules and exec allow-list (tego adopt --boundary)")
			fs.StringVar(&recordMode, "record", "", "with --adopt, the record level of each adoption (full|summary|off)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego agents: no arguments; the rules are --signature", codeUsage)
				return identity.ExitUsage
			}
			if children && !follow {
				message(stderr, "", 0, 0, "tego agents: --children needs --follow", codeUsage)
				return identity.ExitUsage
			}
			if adoptAll && !follow {
				message(stderr, "", 0, 0, "tego agents: --adopt needs --follow", codeUsage)
				return identity.ExitUsage
			}
			if boundary == "" && flagGiven(fs, "boundary") {
				// An unset "$CONTRACT" would otherwise adopt every agent record-only, no rule refusing anything.
				message(stderr, "", 0, 0, "tego agents: --boundary is an empty string; name a contract, or leave --boundary out to only record", codeUsage)
				return identity.ExitUsage
			}
			if !adoptAll && (len(uids) > 0 || boundary != "" || recordMode != "") {
				message(stderr, "", 0, 0, "tego agents: --uid, --boundary and --record need --adopt", codeUsage)
				return identity.ExitUsage
			}
			if adoptAll && len(uids) == 0 {
				message(stderr, "", 0, 0, "tego agents: --adopt needs at least one --uid: a signature alone is a name any local user "+
					"can give a program, so the guard adopts only the agents of the users you list (--uid 1000; --uid 0 for root's)", codeUsage)
				return identity.ExitUsage
			}
			if recordMode != "" {
				if _, err := parseRecordMode(recordMode); err != nil {
					message(stderr, "", 0, 0, "tego agents: "+err.Error(), codeUsage)
					return identity.ExitUsage
				}
			}
			var base sig.List
			if !noDefaults {
				base = sig.Default()
			}
			rules, err := sig.Merge(base, specs)
			if err != nil {
				message(stderr, "", 0, 0, "tego agents: --signature: "+err.Error(), codeUsage)
				return identity.ExitUsage
			}
			if len(rules) == 0 {
				message(stderr, "", 0, 0, "tego agents: no signatures to look for: add one with --signature", codeUsage)
				return identity.ExitUsage
			}
			var guardOpts *agentsAdopt
			if adoptAll {
				guardOpts = &agentsAdopt{uids: uids, o: adoptOptions{boundary: boundary, record: recordMode}}
			}
			return runAgents(ctx, rules, follow, children, asJSON, guardOpts, stdout, stderr)
		},
	}
}

// privilegeMessage is the one sentence a refusal for want of privilege says.
const privilegeMessage = "tego agents: needs root (CAP_NET_ADMIN, to listen to the kernel's process events, and the right to read other " +
	"users' /proc entries): run it with sudo; it only observes and changes no process"

// agentsAdopt is the guard's part of `tego agents --follow --adopt`.
type agentsAdopt struct {
	uids []int
	o    adoptOptions
}

func runAgents(ctx context.Context, rules sig.List, follow, children, asJSON bool, adoptAll *agentsAdopt, stdout, stderr io.Writer) int {
	if !agentsPrivileged() {
		message(stderr, "", 0, 0, privilegeMessage, codePrivilege)
		return identity.ExitLauncher
	}
	emit := watcher.Text(stdout)
	if asJSON {
		emit = watcher.JSONLines(stdout)
	}
	var g *guard
	// The guard's adoptions end with this context: cancelled when the watcher stops for any reason, so a watcher that
	// fails never leaves an adopted agent held.
	gctx, gcancel := context.WithCancel(ctx)
	defer gcancel()
	if adoptAll != nil {
		m, cds, err := loadMachine(config.TrustAbort)
		writeConfigDiagnostics(stderr, cds)
		if err != nil {
			configRefused(stderr, "tego agents", err)
			return identity.ExitConfig
		}
		makeOwnDirs(m)
		if g, err = newGuard(gctx, m, adoptAll.uids, adoptAll.o, emit, stderr); err != nil {
			message(stderr, "", 0, 0, "tego agents: "+err.Error(), codeAdoptRefused)
			return identity.ExitLauncher
		}
		emit = g.emit
	}
	var found int
	counted := func(s watcher.Sighting) error {
		if s.Event == watcher.EventAgentStarted {
			found++
		}
		err := emit(s)
		if g != nil {
			g.observe(s)
		}
		return err
	}
	opts := watcher.Options{Rules: rules, Emit: counted, Children: children}
	if g != nil {
		opts.Tap = g // the adopted agents' exit statuses come from the watcher's own events
	}
	w := watcher.New(watcher.NewFS(agentsProcRoot), opts)
	if g != nil {
		fmt.Fprintf(stderr, "tego agents: looking for %s; adopting each one found outside a governed run whose uid is one of %v: "+
			"its process tree moves into a run that records it from the kernel, nothing else moves, and it is released, never "+
			"killed, when this stops\n", ruleNames(rules), adoptAll.uids)
	} else {
		fmt.Fprintf(stderr, "tego agents: looking for %s; this only observes and never signals, moves, blocks or changes a process\n", ruleNames(rules))
	}
	if !follow {
		if err := w.Scan(); err != nil {
			message(stderr, "", 0, 0, "tego agents: "+err.Error(), codeIO)
			return identity.ExitError
		}
		if found == 0 && !asJSON {
			fmt.Fprintln(stdout, "no agent process is running")
		}
		return identity.ExitOK
	}
	src, err := agentsOpen()
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			message(stderr, "", 0, 0, privilegeMessage, codePrivilege)
			return identity.ExitLauncher
		}
		hint := ""
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.EAFNOSUPPORT) {
			hint = " (this kernel has no proc connector: CONFIG_PROC_EVENTS and CONFIG_CONNECTOR)"
		}
		message(stderr, "", 0, 0, "tego agents: "+err.Error()+hint, codeIO)
		return identity.ExitLauncher
	}
	runErr := w.Run(ctx, src)
	gcancel()
	if g != nil {
		// Every adoption ends before the guard does: with ctx done each releases its agent.
		gs := g.wait()
		fmt.Fprintf(stderr, "tego agents: %d agent(s) adopted, %d refused, %d failed; every adopted agent was released or had ended\n",
			gs.adopted, gs.refused, gs.failed)
	}
	if runErr != nil {
		message(stderr, "", 0, 0, "tego agents: "+runErr.Error(), codeIO)
		return identity.ExitError
	}
	st := w.Stats()
	fmt.Fprintf(stderr, "tego agents: stopped; %d agent(s) recognised, %d overrun(s) of the kernel's event buffer, %d session(s) dropped\n",
		st.Matched, st.Overruns, st.Dropped)
	return identity.ExitOK
}

// ruleNames is the distinct rule names, in order, for the one line that says what is being looked for.
func ruleNames(rules sig.List) string {
	var names []string
	seen := map[string]bool{}
	for _, r := range rules {
		if !seen[r.Name] {
			seen[r.Name] = true
			names = append(names, r.Name)
		}
	}
	return strings.Join(names, ", ")
}
