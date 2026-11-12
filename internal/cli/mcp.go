// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/mcprelay"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdMCP) }

// mcpJSONVersion is the version of `tego mcp tools --json`.
const mcpJSONVersion = 1

// mcpStdin is where a loosening's y/N is read; a test replaces it.
var mcpStdin io.Reader = os.Stdin

// mcpBeforeLock runs between a switch's read of the overlay and the writers' lock; nil but in tests, which move the
// overlay there.
var mcpBeforeLock func()

// cmdMCP is `tego mcp <tools|allow|ask|deny|reset|relay> ...` (ADR 0126 §4, §6): the live per-tool MCP switches of a
// running run, and the relay shim the run's MCP client starts in place of a relayed stdio server.
//
//	tego mcp tools <run> [--json]                     each relayed server's tools, the decision now and where it comes from
//	tego mcp allow|ask|deny <run> <server> <tool> [--yes]   a live switch for the rest of the run
//	tego mcp reset <run> <server> <tool> [--yes]      drop the switch: the contract decides again
//	tego mcp relay --server <name> [--run <id>] -- <command...>   the stdio shim (run by the agent's MCP client)
//
// A switch that tightens (to deny, or allow to ask) applies at once, and may come from inside the run itself, as
// tego block may. One that loosens asks y/N unless --yes, and is refused from inside any run: an agent cannot widen
// its own governance (refuseGoverned). On a Locked run a switch to a decision looser than the contract's is refused
// ([locked], ADR 0126 §4): such a run loosens from its next run.
func cmdMCP() Command {
	var (
		asJSON, yes bool
		server, run string
	)
	return Command{
		Name:    "mcp",
		Summary: "per-tool MCP rules of a running run, live: see, allow, ask, deny, reset",
		Usage:   "tools <run> [--json] | allow|ask|deny|reset <run> <server> <tool> [--yes] | relay --server <name> -- <command...>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "tools: print as JSON")
			fs.BoolVar(&yes, "yes", false, "allow, ask, reset: do not ask before a change that loosens")
			fs.StringVar(&server, "server", "", "relay: the contract's name of the server")
			fs.StringVar(&run, "run", "", "relay: the run id (informational; the relay is the run's own)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() == 0 {
				message(stderr, "", 0, 0, "tego mcp: name a subcommand: tools, allow, ask, deny, reset or relay", codeUsage)
				return identity.ExitUsage
			}
			args := fs.Args()[1:]
			switch sub := fs.Arg(0); sub {
			case "relay":
				sh := &relayShim{server: server, argv: args, in: os.Stdin, out: os.Stdout, stderr: stderr,
					env: os.Getenv, start: startRelayedServer}
				return sh.run(ctx)
			case "tools":
				if len(args) != 1 {
					message(stderr, "", 0, 0, "tego mcp tools: exactly <run>", codeUsage)
					return identity.ExitUsage
				}
				return mcpTools(args[0], asJSON, stdout, stderr)
			case mcptool.Allow, mcptool.Ask, mcptool.Deny, "reset":
				if len(args) != 3 {
					message(stderr, "", 0, 0, "tego mcp "+sub+": exactly <run> <server> <tool>", codeUsage)
					return identity.ExitUsage
				}
				return mcpSwitch(ctx, sub, args[0], args[1], args[2], yes, stdout, stderr)
			default:
				message(stderr, "", 0, 0, "tego mcp: unknown subcommand "+record.Printable(sub)+"; use tools, allow, ask, deny, reset or relay", codeUsage)
				return identity.ExitUsage
			}
		},
	}
}

// mcpRelayFor builds the run's MCP relay when the contract puts any server behind it (mcp[].tools), nil otherwise:
// a contract without tools: runs exactly as before (ADR 0126 Consequences). A relay that cannot start is said on a
// line naming cmd.
func mcpRelayFor(rt *agent.RuleTable, log *slog.Logger, cmd string, stderr io.Writer) ([]source.Source, int) {
	servers := relayedServers(rt.Contract)
	if len(servers) == 0 {
		return nil, identity.ExitOK
	}
	s, err := mcprelay.New(mcprelay.Options{Servers: servers, Logger: log})
	if err != nil {
		message(stderr, "", 0, 0, cmd+": MCP relay: "+err.Error(), codeRun)
		return nil, identity.ExitLauncher
	}
	return []source.Source{s}, identity.ExitOK
}

// relayedServers are the contract's mcp[] entries with tools:, as the relay takes them.
func relayedServers(c *agent.Contract) []mcprelay.Server {
	if c == nil {
		return nil
	}
	var out []mcprelay.Server
	for _, s := range c.MCP {
		if !s.Relayed() {
			continue
		}
		out = append(out, mcprelay.Server{Name: s.Name, Command: append([]string(nil), s.Command...), URL: s.URL,
			Rules: mcptool.Rules{Allow: s.Tools.Allow, Deny: s.Tools.Deny, Ask: s.Tools.Ask}})
	}
	return out
}

// mcpRunContract is the run's contract as compiled (its run directory's copy).
func mcpRunContract(dir string) (*agent.Contract, error) {
	path := filepath.Join(dir, "contract.yaml")
	data, err := readCopy(path)
	if err != nil {
		return nil, err
	}
	c, _, err := agent.LoadBytes(path, data, sealedSources())
	if err != nil {
		return nil, err
	}
	return c, nil
}

// mcpToolRow is one tool of `tego mcp tools`.
type mcpToolRow struct {
	Tool     string `json:"tool"`
	Contract string `json:"contract"`
	Decision string `json:"decision"`
	Rule     string `json:"rule"`
	Live     bool   `json:"live"`
	Calls    int    `json:"calls"`
	Refused  int    `json:"refused"`
	Asked    int    `json:"asked"`
}

// mcpServerRow is one server of `tego mcp tools`.
type mcpServerRow struct {
	Name      string       `json:"name"`
	Transport string       `json:"transport"`
	Relayed   bool         `json:"relayed"`
	Tools     []mcpToolRow `json:"tools"`
}

func mcpTools(ref string, asJSON bool, stdout, stderr io.Writer) int {
	dir, run, code := blockRun("mcp tools", ref, stderr)
	if code != identity.ExitOK {
		return code
	}
	rows, err := mcpState(dir, run)
	if err != nil {
		message(stderr, "", 0, 0, "tego mcp tools: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if asJSON {
		b, _ := json.MarshalIndent(struct {
			V       int            `json:"v"`
			Run     string         `json:"run"`
			Servers []mcpServerRow `json:"servers"`
		}{mcpJSONVersion, run, rows}, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return identity.ExitOK
	}
	if len(rows) == 0 {
		fmt.Fprintf(stdout, "%s declares no MCP servers.\n", run)
		return identity.ExitOK
	}
	for _, s := range rows {
		state := "behind Tego's relay"
		if !s.Relayed {
			state = "not relayed: add tools: to this server in the contract to get switches"
		}
		fmt.Fprintf(stdout, "%s (%s) %s\n", s.Name, s.Transport, state)
		for _, t := range s.Tools {
			live := ""
			if t.Live {
				live = " (live switch)"
			}
			fmt.Fprintf(stdout, "  %-28s %-5s%s  contract %-5s  calls %d  refused %d  asked %d  %s\n", record.Printable(t.Tool),
				t.Decision, live, t.Contract, t.Calls, t.Refused, t.Asked, t.Rule)
		}
	}
	return identity.ExitOK
}

// mcpState is each declared server with its tools: the ones seen in a tools/list, named by the contract, switched
// live, or called, each with its decision now (pkg/policy/mcptool, the relay's own) and its counts from the ledger.
func mcpState(dir, run string) ([]mcpServerRow, error) {
	c, err := mcpRunContract(dir)
	if err != nil {
		return nil, err
	}
	o, err := mcptools.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		o, err = mcptools.New(run), nil
	}
	if err != nil {
		return nil, err
	}
	seen, _ := mcptools.ReadSeen(dir)
	type key struct{ server, tool string }
	calls, refused, asked := map[key]int{}, map[key]int{}, map[key]int{}
	known := map[key]bool{}
	if rd, err := ledger.OpenReader(dir); err == nil {
		for e, err := range rd.Iter() {
			if err != nil {
				break
			}
			switch {
			case e.Kind == record.KindMCP && e.Source == record.SourceProxy:
				var p record.MCPPayload
				if e.DecodePayload(&p) != nil || p.Tool == "" {
					continue
				}
				k := key{p.Name, p.Tool}
				known[k] = true
				if e.Verdict == record.VerdictAllow {
					calls[k]++
				} else {
					refused[k]++
				}
			case e.Kind == record.KindAsk:
				var p struct {
					Op     string `json:"op"`
					Target string `json:"target"`
				}
				if e.DecodePayload(&p) != nil || p.Op != mcprelay.OpMCPTool {
					continue
				}
				if s, t, ok := strings.Cut(p.Target, " "); ok {
					asked[key{s, t}]++
					known[key{s, t}] = true
				}
			}
		}
		_ = rd.Close()
	}
	var out []mcpServerRow
	for _, s := range c.MCP {
		row := mcpServerRow{Name: s.Name, Transport: mcprelay.TransportStdio, Relayed: s.Relayed()}
		if s.URL != "" {
			row.Transport = mcprelay.TransportHTTP
		}
		rules := mcptool.Rules{}
		names := map[string]bool{}
		if s.Tools != nil {
			rules = mcptool.Rules{Allow: s.Tools.Allow, Deny: s.Tools.Deny, Ask: s.Tools.Ask}
			for _, l := range [][]string{s.Tools.Allow, s.Tools.Deny, s.Tools.Ask} {
				for _, t := range l {
					names[t] = true
				}
			}
		}
		for _, t := range seen[s.Name] {
			names[t] = true
		}
		for _, e := range o.Tools {
			if e.Server == s.Name {
				names[e.Tool] = true
			}
		}
		for k := range known {
			if k.server == s.Name {
				names[k.tool] = true
			}
		}
		sorted := make([]string, 0, len(names))
		for t := range names {
			sorted = append(sorted, t)
		}
		sort.Strings(sorted)
		for _, t := range sorted {
			live := ""
			if e, ok := o.Lookup(s.Name, t); ok && s.Relayed() {
				live = e.Decision
			}
			now := mcptool.Decide(rules, live, s.Name, t)
			if !s.Relayed() {
				now = mcptool.Result{Decision: mcptool.Allow, Rule: "mcp[" + s.Name + "]"}
			}
			k := key{s.Name, t}
			row.Tools = append(row.Tools, mcpToolRow{Tool: t, Contract: mcptool.Contract(rules, s.Name, t).Decision,
				Decision: now.Decision, Rule: now.Rule, Live: live != "", Calls: calls[k], Refused: refused[k], Asked: asked[k]})
		}
		out = append(out, row)
	}
	return out, nil
}

// mcpSwitch is allow, ask, deny and reset.
func mcpSwitch(ctx context.Context, sub, ref, server, tool string, yes bool, stdout, stderr io.Writer) int {
	name := "mcp " + sub
	if !mcptools.ValidName(server) || !mcptools.ValidName(tool) {
		message(stderr, "", 0, 0, "tego "+name+": a server or tool name is ^[A-Za-z0-9_.:/-]{1,128}$", codeUsage)
		return identity.ExitUsage
	}
	dir, run, code := blockRun(name, ref, stderr)
	if code != identity.ExitOK {
		return code
	}
	c, err := mcpRunContract(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": the run's contract: "+err.Error(), codeIO)
		return identity.ExitError
	}
	var decl *agent.MCPServer
	for i := range c.MCP {
		if c.MCP[i].Name == server {
			decl = &c.MCP[i]
		}
	}
	switch {
	case decl == nil:
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: run %s declares no MCP server %s", name, run, record.Printable(server)), codeUsage)
		return identity.ExitUsage
	case !decl.Relayed():
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: server %s is not behind Tego's relay in run %s, so it has no switches; "+
			"add tools: {} to its mcp entry in the contract for the next run", name, server, run), codeUsage)
		return identity.ExitFinding
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	if !held {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s is not running, so a live switch would apply to nothing; "+
			"change the contract's mcp tools for its next run", name, run), codeNotRunning)
		return identity.ExitFinding
	}
	rules := mcptool.Rules{Allow: decl.Tools.Allow, Deny: decl.Tools.Deny, Ask: decl.Tools.Ask}
	o, err := mcptools.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		o, err = mcptools.New(run), nil
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	live := ""
	if e, ok := o.Lookup(server, tool); ok {
		live = e.Decision
	}
	from := mcptool.Decide(rules, live, server, tool)
	to := sub
	if sub == "reset" {
		to = mcptool.Contract(rules, server, tool).Decision
	}
	// A Locked run is never looser than its contract while it runs (ADR 0125), so a switch to a decision looser than the
	// contract's is refused [locked], in the words a lift of a Locked run gets; one that tightens, or a reset to the
	// contract, is taken, as a block and an unblock are. A run_start that cannot be read is refused too, as not known
	// (fail closed; liveblock.ErrStarting, or ErrStartUnreadable for a first line this tego does not read), never as Locked.
	if mcptool.Loosens(mcptool.Contract(rules, server, tool).Decision, to) {
		if err := liveblock.CheckLoosening(liveTarget(run, held, startFacts(dir))); err != nil {
			return fenceRefused(name, err, stderr)
		}
	}
	if to == mcptool.Ask {
		if _, err := os.Stat(filepath.Join(dir, ask.SocketName)); err != nil {
			message(stderr, "", 0, 0, fmt.Sprintf("tego %s: run %s has no approvals (its contract has no ask: section), so an "+
				"asked tool would be refused every time; use deny, or allow", name, run), codeUsage)
			return identity.ExitFinding
		}
	}
	confirmed := false
	if mcptool.Loosens(from.Decision, to) {
		if refuseGoverned(name, stderr) {
			return identity.ExitFinding
		}
		if !yes {
			fmt.Fprintf(stdout, "This loosens %s %s in run %s: %s (by %s) becomes %s for the rest of the run.\nGo ahead? [y/N] ",
				server, record.Printable(tool), run, from.Decision, from.Rule, to)
			line, _ := bufio.NewReader(mcpStdin).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
				fmt.Fprintln(stdout, "Nothing changed.")
				return identity.ExitFinding
			}
		}
		confirmed = true
	} else if refuseCrossRun(name, run, stderr) {
		return identity.ExitFinding
	}
	by := mcptools.By("cli")
	if mcpBeforeLock != nil {
		mcpBeforeLock()
	}
	var changed, stale bool
	_, err = mcptools.Update(ctx, dir, run, func(o *mcptools.Overlay) (bool, error) {
		// Decided again under the writers' lock: the question and refuseGoverned were skipped for the decision read above,
		// and a Deny made since (from another terminal) must not be undone by a loosening nobody confirmed.
		live := ""
		if e, ok := o.Lookup(server, tool); ok {
			live = e.Decision
		}
		from = mcptool.Decide(rules, live, server, tool)
		if mcptool.Loosens(from.Decision, to) && !confirmed {
			stale = true
			return false, nil
		}
		var err error
		if sub == "reset" {
			changed, err = o.Reset(server, tool, by, time.Now())
		} else {
			changed, err = o.Set(server, tool, sub, by, time.Now())
		}
		return changed, err
	})
	if err == nil && stale {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s %s moved to %s while this ran, so making it %s now needs your "+
			"confirmation; run it again", name, server, record.Printable(tool), from.Decision, to), codeUsage)
		return identity.ExitFinding
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	switch {
	case !changed && sub == "reset":
		fmt.Fprintf(stdout, "%s: %s %s had no live switch; the contract decides it (%s)\n", run, server, record.Printable(tool), to)
	case !changed:
		fmt.Fprintf(stdout, "%s: %s %s is already %s\n", run, server, record.Printable(tool), to)
	default:
		fmt.Fprintf(stdout, "%s: %s %s is now %s (was %s by %s)\n", run, server, record.Printable(tool), to, from.Decision, from.Rule)
		fmt.Fprintln(stdout, "The run's relay applies it to the next call, within half a second; the switch lasts for this run.")
	}
	return identity.ExitOK
}
