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
	"os"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/modelroutes"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/policy/modelroute"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdRoute) }

// routeJSONVersion is the version of `tego route list --json`.
const routeJSONVersion = 1

// routeStdin is where a widening's y/N is read; a test replaces it.
var routeStdin io.Reader = os.Stdin

// routeBeforeLock runs between routeChange's read of the overlay and the writers' lock; nil but in tests, which move the
// overlay there.
var routeBeforeLock func()

// routeKeyNote is the key layer's sentence for a widening's question, set from its init. What a layer does to a request
// is the layer's to promise, so with no layer the question says only what a route carries.
var routeKeyNote string

// routeQuestion is what a person reads before a widening: where the requests go and what goes with them (ADR 0127 §5).
func routeQuestion(auth, run, route, backend string) string {
	q := fmt.Sprintf("This sends the requests of %s in run %s to %s (%s) from the next one, for the rest of the run: the "+
		"prompts and the request's headers go to that backend, so a key the agent holds itself goes there too.", auth, run, route, backend)
	if routeKeyNote != "" {
		q += " " + routeKeyNote
	}
	return q
}

// cmdRoute is `tego route <list|set|clear> ...` (ADR 0127): the live model routes of a running run.
//
//	tego route list <run> [--json]                each models[] endpoint, the route in force and the routes declared
//	tego route set <run> <endpoint> <route> [--yes]   send the endpoint's requests to a declared route, from the next one
//	tego route clear <run> <endpoint>             send them to the endpoint itself again (the route named direct)
//
// <endpoint> is the models[] entry's host:port (host alone for port 443), or its provider when one entry has it. Only
// routes the run's contract declares can be chosen. A set that widens (to any route but direct) asks y/N unless --yes;
// every change is refused from inside any run, since the agent never chooses its route (refuseGoverned). On a Locked
// run a set to any route but direct is refused ([locked], ADR 0127 §6): such a run loosens from its next run.
func cmdRoute() Command {
	var asJSON, yes bool
	return Command{
		Name:    "route",
		Summary: "model routes of a running run, live: list, set, clear",
		Usage:   "list <run> [--json] | set <run> <endpoint> <route> [--yes] | clear <run> <endpoint>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "list: print as JSON")
			fs.BoolVar(&yes, "yes", false, "set: do not ask before sending an endpoint's requests to another backend")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() == 0 {
				message(stderr, "", 0, 0, "tego route: name a subcommand: list, set or clear", codeUsage)
				return identity.ExitUsage
			}
			args := fs.Args()[1:]
			switch sub := fs.Arg(0); sub {
			case "list":
				if len(args) != 1 {
					message(stderr, "", 0, 0, "tego route list: exactly <run>", codeUsage)
					return identity.ExitUsage
				}
				return routeList(args[0], asJSON, stdout, stderr)
			case "set":
				if len(args) != 3 {
					message(stderr, "", 0, 0, "tego route set: exactly <run> <endpoint> <route>", codeUsage)
					return identity.ExitUsage
				}
				return routeChange(ctx, "route set", args[0], args[1], args[2], yes, stdout, stderr)
			case "clear":
				if len(args) != 2 {
					message(stderr, "", 0, 0, "tego route clear: exactly <run> <endpoint>", codeUsage)
					return identity.ExitUsage
				}
				return routeChange(ctx, "route clear", args[0], args[1], modelroute.Direct, true, stdout, stderr)
			default:
				message(stderr, "", 0, 0, "tego route: unknown subcommand "+record.Printable(sub)+"; use list, set or clear", codeUsage)
				return identity.ExitUsage
			}
		},
	}
}

// routeOptJSON is one route an endpoint may take.
type routeOptJSON struct {
	Name      string `json:"name"`
	Authority string `json:"authority"`
	TLS       bool   `json:"tls"`
}

// routeRowJSON is one endpoint of `tego route list`.
type routeRowJSON struct {
	Endpoint string         `json:"endpoint"`
	Provider string         `json:"provider"`
	Route    string         `json:"route"`
	SendsTo  string         `json:"sends_to"`
	By       string         `json:"by,omitempty"`
	At       *time.Time     `json:"at,omitempty"`
	Routes   []routeOptJSON `json:"routes"`
	Requests map[string]int `json:"requests"`
}

func routeList(ref string, asJSON bool, stdout, stderr io.Writer) int {
	dir, run, code := blockRun("route list", ref, stderr)
	if code != identity.ExitOK {
		return code
	}
	rows, err := routeState(dir, run)
	if err != nil {
		message(stderr, "", 0, 0, "tego route list: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if asJSON {
		b, _ := json.MarshalIndent(struct {
			V      int            `json:"v"`
			Run    string         `json:"run"`
			Models []routeRowJSON `json:"models"`
		}{routeJSONVersion, run, rows}, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return identity.ExitOK
	}
	if len(rows) == 0 {
		fmt.Fprintf(stdout, "%s declares no model endpoint.\n", run)
		return identity.ExitOK
	}
	for _, r := range rows {
		fmt.Fprintf(stdout, "%s (%s): route %s, sends to %s", r.Endpoint, record.Printable(r.Provider), r.Route, r.SendsTo)
		if r.By != "" {
			fmt.Fprintf(stdout, " (set by %s)", record.Printable(r.By))
		}
		fmt.Fprintln(stdout)
		if len(r.Routes) == 1 {
			fmt.Fprintln(stdout, "  no routes declared: add routes: to this models[] entry in the contract to reroute it")
			continue
		}
		for _, o := range r.Routes {
			mark := " "
			if o.Name == r.Route {
				mark = "*"
			}
			tls := "tls"
			if !o.TLS {
				tls = "plaintext"
			}
			fmt.Fprintf(stdout, "  %s %-14s %-32s %-9s requests %d\n", mark, o.Name, o.Authority, tls, r.Requests[o.Name])
		}
	}
	return identity.ExitOK
}

// routeState is each declared models[] entry with the route in force, the routes it may take and the requests the
// ledger says went by each.
func routeState(dir, run string) ([]routeRowJSON, error) {
	c, err := mcpRunContract(dir)
	if err != nil {
		return nil, err
	}
	o, err := modelroutes.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		o, err = modelroutes.New(run), nil
	}
	if err != nil {
		return nil, err
	}
	counts := routeCounts(dir)
	var out []routeRowJSON
	for _, m := range c.Models {
		if m.Port == 0 {
			m.Port = 443
		}
		auth := m.ModelAuthority()
		live, row := "", routeRowJSON{Endpoint: auth, Provider: m.Provider, Requests: map[string]int{}}
		if e, ok := o.Lookup(auth); ok {
			live, row.By = e.Route, e.By
			at := e.At
			row.At = &at
		}
		r, _ := modelroute.Resolve(m, live)
		row.Route, row.SendsTo = r.Name, r.Authority()
		for _, name := range modelroute.Names(m) {
			opt, _ := modelroute.Resolve(m, name)
			row.Routes = append(row.Routes, routeOptJSON{Name: name, Authority: opt.Authority(), TLS: opt.TLS})
			row.Requests[name] = counts[[2]string{auth, name}]
		}
		out = append(out, row)
	}
	return out, nil
}

// routeCounts reads the run's ssl_request lines: per (endpoint, route), how many requests went by it, counted by the
// Model routes page's own counter (modelroute.RequestCounter).
func routeCounts(dir string) map[[2]string]int {
	out := map[[2]string]int{}
	c, err := mcpRunContract(dir)
	if err != nil {
		return out
	}
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return out
	}
	defer func() { _ = rd.Close() }()
	count := modelroute.RequestCounter(c.Models)
	for e, err := range rd.Iter() {
		if err != nil {
			break
		}
		count(e, out)
	}
	return out
}

// routeEndpoint finds the models[] entry ref names: its host:port, its host when the port is 443, or its provider
// when exactly one entry has it.
func routeEndpoint(c *agent.Contract, ref string) (agent.ModelEndpoint, bool) {
	want := ref
	if a, ok := agent.ParseCredentialAuthority(ref); ok {
		want = a
	}
	var byProvider []agent.ModelEndpoint
	for _, m := range c.Models {
		if m.Port == 0 {
			m.Port = 443
		}
		if m.ModelAuthority() == want {
			return m, true
		}
		if strings.EqualFold(strings.TrimSpace(m.Provider), ref) {
			byProvider = append(byProvider, m)
		}
	}
	if len(byProvider) == 1 {
		return byProvider[0], true
	}
	return agent.ModelEndpoint{}, false
}

// routeChange is set and clear: route is a declared route's name, or direct.
func routeChange(ctx context.Context, name, ref, endpoint, route string, yes bool, stdout, stderr io.Writer) int {
	// The agent never chooses its route, so neither direction is taken from inside a run.
	if refuseGoverned(name, stderr) {
		return identity.ExitFinding
	}
	if !modelroutes.ValidRoute(route) {
		message(stderr, "", 0, 0, "tego "+name+": a route name is ^[a-z0-9-]{1,40}$", codeUsage)
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
	m, ok := routeEndpoint(c, endpoint)
	if !ok {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: run %s declares no models[] endpoint %s; see tego route list %s", name, run,
			record.Printable(endpoint), run), codeUsage)
		return identity.ExitUsage
	}
	auth := m.ModelAuthority()
	if _, declared := modelroute.Resolve(m, route); !declared {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s declares no route %s in run %s (declared: %s); only a route the contract "+
			"names can be chosen", name, auth, record.Printable(route), run, strings.Join(modelroute.Names(m), ", ")), codeUsage)
		return identity.ExitUsage
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	if !held {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s is not running, so a route change would apply to nothing", name, run), codeNotRunning)
		return identity.ExitFinding
	}
	// A Locked run is never looser than its contract while it runs (ADR 0125), and its contract starts every endpoint on
	// direct: any other route is refused [locked], in the words a lift of a Locked run gets, while direct is taken, as an
	// unblock is. A run_start that cannot be read is refused too, as not known (fail closed; liveblock.ErrStarting, or
	// ErrStartUnreadable for a first line this tego does not read).
	if route != modelroute.Direct {
		if err := liveblock.CheckLoosening(liveTarget(run, held, startFacts(dir))); err != nil {
			return fenceRefused(name, err, stderr)
		}
	}
	o, err := modelroutes.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		o, err = modelroutes.New(run), nil
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	from := modelroute.Direct
	if e, ok := o.Lookup(auth); ok {
		from = e.Route
	}
	to, _ := modelroute.Resolve(m, route)
	confirmed := yes
	if modelroute.Widens(from, route) && !yes {
		fmt.Fprintf(stdout, "%s\nGo ahead? [y/N] ", routeQuestion(auth, run, route, to.Authority()))
		line, _ := bufio.NewReader(routeStdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(stdout, "Nothing changed.")
			return identity.ExitFinding
		}
		confirmed = true
	}
	by := modelroutes.By("cli")
	if routeBeforeLock != nil {
		routeBeforeLock()
	}
	var changed, stale bool
	_, err = modelroutes.Update(ctx, dir, run, func(o *modelroutes.Overlay) (bool, error) {
		// Decided again under the writers' lock: the question was skipped for the route read above, and a change made
		// since (a clear from another terminal) must not make this a widening nobody confirmed.
		from = modelroute.Direct
		if e, ok := o.Lookup(auth); ok {
			from = e.Route
		}
		if modelroute.Widens(from, route) && !confirmed {
			stale = true
			return false, nil
		}
		var err error
		changed, err = o.Set(auth, route, by, time.Now())
		return changed, err
	})
	if err == nil && stale {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s moved to %s while this ran, so sending it to %s now needs your "+
			"confirmation; run it again", name, auth, from, route), codeUsage)
		return identity.ExitFinding
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	if !changed {
		fmt.Fprintf(stdout, "%s: %s is already on route %s (%s)\n", run, auth, to.Name, to.Authority())
		return identity.ExitOK
	}
	fmt.Fprintf(stdout, "%s: %s now sends to %s (%s); it was on %s\n", run, auth, to.Name, to.Authority(), from)
	fmt.Fprintln(stdout, "The run's forwarder uses it for the next request; a request already streaming finishes where it began.")
	return identity.ExitOK
}
