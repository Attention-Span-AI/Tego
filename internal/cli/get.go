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
	"text/tabwriter"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdGet) }

// cmdGet is `tego get agents|sessions|presets|approvals [--json]`: one table of a kind of thing. sessions --json is
// tego status --all --json, and approvals is tego ask, so a script reads the shape it already knows.
func cmdGet() Command {
	var asJSON bool
	return Command{
		Name:    "get",
		Summary: "list agents, sessions, presets or approvals",
		Usage:   "agents|sessions|presets|approvals [--json]",
		Flags:   func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "one JSON object") },
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego get: name what to list: agents, sessions, presets or approvals", codeUsage)
				return identity.ExitUsage
			}
			switch fs.Arg(0) {
			case "agents", "agent":
				return getAgents(ctx, asJSON, stdout, stderr)
			case "sessions", "session":
				if asJSON {
					return delegate(ctx, stdout, stderr, "status", "--all", "--json")
				}
				return getSessions(ctx, stdout, stderr)
			case "presets", "preset":
				return getPresets(asJSON, stdout, stderr)
			case "approvals", "approval":
				if asJSON {
					return delegate(ctx, stdout, stderr, "ask", "--json")
				}
				return delegate(ctx, stdout, stderr, "ask")
			}
			message(stderr, "", 0, 0, fmt.Sprintf("tego get: %q is not something tego lists: agents, sessions, presets or approvals", fs.Arg(0)), codeUsage)
			return identity.ExitUsage
		},
	}
}

// delegate runs another tego command in this process, the way Main would.
func delegate(ctx context.Context, stdout, stderr io.Writer, argv ...string) int {
	code, _ := dispatch(ctx, append([]string{"tego"}, argv...), stdout, stderr, commands())
	return code
}

// verbMachine loads the machine config for a verb, printing its diagnostics; nil after printing why it could not.
func verbMachine(verb string, stderr io.Writer) *config.Machine {
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego "+verb+": machine config: "+err.Error(), identity.CodeConfigUntrusted)
		return nil
	}
	return m
}

// allSessions is every run under the ledger root, oldest first, as tego status --all reads them; runs it cannot read
// are left out (tego status --all names them).
func allSessions(ctx context.Context, m *config.Machine) (string, []*status.Snapshot) {
	root, err := ledgerRootOf(m)
	if err != nil {
		return "", nil
	}
	snaps, _ := status.DeriveAll(ctx, root, time.Now())
	return root, snaps
}

// sessionRunning reports whether a session is still going.
func sessionRunning(s *status.Snapshot) bool {
	return !s.Ended && s.St != status.Done && s.St != status.NeverStarted && s.St != status.Lost
}

func getSessions(ctx context.Context, stdout, stderr io.Writer) int {
	m := verbMachine("get", stderr)
	if m == nil {
		return identity.ExitError
	}
	root, snaps := allSessions(ctx, m)
	if len(snaps) == 0 {
		fmt.Fprintln(stdout, "No sessions yet. Start one: tego run AGENT")
		return identity.ExitOK
	}
	pauses := runPauses(root, snaps)
	now := time.Now()
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tAGENT\tSTATUS\tAGE\tBLOCKED")
	for _, s := range snaps {
		state := "ended"
		switch {
		case sessionRunning(s) && pauses[s.Run].Paused:
			state = "paused"
		case sessionRunning(s):
			state = "running"
		}
		age := ""
		if t := runMinted(s.Run); !t.IsZero() {
			age = shortAge(now.Sub(t))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", record.Printable(sessionName(s.Agent, s.Run)), record.Printable(s.Agent), state, age,
			blockedCount(ctx, filepath.Join(root, s.Run)))
	}
	if err := tw.Flush(); err != nil {
		message(stderr, "", 0, 0, "tego get: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return identity.ExitOK
}

// blockedCount is how many actions Tego refused in a session, as its receipt counts them; "" when its record cannot
// be read.
func blockedCount(ctx context.Context, dir string) string {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return ""
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	rc, err := receipt.Compute(ctx, r, receipt.Options{})
	if err != nil {
		return ""
	}
	return fmt.Sprint(rc.Refusals.Total)
}

// agentRow is one agent of tego get agents.
type agentRow struct {
	Name     string   `json:"name"`
	Project  string   `json:"project"`
	Presets  []string `json:"presets"`
	Sessions int      `json:"sessions"`
	File     string   `json:"file"`
}

func getAgents(ctx context.Context, asJSON bool, stdout, stderr io.Writer) int {
	m := verbMachine("get", stderr)
	if m == nil {
		return identity.ExitError
	}
	rows := []agentRow{}
	if m.Registry.Value != "" {
		places, _ := registryPlaces(m)
		places.Dir = "" // the agents saved for this user, wherever this is typed
		ents, _ := os.ReadDir(filepath.Join(m.Registry.Value, registry.AgentsDir))
		_, snaps := allSessions(ctx, m)
		for _, e := range ents {
			name, ok := strings.CutSuffix(e.Name(), ".yaml")
			if !ok || !registry.IsName(name) {
				continue
			}
			row := agentRow{Name: name, Presets: []string{}, File: filepath.Join(m.Registry.Value, registry.AgentsDir, e.Name())}
			if en, err := places.Resolve(name); err == nil {
				if c, _, err := agent.LoadBytes(en.Path, en.Data, profileSources(m)); err == nil {
					row.Presets = append(row.Presets, c.Extends...)
					row.Project = agentProject(c)
				}
			}
			for _, s := range snaps {
				if s.Agent == name && sessionRunning(s) {
					row.Sessions++
				}
			}
			rows = append(rows, row)
		}
	}
	if asJSON {
		return jsonOut("get", stdout, stderr, struct {
			Agents []agentRow `json:"agents"`
		}{rows})
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "No agents yet. Create one: tego start")
		return identity.ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPROJECT\tPRESETS\tSESSIONS")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", r.Name, record.Printable(tildeHome(r.Project, m.Home)), record.Printable(strings.Join(r.Presets, ", ")), r.Sessions)
	}
	if err := tw.Flush(); err != nil {
		message(stderr, "", 0, 0, "tego get: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return identity.ExitOK
}

// agentProject is the folder an agent works in, as its rules file says: the first folder it may change (tego start
// gives the agent its whole project); "" when it may change none.
func agentProject(c *agent.Contract) string {
	if c.FS == nil {
		return ""
	}
	for _, w := range c.FS.Write {
		if w != "/dev/null" {
			return w
		}
	}
	return ""
}

// presetRow is one preset of tego get presets.
type presetRow struct {
	Name    string `json:"name"`
	Promise string `json:"promise"`
}

func getPresets(asJSON bool, stdout, stderr io.Writer) int {
	rows := []presetRow{}
	for _, p := range presets.List() {
		rows = append(rows, presetRow{Name: p.Name, Promise: p.Promise})
	}
	if asJSON {
		return jsonOut("get", stdout, stderr, struct {
			Presets []presetRow `json:"presets"`
		}{rows})
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tWHAT IT DOES")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r.Name, upperFirst(r.Promise))
	}
	if err := tw.Flush(); err != nil {
		message(stderr, "", 0, 0, "tego get: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return identity.ExitOK
}

// jsonOut writes v as one JSON object.
func jsonOut(verb string, stdout, stderr io.Writer, v any) int {
	if err := writeJSON(stdout, v); err != nil {
		message(stderr, "", 0, 0, "tego "+verb+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	return identity.ExitOK
}

// upperFirst is s with its first letter capitalised.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
