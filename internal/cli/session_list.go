// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// cmdSessionList is `tego session list [--json]`: one line per session. --json is tego status --all --json, so a script
// reads the shape it already knows.
func cmdSessionList() Command {
	var asJSON bool
	return Command{
		Name:    "session list",
		Summary: "list sessions",
		Usage:   "[--json]",
		Flags:   func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "print tego status --all --json") },
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego session list: takes no arguments", codeUsage)
				return identity.ExitUsage
			}
			if asJSON {
				return delegate(ctx, stdout, stderr, "status", "--all", "--json")
			}
			return listSessions(ctx, stdout, stderr)
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

func listSessions(ctx context.Context, stdout, stderr io.Writer) int {
	m := verbMachine("session list", stderr)
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
	fmt.Fprintln(tw, "NAME\tAGENT\tSTATUS\tSTARTED\tBLOCKED")
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
			age = shortAge(now.Sub(t)) + " ago"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", record.Printable(sessionName(s.Agent, s.Run)), record.Printable(s.Agent), state, age,
			blockedCount(ctx, filepath.Join(root, s.Run)))
	}
	if err := tw.Flush(); err != nil {
		message(stderr, "", 0, 0, "tego session list: "+err.Error(), codeIO)
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
