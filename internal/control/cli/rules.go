// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdRules) }

func cmdRules() Command {
	return Command{Name: "rules", Summary: "show a run's rules, their enforcement and hits", Usage: "<run> | --last [--json]",
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			fs := flag.NewFlagSet("tego rules", flag.ContinueOnError)
			fs.SetOutput(stderr)
			fs.Usage = func() {
				fmt.Fprintln(stderr, "usage: tego rules <run> | --last [--json]")
				fs.PrintDefaults()
			}
			asJSON := fs.Bool("json", false, "print the same rules view as the dashboard, as versioned JSON")
			last := fs.Bool("last", false, "select the newest run")
			var positional []string
			for len(args) > 0 {
				if err := fs.Parse(args); err != nil {
					if errors.Is(err, flag.ErrHelp) {
						return identity.ExitOK
					}
					return identity.ExitUsage
				}
				rest := fs.Args()
				consumed := args[:len(args)-len(rest)]
				if len(consumed) > 0 && consumed[len(consumed)-1] == "--" {
					positional = append(positional, rest...)
					break
				}
				args = rest
				if len(args) == 0 {
					break
				}
				positional, args = append(positional, args[0]), args[1:]
			}
			if (*last && len(positional) != 0) || (!*last && len(positional) != 1) {
				diag(stderr, "tego rules needs one run id or --last", codeUsage, "run tego rules --last")
				return identity.ExitUsage
			}
			mr := loadMachineReport()
			for _, d := range mr.diags {
				fmt.Fprintln(stderr, d.String())
			}
			if why, code := mr.envSkip(); why != "" {
				diag(stderr, "tego rules: TEGO_CONFIG was skipped: "+record.Printable(why), code, "fix the config file, then run tego rules --last")
				return identity.ExitError
			}
			if mr.err != nil {
				diag(stderr, "tego rules: "+mr.err.Error(), codeIO, "check TEGO_CONFIG, then run tego rules --last")
				return identity.ExitError
			}
			root, err := ledgerRootOf(mr.m, mr.secure)
			if err != nil {
				diag(stderr, "tego rules: "+err.Error(), codeIO, "check ledger_root in TEGO_CONFIG")
				return identity.ExitError
			}
			ref := ""
			if len(positional) == 1 {
				ref = positional[0]
			}
			id, err := rulesRunID(root, ref, *last)
			if err != nil {
				if errors.Is(err, errRulesNoRuns) {
					diag(stderr, "tego rules: there are no runs yet", codeNotFound, "run tego init --preset no-secrets,repo-only-writes --write ./out, then tego run agent.yaml")
					return identity.ExitError
				}
				code := identity.ExitError
				if errors.Is(err, errRulesRun) {
					code = identity.ExitUsage
				}
				reason := codeIO
				if code == identity.ExitUsage {
					reason = codeUsage
				}
				diag(stderr, "tego rules: "+err.Error(), reason, "tego status --all lists the runs")
				return code
			}
			anchor, err := anchorPath()
			if err != nil {
				diag(stderr, "tego rules: "+err.Error(), codeIO, "check the chain anchor, then run tego rules --last")
				return identity.ExitError
			}
			v := rulesview.InForce(ctx, root, id, rulesview.Options{Machine: mr.m, Anchor: anchor, Profiles: profilesrc.Chain(mr.m)})
			if v.Err != "" {
				diag(stderr, "tego rules: "+v.Err, codeIO, "run tego events "+id+" --verify")
				return identity.ExitError
			}
			if *asJSON {
				err = json.NewEncoder(stdout).Encode(struct {
					V int `json:"v"`
					*rulesview.InForceView
				}{1, v})
			} else {
				err = writeRules(stdout, v)
			}
			if err != nil {
				diag(stderr, "tego rules: "+err.Error(), codeIO, "check the output destination")
				return identity.ExitError
			}
			if v.LiveErr != "" {
				return identity.ExitError
			}
			return identity.ExitOK
		}}
}

var (
	errRulesRun    = errors.New("no unique run")
	errRulesNoRuns = errors.New("there are no runs yet")
)

func rulesRunID(root, ref string, last bool) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var ids []string
	for _, e := range entries {
		id := e.Name()
		if !ledger.IsRunID(id) {
			continue
		}
		// A prefix must extend four characters past r-<host8>-, as the engine's run arguments do.
		if last && e.IsDir() || id == ref || len(ref) >= 15 && strings.HasPrefix(id, ref) || len(ref) >= 4 && strings.HasSuffix(id, ref) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		if last {
			return "", errRulesNoRuns
		}
		return "", fmt.Errorf("%w: %q matches no run", errRulesRun, ref)
	}
	slices.SortFunc(ids, func(a, b string) int { return ledger.CompareRunIDs(b, a) })
	if last {
		for _, id := range ids {
			st, err := os.Lstat(filepath.Join(root, id, ledger.EventsFile))
			if errors.Is(err, os.ErrNotExist) {
				continue // A launch can end before it creates or appends its first event.
			}
			if err != nil {
				return "", fmt.Errorf("run %s: inspect events: %w", id, err)
			}
			if !st.Mode().IsRegular() {
				return "", fmt.Errorf("run %s: events is not a regular file", id)
			}
			if st.Size() > 0 {
				return id, nil // Read/verification errors must reach InForce, never select an older record.
			}
		}
		return "", errRulesNoRuns
	}
	if len(ids) == 1 {
		return ids[0], nil
	}
	return "", fmt.Errorf("%w: %q matches several runs; give more of its id", errRulesRun, ref)
}

func writeRules(w io.Writer, v *rulesview.InForceView) error {
	p := record.Printable
	var b strings.Builder
	fmt.Fprintf(&b, "Rules for run %s (%s), tier %s\n", p(v.Run), p(v.View.Agent), p(v.View.Tier))
	if v.Ended {
		b.WriteString("The run has ended; these are the rules it ran with.\n")
	}
	if v.PositionsWhy != "" {
		fmt.Fprintf(&b, "Sources: run copy (%s).\n", p(v.PositionsWhy))
	}
	for _, note := range v.View.Notes {
		fmt.Fprintf(&b, "%s\n", p(note))
	}
	for _, g := range v.View.Groups {
		if len(g.Rules) == 0 && g.Default == "" {
			continue
		}
		fmt.Fprintf(&b, "\n%s\n", p(g.Title))
		if g.Lede != "" {
			fmt.Fprintf(&b, "  %s\n", p(g.Lede))
		}
		for _, r := range g.Rules {
			fmt.Fprintf(&b, "  %s", p(r.Sentence))
			if r.EnforcedText != "" {
				fmt.Fprintf(&b, " [%s]", p(r.EnforcedText))
			}
			fmt.Fprintf(&b, " (hits: %d; %s", r.Hits, p(r.Source.Origin))
			if r.Source.File != "" {
				fmt.Fprintf(&b, " %s:%d", p(r.Source.File), r.Source.Line)
			}
			b.WriteString(")\n")
		}
		if g.Default != "" {
			fmt.Fprintf(&b, "  %s (hits: %d)\n", p(g.Default), g.DefaultHits)
		}
	}
	for _, r := range v.EndedLive {
		fmt.Fprintf(&b, "\n%s (hits: %d)\n", p(r.Sentence), r.Hits)
	}
	if v.LiveErr != "" {
		fmt.Fprintf(&b, "Live blocks could not be read: %s\n", p(v.LiveErr))
	}
	if v.Pending != nil {
		if v.Pending.Unchecked {
			b.WriteString("\nThe rules file was edited after this run started; its current rules could not be compared.\n")
		} else {
			b.WriteString("\nThe rules file differs from this run.\n")
		}
		fmt.Fprintf(&b, "Check it with tego compile %s\n", shellArg(p(v.Source)))
	}
	fmt.Fprintf(&b, "\nNext: tego receipt %s\n", p(v.Run))
	_, err := io.WriteString(w, b.String())
	return err
}

func shellArg(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
