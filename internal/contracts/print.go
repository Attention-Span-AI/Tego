// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// PrintList writes the newcomer list. Verbose includes full hashes, compile
// context and all warnings. First errors and discovery roots are always shown.
func PrintList(w io.Writer, c Catalog, verbose bool) error {
	var err error
	line := func(format string, args ...any) {
		if err != nil {
			return
		}
		for i, v := range args {
			if s, ok := v.(string); ok {
				args[i] = record.Printable(s)
			}
		}
		_, err = fmt.Fprintf(w, format+"\n", args...)
	}
	if g := c.General; g != nil {
		line("General contract: %s", g.State)
		line("%s", g.Note)
		if g.Hash != "" {
			line("General hash: %s", g.Hash)
		}
		if g.Scope != "" {
			line("Scope: %s", g.Scope)
		}
		for _, source := range g.Sources {
			line("  %s: %s (%s)", source.Layer, source.Path, string(source.State))
			if source.SHA256 != "" {
				line("    source sha256: %s", source.SHA256)
			}
			if source.Owner != nil {
				line("    owner uid=%d mode=%s; resolved %s", *source.Owner, source.Mode, source.Resolved)
			}
			if source.Reason != "" {
				line("    %s", source.Reason)
			}
		}
		for _, p := range g.Profiles {
			line("  profile %s (%s): %s", p.Name, string(p.Kind), p.SHA256)
		}
		for _, d := range g.Diagnostics {
			line("  %s", d.Error())
		}
		line("Machine baseline: locked. Configured entries are NOT YET APPLIED to runs.")
		line("Agents outside a Tego run are not held to these rules. Existing own contracts keep their rules until you choose to migrate them.")
	}
	line("Rules files found: %d", len(c.Contracts))
	if len(c.Contracts) == 0 {
		line("No rules files were found.")
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if len(c.Contracts) > 0 {
		if err == nil {
			_, err = fmt.Fprintln(tw, "NAME\tFILE\tCHECK\tHASH\tLAST RAN\tTIER\tSAME TEXT AS LAST RUN")
		}
		for _, e := range c.Contracts {
			check := e.State
			if e.Ambiguous {
				check += "; ambiguous name"
			}
			hash := e.Hash
			if hash == "" {
				hash = "unknown"
			} else if !verbose {
				hash = hash[:12]
			}
			last, tier, same := "never", "-", "-"
			if r := e.LastRun; r != nil {
				last = r.At.UTC().Format(time.RFC3339)
				tier = r.Tier
				same = r.SameContract
			}
			cols := []string{e.Name, e.Path, check, hash, last, tier, same}
			for i := range cols {
				cols[i] = record.Printable(cols[i])
			}
			if err == nil {
				_, err = fmt.Fprintln(tw, strings.Join(cols, "\t"))
			}
		}
		if flushErr := tw.Flush(); err == nil {
			err = flushErr
		}
	}
	for _, e := range c.Contracts {
		if verbose {
			line("%s: cwd %s; found in %s", e.Path, e.Cwd, strings.Join(e.FoundIn, ", "))
			for _, alias := range e.Aliases {
				line("  also found as %s", alias)
			}
			if e.LastRun != nil {
				hash := e.LastRun.ContractHash
				if hash == "" {
					hash = "unknown"
				}
				line("  last run %s; recorded hash %s", e.LastRun.ID, hash)
			}
		}
		first := true
		for _, d := range e.Diagnostics {
			if verbose || (first && d.Severity == agent.SeverityError) {
				line("  %s", diagnosticWords(d))
				if d.Severity == agent.SeverityError {
					first = false
				}
			}
		}
	}
	line("Looked in:")
	for _, r := range c.Roots {
		line("  %s: %s (%s)", r.Kind, r.Path, r.State)
		if r.Problem != "" {
			line("    %s", r.Problem)
		}
	}
	for _, d := range c.Issues {
		line("  %s", diagnosticWords(d))
	}
	if c.Incomplete {
		line("The list is incomplete; see the findings above.")
	}
	line("%s", c.Context)
	line("%s", c.Footer)
	return err
}

// PrintShow writes each compiled rule with provenance, using the existing rule
// view's words. Verbose appends exactly the table that tego rules check prints.
func PrintShow(w io.Writer, s Show, verbose bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Rules file %s\nFile: %s\nCheck: %s\nHash: %s\n", record.Printable(s.Contract.Name), record.Printable(s.Contract.Path), s.Contract.State, s.Contract.Hash)
	for _, r := range s.Rules {
		fmt.Fprintf(&b, "  %s [%s]\n", record.Printable(r.Words), record.Printable(r.Key))
		for _, source := range r.Sources {
			where := source.Kind
			if where == "contract" {
				where = "rules file" // the JSON keeps its kind; a person reads the file's name for it
			}
			if source.File != "" {
				where += " " + source.File
				if source.Line > 0 {
					where += ":" + strconv.Itoa(source.Line)
				}
			}
			fmt.Fprintf(&b, "    from %s\n", record.Printable(where))
		}
	}
	for _, d := range s.Contract.Diagnostics {
		if verbose || d.Severity == agent.SeverityError {
			fmt.Fprintf(&b, "  %s\n", record.Printable(diagnosticWords(d)))
		}
	}
	if verbose && s.Table != "" {
		b.WriteString("\nCompiled table (tego rules check):\n")
		b.WriteString(s.Table)
	}
	fmt.Fprintf(&b, "%s\n%s\n", s.Context, s.Footer)
	_, err := io.WriteString(w, b.String())
	return err
}

func diagnosticWords(d Diagnostic) string {
	return (agent.Diagnostic{File: d.File, Line: d.Line, Col: d.Column, Code: d.Code, Message: d.Message, Severity: d.Severity}).Error()
}
