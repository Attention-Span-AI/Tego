// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// runCompileExec is compile --exec (ADR 0048 (4)): one command line, split as an exec pattern is (spaces, "..." and
// '...' grouping a word), evaluated as a compile --test exec row is, through the image floor, the command rules and
// the gate, in every tier a run can get (or --tier's). It prints each interpretation the facts yield with its
// readings, the argv elements the decision read, and the deciding rule per tier column. No YAML table is needed to try
// one command; exit 0 whatever the verdict, since nothing is asserted.
func runCompileExec(rt *agent.RuleTable, m *config.Machine, line string, tiers []backend.Tier, stdout, stderr io.Writer) int {
	argv, _, err := execmatch.SplitWords(line)
	if err != nil || len(argv) == 0 {
		message(stderr, "", 0, 0, "tego compile: --exec: write a command line", codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	a := agent.Action{Kind: agent.ActionExec, Argv: argv}
	w := &lineWriter{w: stdout}
	w.printf("exec %s", record.Printable(strings.Join(argv, " ")))
	if strings.ContainsRune(argv[0], '/') {
		cwd := rowCwd()
		a.Path = absPath(cwd, argv[0])
		// A script's #! line is a fact of the exec, as the supervisor reads it (ADR 0048 (3)): its interpreter, and
		// the line's argument before the script, are the interpretation the kernel runs. Its first stage only.
		interp, arg, ok, err := agent.ReadShebangLine(a.Path)
		switch {
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			w.printf("  #! line not read: %v", err)
		case ok:
			a.Script, a.ScriptArg = absPath(cwd, interp), arg
			line := "#!" + interp
			if arg != "" {
				line += " " + arg
			}
			w.printf("  script: %s", record.Printable(line))
		}
		a, _ = agent.ResolveAction(a, landers(stderr, ""))
	} else {
		w.printf("  a bare name is not looked up, so a script's #! line is not read: give its path to read it")
	}
	from := "--tier"
	if len(tiers) == 0 {
		tiers, from = rt.Reach, reachOrigin(rt, m)
	}
	if rt.ExecCommands != nil {
		f := decide.CommandFacts(rt, a, agent.EvalResult{})
		for _, inv := range rt.ExecCommands.Index.Interpretations(&f) {
			if inv.Via == execmatch.ViaOverflow {
				w.printf("  a dispatcher's dispatch is not resolved within the bounds, so the exec is refused command-unresolved (fail closed)")
				continue
			}
			w.printf("  interpretation %s via %s: %s", record.Printable(inv.Tool), inv.Via, record.Printable(strings.Join(inv.Tokens, " ")))
			for _, r := range inv.Readings {
				w.printf("    reading: %s", record.Printable(describeReading(r)))
			}
		}
		res := decide.ExecCommand(rt, &f)
		w.printf("  k %d of %d argv elements read", res.K, len(argv))
	} else {
		w.printf("  no command rules: the image floor and the gate decide")
	}
	w.printf("tiers %s (%s)", tierList(tiers), from)
	env := testEnv(rt, m)
	var plane *decide.PlaneEvaluator
	if slices.Contains(tiers, backend.TierBPFLSM) {
		plane = decide.NewPlaneEvaluator(rt)
	}
	model := decide.NewEvaluator(rt)
	for _, tier := range tiers {
		var floor agent.EvalResult
		if tier == backend.TierBPFLSM && plane != nil {
			floor = plane.Evaluate(a, env)
		} else {
			floor = model.EvaluateIn(a, tier, env)
		}
		got := agent.EvaluateGateRow(rt, a, floor)
		detail := ""
		if got.CommandRule != "" {
			parts := []string{got.CommandList}
			if got.CommandMatch != "" {
				parts = append(parts, got.CommandMatch) // an unlisted refusal matched no entry
			}
			detail = fmt.Sprintf(" (%s, via %s)", strings.Join(parts, ", "), got.CommandVia)
		} else if got.CommandVia != "" {
			// A fail-closed refusal (command-unresolved) names no entry but carries its via (overflow).
			detail = fmt.Sprintf(" (via %s)", got.CommandVia)
		}
		if got.CompletionUnsupported {
			detail += " completion_unsupported"
		}
		w.printf("  %s: %s %s%s", tier, got.Verdict, record.Printable(got.Rule), detail)
	}
	if w.err != nil {
		message(stderr, "", 0, 0, "tego compile: "+w.err.Error(), codeIO)
		return identity.ExitError // R25: Tego's own error
	}
	return identity.ExitOK
}

// describeReading is one reading as --exec prints it: the subcommand path, the options with their values, the
// operands, and what makes it uncertain.
func describeReading(r execmatch.Reading) string {
	if r.Unlocatable {
		return "unlocatable (a visible rewrite trigger, or too many readings): every deny and ask entry naming the tool matches"
	}
	var parts []string
	if len(r.Path) > 0 {
		parts = append(parts, "subcommand "+strings.Join(r.Path, " "))
	} else {
		parts = append(parts, "no subcommand")
	}
	var opts []string
	for _, h := range r.Hits {
		s := h.Raw
		if h.Opt != nil {
			s = h.Opt.Name
			if h.Neg {
				s = "no-" + s
			}
		}
		if h.Opt == nil {
			s += "?"
		}
		if h.HasValue {
			s += "=" + h.Value
		}
		opts = append(opts, s)
	}
	if len(opts) > 0 {
		parts = append(parts, "options "+strings.Join(opts, " "))
	}
	if len(r.Operands) > 0 {
		parts = append(parts, "operands "+strings.Join(r.Operands, " "))
	}
	switch {
	case r.Corrected:
		parts = append(parts, "git's autocorrection of the token")
	case r.UnknownBefore:
		parts = append(parts, "an option the row does not list stands before the subcommand")
	case r.Unknown:
		parts = append(parts, "an option the row does not list (marked ?)")
	}
	return strings.Join(parts, "; ")
}

// absPath is p made absolute against cwd.
func absPath(cwd, p string) string {
	if strings.HasPrefix(p, "/") || cwd == "" {
		return p
	}
	return cwd + "/" + p
}

// lineWriter writes lines and keeps the first error.
type lineWriter struct {
	w   io.Writer
	err error
}

func (l *lineWriter) printf(format string, args ...any) {
	if l.err != nil {
		return
	}
	_, l.err = fmt.Fprintf(l.w, format+"\n", args...)
}
