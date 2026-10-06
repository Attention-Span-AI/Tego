// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// CommandResult is a command-rule decision: the verdict, the rule, the list, definite or ambiguous, the
// interpretation that decided, and k, the argv elements it read (ADR 0048 (4)).
type CommandResult = execmatch.Result

// ExecCommand decides an exec's facts against the table's command rules (ADR 0048 (4)): the one decision both the
// supervisor and compile --test ask (ADR 0028). Normalization runs once per exec per row, never once per rule, and
// an exec whose tool no pattern names costs an index lookup. A table without command rules decides nothing.
func ExecCommand(rt *agent.RuleTable, f *execmatch.Facts) CommandResult {
	if rt == nil || rt.ExecCommands == nil {
		return CommandResult{Final: true, K: len(f.Argv)}
	}
	return rt.ExecCommands.Index.Decide(f)
}

// CommandFacts are the facts a compile --test exec row gives (ADR 0048 (4)): the requested name is the row's path or
// argv[0], the image the file the floor's rule resolved to, argv the row's (argv[0] the path when the row gives
// none), and a #! chain of one stage when the row names a script interpreter. A row has no file identity: compile
// --test makes no stat of a row's own file.
func CommandFacts(rt *agent.RuleTable, a agent.Action, floor agent.EvalResult) execmatch.Facts {
	argv := a.Argv
	if len(argv) == 0 && a.Path != "" {
		argv = []string{a.Path}
	}
	requested := a.Path
	if requested == "" && len(argv) > 0 {
		requested = argv[0]
	}
	image := filepath.Base(requested)
	for i := range rt.Exec {
		r := &rt.Exec[i]
		if r.RuleName() == floor.Rule && r.Path != "" {
			// A directory entry grants any file under it, so the image is the requested file's basename, not the
			// directory's: `<dir>/mytool` run from an allowed <dir>/ is mytool, never the dir's last component. Only a file
			// entry names the image the grant resolves to.
			if r.IsDir {
				break
			}
			image = filepath.Base(r.Path)
			if r.Resolved != "" {
				image = filepath.Base(r.Resolved)
			}
			break
		}
	}
	f := execmatch.Facts{Requested: filepath.Base(requested), Path: requested, Image: image, Argv: argv, ArgvComplete: true}
	if len(argv) > 0 {
		f.Argv0 = argv[0]
	}
	if a.Script != "" {
		f.Form = execmatch.FormScript
		f.Interp = []execmatch.Stage{{Path: a.Script, Arg: a.ScriptArg}}
	}
	// A dynamic loader run as a command (the image, or the #! interpreter) runs its program in-process, which is read
	// as the exec's image (ADR 0048 (3)). Compile reads the program by its operand's name; the
	// supervisor also walks it, and refuses an operand it cannot read as the loader will (loader-unresolved). Both
	// know a loader by its name, never by its ELF, which a static-pie program shares; only the
	// supervisor also knows one by its identity (a hard link under another name), since a row has none.
	largv, loader := f.Argv, execmatch.LoaderName(f.Image) || execmatch.LoaderName(f.Requested)
	if f.Form == execmatch.FormScript {
		largv, loader = f.ScriptArgv(), execmatch.LoaderName(a.Script)
	}
	if loader {
		if i, prog, out := execmatch.LoaderProgram(largv); out == execmatch.LoaderRuns {
			f.Loaded = &execmatch.Loaded{Path: largv[i], Image: filepath.Base(largv[i]), Argv: prog}
		}
	}
	return f
}

// ExecCommandRow applies the command rules to an exec row after the image floor (ADR 0048 (1) precedence, (4)): a
// floor the image rules refused is never asked about; a deny or ask match refuses (an ask with
// completion_unsupported, since exec.ask is reserved); a constrained tool's unlisted invocation refuses under
// exec.args[<tool>]; an admitting entry keeps the floor's verdict and names itself. An observe run enforces nothing.
// The gate escalates after it (agent.EvaluateGateRow).
func ExecCommandRow(rt *agent.RuleTable, a agent.Action, floor agent.EvalResult, tier backend.Tier) agent.EvalResult {
	if rt == nil || rt.ExecCommands == nil || floor.Verdict == agent.VerdictRefused || tier == backend.TierObserve {
		return floor
	}
	f := CommandFacts(rt, a, floor)
	res := ExecCommand(rt, &f)
	switch res.Outcome {
	case execmatch.OutcomeNone:
		return floor
	case execmatch.OutcomeAllowed:
		out := floor
		out.CommandRule, out.CommandList, out.CommandMatch, out.CommandVia, out.ArgvFacts = commandRule(res), res.ListName(), res.MatchName(), res.Via.String(), "test_row"
		return out
	case execmatch.OutcomeRefused:
	}
	out := agent.EvalResult{Verdict: agent.VerdictRefused, Rule: res.Rule(), Reason: record.ReasonExecNotAllowed,
		CommandRule: commandRule(res), CommandList: res.ListName(), CommandMatch: res.MatchName(), CommandVia: res.Via.String(), ArgvFacts: "test_row"}
	if res.List == execmatch.ListAsk && !res.Unlisted {
		out.CompletionUnsupported = true
	}
	return out
}

// commandRule is the entry a decision names in command_rule: the pattern as compiled, the allowed entry whose
// closure admitted it, or the constrained tool for an unlisted invocation.
func commandRule(r CommandResult) string {
	switch {
	case r.Pattern != nil:
		return r.Pattern.Entry
	case r.ClosureOf != nil:
		return r.ClosureOf.Entry
	}
	return r.Tool
}
