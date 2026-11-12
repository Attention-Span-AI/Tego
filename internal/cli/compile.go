// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdCompile) }

// launchEnviron is the environment `tego compile` and `tego run` hand Compile (agent.WithEnviron), whose names
// secret-env checks: this process's. A variable so a test can compile against a fixed environment instead of its
// caller's shell.
var launchEnviron = os.Environ

// cmdCompile is `tego compile <agent.yaml | name> [--test <table> [--tier <t>[,<t>]]] [--offline] [--json] [--merged] [--upgrade]` (R29):
// agent.Load, agent.Compile against the machine ceilings, diagnostics on stderr in
// agent.Diagnostic's codes (R26), the rule table on stdout. With --test the compiled table is
// evaluated against a table of hypothetical actions instead of printed (R28). Exit 0 with only
// warnings, 1 on any error diagnostic or failing row (R25), 2 on usage or a malformed table. A contract
// argument of "-" reads the contract from standard input (loadContract), and an agent's name the contract the
// registries resolve it to (agent-contract.md R26), whose source the print names.
//
// --merged prints the merged contract (agent.Contract.Canonical: every profile of its extends laid in, a preset's
// included) in place of the rule table, once it has compiled: the one rule file a run records as contract.yaml, whose
// sha256 is contract_hash (R13, ADR 0068).
//
// --upgrade is the rewrite of a contract to the next contract version (docs/VERSIONING.md §3). Contract
// version 0 is the only one that exists, so there is nothing to rewrite to: the flag is accepted and
// refused with exit 2, saying so, rather than rejected as unknown or passed over in silence. The
// rewrite lands with contract version 1 (errUpgradeNoTarget).
func cmdCompile() Command {
	var (
		offline   bool
		asJSON    bool
		upgrade   bool
		merged    bool
		testTable string
		tiers     string
		execLine  string
	)
	return Command{
		Name:    "compile",
		Summary: "load a contract, validate it and print the rule table",
		Usage:   "<agent.yaml | name | - for stdin> [--test <table.yaml> [--tier <t>[,<t>]]] [--offline] [--json] [--merged] [--upgrade]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&offline, "offline", false, "an unresolvable host is a warning; run resolves it")
			fs.BoolVar(&asJSON, "json", false, "print the compiled table as one JSON object")
			fs.StringVar(&testTable, "test", "", "evaluate a table of action/expected-verdict rows against the compiled table")
			fs.StringVar(&tiers, "tier", "", "with --test: the tiers to answer in, comma-separated (default: every tier a run of the contract can get)")
			fs.BoolVar(&upgrade, "upgrade", false, "rewrite the contract to the newest contract version (none newer than 0 exists yet)")
			fs.BoolVar(&merged, "merged", false, "print the merged contract, every profile it extends laid in: the one rule file, whose sha256 is contract_hash")
			fs.StringVar(&execLine, "exec", "", "evaluate one command line against the exec rules in every tier, words split on spaces, quotes grouping (ADR 0048)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 || fs.Arg(0) == "" {
				message(stderr, "", 0, 0, "tego compile: exactly one contract file or agent name", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if upgrade {
				message(stderr, fs.Arg(0), 0, 0, "tego compile: --upgrade: "+errUpgradeNoTarget.Error(), codeUsage)
				return identity.ExitUsage // R25: usage error — nothing this binary can rewrite to
			}
			var only []backend.Tier
			if merged && (testTable != "" || execLine != "" || asJSON) {
				message(stderr, "", 0, 0, "tego compile: --merged prints the merged contract; --test, --exec and --json are other prints, give one", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if execLine != "" && testTable != "" {
				message(stderr, "", 0, 0, "tego compile: --exec and --test are two ways to ask; give one", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if execLine != "" && asJSON {
				message(stderr, "", 0, 0, "tego compile: --exec prints a report to read, with no --json form; use --test with --json for output a script parses", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if execLine != "" {
				if argv, _, err := execmatch.SplitWords(execLine); err != nil || len(argv) == 0 {
					message(stderr, "", 0, 0, "tego compile: --exec: write a command line, words split on spaces, \"...\" or '...' grouping one", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
			}
			if tiers != "" {
				if testTable == "" && execLine == "" {
					message(stderr, "", 0, 0, "tego compile: --tier needs --test: it names the tiers a test table answers in", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				var err error
				if only, err = parseTierList(tiers); err != nil {
					message(stderr, "", 0, 0, "tego compile: --tier: "+err.Error(), codeUsage)
					return identity.ExitUsage // R25: usage error
				}
			}
			return runCompile(ctx, fs.Arg(0), compileRequest{testTable: testTable, execLine: execLine, tiers: only, offline: offline, asJSON: asJSON, merged: merged}, stdout, stderr)
		},
	}
}

// errUpgradeNoTarget is compile --upgrade until a contract version after 0 exists. It is buildable the
// day spec/agent/v1 lands: a v0 file then loads, is rewritten field by field into v1 and its diff is
// printed (VERSIONING.md §3), and this refusal becomes that rewrite.
var errUpgradeNoTarget = errors.New("this binary knows contract version 0 only, so there is no newer version " +
	"to rewrite the file to; --upgrade rewrites a v0 contract once contract version 1 exists (docs/VERSIONING.md §3)")

// compileRequest is what one compile was asked for, beyond the contract's path.
type compileRequest struct {
	testTable string
	// execLine is --exec: one command line to evaluate against the exec rules (ADR 0048 (4)).
	execLine string
	// tiers is --tier: the tiers the test table answers in, in place of the tiers a run can get.
	tiers   []backend.Tier
	offline bool
	asJSON  bool
	// merged is --merged: print the merged contract in place of the table.
	merged bool
	// resolver is a per-call dependency; nil keeps the system resolver.
	resolver agent.Resolver
}

// parseTierList reads --tier's comma-separated enforcement tiers, each once.
func parseTierList(s string) ([]backend.Tier, error) {
	var out []backend.Tier
	for name := range strings.SplitSeq(s, ",") {
		t, err := backend.ParseTier(strings.TrimSpace(name))
		if err != nil || !t.AtOrBelow(backend.TierBPFLSM) {
			return nil, fmt.Errorf("%q is not landlock, cgroup or bpflsm", strings.TrimSpace(name))
		}
		if slices.Contains(out, t) {
			return nil, fmt.Errorf("%s is named twice", t)
		}
		out = append(out, t)
	}
	return out, nil
}

// autoSet is every enforcement tier a run of an auto contract by this process can get (doctor.AutoTiers): those
// this binary constructs (enforce.Buildable), tier cgroup and above only as root, tier bpflsm only with bpf in the
// LSM list, with the built tiers it leaves out. Compile resolves auto to the highest of them, compile --test answers
// in each, and its header names the built tiers left out (ADR 0019). Only the preconditions no probe changes are
// read: compile loads no program and needs no privilege, so a tier whose functional probes fail here is still
// answered for, which errs toward reporting a difference, never toward certifying a refusal. Reading the build alone,
// a tegobpf build run by a normal user compiled an auto contract at tier bpflsm and refused its fs.ask_read for a
// tier no run of that user gets. A variable so tests can describe another build and machine.
var autoSet = doctor.AutoTiers

// builtTiers is the tiers an auto run by this process can get (autoSet), the set every compile passes to
// agent.WithTiers.
func builtTiers() []backend.Tier { return autoSet().Tiers }

// runCompile is the in-process body of compile.
func runCompile(ctx context.Context, path string, req compileRequest, stdout, stderr io.Writer) int {
	testTable, offline, asJSON := req.testTable, req.offline, req.asJSON
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego compile: machine config: "+err.Error(), config.CodeUntrusted)
		return identity.ExitError // R25: Tego's own error (I/O on a config layer)
	}
	ref, rerr := resolveContract(path, false, m)
	if rerr != nil {
		printRefusedName(stderr, "tego compile", rerr)
		return identity.ExitFinding // R25: a finding, as a missing contract file is
	}
	c, ds, err := ref.load(profileSources(m))
	_ = agent.WriteDiagnostics(stderr, ds)
	label := ref.label()
	if err != nil {
		return loadFailed(stderr, label, ds, err)
	}
	if ctx.Err() != nil {
		message(stderr, "", 0, 0, "tego compile: interrupted", codeIO)
		return identity.ExitError // R25: Tego's own error (interrupted)
	}
	opts := []agent.CompileOption{agent.WithContext(ctx), agent.WithPATH(os.Getenv("PATH")), agent.WithEnviron(launchEnviron()), agent.WithClock(time.Now), agent.WithTiers(builtTiers()...)}
	if req.resolver != nil {
		opts = append(opts, agent.WithResolver(req.resolver))
	}
	if m.Home != "" {
		opts = append(opts, agent.WithHome(m.Home))
	}
	// The same chain anchor `run` guards, so compile and run agree on R10 (agent-contract.md).
	opts = append(opts, anchorCompileOptions(m)...)
	if offline {
		opts = append(opts, agent.Offline())
	}
	rt, ds, err := agent.Compile(c, m, opts...)
	if ctx.Err() != nil {
		message(stderr, "", 0, 0, "tego compile: interrupted", codeIO)
		return identity.ExitError // R25: interrupted compilation is an I/O failure, not a contract finding
	}
	_ = agent.WriteDiagnostics(stderr, ds)
	if err != nil {
		return loadFailed(stderr, label, ds, err)
	}
	warnCostUnpriced(stderr, label, rt, m)
	// The decision plane's keyed-inode cap (TIER3-PLAN T5, enforce-plane §6 E13) and this launcher's descriptor cap
	// (§2.4 condition 7): a table over either is refused at a pinned bpflsm, never truncated, and an auto run of it is
	// given tier cgroup.
	if d, ok := decide.PlaneDiagnostic(rt, label, enforce.PlaneFDCap()); ok {
		_ = agent.WriteDiagnostics(stderr, []agent.Diagnostic{d})
		if d.Severity == agent.SeverityError {
			return identity.ExitFinding // R25: compile found an error
		}
	}
	if req.merged {
		return printMerged(stdout, stderr, c)
	}
	if testTable != "" {
		return runCompileTest(rt, m, testTable, req.tiers, asJSON, stdout, stderr)
	}
	if req.execLine != "" {
		return runCompileExec(rt, m, req.execLine, req.tiers, stdout, stderr)
	}
	if asJSON {
		t := tableJSON(rt)
		t.Source = sourceJSON(ref, rt)
		t.Machine = machineJSON(m)
		err = writeJSON(stdout, t)
	} else {
		err = printSource(stdout, ref)
		if err == nil {
			err = agent.PrintRuleTable(stdout, rt)
		}
		if err == nil {
			err = printHarnessProvision(stdout, stderr, label, rt)
		}
		if err == nil {
			err = printPlaneCompaction(stdout, rt)
		}
		if err == nil {
			err = printFrozen(stdout, rt)
		}
		if err == nil {
			err = printEffective(stdout, m)
		}
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego compile: "+err.Error(), codeIO)
		return identity.ExitError // R25: Tego's own error
	}
	return identity.ExitOK
}

// printMerged writes the merged contract's canonical form, the bytes contract_hash is the sha256 of (R13), and
// nothing else, so `tego compile --merged agent.yaml | sha256sum` is the run's contract_hash.
func printMerged(stdout, stderr io.Writer, c *agent.Contract) int {
	data, err := c.Canonical()
	if err == nil {
		_, err = stdout.Write(data)
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego compile: --merged: "+err.Error(), codeIO)
		return identity.ExitError // R25: Tego's own error
	}
	return identity.ExitOK
}

// warnCostUnpriced warns that a cost_usd budget never trips on this machine, where no price table loads: a
// run estimates no cost without one (limits.FromMachine, E15), so the budget is never reached, and compile
// said nothing (R32). A budget the contract declares is reported [budget-unmetered], since its run is then refused;
// one a machine ceiling alone imposes stays [unenforced]. A table that loads but names no server_tool_per_request fee is warned
// about too: a run ends at the first response reporting server-tool requests, whose cost the table cannot bound
// (ADR 0037 amendment 2026-09-24), and one whose every entry lacks an input or output price: a budget the contract
// declares is then [budget-unmetered], its run refused as under no table, and one a machine ceiling
// alone imposes [unenforced], a run ending at its first response (R2). The table is read as run reads it, and never
// fails the compile.
func warnCostUnpriced(stderr io.Writer, path string, rt *agent.RuleTable, m *config.Machine) {
	if !rt.Limits.Bounded(agent.BudgetCostUSD) {
		return
	}
	table, warn := limits.FromMachine(m)
	var d agent.Diagnostic
	switch {
	case warn != nil && rt.Contract != nil && rt.Contract.Limits.CostUSD != nil:
		// A budget the contract declares: its run is refused, 125 [budget-unmetered] (runtime.ErrBudgetUnmetered).
		d = agent.Diagnostic{File: path, Code: identity.CodeBudgetUnmetered, Severity: agent.SeverityWarning,
			Message: "limits.cost_usd budget never trips: no price table (" + warn.Message + "), and every run of this contract on this machine is refused",
			Fix:     "install a price table at the machine config's prices: path, or bound the run with tokens instead"}
	case warn != nil:
		d = agent.Diagnostic{File: path, Code: agent.CodeUnenforced, Severity: agent.SeverityWarning,
			Message: "limits.cost_usd budget never trips: no price table (" + warn.Message + ")",
			Fix:     "install a price table at the machine config's prices: path, or bound the run with tokens instead"}
	case table != nil && !table.PricesAnyModel() && rt.Contract != nil && rt.Contract.Limits.CostUSD != nil:
		// A budget the contract declares under a table that prices no model: its run is refused, as under no
		// table (runtime.refuseUncountedBudget).
		d = agent.Diagnostic{File: path, Code: identity.CodeBudgetUnmetered, Severity: agent.SeverityWarning,
			Message: "limits.cost_usd budget prices no model: every entry of the price table " + table.Path +
				" lacks an input_per_mtok or an output_per_mtok, and every run of this contract on this machine is refused",
			Fix: "give at least one model entry both input_per_mtok and output_per_mtok, or bound the run with tokens instead"}
	case table != nil && !table.PricesAnyModel():
		d = agent.Diagnostic{File: path, Code: agent.CodeUnenforced, Severity: agent.SeverityWarning,
			Message: "limits.cost_usd budget prices no model: every entry of the price table " + table.Path +
				" lacks an input_per_mtok or an output_per_mtok; a run ends at its first response",
			Fix: "give at least one model entry both input_per_mtok and output_per_mtok"}
	case table != nil && len(table.Models) > 0 && len(table.ServerToolPerRequest) == 0:
		d = agent.Diagnostic{File: path, Code: agent.CodeUnenforced, Severity: agent.SeverityWarning,
			Message: "limits.cost_usd budget cannot price server-tool requests: the price table " + table.Path +
				" has no server_tool_per_request; a run ends at the first response that reports any",
			Fix: "add server_tool_per_request fees (e.g. web_search_requests) to the price table"}
	default:
		return
	}
	if rt.Contract != nil {
		if p, ok := rt.Contract.Pos("limits.cost_usd"); ok {
			d.File, d.Line, d.Col = p.File, p.Line, p.Col
		}
	}
	_ = agent.WriteDiagnostics(stderr, []agent.Diagnostic{d})
}

// runCompileTest evaluates a `compile --test` table against the compiled rule table (R28): a line
// naming the tiers the table answers in, one PASS or FAIL line per row, in file order, and a summary.
// A malformed table is a usage error and no row runs (§7); a failing row is a finding, exit 1 (R25).
//
// A row answers in every tier a run of the contract can get (RuleTable.Reach: the pinned tier, or every tier
// this binary builds that a run by this process can get here, autoSet), or in --tier's, and passes only if it holds
// in each (ADR 0019); the first line names where the tiers came from (reachOrigin). A row's own tier: narrows it to
// that tier. Rows used to be answered in the tier auto compiled to,
// bpflsm, which no build then contained, and so certified refusals the run's own tier did not make. No machine
// is probed (R33).
func runCompileTest(rt *agent.RuleTable, m *config.Machine, path string, tiers []backend.Tier, asJSON bool, stdout, stderr io.Writer) int {
	table, ds, err := agent.LoadTestTable(path)
	_ = agent.WriteDiagnostics(stderr, ds)
	if err != nil {
		if !agent.HasErrors(ds) {
			message(stderr, path, 0, 0, err.Error(), loadCode(err))
		}
		return identity.ExitUsage // §7: a malformed table fails before any row runs
	}
	from := "--tier"
	if len(tiers) == 0 {
		tiers, from = rt.Reach, reachOrigin(rt, m)
	}
	cwd := rowCwd()
	env := testEnv(rt, m)
	// The bpflsm column is the plane's own rows walked as the kernel walks them, compiled once (TIER3-PLAN T10,
	// ADR 0019's 2026-09-29 note); every other column is the root model's.
	var plane *decide.PlaneEvaluator
	if slices.Contains(tiers, backend.TierBPFLSM) {
		plane = decide.NewPlaneEvaluator(rt)
		if err := plane.Err(); err != nil {
			message(stderr, path, 0, 0, "tego compile: the bpflsm column refuses every fs and exec row: "+err.Error(), agent.CodeUnenforced)
		}
	}
	model := decide.NewEvaluator(rt)
	eval := func(_ *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
		if tier == backend.TierBPFLSM && plane != nil {
			return plane.Evaluate(a, env)
		}
		return model.EvaluateIn(a, tier, env)
	}
	results := table.RunResolved(eval, rt, cwd, landers(stderr, path), tiers...)
	failed := 0
	for _, r := range results {
		if !r.Pass {
			failed++
		}
	}
	if asJSON {
		if err := writeJSON(stdout, testJSON(path, tiers, from, results, failed)); err != nil {
			message(stderr, "", 0, 0, "tego compile: "+err.Error(), codeIO)
			return identity.ExitError // R25: Tego's own error
		}
	} else {
		fmt.Fprintf(stdout, "tiers %s (%s)\n", tierList(tiers), from)
		if plane != nil {
			note := PlaneColumnNote
			if plane.NameEntries() > 0 {
				note += "; " + PlaneColumnNamesNote
			}
			fmt.Fprintf(stdout, "bpflsm: %s\n", note)
		}
		for _, r := range results {
			if r.Pass {
				fmt.Fprintf(stdout, "PASS %s%s%s\n", record.Printable(r.Row.Label()), resolvedNote(r.Resolved), bestEffortNote(r.Columns))
				continue
			}
			fmt.Fprintf(stdout, "FAIL %s%s%s (%s:%d): %s\n", record.Printable(r.Row.Label()), resolvedNote(r.Resolved), bestEffortNote(r.Columns), record.Printable(path), r.Row.Line, testFailure(rt, r))
		}
		fmt.Fprintf(stdout, "%d rows: %d passed, %d failed\n", len(results), len(results)-failed, failed)
	}
	if failed > 0 {
		return identity.ExitFinding // R25: compile --test has a failing row
	}
	return identity.ExitOK
}

// testEnv is the machine env compile --test answers rows in, read as a run reads it at start: the resolver
// endpoints R14's exception covers (dns.MachineResolvers), so a row connecting to one is answered
// net.resolver as the supervisor and the tier-2 recorder name it. Under net.dns.mode off or broker the run
// grants none (agent.DNSPolicy.SystemResolvers, runtime runResolvers), and neither does this env: it used to
// read the machine config alone and answered net.resolver allow for a query the run refuses.
func testEnv(rt *agent.RuleTable, m *config.Machine) decide.Env {
	if rt != nil && !rt.DNS.SystemResolvers() {
		return decide.Env{}
	}
	if m == nil {
		return decide.Env{Resolvers: dns.MachineResolvers(true, nil)}
	}
	return decide.Env{Resolvers: dns.MachineResolvers(m.Resolver.Value.Auto, m.Resolver.Value.Servers)}
}

// resolvedNote is the text a row's line carries when RunResolved evaluated it on a path other than the
// row's own: the path the kernel's walk reached through a symlink.
func resolvedNote(r agent.ResolvedPaths) string {
	var parts []string
	for _, p := range []struct{ what, path string }{{"path", r.Path}, {"dest", r.Dest}, {"script", r.Script}} {
		if p.path != "" {
			parts = append(parts, p.what+" resolved to "+record.Printable(p.path))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, ", ") + "]"
}

// bestEffortNote is the text a row's line carries when an answer rests on a best-effort cell (ADR 0041 D7, the
// column's BestEffort): each id once, in the order the columns name them, followed by the tiers it holds in unless
// it holds in every column. "" when no column rests on one.
func bestEffortNote(cols []agent.TestColumn) string {
	var ids []string
	tiers := map[string][]string{}
	for _, c := range cols {
		for _, id := range c.BestEffort {
			if _, seen := tiers[id]; !seen {
				ids = append(ids, id)
			}
			tiers[id] = append(tiers[id], string(c.Tier))
		}
	}
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id
		if len(tiers[id]) < len(cols) {
			parts[i] += " at " + strings.Join(tiers[id], ", ")
		}
	}
	return " [best effort: " + strings.Join(parts, "; ") + "]"
}

// reachOrigin says where a table's tiers came from, for the header of compile --test: the contract's pin,
// the machine config's (a concrete tier there pins it, as enforce.Select reads it), or neither (autoOrigin).
func reachOrigin(rt *agent.RuleTable, m *config.Machine) string {
	if rt.Contract != nil {
		if t := backend.Tier(rt.Contract.Tier); t != "" && t != backend.TierAuto {
			return "pinned by the contract"
		}
	}
	if m != nil && m.Tier.Bounded && !m.Tier.Value.Auto && m.Tier.Value.Tier != "" {
		return "pinned by the machine config at " + m.Tier.Source.String()
	}
	return autoOrigin(autoSet())
}

// autoOrigin is where an auto table's tiers came from: every tier this tego builds, but those a run by this process
// cannot get here, each named with the precondition it lacks ("but cgroup and bpflsm, which need root"). It said every
// tier this tego builds whatever the set was, so a normal user of a tegobpf build read that it built tier landlock
// alone.
func autoOrigin(s doctor.AutoSet) string {
	origin, sep := "tier auto: every tier this tego builds", " but "
	for _, left := range []struct {
		tiers []backend.Tier
		need  string
	}{{s.NeedRoot, "root"}, {s.NeedBPFLSM, "bpf in the LSM list"}} {
		if len(left.tiers) == 0 {
			continue
		}
		verb := "needs"
		if len(left.tiers) > 1 {
			verb = "need"
		}
		origin += sep + strings.Join(tierNames(left.tiers), " and ") + ", which " + verb + " " + left.need
		sep = ", and "
	}
	return origin
}

// tierNames is tiers as strings, never nil.
func tierNames(tiers []backend.Tier) []string {
	out := []string{}
	for _, t := range tiers {
		out = append(out, string(t))
	}
	return out
}

// tierList joins tiers for a line of output.
func tierList(tiers []backend.Tier) string {
	names := make([]string, len(tiers))
	for i, t := range tiers {
		names[i] = string(t)
	}
	return strings.Join(names, ", ")
}

// testFailure says why a row failed: an unresolved host is reported as such rather than as a
// verdict mismatch (§6 E19), with the declared host or hosts that could not be resolved. A row answered in more than one tier names each tier it failed in.
func testFailure(rt *agent.RuleTable, r agent.TestResult) string {
	if r.Got.Rule == agent.UnresolvedRule {
		msg := "could not resolve " + record.Printable(r.Row.Host)
		if hosts := decide.UnresolvedHosts(rt, r.Row.Host, r.Row.Port, r.Row.Proto); len(hosts) > 0 {
			msg += " (declared host " + record.Printable(strings.Join(hosts, ", ")) + ")"
		}
		return msg
	}
	want := string(r.Row.Expect)
	if r.Row.Rule != "" {
		want += " via " + record.Printable(r.Row.Rule)
	}
	if len(r.Columns) <= 1 {
		return fmt.Sprintf("got %s via %s, want %s", r.Got.Verdict, record.Printable(r.Got.Rule), want)
	}
	var fails []string
	for _, c := range r.Columns {
		if !c.Pass {
			fails = append(fails, fmt.Sprintf("at %s got %s via %s", c.Tier, c.Got.Verdict, record.Printable(c.Got.Rule)))
		}
	}
	return strings.Join(fails, "; ") + ", want " + want
}

// TestReport is compile --test --json: one versioned object (ADR 0019 (4)), each row with its answer in
// every tier it was evaluated in.
type TestReport struct {
	V      int             `json:"v"`
	Table  string          `json:"table"`
	Tiers  []string        `json:"tiers"`
	From   string          `json:"from"`
	Rows   []TestReportRow `json:"rows"`
	Passed int             `json:"passed"`
	Failed int             `json:"failed"`
}

// TestReportRow is one row of TestReport.
type TestReportRow struct {
	Name    string           `json:"name"`
	Line    int              `json:"line"`
	Expect  string           `json:"expect"`
	Rule    string           `json:"rule,omitempty"`
	Pass    bool             `json:"pass"`
	Columns []TestReportCell `json:"columns"`
	// ResolvedPath, ResolvedDest and ResolvedScript are the paths the row was evaluated on when the
	// filesystem resolved its own elsewhere (a symlink); absent when it was evaluated as written.
	ResolvedPath   string `json:"resolved_path,omitempty"`
	ResolvedDest   string `json:"resolved_dest,omitempty"`
	ResolvedScript string `json:"resolved_script,omitempty"`
}

// TestReportCell is one row's answer in one tier. Mechanism and DecisionPlane are set only for the bpflsm
// column's FS, exec and executable-map answers, which walk the plane's rows (ADR 0019's 2026-09-29 note).
// Network answers use the policy model and carry neither field. These are test-column provenance, not
// measurements of an attached runtime mechanism.
type TestReportCell struct {
	Score                 *int   `json:"score,omitempty"`
	GateRule              string `json:"gate_rule,omitempty"`
	GateOutcome           string `json:"gate_outcome,omitempty"`
	GateFacts             string `json:"gate_facts,omitempty"`
	CompletionUnsupported bool   `json:"completion_unsupported,omitempty"`
	Tier                  string `json:"tier"`
	Verdict               string `json:"verdict"`
	Rule                  string `json:"rule"`
	Pass                  bool   `json:"pass"`
	Mechanism             string `json:"mechanism,omitempty"`
	DecisionPlane         string `json:"decision_plane,omitempty"`
	// CommandRule, CommandList, CommandMatch and CommandVia are an exec row's command-rule decision (ADR 0048 (4)),
	// ArgvFacts is test_row (the row's argv), and ArgvAssurance is copied in every column: the supervisor decides on
	// its copy of argv at every tier until ADR 0048's P2 pins exec facts in the kernel.
	CommandRule   string `json:"command_rule,omitempty"`
	CommandList   string `json:"command_list,omitempty"`
	CommandMatch  string `json:"command_match,omitempty"`
	CommandVia    string `json:"command_via,omitempty"`
	ArgvFacts     string `json:"argv_facts,omitempty"`
	ArgvAssurance string `json:"argv_assurance,omitempty"`
	// BestEffort are the ids of the run's best-effort cells this answer rests on in this tier (ADR 0041 D7,
	// agent.RuleTable.BestEffortCellsFor): what run_start.best_effort lists for a run of the contract there, narrowed to
	// the row. Absent when the answer rests on none.
	BestEffort []string `json:"best_effort,omitempty"`
}

// PlaneColumnNote is the line compile --test prints under the tiers line when the bpflsm column is answered:
// what the column is and the decision plane it answers for (enforce-plane R25). The fs and exec answers compose the
// Landlock floor tier 3 keeps under the plane (a #! script's EXECUTE, a link's or a rename's REFER); exec.anonymous
// and the network rows (net.connect, net.bind, net.http, net.send, net.socket) are the policy model's, with no
// plane provenance in --json (correctness F3).
const PlaneColumnNote = "fs, exec and exec.map answered from the plane's rows and the Landlock floor under them (decision_plane lsm: tier bpflsm needs LSM mode); exec.anonymous and network answer from the policy model"

// PlaneColumnNamesNote is the clause the bpflsm column's note gains where the plane's rows carry the table's name
// entries (ADR 0043 C9; a build that enforces them): a row's file is decided by its final name beneath each scope, as
// the kernel's name check and climb decide it, whether or not the file existed at compile.
const PlaneColumnNamesNote = "deny_read's name entries answered from the plane's name rows and the climb to their scopes, a file created after compile at a covered name included"

// testJSON builds compile --test --json's report.
func testJSON(path string, tiers []backend.Tier, from string, results []agent.TestResult, failed int) TestReport {
	rep := TestReport{V: 1, Table: path, From: from, Rows: []TestReportRow{},
		Passed: len(results) - failed, Failed: failed}
	for _, t := range tiers {
		rep.Tiers = append(rep.Tiers, string(t))
	}
	for _, r := range results {
		row := TestReportRow{Name: r.Row.Label(), Line: r.Row.Line, Expect: string(r.Row.Expect), Rule: r.Row.Rule,
			Pass: r.Pass, Columns: []TestReportCell{},
			ResolvedPath: r.Resolved.Path, ResolvedDest: r.Resolved.Dest, ResolvedScript: r.Resolved.Script}
		for _, c := range r.Columns {
			cell := TestReportCell{Tier: string(c.Tier), Verdict: string(c.Got.Verdict), Rule: c.Got.Rule, Pass: c.Pass, Score: c.Got.Score, GateRule: c.Got.GateRule, GateOutcome: c.Got.GateOutcome, CompletionUnsupported: c.Got.CompletionUnsupported, BestEffort: c.BestEffort}
			if c.Got.Score != nil {
				cell.GateFacts = "test_row"
			}
			if c.Got.CommandRule != "" {
				cell.CommandRule, cell.CommandList, cell.CommandMatch, cell.CommandVia = c.Got.CommandRule, c.Got.CommandList, c.Got.CommandMatch, c.Got.CommandVia
				cell.ArgvFacts, cell.ArgvAssurance = c.Got.ArgvFacts, "copied"
			}
			if c.Tier == backend.TierBPFLSM {
				switch r.Row.Kind {
				case agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir, agent.ActionFSRename,
					agent.ActionFSLink, agent.ActionFSAttr, agent.ActionExec, agent.ActionMapExec:
					cell.Mechanism, cell.DecisionPlane = "plane", "lsm"
				case agent.ActionNetConnect, agent.ActionNetBind, agent.ActionNetHTTP, agent.ActionNetSend, agent.ActionNetSocket,
					agent.ActionExecAnon:
					// PlaneEvaluator delegates these actions to the policy model: the plane's slot header carries the
					// same predicates (NetSocketPolicy, ExecAnonymous), and no row decides them.
				}
			}
			row.Columns = append(row.Columns, cell)
		}
		rep.Rows = append(rep.Rows, row)
	}
	return rep
}

// stdinContract is the contract argument that reads the contract from standard input, and stdinLabel the
// name its diagnostics carry. A contract read from stdin has no file, so the working directory stands in for
// the contract's directory, where relative entries already resolve (E28): R10's contract-file target is
// <cwd>/<stdin>, and the .env scan starts there, as they would for an agent.yaml there.
const (
	stdinContract = "-"
	stdinLabel    = "<stdin>"
)

// contractStdin is where `compile -` reads the contract; a variable so tests can hand it a pipe.
var contractStdin = func() *os.File { return os.Stdin }

// contractLabel is the name compile's own messages give the contract argument path: stdinLabel for "-", as the
// contract's diagnostics name it.
func contractLabel(path string) string {
	if path == stdinContract {
		return stdinLabel
	}
	return path
}

// loadContract is agent.Load, or for "-" agent.LoadBytes over standard input, read as a contract file is read
// (a regular file, a pipe or a socket, at most MaxContractSize bytes: a terminal is refused rather than waited
// on).
func loadContract(path string, profiles agent.ProfileSource) (*agent.Contract, []agent.Diagnostic, error) {
	if path != stdinContract {
		return agent.Load(path, profiles)
	}
	data, err := agent.ReadCapped(contractStdin(), "stdin")
	if err != nil {
		return nil, nil, err
	}
	return agent.LoadBytes(stdinLabel, data, profiles)
}

// loadFailed reports a compile's load or Compile error, err, that its diagnostics ds may already name, and is the exit:
// a finding (R25), except a file the reader may not open, an I/O failure at 125 [io] as every other one is (E26).
func loadFailed(stderr io.Writer, label string, ds []agent.Diagnostic, err error) int {
	if agent.HasErrors(ds) {
		return identity.ExitFinding // R25: compile found an error
	}
	code := loadCode(err)
	message(stderr, label, 0, 0, err.Error(), code)
	if code == codeIO {
		return identity.ExitError // R25: an I/O failure, not a contract finding
	}
	return identity.ExitFinding // R25: compile found an error
}

// loadCode picks the diagnostic code for a Load error that carried no diagnostic: a missing file is path-missing, one
// the reader may not open is io, a file with a second name is config-untrusted, anything else (oversized, malformed)
// is schema.
func loadCode(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return agent.CodePathMissing
	case errors.Is(err, os.ErrPermission):
		return codeIO // the file is not the reader's to open: nothing about its schema is known
	case errors.Is(err, config.ErrUntrusted):
		return config.CodeUntrusted // a contract file with a second name (agent-contract.md R10, ADR 0059)
	}
	return agent.CodeSchema
}

// printFrozen writes one note naming the directories a run of rt will list once at launch to build its deny_read
// entries (decide.FrozenLevels; enforce-landlock R3, GAPS A12), in which a name made during the run is unreadable to it.
// Every contract tier builds that ruleset (a root tier composes tier 1's); nothing is printed when none is listed. A run
// names the directories it did list in run_start.deny_read_frozen and prints the same sentence; an --observe run
// builds no ruleset and lists none.
func printFrozen(w io.Writer, rt *agent.RuleTable) error {
	dirs := decide.FrozenLevels(rt)
	if len(dirs) == 0 {
		return nil
	}
	_, err := fmt.Fprintf(w, "note      %s\n", record.Printable(tegoruntime.FrozenNote(dirs, 0, "a run")))
	return err
}

// printEffective writes the machine config's effective values under the rule table, each with the file
// and line it came from (spec/config/v0: "tego compile prints every effective value with the file and line
// it came from", SEMANTICS §8). config.WriteEffective existed and nothing called it, so the promise was
// printPlaneCompaction says, for a table a decision plane can run (one that can land at tier cgroup, whose plane
// modes are filled from the same rows, or at tier bpflsm), how many covered per-file deny_read rows the plane's row
// compiler left to the name rows that stand in for them (ADR 0043 D6) and how many paths it still keys: the table
// above still lists every file, and tier landlock keeps them all. Nothing for a table it compacted nothing of, or
// one the plane cannot hold (PlaneDiagnostic said so).
func printPlaneCompaction(w io.Writer, rt *agent.RuleTable) error {
	plane := func(t backend.Tier) bool { return t == backend.TierCgroup || t == backend.TierBPFLSM }
	if !plane(rt.Tier) && !slices.ContainsFunc(rt.Reach, plane) {
		return nil
	}
	rows, err := decide.CompilePlane(rt)
	if err != nil || rows.Compacted == 0 {
		return nil
	}
	_, err = fmt.Fprintf(w, "plane     %d per-file deny_read rows held by the name rows (ADR 0043 D6); %d paths keyed\n",
		rows.Compacted, len(rows.Keyed))
	return err
}

// printEffective writes the machine config's effective values under the rule table, each with the file
// and line it came from (spec/config/v0: "tego compile prints every effective value with the file and line
// it came from", SEMANTICS §8). config.WriteEffective existed and nothing called it, so the promise was
// false and a ceiling's source was visible only when a raise was refused. Escaped for the
// terminal like the rest of the print: a path in a layer file is text its owner wrote.
func printEffective(w io.Writer, m *config.Machine) error {
	var buf bytes.Buffer
	if err := m.WriteEffective(&buf); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "machine   the machine config in force, each value with the file and line it came from"); err != nil {
		return err
	}
	for line := range strings.Lines(buf.String()) {
		if _, err := fmt.Fprintf(w, "  %s\n", record.Printable(strings.TrimSuffix(line, "\n"))); err != nil {
			return err
		}
	}
	return nil
}

// TableMachineValue is one effective machine config value in --json (config.Value).
type TableMachineValue struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Source    string `json:"source"`
	Ceiling   bool   `json:"ceiling"`
	Unbounded bool   `json:"unbounded,omitempty"`
}

// machineJSON projects the machine config's effective values onto their --json shape.
func machineJSON(m *config.Machine) []TableMachineValue {
	out := []TableMachineValue{}
	for _, v := range m.Effective() {
		out = append(out, TableMachineValue{Key: v.Key, Value: v.Value, Source: v.Source.String(), Ceiling: v.Ceiling, Unbounded: v.Unbounded})
	}
	return out
}

// Table is the --json shape of a compiled contract: one object, fields in declaration order.
type Table struct {
	Gate         *TableGate `json:"gate,omitempty"`
	Name         string     `json:"name"`
	ContractHash string     `json:"contract_hash"`
	// Revision is the contract's revision (agent-contract.md R28); absent when it has none.
	Revision string `json:"revision,omitempty"`
	// Source is the contract file, and the name and registry it was resolved from (agent-contract.md R26); absent
	// for standard input.
	Source *TableSource `json:"source,omitempty"`
	Tier   string       `json:"tier"`
	// Reach is every tier a run of the table can get (agent.RuleTable.Reach, ADR 0019).
	Reach   []string    `json:"reach"`
	Capture string      `json:"capture"`
	Record  string      `json:"record"`
	Limits  TableLimits `json:"limits"`
	FS      []TableFS   `json:"fs"`
	// Reads is fs.reads as compiled (ADR 0069): the effective value, whether a run at tier landlock holds its reads
	// and why, and the deny_read targets inside write entries by rule.
	Reads TableReads  `json:"reads"`
	Exec  []TableExec `json:"exec"`
	// ExecUnrestricted and NetUnrestricted are true for a contract with no exec: or no net: section, which
	// SEMANTICS §1 reads as unrestricted: the entry lists alone (the command, or none) read like a section
	// that refuses everything else.
	ExecUnrestricted bool `json:"exec_unrestricted"`
	// ExecCommands are the command patterns (ADR 0048 (9)), each with its row and exact reading; absent when the
	// contract names none.
	ExecCommands    []TableExecCommand `json:"exec_commands,omitempty"`
	Net             []TableNet         `json:"net"`
	NetUnrestricted bool               `json:"net_unrestricted"`
	// HostSocketsRefused is ADR 0070's unix-only state (agent.RuleTable.HostSocketsRefused): no net: section and no
	// host_sockets: true, so the IP side is unrestricted (net_unrestricted) and a unix socket the run did not bind is
	// refused, rule host-sockets. False under a net: section, which decides every destination, and under the opt-out.
	HostSocketsRefused bool `json:"host_sockets_refused"`
	// EnvPass is null for a contract with no env.pass, whose agent inherits the environment, and [] for one
	// that passes nothing (agent-contract R12). EnvDeny and EnvSet are [] and {} when empty, never null.
	EnvPass []string          `json:"env_pass"`
	EnvDeny []string          `json:"env_deny"`
	EnvSet  map[string]string `json:"env_set"`
	// Machine is every effective machine config value with its source.
	Machine []TableMachineValue `json:"machine"`
	// Harness is the harness a run of the table is provisioned for (agent-contract.md R27): auto resolved from the
	// contract's own command, or auto when it has none.
	Harness string `json:"harness"`
}

// TableExecCommand is one command pattern in --json: its list, the entry, the row that read it (its tool, version
// and source, "generic" for none), its reading and its notes.
type TableExecCommand struct {
	List      string   `json:"list"`
	Entry     string   `json:"entry"`
	Row       string   `json:"row"`
	RowSource string   `json:"row_source"`
	Version   string   `json:"row_version,omitempty"`
	Reading   string   `json:"reading"`
	Notes     []string `json:"notes,omitempty"`
}

// TableReads is Table.Reads.
type TableReads struct {
	Mode     string   `json:"mode"`
	Landlock string   `json:"landlock"` // held or direct, at tier landlock
	Why      string   `json:"why"`      // agent.ReadsWhy at tier landlock
	Nested   []string `json:"nested"`
}

type TableGateRule struct {
	Rule      string `json:"rule"`
	Predicate string `json:"predicate"`
	Score     int    `json:"score"`
}

type TableGate struct {
	Allow                 int             `json:"allow_threshold"`
	Ask                   int             `json:"ask_threshold"`
	Worktree              string          `json:"worktree"`
	Facts                 string          `json:"facts"`
	Rules                 []TableGateRule `json:"rules"`
	ExecApprovalSupported bool            `json:"exec_approval_supported"`
}

// TableLimits renders ResolvedLimits with durations as strings. null is unbounded, mirroring the
// contract's own spelling of "no budget" — the omitted key. A number is a budget, 0 included: with
// numbers alone a ceiling of exactly 0 printed as the unbounded case, telling an operator who asked
// for the tightest budget that they had none (E16). cpu is null when unbounded like every other key;
// it printed "".
type TableLimits struct {
	CPU        *string  `json:"cpu"`
	CPUWeight  *int     `json:"cpu_weight"`
	Memory     *int64   `json:"memory"`
	MemoryHigh *int64   `json:"memory_high"`
	Pids       *int     `json:"pids"`
	Tokens     *int64   `json:"tokens"`
	CostUSD    *float64 `json:"cost_usd"`
	Wall       *string  `json:"wall"`
	StallAfter *string  `json:"stall_after"`
	Repeats    *int     `json:"repeats"`
}

// boundedValue returns &v when the dimension carries a budget, nil when it does not.
func boundedValue[T any](l agent.ResolvedLimits, k agent.BudgetSet, v T) *T {
	if !l.Bounded(k) {
		return nil
	}
	return &v
}

// TableFS is one filesystem entry: every entry of the compiled table and of the built-in deny_write set
// (kind deny_write), as the printed table lists them.
type TableFS struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Raw     string `json:"raw,omitempty"`
	Mount   string `json:"mount,omitempty"`
	FSType  string `json:"filesystem,omitempty"`
	Missing bool   `json:"missing,omitempty"`
	BuiltIn bool   `json:"builtin,omitempty"`
	Rule    string `json:"rule,omitempty"` // immutable built-in rule, when this entry carries one
	// The printed table's NOTES column. --json left out the deny_write set and these, so a reader of it could
	// not tell an unenforced deny_read (landlock: parent writable) from an enforced one, nor see the
	// supervisor-only deny_write entries at all. Added keys only: --json never renames one.
	MountPoint bool `json:"mount_point,omitempty"`
	Overlay    bool `json:"overlay,omitempty"`
	Btrfs      bool `json:"btrfs,omitempty"`
	// AskRead marks a deny_read entry declared in fs.ask_read (POC 2026-10-06): kind stays deny_read, which is what
	// every mechanism but tier 1's supervisor applies; tier 1 holds a read beneath it for a person. Added key.
	AskRead bool `json:"ask_read,omitempty"`
	// Unenforced is a deny_read Landlock cannot hold beneath a writable parent. A deny_write entry beneath one
	// is BestEffort by default, refused below a decision plane by the seccomp supervisor only (agent-contract
	// R20), and KernelPlaneRequired under fs.assurance: kernel, where a run no plane decides is refused before
	// its child starts (ADR 0041 D1 (a)); never both.
	Unenforced          bool `json:"unenforced,omitempty"`
	KernelPlaneRequired bool `json:"kernel_plane_required,omitempty"`
	BestEffort          bool `json:"best_effort,omitempty"`
}

// TableExec is one executable entry.
type TableExec struct {
	Raw      string `json:"raw,omitempty"`
	Path     string `json:"path"`
	Basename string `json:"basename"`
	Interp   string `json:"interp,omitempty"`
	Source   string `json:"source"`
	IsDir    bool   `json:"dir,omitempty"`
}

// TableNet is one network entry.
type TableNet struct {
	Raw    string   `json:"raw"`
	Host   string   `json:"host,omitempty"`
	Port   int      `json:"port,omitempty"`
	Proto  string   `json:"proto"`
	IPs    []string `json:"ips,omitempty"`
	Static bool     `json:"static,omitempty"`
	Rule   string   `json:"rule"`
}

// TableSource is where the compiled contract came from: run_start's contract_source for the same argument.
type TableSource struct {
	Path     string `json:"path"`
	Name     string `json:"name,omitempty"`
	Registry string `json:"registry,omitempty"`
}

// sourceJSON is the --json source of a compiled contract, nil for standard input.
func sourceJSON(ref contractRef, rt *agent.RuleTable) *TableSource {
	src := ref.source(rt)
	if src == nil {
		return nil
	}
	return &TableSource{Path: src.Path, Name: src.Name, Registry: src.Registry}
}

// printSource names, above the rule table, the registry a contract given by name was resolved in; a contract given by
// path prints nothing here (the table's contract line names its file).
func printSource(w io.Writer, ref contractRef) error {
	e := ref.entry
	if e == nil {
		return nil
	}
	_, err := fmt.Fprintln(w, record.Printable(fmt.Sprintf("agent     %s, from the %s registry", e.Name, e.Registry)))
	return err
}

// tableJSON projects a RuleTable onto Table.
// tableReads is Table.Reads: fs.reads at tier landlock, where holding reads changes what a nested deny_read does.
func tableReads(rt *agent.RuleTable) TableReads {
	r := TableReads{Mode: string(rt.Reads.Mode), Landlock: "direct", Why: rt.ReadsWhy(backend.TierLandlock), Nested: []string{}}
	if rt.ReadsHeldAt(backend.TierLandlock) {
		r.Landlock = "held"
	}
	for _, n := range rt.Reads.Nested {
		r.Nested = append(r.Nested, n.Rule)
	}
	return r
}

func tableJSON(rt *agent.RuleTable) Table {
	t := Table{
		Name:         rt.Contract.Name,
		ContractHash: hex.EncodeToString(rt.Hash[:]),
		Revision:     rt.Contract.Revision,
		Tier:         string(rt.Tier),
		Reach:        tierNames(rt.Reach),
		Capture:      string(rt.Capture),
		Record:       string(rt.Record),
		Limits: TableLimits{
			CPU:        boundedValue(rt.Limits, agent.BudgetCPU, rt.Limits.CPU),
			CPUWeight:  boundedValue(rt.Limits, agent.BudgetCPUWeight, rt.Limits.CPUWeight),
			Memory:     boundedValue(rt.Limits, agent.BudgetMemory, rt.Limits.MemoryB),
			MemoryHigh: boundedValue(rt.Limits, agent.BudgetMemoryHigh, rt.Limits.MemoryHigh),
			Pids:       boundedValue(rt.Limits, agent.BudgetPids, rt.Limits.Pids),
			Tokens:     boundedValue(rt.Limits, agent.BudgetTokens, rt.Limits.Tokens),
			CostUSD:    boundedValue(rt.Limits, agent.BudgetCostUSD, rt.Limits.CostUSD),
			Wall:       boundedValue(rt.Limits, agent.BudgetWall, durationText(rt.Limits.Wall)),
			StallAfter: boundedValue(rt.Limits, agent.BudgetStallAfter, durationText(rt.Limits.StallAfter)),
			Repeats:    boundedValue(rt.Limits, agent.BudgetRepeats, rt.Limits.Repeats),
		},
		FS:               []TableFS{},
		Reads:            tableReads(rt),
		Exec:             []TableExec{},
		ExecUnrestricted: rt.ExecUnrestricted(),
		Net:              []TableNet{},
		NetUnrestricted:  rt.NetUnrestricted(),
		// The unix half of a contract with no net: section (ADR 0070).
		HostSocketsRefused: rt.HostSocketsRefused(),
		EnvPass:            rt.Env,
		EnvDeny:            append([]string{}, rt.Deny...),
		EnvSet:             map[string]string{},
	}
	if rt.Gate != nil {
		allow, ask := rt.Gate.Thresholds()
		t.Gate = &TableGate{Allow: allow, Ask: ask, Worktree: rt.Workdir, Facts: "copied_syscall", Rules: []TableGateRule{}}
		for i, r := range rt.Gate.Rules() {
			t.Gate.Rules = append(t.Gate.Rules, TableGateRule{Rule: fmt.Sprintf("gate.rules[%d]", i), Predicate: r.Text(), Score: r.Score})
		}
	}
	maps.Copy(t.EnvSet, rt.Set)
	kernel := rt.FilesystemAssurance() == agent.FSAssuranceKernel
	for _, r := range append(append([]agent.FSRule(nil), rt.FS...), rt.DenyWrite...) {
		deny := r.Unenforced && r.Kind == agent.FSDenyWrite
		t.FS = append(t.FS, TableFS{Path: r.Path, Kind: string(r.Kind), Raw: r.Raw, Mount: r.Mount,
			FSType: r.Filesystem, Missing: r.Missing, BuiltIn: r.BuiltIn, Rule: r.BuiltinRule,
			MountPoint: r.IsMountPoint, Overlay: r.Overlay, Btrfs: r.Btrfs, AskRead: r.AskRead && r.Kind == agent.FSDenyRead,
			Unenforced:          r.Unenforced && r.Kind != agent.FSDenyWrite,
			KernelPlaneRequired: deny && kernel,
			BestEffort:          deny && !kernel})
	}
	for _, r := range rt.Exec {
		t.Exec = append(t.Exec, TableExec{Raw: r.Raw, Path: r.Path, Basename: r.Basename, Interp: r.Interp,
			Source: r.Source, IsDir: r.IsDir})
	}
	if ec := rt.ExecCommands; ec != nil {
		for _, en := range ec.Entries {
			p := en.Pattern
			tc := TableExecCommand{List: p.List.String(), Entry: p.Entry, Row: "generic", RowSource: "generic", Reading: p.Reading(), Notes: en.Notes}
			if p.Row != nil {
				tc.Row, tc.RowSource, tc.Version = p.Row.Tool, p.Row.Source.String(), p.Row.Version
			}
			t.ExecCommands = append(t.ExecCommands, tc)
		}
	}
	for _, r := range rt.Net {
		n := TableNet{Raw: r.Raw, Host: r.Host, Port: r.Port, Proto: r.Proto, Static: r.Static, Rule: r.RuleName()}
		for _, ip := range r.IPs {
			n.IPs = append(n.IPs, ip.String())
		}
		t.Net = append(t.Net, n)
	}
	t.Harness = string(rt.Harness)
	return t
}

// durationText renders a limit duration. Unbounded is the caller's null, not a spelling here: a
// duration budget of 0 is a real budget and has to render as one (E16).
func durationText(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	return fmt.Sprint(d)
}
