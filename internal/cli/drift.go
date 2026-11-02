// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdDrift) }

// cmdDrift is `tego drift <run> [--json] [--aggregate]` (R29): declared versus observed per rule,
// read from the run's ledger and its own contract.yaml copy (R13-R17). Exit 1 when it finds drift
// — a changed contract, a declared entry nothing used, an MCP server the record could have seen
// start and did not (R15), a refusal, or an action against a rule the contract never declared
// (R25); exit 0 when the run did exactly what the contract describes, 2 on usage. A server no
// producer could have observed is printed as unobservable and is not drift, and so is a deny_read
// or watch entry of a run that recorded no reads (R14); the gap line (R34) says what else
// the record could not see. The execs the record flags fileless (an image with no file) or dropped (a
// file written during the run) are listed by image with their verdicts, and are not drift on their own (R17a).
func cmdDrift() Command {
	var (
		asJSON    bool
		aggregate bool
	)
	return Command{
		Name:    "drift",
		Summary: "declared vs observed",
		Usage:   "<run> [--json] [--aggregate]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object")
			fs.BoolVar(&aggregate, "aggregate", false, "sum every run of this run's agent under the ledger root")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego drift: exactly one run id or run directory", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			return runDrift(ctx, fs.Arg(0), aggregate, asJSON, stdout, stderr)
		},
	}
}

// runDrift is the in-process body of drift.
func runDrift(ctx context.Context, ref string, aggregate, asJSON bool, stdout, stderr io.Writer) int {
	mc := &machineOnce{stderr: stderr}
	dir, err := resolveRunDir("drift", ref, true, mc)
	if err != nil {
		return runRefFailed(stderr, "drift", err)
	}
	rep, err := driftReport(ctx, dir, mc, stderr)
	if err != nil {
		return driftError(stderr, err)
	}
	var skipped []string
	if aggregate {
		var errs []skippedRun
		rep, errs, err = aggregateAgent(ctx, filepath.Dir(dir), rep, mc, stderr)
		if err != nil {
			return driftError(stderr, err)
		}
		// §6 case 8: collecting is not swallowing. Each run the sum left out is named on stderr and in
		// --json, and the exit is 125, never the 0 or 1 of a total that reads as complete (E26). A run
		// directory with no events.jsonl yet, or one whose ledger holds no complete line, is younger than its
		// ledger: nothing is missing from the sum.
		for _, e := range errs {
			if errors.Is(e, fs.ErrNotExist) || errors.Is(e, errNeverStarted) {
				continue
			}
			message(stderr, "", 0, 0, "tego drift: skipped "+e.Error(), readCode(e))
			logOwn("drift: " + e.Error())
			skipped = append(skipped, e.run)
		}
	}
	if err := writeDrift(stdout, rep, skipped, asJSON); err != nil {
		message(stderr, "", 0, 0, "tego drift: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if len(skipped) > 0 {
		return identity.ExitError
	}
	if rep.Drifted() {
		return identity.ExitFinding // R25: drift found drift
	}
	return identity.ExitOK
}

// driftError maps a failure onto its exit code: a mixed-agent aggregation is a usage error (§7),
// anything else is Tego's own (a corrupt ledger, an unreadable directory).
func driftError(stderr io.Writer, err error) int {
	if errors.Is(err, context.Canceled) {
		return readFailed(stderr, "drift", err)
	}
	if errors.Is(err, drift.ErrMixedAgent) {
		message(stderr, "", 0, 0, "tego drift: refusing to aggregate: "+err.Error(), codeUsage)
		return identity.ExitUsage
	}
	message(stderr, "", 0, 0, "tego drift: "+err.Error(), readCode(err))
	return identity.ExitError
}

// machineOnce resolves the machine config once per invocation (R24) however many runs drift reads, and
// prints its diagnostics, or its failure, once: --aggregate loaded it and printed each warning once per run.
// It also keeps the rule tables compiled under that config, so --aggregate compiles an agent's contract once
// per distinct (contract, cwd, run command) rather than once per run: Compile lists directories and resolves
// links for every deny-write search.
type machineOnce struct {
	stderr   io.Writer
	done     bool
	reported bool // get printed the failure
	m        *config.Machine
	err      error
	tables   map[tableKey]*agent.RuleTable
}

// tableKey is what a recompiled table depends on besides the machine config, which is one per invocation:
// the merged contract (its canonical hash, which covers the extends chain it was loaded with), the run's cwd
// and its command-line command.
type tableKey struct {
	hash       [32]byte
	cwd        string
	runCommand string
}

// compileTable is agent.Compile; a variable so a test can count the compiles an aggregation makes.
var compileTable = agent.Compile

// get is the machine config, loaded on the first call.
func (o *machineOnce) get() (*config.Machine, error) {
	m, err := o.load()
	if err != nil && !o.reported {
		o.reported = true
		message(o.stderr, "", 0, 0, "machine config: "+err.Error(), config.CodeUntrusted)
	}
	return m, err
}

// load is the machine config, loaded on the first call with its diagnostics printed then, and no message
// for a failure: the caller words that itself. Every consumer of one invocation (the run id's ledger root,
// the prices, the anchor, drift's rule tables) reads this one load (R24).
func (o *machineOnce) load() (*config.Machine, error) {
	if !o.done {
		o.done = true
		m, cds, err := loadMachine(config.TrustWarn)
		writeConfigDiagnostics(o.stderr, cds)
		o.m, o.err = m, err
	}
	return o.m, o.err
}

// driftReport computes one run directory's report. The reader is closed before it returns, so an
// aggregation over hundreds of runs holds one descriptor at a time (§9 C4).
func driftReport(ctx context.Context, dir string, mc *machineOnce, stderr io.Writer) (*drift.Report, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, noRunRecord{dir: dir, err: err}
		}
		return nil, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	defer func() { warnNewer(stderr, "drift", dir, r.SkippedNewer()) }()
	if err := needRunRecord(r, dir); err != nil {
		if errors.Is(err, ledger.ErrCorruptLedger) {
			return nil, fmt.Errorf("%w: %w", drift.ErrRead, err)
		}
		return nil, err
	}
	origin, err := readRunOrigin(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", drift.ErrRead, err)
	}
	rt, unknown := contractTable(ctx, dir, origin, mc, stderr)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rep, err := drift.ComputeCtx(ctx, r, rt)
	if err != nil {
		return nil, err
	}
	rep.DeclaredUnknown = unknown
	if rep.Run == "" {
		rep.Run = filepath.Base(dir)
	}
	// status.Lost's test: a lock that cannot be read says nothing, so such a run is not called cut off.
	if held, err := ledger.LockHeld(dir); err == nil {
		rep.CutOff = !rep.Ended && !held
	}
	return rep, nil
}

// contractTable recompiles the run directory's own contract.yaml copy with today's compiler, which
// is what makes CurrentHash comparable with what the run recorded (R16) and what supplies the
// declared entries. The copy is the canonical merged contract (contractCopy), so it loads with its
// extends sealed rather than against today's profiles directory, and it compiles against the run's
// own working directory from run_start, where its relative entries resolved. Taking either from the
// invocation instead made a profile edited after the run, or drift run from another directory, read
// as a changed contract. The run's command-line command is granted as the run granted it (runOrigin.runCommand).
// A missing copy is not an error — the run crashed before it was written (§6 case
// 23) — and neither is a contract that no longer compiles here (its paths may be gone): the hash
// still answers "did the contract change", so the report degrades instead of failing.
func contractTable(ctx context.Context, dir string, origin runOrigin, mc *machineOnce, stderr io.Writer) (rt *agent.RuleTable, unknown bool) {
	path := filepath.Join(dir, ledger.ContractFile)
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}
	m, err := mc.get()
	if err != nil {
		return nil, false
	}
	c, ds, err := loadContractCopy(path, origin.contractHash, profileSources(m))
	if err != nil {
		what, code := firstDiagnostic(ds, err)
		message(stderr, path, 0, 0, "contract.yaml no longer loads: "+what, code)
		return nil, false
	}
	opts := []agent.CompileOption{
		agent.WithContext(ctx),
		agent.WithPATH(os.Getenv("PATH")), agent.WithClock(time.Now), agent.Offline(),
	}
	if m.Home != "" {
		opts = append(opts, agent.WithHome(m.Home))
	}
	opts = append(opts, anchorCompileOptions(m)...)
	if origin.cwd != "" {
		opts = append(opts, agent.WithCwd(origin.cwd))
	}
	// The run's table granted the command it was given on its command line; recompiled without it, every
	// exec of that command read as an action no entry declares, and every such run drifted (agent-contract.md R8).
	if origin.runCommand != "" {
		opts = append(opts, agent.WithRunCommand(origin.runCommand))
	}
	key, keyed := tableKey{cwd: origin.cwd, runCommand: origin.runCommand}, false
	if h, err := c.Hash(); err == nil {
		key.hash, keyed = h, true
		if rt, ok := mc.tables[key]; ok {
			return rt, false
		}
	}
	rt, ds, err = compileTable(c, m, opts...)
	if ctx.Err() != nil {
		return nil, false // driftReport returns the interrupt, never a degraded contract report
	}
	if err == nil {
		// Only a table that compiled is kept: a failure is reported for each run it affects, as before.
		if keyed {
			if mc.tables == nil {
				mc.tables = map[tableKey]*agent.RuleTable{}
			}
			mc.tables[key] = rt
		}
		return rt, false
	}
	// The contract still hashes, so the hash comparison survives; the declared
	// entries do not, so a rule no entry covers is unknown, not undeclared (the second result; Report.DeclaredUnknown).
	what, code := firstDiagnostic(ds, err)
	message(stderr, path, 0, 0, "contract.yaml no longer compiles here: "+what, code)
	hash, herr := c.Hash()
	if herr != nil {
		return nil, false
	}
	return &agent.RuleTable{Contract: c, Hash: hash}, true
}

// firstDiagnostic is the first error diagnostic's message and code, falling back to the error itself under
// schema. The code is returned apart, for message to append once: rendered into the message too, it
// printed "[schema] [schema]".
func firstDiagnostic(ds []agent.Diagnostic, err error) (string, string) {
	for _, d := range ds {
		if d.IsError() {
			return d.Message, d.Code
		}
	}
	return err.Error(), agent.CodeSchema
}

// noRunRecord is a run directory with no events.jsonl. It prints as it always did and keeps
// fs.ErrNotExist wrapped, so --aggregate can tell a run younger than its ledger from an unreadable one.
type noRunRecord struct {
	dir string
	err error
}

func (e noRunRecord) Error() string { return "no run record at " + e.dir }
func (e noRunRecord) Unwrap() error { return e.err }

// skippedRun is one run aggregateAgent could not read, named by its run id.
type skippedRun struct {
	run string
	err error
}

func (e skippedRun) Error() string { return e.run + ": " + e.err.Error() }
func (e skippedRun) Unwrap() error { return e.err }

// aggregateAgent sums every run of this run's agent under the ledger root (R17). One unreadable
// run never hides the rest (§6 case 8): it is returned in skipped, for the caller to report, and the sum
// goes on. Another agent's run is skipped on its first line, before its contract is recompiled; a run
// whose agent cannot be read is not known to be another agent's, so it is read, and fails, in full.
func aggregateAgent(ctx context.Context, root string, first *drift.Report, mc *machineOnce,
	stderr io.Writer) (*drift.Report, []skippedRun, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, fmt.Errorf("read ledger root: %w", err)
	}
	reports := []*drift.Report{first}
	var skipped []skippedRun
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !e.IsDir() || !ledger.IsRunID(e.Name()) || e.Name() == first.Run {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if agentID, err := runAgent(dir); err == nil && string(agentID) != first.Agent {
			continue
		}
		rep, err := driftReport(ctx, dir, mc, stderr)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, nil, err
			}
			skipped = append(skipped, skippedRun{run: e.Name(), err: err})
			continue
		}
		if rep.Agent != first.Agent {
			continue
		}
		reports = append(reports, rep)
	}
	sum, err := drift.Aggregate(reports)
	return sum, skipped, err
}

// driftJSON is the --json shape: one object per invocation, fields in the report's own order (R31).
type driftJSON struct {
	Run          string `json:"run,omitempty"`
	Agent        string `json:"agent"`
	Runs         int    `json:"runs"`
	ContractHash string `json:"contract_hash,omitempty"`
	CurrentHash  string `json:"current_hash,omitempty"`
	HashChanged  bool   `json:"hash_changed"`
	// DeclaredUnknown was added after the rest: --json gains keys and never renames one.
	DeclaredUnknown bool            `json:"declared_unknown,omitempty"`
	Hashes          []driftHashJSON `json:"hashes,omitempty"`
	Actions         int             `json:"actions"`
	Rules           []driftRuleJSON `json:"rules"`
	Undone          []string        `json:"undone"`
	UnusedMCP       []string        `json:"unused_mcp"`
	// UnobservableMCP and Gaps were added after the rest: --json gains keys and never renames one.
	UnobservableMCP []string  `json:"unobservable_mcp"`
	Gaps            []gapJSON `json:"gaps"`
	// GapWords is what those gaps mean in a person's words (gaps.Words, the table's "in words:" line), as in status.
	GapWords string `json:"gap_words,omitempty"`
	Drift    bool   `json:"drift"`
	// UnobservableFS: deny_read and watch entries a run without read records could not see used
	// (R14).
	UnobservableFS []string `json:"unobservable_fs"`
	// UnobservableRecord: entries a record: off run (no allowed events) could not see used (R14).
	UnobservableRecord []string `json:"unobservable_record"`
	// BestEffort: the cells the run (or any aggregated run) decided on copied syscall facts, never
	// counted as enforced (ADR 0041 D1, D7); absent when there were none.
	BestEffort []string `json:"best_effort,omitempty"`
	// GuardsNotExercised: exec.deny and exec.ask entries no line named (ADR 0048 (8)); reported, never drift;
	// absent when there were none.
	GuardsNotExercised []string `json:"guards_not_exercised,omitempty"`
	// FilelessExecs and DroppedExecs: the images exec lines flagged fileless or dropped, each with its execs by
	// verdict (R17a); reported, never drift on their own; [] when there were none. FilelessMore and DroppedMore count
	// the flagged execs of images past the report's bound (32 per list); absent when there were none.
	FilelessExecs []driftExecJSON `json:"fileless_execs"`
	FilelessMore  int             `json:"fileless_more,omitempty"`
	DroppedExecs  []driftExecJSON `json:"dropped_execs"`
	DroppedMore   int             `json:"dropped_more,omitempty"`
	// Skipped: the runs --aggregate could not read and left out of the sum (§6 case 8); the exit is then
	// 125. Always [] without --aggregate.
	Skipped []string `json:"skipped"`
}

// driftHashJSON is one distinct contract hash of an aggregated report.
type driftHashJSON struct {
	Hash string `json:"hash"`
	Runs int    `json:"runs"`
}

// driftRuleJSON is one rule's counts.
type driftRuleJSON struct {
	Section  string `json:"section"`
	Rule     string `json:"rule"`
	Declared bool   `json:"declared"`
	Allow    int    `json:"allow"`
	Ask      int    `json:"ask"`
	Refused  int    `json:"refused"`
	Observed int    `json:"observed"`
	// Alternate is the rule's held opens a person answered with another file (ADR 0057 D1).
	Alternate int `json:"alternate"`
}

// driftExecJSON is one image a fileless or dropped exec named, with its execs by verdict (R17a).
type driftExecJSON struct {
	Path     string `json:"path"`
	Allow    int    `json:"allow"`
	Ask      int    `json:"ask"`
	Refused  int    `json:"refused"`
	Observed int    `json:"observed"`
}

// writeDrift renders the report as one aligned table, or as JSON (R31).
func writeDrift(w io.Writer, rep *drift.Report, skipped []string, asJSON bool) error {
	if asJSON {
		o := driftObject(rep)
		o.Skipped = append(o.Skipped, skipped...)
		return writeJSON(w, o)
	}
	head := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if rep.Run != "" {
		fmt.Fprintf(head, "RUN\t%s\n", record.Printable(rep.Run))
	}
	fmt.Fprintf(head, "AGENT\t%s\n", record.Printable(rep.Agent))
	fmt.Fprintf(head, "RUNS\t%d\n", rep.Runs)
	fmt.Fprintf(head, "CONTRACT\t%s\n", contractLine(rep))
	fmt.Fprintf(head, "ACTIONS\t%d\n", rep.Actions)
	if err := head.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SECTION\tRULE\tDECLARED\tALLOW\tASK\tREFUSED\tOBSERVED\tALTERNATE")
	rows := 0
	for _, s := range rep.Sections() {
		for _, c := range s.Counts {
			rows++
			// The ledger and the contract copy are readable text anyone with the user's uid can edit, so
			// every name printed here is escaped for the terminal (record.Printable).
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n", record.Printable(string(s.Section)), record.Printable(c.Rule), yesNo(c.Declared),
				c.Allow, c.Ask, c.Refused, c.Observed, c.Alternate)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if rows == 0 {
		fmt.Fprintln(w, "(no rules declared and none recorded)")
	}
	if len(rep.Undone) > 0 {
		fmt.Fprintf(w, "\ndeclared, never used: %s\n", printableJoin(rep.Undone))
	}
	if len(rep.UnusedMCP) > 0 {
		fmt.Fprintf(w, "unused mcp servers: %s\n", printableJoin(rep.UnusedMCP))
	}
	// The images the record flags (R17a), whatever the verdict: each says by its counts whether it ran.
	if len(rep.Fileless) > 0 || rep.FilelessMore > 0 {
		fmt.Fprintf(w, "execs of an image with no file (fileless): %s\n", flaggedText(rep.Fileless, rep.FilelessMore))
	}
	if len(rep.Dropped) > 0 || rep.DroppedMore > 0 {
		fmt.Fprintf(w, "execs that ran a file the run wrote (dropped; the program named, its #! interpreter or a loaded binary): %s\n", flaggedText(rep.Dropped, rep.DroppedMore))
	}
	if len(rep.UnobservableMCP) > 0 {
		fmt.Fprintf(w, "mcp servers not observable (no MCP producer recorded): %s\n",
			printableJoin(rep.UnobservableMCP))
	}
	if len(rep.UnobservableFS) > 0 {
		fmt.Fprintf(w, "fs entries not observable (the run recorded no reads): %s\n",
			printableJoin(rep.UnobservableFS))
	}
	if len(rep.UnobservableRecord) > 0 {
		fmt.Fprintf(w, "entries not observable (the run recorded no allowed events): %s\n",
			printableJoin(rep.UnobservableRecord))
	}
	if len(rep.GuardsNotExercised) > 0 {
		fmt.Fprintf(w, "exec guards not exercised (deny and ask entries nothing tried): %s\n",
			printableJoin(rep.GuardsNotExercised))
	}
	if len(rep.BestEffort) > 0 {
		fmt.Fprintf(w, "best effort (decisions on copied syscall facts, not enforced): %s\n",
			printableJoin(rep.BestEffort))
	}
	if len(skipped) > 0 {
		fmt.Fprintf(w, "runs left out of the sum (unreadable): %s\n", printableJoin(skipped))
	}
	// A person's live changes (a block, a lift, a pause) are recorded as gap lines but are not gaps (gaps.Split).
	missed, live := gaps.Split(rep.Gaps)
	if _, err := fmt.Fprintf(w, "gaps: %s\n", gaps.Line(missed)); err != nil {
		return err
	}
	if len(live) > 0 {
		if _, err := fmt.Fprintf(w, "live changes: %s\n", gaps.Line(live)); err != nil {
			return err
		}
	}
	// Those two lines give the kinds as the record spells them; this one says what they mean, as status does.
	if words := gaps.Words(rep.Gaps, rep.CutOff); words != "" {
		_, err := fmt.Fprintf(w, "in words: %s\n", words)
		return err
	}
	return nil
}

// flaggedText renders one of R17a's lists for its line of text: each image, escaped for the terminal (its name is the
// agent's to choose), with its execs by verdict, as in "/memfd:x (refused x1)", then the execs of the images past the
// report's bound.
func flaggedText(images []drift.FlaggedExec, more int) string {
	parts := make([]string, 0, len(images)+1)
	for _, f := range images {
		var counts []string
		for _, c := range []struct {
			verdict string
			n       int
		}{{"allow", f.Allow}, {"ask", f.Ask}, {"refused", f.Refused}, {"observed", f.Observed}} {
			if c.n > 0 {
				counts = append(counts, fmt.Sprintf("%s x%d", c.verdict, c.n))
			}
		}
		parts = append(parts, record.Printable(f.Path)+" ("+strings.Join(counts, ", ")+")")
	}
	if more > 0 {
		parts = append(parts, fmt.Sprintf("+%d execs of other images", more))
	}
	return strings.Join(parts, ", ")
}

// printableJoin joins names for one line of text, each escaped for the terminal.
func printableJoin(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = record.Printable(n)
	}
	return strings.Join(out, ", ")
}

// contractLine says what happened to the contract since the run: unchanged, changed and from
// what, unknown when the run directory has no contract.yaml copy, or the distinct hashes of an
// aggregated report (R16, R17).
func contractLine(rep *drift.Report) string {
	if len(rep.Hashes) > 1 {
		parts := make([]string, 0, len(rep.Hashes))
		for _, h := range rep.Hashes {
			parts = append(parts, fmt.Sprintf("%s (%d runs)", short(h.Hash), h.Runs))
		}
		return strings.Join(parts, ", ") + " — changed across runs"
	}
	switch {
	case rep.ContractHash == "":
		return "unknown (the run recorded no contract hash)"
	case rep.CurrentHash == "":
		return short(rep.ContractHash) + " (no contract.yaml copy to compare)"
	case rep.HashChanged:
		return short(rep.CurrentHash) + " now, " + short(rep.ContractHash) + " at the run — changed"
	case rep.DeclaredUnknown:
		return short(rep.ContractHash) + " (unchanged; declared entries could not be recompiled here, undeclared rules are not counted)"
	}
	return short(rep.ContractHash) + " (unchanged)"
}

// short abbreviates a hex hash for a terminal line; the full value is in --json.
func short(hash string) string {
	if len(hash) > 12 {
		hash = hash[:12]
	}
	return record.Printable(hash)
}

// yesNo renders a declared flag.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// driftObject projects a report onto its JSON shape; empty lists render as [] rather than null so
// a jq pipeline never has to special-case them (§6 case 22).
func driftObject(rep *drift.Report) driftJSON {
	o := driftJSON{
		Run: rep.Run, Agent: rep.Agent, Runs: rep.Runs,
		ContractHash: rep.ContractHash, CurrentHash: rep.CurrentHash, HashChanged: rep.HashChanged, DeclaredUnknown: rep.DeclaredUnknown,
		Actions: rep.Actions, Rules: []driftRuleJSON{},
		Undone: []string{}, UnusedMCP: []string{}, UnobservableMCP: []string{}, UnobservableFS: []string{}, UnobservableRecord: []string{},
		Skipped: []string{}, Gaps: gapObjects(rep.Gaps), GapWords: gaps.Words(rep.Gaps, rep.CutOff), Drift: rep.Drifted(),
		FilelessExecs: flaggedObjects(rep.Fileless), FilelessMore: rep.FilelessMore,
		DroppedExecs: flaggedObjects(rep.Dropped), DroppedMore: rep.DroppedMore,
	}
	for _, h := range rep.Hashes {
		o.Hashes = append(o.Hashes, driftHashJSON{Hash: h.Hash, Runs: h.Runs})
	}
	for _, s := range rep.Sections() {
		for _, c := range s.Counts {
			o.Rules = append(o.Rules, driftRuleJSON{
				Section: string(s.Section), Rule: c.Rule, Declared: c.Declared,
				Allow: c.Allow, Ask: c.Ask, Refused: c.Refused, Observed: c.Observed, Alternate: c.Alternate,
			})
		}
	}
	o.Undone = append(o.Undone, rep.Undone...)
	o.UnusedMCP = append(o.UnusedMCP, rep.UnusedMCP...)
	o.UnobservableMCP = append(o.UnobservableMCP, rep.UnobservableMCP...)
	o.UnobservableFS = append(o.UnobservableFS, rep.UnobservableFS...)
	o.UnobservableRecord = append(o.UnobservableRecord, rep.UnobservableRecord...)
	o.BestEffort = rep.BestEffort
	o.GuardsNotExercised = rep.GuardsNotExercised
	return o
}

// flaggedObjects projects one of R17a's lists onto its JSON shape, [] when it is empty.
func flaggedObjects(images []drift.FlaggedExec) []driftExecJSON {
	out := make([]driftExecJSON, 0, len(images))
	for _, f := range images {
		out = append(out, driftExecJSON{Path: f.Path, Allow: f.Allow, Ask: f.Ask, Refused: f.Refused, Observed: f.Observed})
	}
	return out
}
