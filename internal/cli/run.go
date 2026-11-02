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
	"runtime/debug"
	"slices"
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdRun) }

// cmdRun is `tego run <agent.yaml | name> [-v] [--tier T] [--record M] [--observe] [-- <cmd> [args]]` (R29); with no
// <cmd> it runs the contract's own command: (commandFor). A name is resolved in the registries (agent-contract.md R26).
// It owns step 1 of P0-DESIGN §4.1 — load the machine config, load and compile the contract, select
// the tier — and hands step 2 onward to runtime.Run. Its exit code is the agent's own, or one of
// tego's (124, 125, 126, 127, 137, 143) as spec/identity/RUN-IDENTITY.md assigns them.
func cmdRun() Command {
	var (
		tier       string
		recordMode string
		observe    bool
		offline    bool
		verbose    bool
		noSummary  bool
	)
	return Command{
		Name:         "run",
		CommandAfter: 1,
		Passthrough:  true,
		Supervises:   true,
		Summary:      "run a command under a contract",
		Usage:        "<agent.yaml | name> [--tier <t>] [--record <full|summary|off>] [--no-summary] [--observe] [--offline] [-- <cmd> [args]]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&tier, "tier", "", "pin the enforcement tier for this run (auto|landlock|cgroup|bpflsm)")
			fs.StringVar(&recordMode, "record", "", "override the contract's record mode (full|summary|off)")
			fs.BoolVar(&observe, "observe", false, "record only: no enforcement (never selected automatically)")
			fs.BoolVar(&offline, "offline", false, "an unresolvable host is a warning, not an error")
			fs.BoolVar(&verbose, "v", false, "print every compile note at the start, not only those that need you or mean less is enforced")
			fs.BoolVar(&verbose, "verbose", false, "same as -v")
			fs.BoolVar(&noSummary, "no-summary", false, "print no summary when the agent exits (run id, refusals, asks, files written, chain)")
		},
		// The agent owns stdout and stderr: they are passed to the child untouched, and tego's
		// own words go to the command's stderr writer.
		Run: func(ctx context.Context, fs *flag.FlagSet, _, stderr io.Writer) int {
			// With no command after the contract the run execs the contract's own command:, which the
			// schema requires; only a missing contract is a usage error (R29).
			args := fs.Args()
			if len(args) < 1 || args[0] == "" {
				message(stderr, "", 0, 0, "tego run: <agent.yaml | name> [-- <command> [args]]", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if len(args) > 1 && args[1] == "" {
				// An empty $AGENT after --: it reached the runtime as "invalid dependencies: no command", exit 125.
				message(stderr, "", 0, 0, "tego run: the command after the contract is an empty string; name a program, or give none to run the contract's command", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			return runRun(ctx, runOptions{
				contract: args[0], command: args[1:], tier: tier,
				record: recordMode, observe: observe, offline: offline, verbose: verbose, noSummary: noSummary,
			}, stderr)
		},
	}
}

// runOptions is what the flags and arguments resolved to.
type runOptions struct {
	// contract is the contract's path, or an agent's name the registries resolve (agent-contract.md R26).
	contract string
	// generated says tego wrote the contract itself (watch's or adopt's with no --boundary): it is a path, and the
	// run records no contract_source, since no one named a file.
	generated bool
	// command is the command given after the contract, empty when none was: the run then execs the
	// contract's own command: (commandFor).
	command []string
	tier    string
	record  string
	observe bool
	offline bool
	// verbose prints every compile note at the start of the run, informational ones included (runNotices).
	verbose bool
	// resolver is a per-call compilation dependency; nil keeps the system resolver.
	resolver agent.Resolver
	// home is the home "~" and the built-in lists (deny_read's credentials, deny_write's startup files) compile
	// against; "" is the machine's, the invoking user's. An adoption passes its agent's owner's (prepareAdoption).
	home string
	// adopted says the run governs a process already running (tego adopt, the guard): its environment is its own,
	// not this process's, and env: cannot change it, so compile is given no environment and checks no names for
	// secret-env.
	adopted bool
	// loaded is the contract already resolved and loaded (loadRunContract), which compileForRun compiles instead of
	// loading it again; nil loads it there. An adoption loads its boundary before it makes the owner's ~/.tego.
	loaded *loadedContract
	// watched says the run is tego watch's: its notice already says what is recorded and refused, so warnUnenforced
	// is not printed; a bounded watch still gets its --record off line (warnRecordOff).
	watched bool
	// noSummary turns off the end-of-run summary (runsummary.go): only the one line for a run that did not simply
	// exit is printed, as before the summary existed.
	noSummary bool
	// report, when set, is told the run's result once the run is over, with its end summary (nil with noSummary,
	// or for a run that never started), before the exit code is returned. A watched run's summary is printed by
	// report (watch's footer), not by the run path.
	report func(tegoruntime.Result, *endSummary)
}

// runRun is the in-process body of run. Every failure before runtime.Run is exit 125 with a
// diagnostic code (the 2026-09-22 resolution folded the former 210/211/213 into 125).
func runRun(ctx context.Context, o runOptions, stderr io.Writer) int {
	// The capture probes this run was the last to hold are removed once the run is over, off its path and with
	// no fanotify mark of this process left (uprobe.StartDetaches, ADR 0026 (7)).
	defer uprobe.StartDetaches()
	if code := checkRunFlags(o, stderr); code != identity.ExitOK {
		return code
	}
	var finishReserve func()
	if !o.observe && (o.tier == string(backend.TierCgroup) || o.tier == string(backend.TierBPFLSM)) {
		finishReserve = cgroup.StartDescriptorReservation(os.Stderr)
	}
	defer func() {
		if finishReserve != nil {
			finishReserve()
		}
	}()
	// R29's warning is for an --observe or --record off passed by mistake. tego watch says what it records in its
	// own notice, and its flags end at "--", so the line only repeated it. A bounded watch's notice names only
	// the contract, so its --record off is still said here.
	switch {
	case !o.watched:
		warnUnenforced(o, stderr)
	case !o.observe:
		warnRecordOff(o, stderr)
	}
	m, cds, err := loadMachine(config.TrustAbort)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		configRefused(stderr, err)
		return identity.ExitConfig // = 125 [config-untrusted]
	}
	makeOwnDirs(m)
	warnUsersIgnored(stderr, m)
	rt, held, src, code := compileForRun(ctx, o, m, stderr)
	if rt == nil {
		return code
	}
	o.command = commandFor(o, rt)
	// What Compile resolved capture to, before the run's tier can lower it: warnForwarderEnv speaks only where
	// Compile kept a variable the forwarder then overrides.
	compiledCapture := rt.Capture
	// From here on rt is the table selectBackend returns, which names the tier the run got: the capture
	// sources, the kernel recorder and runtime.Run below are all handed this one table.
	b, rt, rep, code := selectBackend(ctx, o, m, rt, stderr)
	if b == nil {
		return code
	}
	if finishReserve == nil && (b.Tier() == backend.TierCgroup || b.Tier() == backend.TierBPFLSM) {
		finishReserve = cgroup.StartDescriptorReservation(os.Stderr)
	}
	_ = agent.WriteDiagnostics(stderr, runNotices(agent.ForTier(held, b.Tier()), o.verbose))
	// R20: `run` sweeps before it starts, so a crashed launcher's orphan is ended and its process
	// tree killed before this run competes with it for the machine.
	sweepBeforeRun(ctx, m, stderr)
	// And, once per gc_interval, gc's retention pass, within its budget.
	retainBeforeRun(ctx, m, stderr)

	// The run directory keeps the contract as compiled, not as written: its sha256 is contract_hash
	// and it needs no profile to reload (contractCopy, agent-contract.md R13).
	yaml, err := contractCopy(rt)
	if err != nil {
		message(stderr, o.contract, 0, 0, "tego run: contract copy: "+err.Error(), codeIO)
		return identity.ExitLauncher
	}
	// The chain anchor is resolved and opened for append — ~/.tego and an empty chain.log created if
	// missing, nothing written — before the run directory exists, so an anchor the run could not
	// extend at Close (no home and no absolute ledger_root, an unwritable home, a planted link) refuses
	// the run here, rather than surfacing as ErrAnchorWrite, exit 125, after the agent already ran.
	// The file can still fail later (a full disk at Close); that is E29's case, not this one.
	anchor, err := anchorPath(m)
	if err == nil {
		err = ledger.ProbeAnchor(anchor)
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego run: chain anchor: "+err.Error(), codeRun)
		return identity.ExitLauncher
	}
	prices, priceGap := runPrices(m, rt, stderr)
	// The capture sources are built before the run so the forwarder's sockets are already bound: the
	// run admits their ports through the enforcement tier it prepares and names their base URLs in the
	// environment the child execs into, both of which happen before the agent runs (capture-derive.md
	// §3, R19, R38).
	sources, captureGaps := captureFor(rt, m, b)
	// What the forwarder that did start overrides of the contract's own environment, when Compile could not
	// know it would start (agent-contract.md R12).
	warnForwarderEnv(stderr, rt, compiledCapture, b.Tier(), sources)
	// The MCP relay (ADR 0126 §4), bound now for the same reason: only for a contract with a relayed server.
	extra, code := mcpRelayFor(rt, ownLogger(m), stderr)
	if code != identity.ExitOK {
		for _, s := range sources {
			_ = s.Stop()
		}
		return code
	}
	stdio := tegoruntime.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	warnStdio(stderr, rt, stdio)
	started, askPending, stopNotice := askNoticesFor(rt, m, b.Tier(), stderr)
	defer stopNotice()
	// A SIGINT or SIGTERM that landed after compileForRun's check (during the probe, the sweep, the capture
	// sources' construction) cancelled a context nothing before this point reads again, and the runtime
	// subscribes to signals of its own only once it prepares the run: without this check the user's
	// interrupt was swallowed and the agent started regardless (R29).
	//
	// The signals are subscribed before that check and handed to the runtime, which reads them once it
	// prepares: notifyContext releases its own handler on the first signal, so one landing between the check and
	// the runtime's own subscription (mintRun's file I/O) would reach neither and the agent would start.
	sigCh, unnotify := launch.Notify()
	defer unnotify()
	if interruptedBeforeStart(ctx, stderr) {
		for _, s := range append(sources, extra...) {
			_ = s.Stop()
		}
		return identity.ExitLauncher
	}
	res, err := startRun(context.WithoutCancel(ctx), rt, o.command, tegoruntime.Deps{
		Config:       m,
		Enforce:      b,
		Build:        runBuild(),
		Stdio:        stdio,
		Signals:      sigCh,
		ContractYAML: yaml,
		AnchorPath:   anchor,
		ParentRun:    parentRunFrom(os.Getenv),
		Prices:       prices,
		PriceGap:     priceGap,
		Capture:      sources,
		CaptureGaps:  captureGaps,
		Extra:        extra,
		// How the person learns an ask waits (ADR 0122): the answer line before the agent's first screen, and a
		// desktop notice per held request; both nil for a run that cannot ask or whose ask.notify turns them off.
		Started:    started,
		AskPending: askPending,
		// The tier's own recorder cannot be built yet: its ring buffer is named by a hash the
		// enforcement handle computes during the run. The runtime calls this once it has one, and
		// only for a tier that writes a ring buffer at all.
		ObserveFactory: recorderFor(rt, ownLogger(m)),
		// tego's own log, never the agent's stderr, which the child owns (OPERATIONS.md): the
		// runtime tags every line with the run id and hands the logger to the supervisor, the
		// ledger writer and the budget watcher.
		Logger: ownLogger(m),
		// The file the user named, by path or by name, which run_start records (agent-contract.md R26).
		ContractSource: src,
		// The provisioner of the run's harness (agent-contract.md R27, ADR 0062), from Layer 3's registry.
		Harness: harnessProvisioner,
		// A condition the run records (a gap, or run_start's best_effort) and the user should hear of before the
		// agent runs, under its own code: a memory cap the swap can bypass (runtime-launch.md R10, swap-uncapped), a
		// held completion whose deputy did not start (held-unavailable), a boundary not held (unenforced).
		Warn: func(code, what string) {
			// The held-label disclosure is a note, not a warning: it says how held opens are decided on this host, and the
			// presenter's first line read like a failure as "warning: ... [unenforced]".
			lead := "warning: "
			if code == tegoruntime.WarnHeldLabel {
				lead = "note: "
			}
			message(stderr, "", 0, 0, lead+"tego run: "+what, code)
		},
	})
	if errors.Is(err, tegoruntime.ErrCaptureUnavailable) {
		// A budget capture was to meter and could not: the machine still does what the cached answer vouched
		// for, so the answer is kept (limits-check-doctor-cli.md R32).
		message(stderr, "", 0, 0, "tego run: "+err.Error(), identity.CodeCaptureUnavailable)
		return identity.ExitLauncher
	}
	if errors.Is(err, tegoruntime.ErrBudgetUnmetered) {
		// A declared budget nothing counts: the contract (or the machine's capture ceiling or price table) is the
		// cause, not the machine's probe answer, which is kept (limits-check-doctor-cli.md R32).
		message(stderr, "", 0, 0, "tego run: "+err.Error(), identity.CodeBudgetUnmetered)
		return identity.ExitLauncher
	}
	if err != nil {
		// A run selected from a cached probe answer that then could not start may be a machine that no longer
		// does what the answer vouched for (a Prepare that cannot load a program, or make its fanotify group):
		// the answer is dropped so the next run probes afresh rather than failing the same way (R27 "What a run
		// probes").
		startFailed(rep)
		message(stderr, "", 0, 0, "tego run: "+err.Error(), codeRun)
		return identity.ExitLauncher // R2: every pre-run_start failure is 125
	}
	// The end summary: after the agent's process tree is gone, from the run's own ledger.
	var sum *endSummary
	if !o.noSummary {
		sum = summarizeRun(ctx, m, anchor, res)
	}
	switch {
	case sum == nil:
		writeRunSummary(stderr, res)
	case !o.watched:
		_, _ = io.WriteString(stderr, sum.text()) // tego's own words; a stderr it cannot write never changes the exit (output_test)
	}
	if o.report != nil {
		o.report(res, sum)
	}
	return runExitCode(stderr, res)
}

// runNotices is the compile findings a run prints before its agent starts. A run prints a notice only when it needs
// the person's action (an error) or when this run enforces less than the contract wrote (a warning about a rule);
// a note that only says how a rule applies (Diagnostic.Informational) is left to `tego compile` and `tego doctor`,
// unless the run is verbose (-v), which prints every one (docs/p0/limits-check-doctor-cli.md, "A quiet start").
func runNotices(ds []agent.Diagnostic, verbose bool) []agent.Diagnostic {
	if verbose {
		return ds
	}
	return slices.DeleteFunc(slices.Clone(ds), agent.Diagnostic.Informational)
}

// commandFor is the command the run execs: the one given on the command line, or, with none, the contract's
// own command: (R29: `tego run a.yaml` was a usage error though the contract names its command). A command
// given on the command line is the launching user's choice, not the agent's, and compileForRun grants it as
// the run's own command for this run (agent.WithRunCommand).
func commandFor(o runOptions, rt *agent.RuleTable) []string {
	if len(o.command) > 0 || rt == nil || rt.Contract == nil {
		return o.command
	}
	return slices.Clone(rt.Contract.Command)
}

// checkRunFlags refuses a --record or --tier value no run takes, as a usage error (exit 2), before the
// machine config is read or the contract compiled: behind a contract that did not compile, a bad flag
// was reported as the contract's exit 125 and its own usage error never shown (R25).
func checkRunFlags(o runOptions, stderr io.Writer) int {
	if o.record != "" {
		if _, err := parseRecordMode(o.record); err != nil {
			message(stderr, "", 0, 0, "tego run: "+err.Error(), codeUsage)
			return identity.ExitUsage
		}
	}
	if _, what := tierPin(o.tier); what != "" {
		message(stderr, "", 0, 0, "tego run: "+what, codeUsage)
		return identity.ExitUsage
	}
	return identity.ExitOK
}

// tierPin is the tier --tier pins, "" for none, or the usage error that refuses the value. --tier auto is no
// pin, as tier: auto is in a contract; observe records without enforcing and is --observe, never a tier to
// select. The usage error named observe among the tiers --tier takes, and --tier observe then failed as
// exit 125 [tier-unavailable] while --tier auto was refused (R29). checkRunFlags and selectBackend share it,
// so the two refusals cannot drift apart.
func tierPin(tier string) (backend.Tier, string) {
	if tier == "" || tier == backend.Auto {
		return "", ""
	}
	t, err := backend.ParseTier(tier)
	switch {
	case t == backend.TierObserve:
		return "", "--tier observe: observe enforces nothing and is not a tier; run with --observe"
	case err != nil:
		return "", fmt.Sprintf("--tier %q is not auto, landlock, cgroup or bpflsm", tier)
	}
	return t, ""
}

// codeUnenforced tags the warning that a flag turned this run's enforcement or its ledger detail off.
const codeUnenforced = "unenforced"

// warnUnenforced says on stderr, every time, that --observe or --record off is in effect: passed by
// mistake (once, an agent's own argument parsed as tego's), either one ran the contract unenforced or
// its run unrecorded with no word said (R29).
func warnUnenforced(o runOptions, stderr io.Writer) {
	if o.observe {
		message(stderr, "", 0, 0, "warning: tego run: --observe is in effect: this run enforces nothing, it only records", codeUnenforced)
	}
	warnRecordOff(o, stderr)
}

// warnRecordOff is R29's --record off half of warnUnenforced. tego watch --boundary prints it alone: its notice says
// whose rules apply, not what the record keeps.
func warnRecordOff(o runOptions, stderr io.Writer) {
	if o.record == string(agent.RecordOff) {
		message(stderr, "", 0, 0, "warning: tego run: --record off is in effect: the ledger keeps only this run's refusals, no exec or allowed events", codeUnenforced)
	}
}

// configRefused prints why run refused the machine config, with the fix compile and doctor already give
// for an untrusted layer: run's line named the file and mode and never said what to change, and it
// prefixed errors that name themselves ("machine config: machine config untrusted: ..."). An invalid
// layer's own errors are on the lines above it.
func configRefused(stderr io.Writer, err error) {
	var ue *config.UntrustedError
	switch {
	case errors.As(err, &ue):
		fmt.Fprintln(stderr, identity.FormatMessage("", 0, 0, "tego run: "+ue.Error(), identity.CodeConfigUntrusted)+" "+ue.Fix())
	case errors.Is(err, config.ErrInvalid) && errors.Is(err, fs.ErrNotExist): // E13: a missing $TEGO_CONFIG printed nothing above
		message(stderr, "", 0, 0, "tego run: "+err.Error(), identity.CodeConfigUntrusted)
	case errors.Is(err, config.ErrInvalid):
		message(stderr, "", 0, 0, "tego run: "+err.Error()+" (its errors are above)", identity.CodeConfigUntrusted)
	default:
		message(stderr, "", 0, 0, "tego run: machine config: "+err.Error(), identity.CodeConfigUntrusted)
	}
}

// warnUsersIgnored is spec/config/v0's "tego run ignores it with a warning" for users:, the per-uid policy
// only tegod reads: an operator who wrote one and saw no word of it could take `tego run` to enforce it.
// Nothing is said when no layer sets it.
func warnUsersIgnored(stderr io.Writer, m *config.Machine) {
	if len(m.Users.Value) == 0 {
		return
	}
	writeConfigDiagnostics(stderr, []config.Diagnostic{{File: m.Users.Source.File, Line: m.Users.Source.Line,
		Code: config.CodeIgnored, Severity: config.SeverityWarning,
		Message: "users: is read by tegod only; tego run ignores it, so its contracts and max_runs bind no run started here"}})
}

// runExitCode is the code `tego run` exits with. The agent's own code, unless the run's record could not be
// completed: that failure is tego's, and 125 says so rather than letting a run whose ledger is incomplete, or
// complete but unanchored, read as the agent's exit (record-ledger.md §7). The summary above it still says
// what the agent did.
func runExitCode(stderr io.Writer, res tegoruntime.Result) int {
	if res.RecordErr == nil {
		return res.ExitCode
	}
	what := "the run's record is incomplete"
	if errors.Is(res.RecordErr, ledger.ErrAnchorWrite) {
		what = "the run is recorded, but its chain anchor was not written"
	}
	message(stderr, "", 0, 0, fmt.Sprintf("tego run: %s (%s): %v", what, res.RunID, res.RecordErr), codeLedger)
	return identity.ExitLauncher
}

// startFailed is what a run that could not start does with the report it selected from, a variable so a test
// can see it called; doctor's own test holds DiscardCache to removing only the answer that report came from.
var startFailed = func(rep *doctor.Report) { rep.DiscardCache() }

// interruptedBeforeStart reports, once it has said so on stderr, whether a SIGINT or SIGTERM cancelled ctx
// before the agent started. Such a run is refused, exit 125 [run], and nothing is launched (R29).
func interruptedBeforeStart(ctx context.Context, stderr io.Writer) bool {
	if ctx.Err() == nil {
		return false
	}
	message(stderr, "", 0, 0, "tego run: interrupted before the agent started; nothing was run", codeRun)
	return true
}

// codeRun is the diagnostic code of a launcher failure before the agent ever ran.
const codeRun = "run"

// codeLedger is the diagnostic code of a run whose record could not be completed (record-ledger §7).
const codeLedger = "ledger"

// The three consumers of the run's table, as variables so a test can see the table each is handed without
// starting an agent. The kernel recorder's is the one no other check covers: it judges every exec the
// tier-2 programs record in its table's tier (internal/runtime/observe, Evaluate at rt.Tier), and the
// runtime's own restamp of the table it enforces never reaches the table this closure holds.
var (
	startRun    = tegoruntime.Run
	captureFor  = selectCapture
	recorderFor = observeFactory
)

// runPrices loads the machine's price table once, here, before the run starts (§7 "open/version
// check at cli startup"): the run's cost ceiling (R2) needs it, and the one warning a missing,
// unreadable or wrong-version table produces has to be printed where the user is, which a launcher
// writing to tego.log cannot do.
//
// It does not fail the run itself. A table this binary declined is a nil table and the gap reason the
// runtime records after run_start, so the ledger says plainly that no cost could be estimated
// (E15, R32) — every other ceiling still holds. A cost_usd budget the contract declares is the exception: the
// runtime refuses that run, 125 [budget-unmetered] (runtime.ErrBudgetUnmetered), since the budget never trips.
//
// With a cost_usd budget a machine ceiling alone imposes the line names it: that budget never trips without
// prices, and the line said only that cost was not estimated.
//
// A table nobody installed (warn.Missing) is a fresh machine's normal state, and with no cost_usd budget in force
// nothing depends on it: the run says nothing at the terminal (the gap is still recorded, and tego measure names
// the missing table where a cost is asked for). A table that is there and refused, or any missing one under a
// cost_usd budget, is always said.
func runPrices(m *config.Machine, rt *agent.RuleTable, stderr io.Writer) (*limits.PriceTable, string) {
	table, warn := limits.FromMachine(m)
	if warn == nil {
		return table, ""
	}
	if warn.Missing && (rt == nil || !rt.Limits.Bounded(agent.BudgetCostUSD)) {
		return nil, warn.Why
	}
	message(stderr, "", 0, 0, "tego run: "+warn.Message+costBudgetUnseen(rt), codeNotFound)
	return nil, warn.Why
}

// costBudgetUnseen is what a missing price table means for the table's cost_usd budget, "" with none, and "" for
// one the contract declares, whose run is refused with its own message.
func costBudgetUnseen(rt *agent.RuleTable) string {
	if rt == nil || !rt.Limits.Bounded(agent.BudgetCostUSD) || (rt.Contract != nil && rt.Contract.Limits.CostUSD != nil) {
		return ""
	}
	return fmt.Sprintf(", so the cost_usd budget of %s never trips", strconv.FormatFloat(rt.Limits.CostUSD, 'f', -1, 64))
}

// makeOwnDirs makes the ledger root and the chain anchor's directory before the contract is compiled:
// the read denies that keep tego's own files from the agent attach to directories that exist
// (agent-contract.md R6a), and a machine's first run is when neither does yet. Made as MakeDirs makes
// them, a root launcher's handed to the user they belong to; a failure is left to the step that needs
// the directory (the sweep, the anchor probe, the run), which reports it.
func makeOwnDirs(m *config.Machine) {
	if root, err := ledgerRootOf(m); err == nil {
		_ = ledger.MakeDirs(root)
	}
	if anchor, err := anchorPath(m); err == nil {
		_ = ledger.MakeDirs(filepath.Dir(anchor))
	}
}

// compileForRun loads and compiles the contract for this run (§4.1 step 1). A contract that does not
// compile never reaches the runtime. The findings that hold in one tier alone (agent.Diagnostic.Tier) are
// returned rather than printed: the run learns its tier only at selection, and an auto contract that lands
// at cgroup is not to be told what Landlock cannot enforce (ADR 0019); printTierFindings prints them then.
// A contract given by name is resolved first (agent-contract.md R26), and a refused name is exit 125, as a missing
// contract file is; "-", standard input, is a usage error (exit 2): it is compile's alone. src is the contract's source
// for run_start, nil for a generated contract.
func compileForRun(ctx context.Context, o runOptions, m *config.Machine, stderr io.Writer) (*agent.RuleTable, []agent.Diagnostic, *record.ContractSource, int) {
	l := o.loaded
	if l == nil {
		var code int
		if l, code = loadRunContract(o, m, stderr); l == nil {
			return nil, nil, nil, code
		}
	}
	ref, c := l.ref, l.contract
	if interruptedBeforeStart(ctx, stderr) {
		return nil, nil, nil, identity.ExitLauncher
	}
	// The tiers this binary builds, as compile passes them: auto resolves to the highest, never to a tier the
	// run cannot get, so the capture and the findings Compile derives from the tier are the run's (ADR 0019).
	opts := []agent.CompileOption{agent.WithContext(ctx), agent.WithPATH(os.Getenv("PATH")), agent.WithClock(time.Now), agent.WithTiers(builtTiers()...)}
	// A generated contract (watch's, adopt's with no --boundary) passes the whole environment because tego chose to
	// observe everything, and its author cannot add the env.pass secret-env's fix names: compile checks no names
	// for it, as it prints none of an adoption's generated warnings (ADR 0067; r6 B1-SECRETS-DEFAULTS).
	if !o.adopted && !o.generated {
		opts = append(opts, agent.WithEnviron(launchEnviron()))
	}
	if o.resolver != nil {
		opts = append(opts, agent.WithResolver(o.resolver))
	}
	home := m.Home
	if o.home != "" {
		home = o.home
	}
	if home != "" {
		opts = append(opts, agent.WithHome(home))
	}
	opts = append(opts, anchorCompileOptions(m)...)
	if o.offline {
		opts = append(opts, agent.Offline())
	}
	// The command given on the command line is the launching user's, granted as the run's own command.
	if len(o.command) > 0 {
		opts = append(opts, agent.WithRunCommand(o.command[0]))
	}
	// --record is the CLI's own override, handed to Compile so that the table's record mode is final before any
	// finding is derived from it (stall-reads-unseen, the record-off budgets): the run is warned about the record it
	// makes. The seccomp filter the backend builds from the table is derived after this, so the
	// run's filter and its record mode can never disagree (I4).
	if o.record != "" {
		mode, err := parseRecordMode(o.record)
		if err != nil {
			message(stderr, "", 0, 0, "tego run: "+err.Error(), codeUsage)
			return nil, nil, nil, identity.ExitUsage
		}
		opts = append(opts, agent.WithRecord(mode))
	}
	// An --observe run installs tier landlock's filter, so what that filter does not see is said of it too.
	if o.observe {
		opts = append(opts, agent.WithObserve())
	}
	// --tier pins the run in the selection, after Compile; a fix that offers to pin another tier in the contract
	// says to drop the flag, since the selection refuses the two as a conflict.
	if t, what := tierPin(o.tier); what == "" && t != "" {
		opts = append(opts, agent.WithTierFlag(t))
	}
	endCompile := startphase.Begin(nil, "compile")
	rt, ds, err := agent.Compile(c, m, opts...)
	endCompile()
	if interruptedBeforeStart(ctx, stderr) {
		return nil, nil, nil, identity.ExitLauncher
	}
	label := ref.label()
	if o.generated {
		label, ds = agent.CommandLineFile, onCommandLine(ds)
	}
	_ = agent.WriteDiagnostics(stderr, runNotices(agent.ForTier(ds, ""), o.verbose))
	if err != nil {
		if !agent.HasErrors(ds) {
			message(stderr, label, 0, 0, err.Error(), loadCode(err))
		}
		return nil, nil, nil, identity.ExitLauncher
	}
	if code := refuseAdjustableRun(rt, ref.label(), o.adopted, stderr); code != 0 {
		return nil, nil, nil, code
	}
	var held []agent.Diagnostic
	for _, d := range ds {
		if d.Tier != "" {
			held = append(held, d)
		}
	}
	var src *record.ContractSource
	if !o.generated {
		src = ref.source(rt)
	}
	return rt, held, src, identity.ExitOK
}

// onCommandLine is ds for a contract tego generated from what the person typed (tego watch -- <command>): they wrote a
// command line, and a finding at "/tmp/tego-watch-123/watch.yaml:4:7" names a file they never saw, gone by the time they
// read the line.
func onCommandLine(ds []agent.Diagnostic) []agent.Diagnostic {
	out := slices.Clone(ds)
	for i := range out {
		out[i].File, out[i].Line, out[i].Col = agent.CommandLineFile, 0, 0
	}
	return out
}

// loadedContract is a run's contract resolved and loaded: the reference it came from (a path, or a name's registry
// entry, whose bytes are the ones compiled) and the contract.
type loadedContract struct {
	ref      contractRef
	contract *agent.Contract
}

// loadRunContract is compileForRun's first step, which changes nothing: "-" refused (exit 2), a name resolved in the
// registries and the file loaded, its notices printed. A refused name, a missing file or one that does not load is
// exit 125, printed. nil is a refusal already printed, with its exit code.
func loadRunContract(o runOptions, m *config.Machine, stderr io.Writer) (*loadedContract, int) {
	if o.contract == stdinContract && !o.generated {
		return nil, refuseStdinContract(stderr)
	}
	ref, rerr := resolveContract(o.contract, o.generated, m)
	if rerr != nil {
		printRefusedName(stderr, "tego run", rerr)
		return nil, identity.ExitLauncher
	}
	c, ds, err := ref.load(profileSources(m))
	_ = agent.WriteDiagnostics(stderr, runNotices(ds, o.verbose))
	if err != nil {
		if !agent.HasErrors(ds) {
			message(stderr, ref.label(), 0, 0, err.Error(), loadCode(err))
		}
		return nil, identity.ExitLauncher
	}
	return &loadedContract{ref: ref, contract: c}, identity.ExitOK
}

// refuseStdinContract is the usage error (exit 2) for "-" as a run's or an adoption's contract. Standard input is
// compile's alone: a run's is the agent's, and a contract read from it names no file for run_start's contract_source,
// whose absence says tego generated the contract (agent-contract.md R26).
func refuseStdinContract(stderr io.Writer) int {
	message(stderr, "", 0, 0, "tego: \"-\" (standard input) is no contract for a run; give the contract's path "+
		"(./- for a file named -) or an agent's name", codeUsage)
	return identity.ExitUsage
}

// parseRecordMode validates --record.
func parseRecordMode(s string) (agent.RecordMode, error) {
	switch agent.RecordMode(s) {
	case agent.RecordFull, agent.RecordSummary, agent.RecordOff:
		return agent.RecordMode(s), nil
	}
	return "", fmt.Errorf("record mode %q is not full, summary or off", s)
}

// selectBackend runs §4.1 step 1's tier selection: the machine ceiling, the contract's pin and what
// this machine and this binary offer. A nil backend is exit 125 [tier-unavailable], decided here and
// never inside runtime.Run (docs/p0/runtime-launch.md R2, invariant 10).
//
// It returns the table the run enforces with the backend: rt at the tier the run got, not the one Compile
// resolved auto to (agent-contract.md R14). Every reader of the table answers in its tier's semantics —
// the kernel recorder judges each exec with Evaluate at rt.Tier, so an auto contract left at bpflsm would
// have its tier-2 execs judged by basename with tier 3's unlisted-script rule (R15) — and the tier-2
// backend refuses a table naming another tier. Returning the stamped table, rather than leaving the stamp
// to the caller, keeps selection and stamp in one place a test can hold to each other. The report the
// selection came from is returned too, nil for --observe, for what the run does if it cannot start
// (startFailed).
func selectBackend(ctx context.Context, o runOptions, m *config.Machine, rt *agent.RuleTable, stderr io.Writer) (enforce.Backend, *agent.RuleTable, *doctor.Report, int) {
	if o.observe {
		return enforce.Observe(), rt, nil, identity.ExitOK
	}
	// --tier pins this run: the selection is offered only that tier, so an unavailable one fails with
	// [tier-unavailable], naming that tier and what doctor says it is missing, instead of silently running
	// at a lower tier. cmdRun refused a bad value already (checkRunFlags); a caller that did not is refused
	// here the same way.
	only, what := tierPin(o.tier)
	if what != "" {
		message(stderr, "", 0, 0, "tego run: "+what, codeUsage)
		return nil, nil, nil, identity.ExitUsage
	}
	endProbe := startphase.Begin(nil, "probe")
	rep, err := probeMachine(ctx, m, doctor.Reach(m, rt, only))
	endProbe()
	if err != nil && interruptedBeforeStart(ctx, stderr) {
		// The probe stopped because the user interrupted the run, not because a tier is missing: it is
		// reported as the interrupt it is, never as [tier-unavailable].
		return nil, nil, nil, identity.ExitLauncher
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego run: "+err.Error(), backend.CodeTierUnavailable)
		return nil, nil, nil, identity.ExitLauncher
	}
	if note := rep.CacheNote(); note != "" {
		fmt.Fprintln(stderr, record.Printable("tego run: note: the run-probe cache is unusable, so this run probed in full: "+note))
	}
	if note := rep.CoordinationNote(); note != "" {
		fmt.Fprintln(stderr, record.Printable("tego run: note: this run could not wait for a concurrent run's probe, so it probed on its own: "+note))
	}
	endSelect := startphase.Begin(nil, "select")
	b, ds := rep.Select(m, rt, only)
	endSelect()
	for _, d := range ds {
		fmt.Fprintln(stderr, record.Printable(d.String()))
	}
	if b == nil {
		return nil, nil, nil, identity.ExitLauncher // 125 [tier-unavailable]
	}
	return b, rt.AtTier(b.Tier()), rep, identity.ExitOK
}

// probeMachine is the tier derivation `tego doctor` reports (derive.go), over the checks of the tiers this
// run's selection can reach (doctor.Reach: the tier --tier, the contract or the machine config names, else the
// highest one root and this build allow under the ceiling): D1, D3, D4 and both halves of D5 for tier
// landlock, root, D2, D7's tier-2 rows and D8 for tier cgroup, and D6's LSM list and the plane's LSM mode for tier
// bpflsm (doctor.ForRun), with whether this binary can construct each tier at all (enforce.Buildable). Every root run used to take the whole of doctor.Run first, tier 3's and
// capture's program loads included, whatever tier it asked for: about 3 s on Ubuntu 24.04's 6.8 in the KVM
// guest for a run of `true` at tier landlock, which failed kill test 4 there (the acceptance run of 2026-09-23). Run
// used to keep a gate of its own before that, tier 1 only, so a root machine never ran at
// tier cgroup and `--tier cgroup` was always exit 125, while doctor on the same machine reported the tier. The
// machine config is passed so the report is the one `tego doctor` prints under the same
// config; Report.Probe is taken before any ceiling, which enforce.Select applies together with the
// contract's pin. The whole report is kept, not only its probe, so a refused tier is explained in doctor's
// words (Report.Select): at and below reach, the report's Probe and WhyNot are doctor.Run's. A variable so
// tests can describe another machine.
var probeMachine = doctor.ForRun

// sweepBeforeRun ends any run whose launcher died, killing what it left behind first (R20). It never
// fails the run that is starting: a sweep error is a warning, because the new run is independent of
// whatever the old one left. It sweeps the runs the ledger root's live index names, not every run the
// root holds (tegoruntime.SweepLive): a pass over the whole root cost every start about 73 µs per
// stored run, and that pass is `tego gc`'s.
func sweepBeforeRun(ctx context.Context, m *config.Machine, stderr io.Writer) {
	root, err := ledgerRootOf(m)
	if err != nil {
		return
	}
	res, err := sweepLive(ctx, root, sweepOptions(m, tegoruntime.WithSweepLogger(ownLogger(m)))...)
	if err != nil {
		message(stderr, "", 0, 0, "tego run: sweep: "+err.Error(), codeIO)
		return
	}
	for _, e := range res.Errs {
		logOwn("sweep: " + e.Error())
	}
	if res.Orphaned > 0 {
		message(stderr, "", 0, 0,
			fmt.Sprintf("tego run: ended %d orphaned run(s) left by a previous launcher", res.Orphaned), codeSweep)
	}
}

// codeSweep tags the one-line note a sweep prints when it ended an orphan.
const codeSweep = "sweep"

// codeStdio tags the warning about a standard stream that reaches the agent with access no rule gives.
const codeStdio = "stdio"

// warnStdio says which of the agent's standard streams give it access its contract does not: the agent
// keeps fds 0-2 whatever they are (runtime-launch invariant 4a), and Landlock checks
// a file's access only at open, so a socket reaches it as a live channel whatever net: says, and a file the
// caller opened beyond the stream's direction (stdin for writing, stdout or stderr for reading) outside every
// write entry is the agent's to use. run_start records every stream's kind either way.
func warnStdio(stderr io.Writer, rt *agent.RuleTable, s tegoruntime.Stdio) {
	for _, st := range tegoruntime.StdioBeyondContract(rt, tegoruntime.DescribeStdio(s)) {
		what := st.Name + " is a socket: the agent reads and writes whatever holds its other end, whatever net: allows"
		if st.Kind == record.StdioFile {
			mode := "reading and writing"
			if !st.Readable {
				mode = "writing"
			} else if !st.Writable {
				mode = "reading"
			}
			what = fmt.Sprintf("%s is %s, open for %s, outside every write entry: the agent keeps that access "+
				"whatever fs: says", st.Name, record.Printable(st.Path), mode)
		}
		message(stderr, "", 0, 0, "warning: tego run: "+what, codeStdio)
	}
}

// sweepLive is the sweep `run` and `stop` make, a variable so a test can see which one they call.
var sweepLive = tegoruntime.SweepLive

// runBuild is what run_start records about this binary.
// parentRunFrom is the run this tego run says it is nested in (Deps.ParentRun, run_start.parent_run, ADR 0073 D3):
// the enclosing run's TEGO_RUN_ID when the launcher's environment has one, since inside a governed agent
// TEGO_PARENT_RUN names that run's own parent (RUN-IDENTITY.md: the identity set passes the inherited value on), so
// reading it would record the grandparent; else the TEGO_PARENT_RUN an orchestrator handed it; "" for neither. Either
// is the environment's claim, which the runtime checks only for being a run id.
func parentRunFrom(getenv func(string) string) string {
	if id := getenv(identity.EnvRunID); id != "" {
		return id
	}
	return getenv(identity.EnvParentRun)
}

func runBuild() tegoruntime.Build {
	b := buildInfo(debug.ReadBuildInfo)
	kernel := ""
	if k, err := sys.Kernel(); err == nil {
		kernel = k.String()
	}
	parsers := map[string]string{}
	for _, p := range b.Parsers {
		parsers[p] = "1"
	}
	// A build without the objects has no hash, and run_start's field is then empty, not the word
	// "none". The runtime records the prepared tier's own hash in its place, and "" at tier 1.
	bpfHash := b.BPFHash
	if bpfHash == none {
		bpfHash = ""
	}
	return tegoruntime.Build{Version: b.Tego, Commit: b.Commit, BPFHash: bpfHash, Kernel: kernel, Parsers: parsers}
}

// writeRunSummary prints tego's own one-line verdict for a run that did not simply exit, so the
// reason never has to be inferred from an exit code alone (§7 "User sees").
func writeRunSummary(stderr io.Writer, res tegoruntime.Result) {
	how := endedHow(res.Reason)
	if how == "" {
		return
	}
	what := "run ended: " + how
	if res.Reason == record.RunEndStopped {
		what = "run stopped"
	}
	message(stderr, "", 0, 0, fmt.Sprintf("tego: %s (%s)", what, res.RunID), res.Reason)
}

// endedHow is how a run that did not simply exit ended, in a few words ("out of memory", "stopped"); "" for a run
// that exited, or whose exec failed (the shell convention's own 126/127 and the child stage's message already said
// it).
func endedHow(reason string) string {
	switch reason {
	case record.RunEndExit, "", record.RunEndExecFailed:
		return ""
	case record.RunEndOOM:
		return "out of memory"
	case record.RunEndPids:
		return "process limit reached"
	case record.RunEndStopped:
		return "stopped"
	case record.RunEndLimit:
		return "a limit was reached"
	case record.RunEndSignal:
		return "signalled"
	}
	return reason
}

// Argument errors the run-side commands share; both are usage errors (R25), never tego's own.
var (
	// errRunNotFound is a run id that names no directory under the ledger root.
	errRunNotFound = errors.New("no such run")
	// errBadRunID is an argument that is not shaped like a run id at all.
	errBadRunID = errors.New("is not a run id")
)
