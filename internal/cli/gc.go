// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/rulefile"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdGC) }

// cmdGC is `tego gc [--keep <d>] [--dry-run] [--json]` (R29). It is the operator's handle on the orphan
// sweep `run` and `stop` perform on every invocation, with two differences: those sweep only the runs the
// ledger root's live index names and only end orphans, while gc walks every run directory under the root,
// ending any orphan whatever the index says, and also applies retention and removes what has aged out.
//
// The pass needs no coordination with a running Tego: each run's flock is the whole serialization. A run
// whose lock its live launcher holds is kept whatever its age; a lock held with its launcher gone is
// reclaimed (the run's tree killed) and the run swept. A run that starts during the pass may not hold its
// lock yet when the pass reads it, and reads as empty, so the pass takes the run's lock itself before it
// removes anything: a launcher that locked first keeps its directory, and one that comes after fails its
// flock or finds the directory gone, before run_start. gc reads no live index, so an ended run whose
// launcher died before its anchor line or its scope's removal is repaired by run's and stop's sweep alone
// (record-ledger.md §3 Live index).
//
// As root it also sweeps the tier-2 builds lingering on the bpf filesystem (ADR 0022): one no launcher holds,
// whose run set names no live cgroup and that has been idle for the machine's bpf.linger is removed, and
// --builds removes such a build whatever its idle time.
//
// --keep 0s keeps nothing: every run that is not running is removed, which is the "gc --keep 0 sweep"
// record-ledger.md names. It used to be read as "no --keep" and silently became the machine's 30-day
// retention (R29).
//
// The same retention prunes the ledger root's rule-change journal (.rule-changes, pruneRuleChanges) once the runs
// are swept: its lines older than it that no reader needs (rulefile.Prune: a run still in the root keeps the lines
// since it started and those that name it, and each contract its newest rulefile.KeepChanges changes that stand while
// its file is there), then the blobs no line left names and the lock files of contracts with no line left. --dry-run
// counts what would go, the runs it would remove counted as gone. When gc applies the machine's retention (no --keep),
// a machine config layer the load skipped leaves the journal as it is, since the retention that layer may set is not
// known. As root, gc prunes the invoking user's journal as that user.
func cmdGC() Command {
	var (
		keepText string
		dryRun   bool
		asJSON   bool
		builds   bool
	)
	return Command{
		Name:    "gc",
		Summary: "sweep orphans and expire old runs",
		Usage:   "[--keep <d>] [--dry-run] [--builds] [--json]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&keepText, "keep", "", "retention window of the runs and the rule-change journal, e.g. 30d or 12h; "+
				"0s keeps no run that is not running (default: the machine's retention)")
			fs.BoolVar(&dryRun, "dry-run", false, "report what the pass would do without writing or removing anything")
			fs.BoolVar(&asJSON, "json", false, "one JSON object")
			fs.BoolVar(&builds, "builds", false, "as root, remove every idle tier-2 build now, not only those idle "+
				"for bpf.linger")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego gc: no arguments", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			keep, given, err := explicitDuration(fs, "keep", keepText)
			if err != nil {
				message(stderr, "", 0, 0, "tego gc: --keep: "+err.Error(), codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if !given {
				keep = -1 // runGC: the machine's retention
			}
			return runGC(ctx, keep, dryRun, builds, asJSON, stdout, stderr)
		},
	}
}

// explicitDuration reads a duration flag registered as a string: given reports whether the command line
// set it (fs.Visit), and its text is parsed with config.ParseDuration, the machine config's own grammar (d,
// h, m, s, ms; never negative). flag.DurationVar refused "1d" although gc itself prints "30d" and the config
// file takes it, and it could not tell an explicit 0s from an absent flag (R29).
func explicitDuration(fs *flag.FlagSet, name, text string) (time.Duration, bool, error) {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	if !given {
		return 0, false, nil
	}
	d, err := config.ParseDuration(text)
	if err != nil {
		return 0, true, errors.New(strings.TrimPrefix(err.Error(), config.ErrUnit.Error()+": "))
	}
	return d, true, nil
}

// gcJSON is the --json shape: the sweep's counts plus one string per run that could not be finished, one
// per failed bpf sweep, prefixed "builds: ", "capture probes: " or "rings: ", and one for a rule-change
// journal not pruned, prefixed "rule-change journal: ".
type gcJSON struct {
	Root     string  `json:"root"`
	KeepS    float64 `json:"keep_s"`
	DryRun   bool    `json:"dry_run"`
	Scanned  int     `json:"scanned"`
	Orphaned int     `json:"orphaned"`
	Deleted  int     `json:"deleted"`
	// BuildsRemoved counts the idle tier-2 builds a root gc removed (ADR 0022).
	BuildsRemoved int `json:"builds_removed,omitempty"`
	// RingsReclaimed counts the run rings no run held that gc --builds removed (ADR 0026 (6) as amended).
	RingsReclaimed int `json:"rings_reclaimed,omitempty"`
	// JournalLines, JournalBlobs and JournalLocks count what the rule-change journal's prune removed, or with
	// dry_run would remove: lines, blobs no line left names, and lock files (rulefile.Pruned).
	JournalLines int      `json:"journal_lines_pruned,omitempty"`
	JournalBlobs int      `json:"journal_blobs_pruned,omitempty"`
	JournalLocks int      `json:"journal_locks_removed,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

// runGC is the in-process body of gc. A negative keep is "no --keep": the machine's retention applies.
//
// gc removes what the machine config's retention and ledger_root select, so it reads the config whole or not at all,
// as `tego run` does (config.TrustAbort): a layer it cannot read, trust or parse refuses the pass, and nothing is
// swept or deleted, whatever --keep says, since that layer may name the ledger root too. gc read it warn-and-skip, so
// such a layer was passed over with a warning and the pass went on with the built-in 30 days and ledger root: one
// agent's chmod 000 of ~/.tego/config.yaml, which no Landlock rule stops, had the daily gc delete the runs the user's
// retention kept (GAPS C52). Before it reads the config, gc gives ~/.tego, the layer and tego.log back to their owner,
// as run does (restoreUserState); a dry run, which changes nothing, leaves them as they are.
func runGC(ctx context.Context, keep time.Duration, dryRun, builds, asJSON bool, stdout, stderr io.Writer) int {
	if !dryRun {
		restoreUserState("tego gc", stderr)
	}
	m, cds, err := loadMachine(config.TrustAbort)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		configRefused(stderr, "tego gc", err)
		why := "tego gc: nothing was swept or deleted: gc deletes by the retention and the ledger root the machine " +
			"config sets, so it reads every layer of it or does nothing"
		if dryRun && errors.Is(err, fs.ErrPermission) {
			why += "; --dry-run gives no mode back to its owner, which tego gc without it, or tego run, does"
		}
		message(stderr, "", 0, 0, why, identity.CodeConfigUntrusted)
		return identity.ExitError
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		message(stderr, "", 0, 0, "tego gc: "+err.Error(), codeIO)
		return identity.ExitError
	}
	explicit := keep >= 0
	if keep < 0 {
		keep = m.Retention.Value
		// The machine's own retention is the pass a run start makes once per gc_interval (retainBeforeRun): this
		// one counts as it, and holds the stamp so no start runs one beside it.
		if !dryRun {
			if release, ok := claimRetention(root, 0, time.Now()); ok {
				defer release()
			}
		}
	}
	res, err := tegoruntime.Sweep(ctx, root, keep, sweepOptions(m, tegoruntime.WithSweepDryRun(dryRun))...)
	if err != nil {
		// Only an unreadable root reaches here; a single run's failure is in res.Errs and never
		// stops the pass (ledger.GC's contract).
		message(stderr, "", 0, 0, "tego gc: "+err.Error(), codeIO)
		return identity.ExitError
	}
	// A run the pass could not finish is reported and the pass still counts as done: the next gc meets
	// it again, and hiding it would make a recurring failure invisible.
	for _, e := range res.Errs {
		message(stderr, "", 0, 0, "tego gc: "+e.Error(), codeIO)
	}
	// The rule-change journal ages with the runs, after them: a run the pass removed (or, dry, would remove) no
	// longer keeps the lines it reads. A journal not pruned is reported and the exit stays 0, as a run the pass could
	// not finish is.
	pruned, perr := pruneRuleChanges(ctx, root, keep, explicit, dryRun, res.Removed, cds)
	if perr != nil {
		code := codeIO
		if errors.Is(perr, errRetentionUnknown) {
			code = config.CodeIgnored
		}
		message(stderr, "", 0, 0, "tego gc: rule-change journal: "+perr.Error(), code)
	}
	removed, reclaimed := 0, 0
	var bpfErrs []error
	switch {
	case dryRun && builds:
		// Neither --builds nor the linger sweep is dry-run aware: under --dry-run nothing on the bpf
		// filesystem is touched, and the summary alone read as "no idle build".
		message(stderr, "", 0, 0, "tego gc: --builds removes nothing under --dry-run; no build was touched", codeUsage)
	case dryRun:
	case !gcPrivileged():
		if builds {
			message(stderr, "", 0, 0, "tego gc: --builds needs root; no build was touched", codeUsage)
		}
	default:
		// After the orphans are ended, so a build whose only run was an orphan is idle by now.
		removed, reclaimed, bpfErrs = gcSweepBPF(m, builds)
	}
	for _, e := range bpfErrs {
		message(stderr, "", 0, 0, "tego gc: "+e.Error(), codeIO)
	}
	if asJSON {
		out := gcJSON{Root: root, KeepS: keep.Seconds(), DryRun: dryRun,
			Scanned: res.Scanned, Orphaned: res.Orphaned, Deleted: res.Deleted, BuildsRemoved: removed,
			RingsReclaimed: reclaimed, JournalLines: pruned.Lines, JournalBlobs: pruned.Blobs,
			JournalLocks: pruned.Locks}
		for _, e := range res.Errs {
			out.Errors = append(out.Errors, e.Error())
		}
		if perr != nil {
			out.Errors = append(out.Errors, "rule-change journal: "+perr.Error())
		}
		// The bpf sweeps' failures too, each prefixed with what failed so none reads as a run id: on
		// stderr alone they left builds_removed 0 reading as "nothing to remove".
		for _, e := range bpfErrs {
			out.Errors = append(out.Errors, e.Error())
		}
		b, err := json.Marshal(out)
		if err != nil {
			message(stderr, "", 0, 0, "tego gc: "+err.Error(), codeIO)
			return identity.ExitError
		}
		fmt.Fprintf(stdout, "%s\n", b)
		return identity.ExitOK
	}
	verb := "deleted"
	if dryRun {
		verb = "would delete"
	}
	fmt.Fprintf(stdout, "scanned %d, ended %d orphaned, %s %d older than %s\n",
		res.Scanned, res.Orphaned, verb, res.Deleted, config.FormatDuration(keep))
	if pruned != (rulefile.Pruned{}) {
		verb = "pruned"
		if dryRun {
			verb = "would prune"
		}
		fmt.Fprintf(stdout, "rule-change journal: %s %d line(s), %d blob(s), %d lock file(s)\n", verb, pruned.Lines,
			pruned.Blobs, pruned.Locks)
	}
	if removed > 0 {
		fmt.Fprintf(stdout, "removed %d idle tier-2 build(s)\n", removed)
	}
	if reclaimed > 0 {
		fmt.Fprintf(stdout, "reclaimed %d run ring(s) no run held\n", reclaimed)
	}
	return identity.ExitOK
}

// gcPrivileged reports whether gc may sweep the bpf filesystem: root of the initial user namespace (ADR 0042
// (5)(d)); a variable so a test can take the root path.
var gcPrivileged = config.InitNSRoot

// gcSweepBPF is a root gc's bpf sweep; a variable so a test can see its failures reported.
var gcSweepBPF = sweepBPF

// sweepBPF removes the idle tier-2 builds (every idle one when force, else those idle for bpf.linger), the
// capture probes a dead detacher left, and, when force, every run ring no run holds (ADR 0022, ADR 0026).
// Each failure is returned prefixed with the sweep it came from; one never stops the others.
func sweepBPF(m *config.Machine, force bool) (removed, reclaimed int, errs []error) {
	states, err := cgroupenforce.SweepBuilds(cgroupenforce.SweepOptions{Linger: m.BPF.Linger.Value, Force: force})
	if err != nil {
		errs = append(errs, fmt.Errorf("builds: %w", err))
	}
	for _, s := range states {
		if s.Removed {
			removed++
		}
	}
	// The capture probes of a library whose detacher never ran, in the builds that stay (ADR 0026 (7)).
	if _, err := uprobe.SweepLibraries("", "", time.Now()); err != nil {
		errs = append(errs, fmt.Errorf("capture probes: %w", err))
	}
	if force {
		// The rings a crashed launcher, an idle build's pool or an old build left count against every run's
		// bpf.ring_budget until something removes them; --builds does, now.
		n, _, err := cgroupenforce.ReclaimRings(cgroupenforce.SweepOptions{})
		if err != nil {
			errs = append(errs, fmt.Errorf("rings: %w", err))
		}
		reclaimed = n
	}
	return removed, reclaimed, errs
}
