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
	"os"
	"path/filepath"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdStatus) }

// cmdStatus is `tego status [run] [--json] [--all]` (R29): the run state machine of R7-R12 read
// from the ledger and the lock alone, with the gap line (R34) saying what the record could not see.
// Exit 1 when what it shows is a finding — a stalled or lost run (R25); exit 0 otherwise.
func cmdStatus() Command {
	var (
		asJSON    bool
		all       bool
		agentName string
	)
	return Command{
		Name:    "status",
		Summary: "state of a run",
		Usage:   "[run | --agent <name>] [--json] [--all]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object")
			fs.BoolVar(&all, "all", false, "every run under the ledger root, oldest first")
			fs.StringVar(&agentName, "agent", "", "select runs of this agent (the contract's name:); newest only unless --all")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if flagGiven(fs, "agent") {
				if _, err := identity.ParseAgentID(agentName); err != nil || fs.NArg() != 0 {
					message(stderr, "", 0, 0, "tego status: --agent needs a valid agent name and no run id; use tego status --agent <name> [--all]", codeUsage)
					return identity.ExitUsage
				}
				return runStatusSelected(ctx, "", agentName, all, asJSON, stdout, stderr)
			}
			if fs.NArg() > 1 {
				message(stderr, "", 0, 0, "tego status: at most one run id", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if all && fs.NArg() == 1 {
				// One run or every run: --all beside a run id was ignored, and the one run printed as if
				// asked for alone (R29).
				message(stderr, "", 0, 0, "tego status: a run id or --all, not both", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if fs.NArg() == 1 && fs.Arg(0) == "" {
				// An empty argument (an unset $RUN) read as no argument and listed the runs, as if asked
				// for none (R25).
				message(stderr, "", 0, 0, `tego status: "" is not a run id`, codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			return runStatus(ctx, fs.Arg(0), all, asJSON, stdout, stderr)
		},
	}
}

// statusJSON is one run's --json shape: the snapshot's fields in declaration order (R31).
type statusJSON struct {
	Run              string  `json:"run"`
	Agent            string  `json:"agent"`
	State            string  `json:"state"`
	SinceTS          string  `json:"since_ts,omitempty"`
	SinceMonoNS      uint64  `json:"since_mono_ns,omitempty"`
	IdleS            float64 `json:"idle_s"`
	IdleClock        string  `json:"idle_clock"`
	IdleFrom         string  `json:"idle_from"` // "ledger", or "activity": the live run's sidecar (R9)
	StallAfterS      float64 `json:"stall_after_s"`
	StallAfterSource string  `json:"stall_after_source"`
	Step             int     `json:"step"`
	Events           int     `json:"events"`
	PendingApprovals int     `json:"pending_approvals,omitempty"`
	LockHeld         bool    `json:"lock_held"`
	ExitReason       string  `json:"exit_reason,omitempty"`
	// ExitCode is present exactly when exit_reason is: a pointer, so an agent that exited 0 says 0 rather
	// than dropping the key as omitempty did for an int (R31).
	ExitCode *int `json:"exit_code,omitempty"`
	// Gaps is the gap line as data (R34): always present, [] for a run with none, so a jq filter
	// never has to tell "no gaps" from "a status that does not report them".
	Gaps []gapJSON `json:"gaps"`
	// GapWords is what those gaps mean in a person's words (gaps.Words, the status table's "in words:" line): whether
	// actions may be missing, and what a person changed. Absent for a run with no gap (QA PW-2).
	GapWords string `json:"gap_words,omitempty"`
	// Tier and Capabilities are run_start's tier and capability line as recorded (R-cap); capabilities
	// is absent for a run whose run_start predates the line, never an empty object standing in for it.
	Tier         string          `json:"tier,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	// TegoVersion is run_start's tego_version, the binary that ran the run and never the one reading it
	// (§6 case 9); absent for a run that died before run_start.
	TegoVersion string `json:"tego_version,omitempty"`
	// Resources is run_end.resources as recorded (R-res), keys this binary does not know included: a key
	// the record lacks is absent here too, never a 0, and the whole object is absent for a run with no
	// run_end yet or one whose run_end carries none.
	Resources json.RawMessage `json:"resources,omitempty"`
	// LedgerBytes is the size of the run's events.jsonl and blobs when status read them, and LedgerCeilingBytes the
	// record.max_run_bytes run_start says the run runs under, absent for none (record.MinorLedgerCap).
	LedgerBytes        int64 `json:"ledger_bytes,omitempty"`
	LedgerCeilingBytes int64 `json:"ledger_ceiling_bytes,omitempty"`
	// RunCommandGrant is run_start's run_command_grant: the file the command given after `--` was granted
	// as for the whole run, absent when none was (agent-contract.md R8).
	RunCommandGrant string `json:"run_command_grant,omitempty"`
	// BestEffort is run_start's best_effort: the run's disclosed best-effort cells, decided on copied
	// syscall facts and never counted as enforced (ADR 0041 D1, D7); absent when there were none.
	BestEffort []string `json:"best_effort,omitempty"`
	// LedgerAnomalies names each anomaly the ledger holds (two run_end lines, the first kept), absent for a
	// healthy one (limits-check-doctor-cli.md §6 case 5).
	LedgerAnomalies []string `json:"ledger_anomalies,omitempty"`
	// Paused is a live run its launcher holds frozen, as its last pause line records it (tego pause, the
	// dashboard's Pause): the table's STATE says "paused" while state keeps the derived one. PausePending is
	// "pause" or "resume" while the run's overlay asks one its launcher has not confirmed yet. Both added within
	// the same shape, absent when there is none.
	Paused       bool   `json:"paused,omitempty"`
	PausePending string `json:"pause_pending,omitempty"`
	// LauncherGone is a run whose launcher is gone, with no run_end, whose last recorded state was paused (ADR 0124,
	// second amendment of 2026-11-11): state reads lost and paused true (the last state recorded, not proof it stayed
	// frozen). ScopeNow is what its scope shows now: frozen, running, empty or unknown. Tego never thaws it; tego stop
	// ends what is left and closes its record with run_end orphaned. Both absent otherwise.
	LauncherGone bool   `json:"launcher_gone,omitempty"`
	ScopeNow     string `json:"scope_now,omitempty"`
	// LauncherUnknown is why a held lock's launcher could not be confirmed alive or gone; absent when it was judged.
	LauncherUnknown string `json:"launcher_unknown,omitempty"`
}

// gapJSON is one entry of the gap line: the gap events of one what and why.
type gapJSON struct {
	What   string `json:"what"`
	Why    string `json:"why"`
	Events int    `json:"events"`
	Lost   int    `json:"lost"`
	// SharedSkipped is reported skipped executions, possibly repeated across overlapping runs, not lost events.
	SharedSkipped int `json:"shared_skipped_executions,omitempty"`
	// Processes is how many processes the gaps that name a binary could not cover (gaps.Count).
	Processes int      `json:"processes,omitempty"`
	Binaries  []string `json:"binaries"`
}

// gapObjects projects a gap tally onto its JSON shape, [] rather than null when empty (§6 case 22).
func gapObjects(cs []gaps.Count) []gapJSON {
	out := make([]gapJSON, 0, len(cs))
	for _, c := range cs {
		bins := append([]string{}, c.Binaries...)
		out = append(out, gapJSON{What: c.What, Why: c.Why, Events: c.Events, Lost: c.Lost, SharedSkipped: c.SharedSkipped, Processes: c.Processes, Binaries: bins})
	}
	return out
}

// statusListJSON is the --all shape: still one JSON object per invocation (R31).
type statusListJSON struct {
	Runs []statusJSON `json:"runs"`
}

// runStatus is the in-process body of status.
func runStatus(ctx context.Context, runID string, all, asJSON bool, stdout, stderr io.Writer) int {
	return runStatusSelected(ctx, runID, "", all, asJSON, stdout, stderr)
}

func runStatusSelected(ctx context.Context, runID, agentName string, all, asJSON bool, stdout, stderr io.Writer) int {
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego status: machine config: "+err.Error(), identity.CodeConfigUntrusted)
		return identity.ExitError
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		message(stderr, "", 0, 0, "tego status: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if err := ctx.Err(); err != nil {
		message(stderr, "", 0, 0, "tego status: interrupted", codeIO)
		return identity.ExitError
	}
	snaps, skipped, err := collectStatus(ctx, root, runID, all || agentName != "", time.Now())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return readFailed(stderr, "status", err)
		}
		if runRefUsage(err) {
			message(stderr, "", 0, 0, "tego status: "+err.Error(), codeUsage)
			return identity.ExitUsage // R25: usage error
		}
		message(stderr, "", 0, 0, "tego status: "+err.Error(), readCode(err))
		return identity.ExitError
	}
	if agentName != "" {
		snaps = slices.DeleteFunc(snaps, func(s *status.Snapshot) bool { return s.Agent != agentName })
		if !all && len(snaps) > 1 {
			slices.SortFunc(snaps, func(a, b *status.Snapshot) int { return ledger.CompareRunIDs(b.Run, a.Run) })
			snaps = snaps[:1]
		}
	}
	// E26: a run this command could not read is reported as itself — one diagnostic line naming the
	// run and the errno — never folded into a shorter table or into "no runs", which would read as
	// "there is nothing there". §6 case 8 still holds: the runs that could be read are printed below.
	for _, e := range skipped {
		if errors.Is(e, os.ErrNotExist) {
			continue // a run directory with no ledger recorded nothing: not a fault (see unreadable)
		}
		message(stderr, "", 0, 0, "tego status: "+e.Error(), readCode(e))
		logOwn("status: " + e.Error())
	}
	for _, s := range snaps {
		warnNewer(stderr, "status", filepath.Join(root, s.Run), s.SkippedNewer)
		warnAnomalies(stderr, "status", filepath.Join(root, s.Run), s.Anomalies())
	}
	bad := unreadable(skipped)
	if len(snaps) == 0 {
		if bad > 0 {
			// Every run under the root was unreadable: there is no report at all, so the exit code
			// is §7's "a ledger check/* could not read", never the 0 that means "nothing is wrong".
			return identity.ExitError
		}
		// --json is always JSON (R31): an empty listing, never the table's words, which a jq pipeline
		// cannot parse.
		if asJSON {
			if err := writeJSON(stdout, statusListJSON{Runs: []statusJSON{}}); err != nil {
				message(stderr, "", 0, 0, "tego status: "+err.Error(), codeIO)
				return identity.ExitError
			}
			return identity.ExitOK
		}
		fmt.Fprintln(stdout, "no runs")
		if agentName != "" {
			fmt.Fprintf(stdout, "No recorded run has agent name %s; tego status --all lists the other agents.\n", agentName)
		} else {
			// The one command a newcomer starts from (ADR 0142 (5)): tego setup says which step this
			// machine is on and what to type next. It was tego init's preset line, which skipped the check and the
			// recorded run a contract is best learned from.
			fmt.Fprintln(stdout, "next: tego setup")
		}
		return identity.ExitOK
	}
	pauses := runPauses(root, snaps)
	if err := writeStatus(stdout, snaps, pauses, asJSON, all || runID == ""); err != nil {
		message(stderr, "", 0, 0, "tego status: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if bad > 0 {
		// The table above is missing runs, so statusExit's verdict is about a subset: an incomplete
		// answer must not exit 0 (or 1, which would claim the finding is the whole story). §7 again.
		return identity.ExitError
	}
	return statusExit(snaps, pauses)
}

// collectStatus resolves the argument: one named run, every run with --all, or the most recent run
// when neither is given (a run id sorts by mint time within one host). It returns the snapshots it
// derived and, separately, one error per run it could not read — §6 case 8 keeps one corrupt or
// foreign-uid run from hiding the rest, and E26 forbids turning that run into no data at all. The
// named run is a whole run id or an abbreviation of one (runIDUnder, H08).
func collectStatus(ctx context.Context, root, ref string, all bool, now time.Time) ([]*status.Snapshot, []error, error) {
	if ref != "" {
		runID, err := runIDUnder(ref, root)
		if err != nil {
			return nil, nil, err
		}
		dir := filepath.Join(root, runID)
		if _, err := os.Stat(dir); err != nil {
			// Only a directory that is not there is the caller's typo (R25). EACCES, ELOOP or EIO on
			// a run that may exist, and may be running, is reported as itself, 125 [io] (E26).
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil, fmt.Errorf("%s: %w under %s; %s", runID, errRunNotFound, root, listRunsHint)
			}
			return nil, nil, err
		}
		s, err := status.DeriveDir(ctx, dir, now)
		if errors.Is(err, fs.ErrNotExist) {
			// A run directory younger than its ledger, or left by a launcher that died before creating it,
			// is §6 case 8's never-started run, not a fault; --all and bare status already treat it so.
			s, err = status.DeriveBorn(dir, now)
		}
		if err != nil {
			return nil, nil, err
		}
		return []*status.Snapshot{s}, nil, nil
	}
	if !all {
		// Bare `tego status` prints one row, so it reads one run. A run id sorts by mint time
		// within one host (spec/identity R1), which makes the newest run identifiable from the
		// directory names alone: deriving every retained run to then discard all but the last made
		// the cost of the command grow with retention (30 days, and gc is manual) for one row.
		ids, err := runIDsNewestFirst(root)
		if err != nil {
			return nil, nil, err
		}
		var skipped []error
		for _, id := range ids {
			s, err := status.DeriveDir(ctx, filepath.Join(root, id), now)
			if err == nil {
				return []*status.Snapshot{s}, skipped, nil
			}
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			skipped = append(skipped, fmt.Errorf("%s: %w", id, err))
			if !errors.Is(err, os.ErrNotExist) {
				// An EACCES or a torn ledger is the answer here: report it rather than quietly
				// answering about an older run, which would read as the newest one (E26).
				return nil, skipped, nil
			}
			// A run directory with no ledger has nothing to report: ledger.Open creates the
			// directory and takes the lock before it creates events.jsonl, so the newest run can
			// be a few microseconds old, and a launcher that died in that window leaves one
			// behind for good. Step to the next newest instead of reporting "no runs".
		}
		return nil, skipped, nil
	}
	snaps, err := status.DeriveAll(ctx, root, now)
	if errors.Is(err, context.Canceled) {
		return nil, nil, err
	}
	return snaps, joinedErrors(err), nil
}

// runIDsNewestFirst is every run-shaped directory under root, newest first: a run id carries its mint
// time (spec/identity R1), so the directory names alone order the runs, with no ledger read at all. They
// are compared by that time, never by the host prefix (ledger.CompareRunIDs). An absent root is a machine that has never run anything, not an error.
func runIDsNewestFirst(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read ledger root: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() && ledger.IsRunID(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	slices.SortFunc(ids, func(a, b string) int { return ledger.CompareRunIDs(b, a) })
	return ids, nil
}

// unreadable counts the runs whose ledger exists but could not be read: an EACCES, a torn middle
// line, a failed lock probe. Each of those makes the report incomplete, and E26 forbids rendering
// an incomplete report as a clean one. A run directory with no events.jsonl is not one of them (see
// the loop above): nothing was ever recorded there, so nothing is missing from the table.
func unreadable(skipped []error) int {
	n := 0
	for _, err := range skipped {
		if !errors.Is(err, os.ErrNotExist) {
			n++
		}
	}
	return n
}

// joinedErrors flattens what DeriveAll joined so each unreadable run gets its own diagnostic line
// (R26: one sentence per error), rather than one line holding every failure run together.
func joinedErrors(err error) []error {
	if err == nil {
		return nil
	}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		return joined.Unwrap()
	}
	return []error{err}
}

// statusExit is R25's rule: a stalled or lost run is a finding. A run held paused records nothing by design, so its
// stall is not one while the pause lasts.
func statusExit(snaps []*status.Snapshot, pauses map[string]pauseFact) int {
	for _, s := range snaps {
		if pauses[s.Run].LauncherGone {
			return identity.ExitFinding // lost while paused, whatever its derived state
		}
		if s.St == status.Stalled && pauses[s.Run].Paused {
			continue
		}
		if s.St == status.Stalled || s.St == status.Lost {
			return identity.ExitFinding
		}
	}
	return identity.ExitOK
}

// writeStatus renders the snapshots as one aligned table, or as JSON (R31). pauses is each live run's pause by run
// id (runPauses); a run it does not name is not paused.
func writeStatus(w io.Writer, snaps []*status.Snapshot, pauses map[string]pauseFact, asJSON, list bool) error {
	if asJSON {
		if !list && len(snaps) == 1 {
			return writeJSON(w, statusObject(snaps[0], pauses[snaps[0].Run]))
		}
		out := statusListJSON{Runs: make([]statusJSON, 0, len(snaps))}
		for _, s := range snaps {
			out.Runs = append(out.Runs, statusObject(s, pauses[s.Run]))
		}
		return writeJSON(w, out)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN\tAGENT\tSTATE\tIDLE\tSTEP\tEVENTS\tEXIT")
	for _, s := range snaps {
		exit := ""
		if s.ExitReason != "" {
			exit = fmt.Sprintf("%s (%d)", record.Printable(s.ExitReason), s.ExitCode)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", record.Printable(s.Run), record.Printable(s.Agent), record.Printable(pauses[s.Run].state(s.St)),
			s.Idle.Round(time.Second), s.Step, s.Events, exit)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if err := writeLostPaused(w, snaps, pauses); err != nil {
		return err
	}
	if err := writeLauncherUnknown(w, snaps, pauses); err != nil {
		return err
	}
	if err := writeStatusGaps(w, snaps, list); err != nil {
		return err
	}
	if err := writeStatusCapabilities(w, snaps, list); err != nil {
		return err
	}
	if err := writeStatusResources(w, snaps, list); err != nil {
		return err
	}
	return writeStatusLedger(w, snaps, list)
}

// writeStatusGaps prints the gap line under the table (R34). One run gets "gaps: <line>", "none"
// included, so its absence is never mistaken for a status that does not look. A listing names each
// run that recorded a gap and stays quiet about the rest, so a long --all table does not double in
// length to say "none" once per row. A person's live changes (a block, a lift, a pause: gaps.Split)
// are not gaps: they get their own "live changes: <line>", only when the run recorded one. Those two lines give the
// kinds as the record spells them; "in words: <sentence>" (gaps.Words) then says what they mean, as the receipt and the
// dashboard say it: whether actions may be missing, and what a person did (QA PW-2).
func writeStatusGaps(w io.Writer, snaps []*status.Snapshot, list bool) error {
	if !list || len(snaps) == 1 {
		missed, live := gaps.Split(snaps[0].Gaps)
		if _, err := fmt.Fprintf(w, "gaps: %s\n", gaps.Line(missed)); err != nil {
			return err
		}
		if len(live) > 0 {
			if _, err := fmt.Fprintf(w, "live changes: %s\n", gaps.Line(live)); err != nil {
				return err
			}
		}
		if words := gapWords(snaps[0]); words != "" {
			_, err := fmt.Fprintf(w, "in words: %s\n", words)
			return err
		}
		return nil
	}
	for _, s := range snaps {
		missed, live := gaps.Split(s.Gaps)
		if len(missed) > 0 {
			if _, err := fmt.Fprintf(w, "gaps %s: %s\n", record.Printable(s.Run), gaps.Line(missed)); err != nil {
				return err
			}
		}
		if len(live) > 0 {
			if _, err := fmt.Fprintf(w, "live changes %s: %s\n", record.Printable(s.Run), gaps.Line(live)); err != nil {
				return err
			}
		}
		if words := gapWords(s); words != "" {
			if _, err := fmt.Fprintf(w, "in words %s: %s\n", record.Printable(s.Run), words); err != nil {
				return err
			}
		}
	}
	return nil
}

// gapWords says what a run's gaps mean, and that a lost run's record may stop short: its launcher died, so the gap lines
// are not all it may lack.
func gapWords(s *status.Snapshot) string { return gaps.Words(s.Gaps, s.St == status.Lost) }

// statusObject projects a snapshot onto its JSON shape; p is the run's pause (runPauses), which adds paused and
// pause_pending and leaves state as derived.
func statusObject(s *status.Snapshot, p pauseFact) statusJSON {
	o := statusJSON{
		Paused: p.Paused, PausePending: p.Pending, LauncherGone: p.LauncherGone, LauncherUnknown: p.LauncherUnknown,
		Run: s.Run, Agent: s.Agent, State: string(s.St), SinceMonoNS: s.SinceMonoNS,
		IdleS: s.Idle.Seconds(), IdleClock: s.IdleClock, IdleFrom: s.IdleFrom, StallAfterS: s.StallAfter.Seconds(),
		StallAfterSource: s.StallAfterSource, Step: s.Step, Events: s.Events, PendingApprovals: s.PendingApprovals,
		LockHeld: s.LockHeld, ExitReason: s.ExitReason,
		Gaps: gapObjects(s.Gaps), GapWords: gapWords(s), Tier: s.Tier, Capabilities: s.Capabilities, TegoVersion: s.TegoVersion, Resources: s.ResourcesRecorded,
		RunCommandGrant: s.RunCommandGrant, BestEffort: s.BestEffort, LedgerAnomalies: s.Anomalies(),
		LedgerBytes: s.LedgerBytes, LedgerCeilingBytes: s.LedgerCeiling,
	}
	if p.LauncherGone {
		o.State = string(status.Lost) // a lock held by a process that is not its launcher reads lost too
		o.ScopeNow = p.Scope.json()
	}
	if s.ExitReason != "" {
		code := s.ExitCode
		o.ExitCode = &code
	}
	if !s.Since.IsZero() {
		o.SinceTS = s.Since.UTC().Format(time.RFC3339Nano)
	}
	return o
}
