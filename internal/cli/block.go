// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/check/livetime"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() {
	register(cmdBlock)
	register(cmdUnblock)
}

// blockJSONVersion is the version of `tego block --list --json`; a field is added without a bump, one is never
// renamed or dropped under the same number.
const blockJSONVersion = 1

// codeNotRunning is the diagnostic of a live block asked of a run no launcher holds.
const codeNotRunning = "not-running"

// codeReadsUnseen is the diagnostic of a read block asked of a run whose supervisor does not see its reads.
const codeReadsUnseen = "reads-unseen"

// codeOldLauncher is the diagnostic of a read or write block asked of a run whose launcher predates those kinds
// (run_start record_minor below record.MinorLiveControl).
const codeOldLauncher = "launcher-too-old"

// cmdBlock is `tego block <run> <exec|net|path|read|write> <value>` and `tego block --list <run> [--json]`: a live block on a
// running run (internal/liveblock), the same overlay the dashboard's Block now writes. The run's launcher reads it
// within about a second, and from then on its supervisor refuses what the block names (an exec, a connection, a file
// open) with EACCES and a refused line carrying the rule live.block[<kind>:<value>]. A live block only tightens: it
// refuses more than the contract does and never allows anything. It is refused for a run that has ended, since
// nothing would enforce it (exit 1). On a tego watch run the block is written and recorded on each matching line, but
// refuses nothing (the watch supervisor continues every refusal): it says "recorded, not enforced" (exit 0). A relative
// path is read against the working directory. A read block (reads only) is refused on a run whose supervisor does not
// see its reads, since it would refuse nothing there (exit 1); a write block refuses changes only. --list prints the
// run's blocks now, also for an ended run, each with
// its state (internal/check/livestatus: in force, waiting for the launcher's confirming line, refusing changes only,
// recorded only). From inside a run, a block is refused unless it names that same run (exit 1, [governed]): an agent
// may narrow its own run, never another's (refuseCrossRun).
//
// --for <duration> or --until <time> gives the block a time limit (ADR 0125 decision 4, internal/check/livetime): it
// ends by itself then, and the run's launcher records live-block-expired. A block only narrows, so a limit never
// shortens a block already held: the later end stays. A run started by a tego older than time limits refuses one
// (exit 1, [launcher-too-old]); without a limit, nothing differs from before.
//
// These refusals are liveblock's (liveblock.CheckBlock), which the dashboard's Block now and Remove make too. An exec
// block says what its value reaches here beyond its own name (liveblock.ReachOf): a note says that a file with other
// names, as a multi-call program's applets are, is refused under each of them, since the launcher matches the file's
// identity, and that a bare name on no folder of this PATH, or a path that is no file, names nothing here now.
func cmdBlock() Command {
	var list, asJSON bool
	var lim liveLimit
	return Command{
		Name:    "block",
		Summary: "refuse a program, a destination or a path in a running run, now",
		Usage:   "<run> <exec|net|path|read|write> <value> [--for D | --until T] | --list <run> [--json]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&list, "list", false, "list the run's live blocks instead of adding one")
			fs.BoolVar(&asJSON, "json", false, "with --list: print the blocks as JSON")
			lim.flags(fs, "the block ends by itself")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if list {
				if fs.NArg() != 1 {
					message(stderr, "", 0, 0, "tego block: --list takes exactly one run id", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				if lim.set() {
					message(stderr, "", 0, 0, "tego block: --for and --until go with a block, not with --list", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				return runBlockList(fs.Arg(0), asJSON, stdout, stderr)
			}
			if asJSON {
				message(stderr, "", 0, 0, "tego block: --json goes with --list", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			return blockChange(ctx, "block", true, lim, fs, stdout, stderr)
		},
	}
}

// liveLimit is the --for and --until flags of a live change: block, unblock, lift and grant.
type liveLimit struct{ forArg, untilArg string }

// flags declares --for and --until; ends says what happens at the limit.
func (l *liveLimit) flags(fs *flag.FlagSet, ends string) {
	fs.StringVar(&l.forArg, "for", "", "a time limit after which "+ends+" (45m, 72h, 3d, 1d12h, 7w)")
	fs.StringVar(&l.untilArg, "until", "", "a time limit at which "+ends+` ("17:00", "tomorrow 09:00", "Fri 17:00", "2026-11-14 17:00")`)
}

// set reports whether either flag was given.
func (l liveLimit) set() bool { return l.forArg != "" || l.untilArg != "" }

// until is the limit's instant read now on this machine's clock and zone (livetime.Parse): zero with neither flag.
func (l liveLimit) until(now time.Time) (time.Time, error) {
	return livetime.Parse(l.forArg, l.untilArg, now, time.Local)
}

// describeUntil says a limit at t as livetime.Describe does, against this machine's clock and zone.
func describeUntil(t time.Time) string { return livetime.Describe(t, time.Now(), time.Local) }

// cmdUnblock is `tego unblock <run> <exec|net|path|read|write> <value>`: it removes a live block `tego block` or the dashboard
// added. Removing a block removes only what it added; whatever the contract refuses stays refused. A run that has
// ended is refused as `tego block` refuses it (exit 1, [not-running]), and as the dashboard's Remove is: its blocks
// ended with it, and its overlay is left as `tego block --list` shows it.
//
// With --for or --until it is an unblock for a while (ADR 0125 decision 4): the block stays in the overlay, refuses
// nothing until the limit, and refuses again from then on; the run's launcher records live-unblock-expired. A limit at
// or after the block's own end removes it for good, since it would never refuse again.
func cmdUnblock() Command {
	var lim liveLimit
	return Command{
		Name:    "unblock",
		Summary: "remove a live block from a running run, for good or for a while",
		Usage:   "<run> <exec|net|path|read|write> <value> [--for D | --until T]",
		Flags: func(fs *flag.FlagSet) {
			lim.flags(fs, "the block refuses again")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			return blockChange(ctx, "unblock", false, lim, fs, stdout, stderr)
		},
	}
}

// blockChange is the body of block and unblock: validate the arguments and the time limit, find the run, refuse one
// that has ended, and add or remove the entry under the overlay's lock.
func blockChange(ctx context.Context, name string, add bool, lim liveLimit, fs *flag.FlagSet, stdout, stderr io.Writer) int {
	if fs.NArg() != 3 {
		message(stderr, "", 0, 0, "tego "+name+": exactly <run> <exec|net|path|read|write> <value>", codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	until, err := lim.until(time.Now())
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	kind, err := liveblock.ParseKind(fs.Arg(1))
	if err == nil {
		raw := fs.Arg(2)
		if kind.Access() != 0 { // a path, read or write block names a path
			if raw, err = absPathValue(raw); err != nil {
				message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if raw != strings.TrimSpace(fs.Arg(2)) {
				// A relative path is read against the working directory, as a shell user means it; say which file.
				fmt.Fprintf(stderr, "tego %s: path %s is %s\n", name, record.Printable(fs.Arg(2)), record.Printable(filepath.Clean(raw)))
			}
		}
		var value string
		if value, err = liveblock.Normalize(kind, raw); err == nil {
			return applyBlock(ctx, name, add, fs.Arg(0), kind, value, until, stdout, stderr)
		}
	}
	message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
	return identity.ExitUsage // R25: usage error
}

// absPathValue is a path block's value made absolute against the working directory; an absolute one, or one Normalize
// will refuse anyway (empty), is returned as given. A leading ~ or ~/ (left unexpanded when the shell got it quoted)
// is the caller's home, as a shell user means it, not a folder named "~" under the working directory; ~user is
// refused with a hint, since guessing another user's home could block the wrong file.
func absPathValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "~" || strings.HasPrefix(v, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", fmt.Errorf("path %q: the home directory is not known, so ~ cannot be read; write the full path", v)
		}
		return filepath.Join(home, strings.TrimPrefix(v, "~")), nil
	}
	if strings.HasPrefix(v, "~") {
		return "", fmt.Errorf("path %q: ~name is not expanded; write the full path", v)
	}
	if v == "" || filepath.IsAbs(v) {
		return v, nil
	}
	abs, err := filepath.Abs(v)
	if err != nil {
		return "", fmt.Errorf("path %q: the working directory cannot be read to make it absolute: %w", v, err)
	}
	return abs, nil
}

// applyBlock adds or removes the block of kind on value on the run ref names, until until (zero: no end).
func applyBlock(ctx context.Context, name string, add bool, ref string, kind liveblock.Kind, value string, until time.Time, stdout, stderr io.Writer) int {
	if !add && refuseGoverned(name, stderr) { // a block only takes away; lifting one is the governed agent's to ask for
		return identity.ExitFinding
	}
	dir, run, code := blockRun(name, ref, stderr)
	if code != identity.ExitOK {
		return code
	}
	if add && refuseCrossRun(name, run, stderr) { // a governed agent may narrow its own run, never another's
		return identity.ExitFinding
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	facts := startFacts(dir)
	// The run's refusals are liveblock's, which runact makes for the dashboard too: a run that has ended is refused a
	// block and an unblock alike, and a launcher too old for the change, or blind to the reads a read block would
	// refuse, is refused it.
	if err := liveblock.CheckBlock(liveTarget(run, held, facts), kind, add, until); err != nil {
		return blockRefused(name, run, add, value, err, stderr)
	}
	by := liveblock.By("cli")
	var word string
	var after liveblock.Entry // the block the overlay holds after the change; Kind "" when it holds none
	_, err = liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		var ok bool
		var err error
		// With a zero until AddUntil is Add and RemoveUntil is Remove: an untimed change is what it always was.
		if add {
			_, ok, err = o.AddUntil(kind, value, by, time.Now(), until)
		} else {
			_, ok, err = o.RemoveUntil(kind, value, by, time.Now(), until)
		}
		word = liveblock.BlockWord(add, ok)
		after, _ = o.Find(kind, value)
		return ok, err
	})
	if err != nil {
		if errors.Is(err, liveblock.ErrInvalid) {
			message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeUsage)
			return identity.ExitUsage
		}
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	// A path written through a link is blocked by where it leads too, since the supervisor matches a file action by
	// where its lookup lands. The block is in force with its value alone already; its real path is worked out now,
	// with a budget, and added in a second write, which only narrows (liveblock.AddReal).
	var link liveblock.RealOutcome
	if add {
		var rerr error
		if link, rerr = liveblock.AddReal(ctx, dir, run, kind, value, after); rerr != nil {
			fmt.Fprintf(stderr, "tego %s: the path the block leads to could not be added: %v\n", name, rerr)
		}
	}
	// The first line keeps its form, "<run>: <word> <rule>", for scripts; what the block does to this run follows.
	fmt.Fprintf(stdout, "%s: %s %s\n", run, word, liveblock.Rule(kind, value))
	if !until.IsZero() {
		fmt.Fprintln(stdout, limitWords(add, word, until, after))
	}
	switch {
	case add && facts.Observe:
		// A watched run's supervisor continues every refusal (tego watch records only), so the block refuses nothing.
		fmt.Fprintf(stdout, "recorded, not enforced: run %s is a tego watch run, so matching actions are recorded and go on.\n", run)
	case word == liveblock.WordBlocked:
		fmt.Fprintf(stdout, "The run's launcher puts it in force within about a second; check with: tego block --list %s\n", run)
		if kind == liveblock.KindPath && !facts.ReadsSeen {
			fmt.Fprintln(stdout, "This run's reads are not seen, so the block refuses changes to it; reading it still works.")
		}
		if kind == liveblock.KindWrite {
			fmt.Fprintln(stdout, "It refuses changes (writes, creates, deletes, renames); reading it still works.")
		}
		if kind == liveblock.KindExec {
			if line := execWords(run, value, execReach(value, os.Getenv("PATH"))); line != "" {
				fmt.Fprintln(stdout, line)
			}
		}
	case word == liveblock.WordRemoved:
		fmt.Fprintf(stdout, "The run's launcher lifts it within about a second; what the contract refuses stays refused (tego block --list %s).\n", run)
	}
	if line := realWords(run, kind, value, link); line != "" {
		fmt.Fprintln(stdout, line)
	}
	return identity.ExitOK
}

// blockRefused writes the refusal of a block or an unblock (liveblock.CheckBlock), in its words naming the run, with
// what to type instead where the terminal has something to offer, and returns exit 1.
func blockRefused(name, run string, add bool, value string, err error, stderr io.Writer) int {
	hint := ""
	path := "block the path instead"
	if cmd := blockCommand(run, liveblock.KindPath, value); cmd != "" {
		path += " (" + cmd + ")"
	}
	switch {
	case errors.Is(err, liveblock.ErrNotRunning) && add:
		hint = "; for its next run, make it a rule of the contract (tego rule)"
	case errors.Is(err, liveblock.ErrNotRunning):
		hint = fmt.Sprintf(" (tego block --list %s shows what it had)", run)
	case errors.Is(err, liveblock.ErrOldLauncher):
		// An older launcher fails to read an overlay holding this kind: it would keep its last blocks and ignore every
		// later change, tego unblock included, until this block is removed. It enforces a path block.
		hint = "; " + path + ", or make it a rule for its next run (tego rule)"
	case errors.Is(err, liveblock.ErrReadsUnseen):
		hint = "; " + path + ", which refuses changes to it"
	}
	message(stderr, "", 0, 0, "tego "+name+": "+liveblock.RunWords(err)+hint, liveCode(err))
	return identity.ExitFinding
}

// liveCode is the diagnostic code of a live change refused before it was written (liveblock's refusals); codeIO for
// any other error.
func liveCode(err error) string {
	switch {
	case errors.Is(err, liveblock.ErrNotRunning):
		return codeNotRunning
	case errors.Is(err, liveblock.ErrNoTimeLimits), errors.Is(err, liveblock.ErrOldLauncher):
		return codeOldLauncher
	case errors.Is(err, liveblock.ErrReadsUnseen):
		return codeReadsUnseen
	case errors.Is(err, liveblock.ErrLocked):
		return codeLocked
	case errors.Is(err, liveblock.ErrOutsideFence):
		return codeOutsideFence
	case errors.Is(err, liveblock.ErrNoKey):
		return codeNoKey
	case errors.Is(err, liveblock.ErrStarting):
		return codeStarting
	case errors.Is(err, liveblock.ErrStartUnreadable):
		return codeStartUnreadable
	}
	return codeIO
}

// liveTarget is liveblock's Target of run, held or not by a launcher, from the facts its run_start gives: what
// liveblock.CheckBlock and liveblock.CheckFence decide on, as runact's own does for the dashboard.
func liveTarget(run string, held bool, f livestatus.Facts) liveblock.Target {
	return liveblock.Target{Run: run, Running: held, Timed: f.Timed, NarrowKinds: f.NarrowKinds(), ReadsSeen: f.ReadsSeen,
		Adjustable: f.Adjustable, Starting: !f.Started, StartUnreadable: f.StartUnreadable}
}

// execReach is liveblock.ReachOf, what an exec block's value reaches on this machine; tests replace it.
var execReach = liveblock.ReachOf

// execWords says what an exec block's value reaches here beyond its own name (liveblock.ReachOf: r): a file with other
// names, which the block refuses under each of them, or a value that names nothing here now. "" when there is
// nothing more to say. A bare name is matched by name alone, so it is what refuses one name of a multi-call program.
func execWords(run, value string, r liveblock.ExecReach) string {
	v, name := record.Printable(value), record.Printable(filepath.Base(value))
	bare := ""
	if cmd := blockCommand(run, liveblock.KindExec, filepath.Base(value)); cmd != "" {
		bare = " To refuse " + name + " alone, block it by name, which is matched by name only: " + cmd
	}
	switch {
	case r.Missing && filepath.IsAbs(value):
		return fmt.Sprintf("Note: %s is not a file here now; the block still refuses it if it appears.", v)
	case r.Missing:
		return fmt.Sprintf("Note: no program named %s is on this PATH; the block still refuses any program by that name the "+
			"run starts, from any folder.", v)
	case r.Names > 1:
		what := v + " is"
		if r.File != value {
			what = v + " leads to " + record.Printable(r.File) + ","
		}
		also := ""
		if others := liveblock.OtherNames(r.File, 5); len(others) > 0 {
			also = " It refuses " + record.Printable(strings.Join(others, ", "))
			if uint64(len(others))+1 < r.Names {
				also += " and the rest"
			}
			also += " too."
		}
		return fmt.Sprintf("Note: %s one file with %d names here (a multi-call program, as coreutils and busybox are); the "+
			"block matches the file, so it refuses every one of those names, not %s alone.", what, r.Names, name) + also + bare
	case r.Renamed:
		return fmt.Sprintf("Note: %s leads to %s; the block matches that file, so it refuses it under every name that leads "+
			"there, not %s alone.", v, record.Printable(r.File), name) + bare
	}
	return ""
}

// realWords says what a path, read or write block does about the path its value leads to through a link (link,
// liveblock.AddReal): refuses it too, does not (a run started by an older tego), or cannot tell (the walk ran out of
// budget). "" when the value leads nowhere else.
func realWords(run string, kind liveblock.Kind, value string, link liveblock.RealOutcome) string {
	v := record.Printable(value)
	switch {
	case link.Real != "":
		return fmt.Sprintf("%s leads to %s through a link; the block refuses both.", v, record.Printable(link.Real))
	case link.Uncovered != "":
		u := record.Printable(link.Uncovered)
		hint := "; block that path too"
		if cmd := blockCommand(run, kind, link.Uncovered); cmd != "" {
			hint += ": " + cmd
		}
		return fmt.Sprintf("%s leads to %s through a link, but %s was started by an older tego that does not follow it, "+
			"so the block refuses %s as written only", v, u, run, v) + hint
	case link.Unknown:
		return fmt.Sprintf("Whether %s leads elsewhere through a link could not be worked out in time, so the block refuses "+
			"it as written only; if it does, block the path it leads to too.", v)
	}
	return ""
}

// blockCommand keeps a suggested command literal without printing terminal controls as executable input.
func blockCommand(run string, kind liveblock.Kind, value string) string {
	if value != record.Printable(value) {
		return ""
	}
	return fmt.Sprintf("tego block %s %s -- %s", shellQuote(run), kind, shellQuote(value))
}

// limitWords says what a time limit did to the block, from the block the overlay holds after the change (after, Kind
// "" when none): a block only narrows, so an add keeps a later end already held, and an unblock past the block's own
// end removes it for good.
func limitWords(add bool, word string, until time.Time, after liveblock.Entry) string {
	switch {
	case add && after.Kind != "" && after.Until.IsZero():
		return "No time limit: the block already held has no end, and a block only narrows, so it stays for the rest of " +
			"the run (tego unblock ends it)."
	case add && after.Kind != "" && after.Until.After(until):
		return "Time limit: the block already held ends later, so it keeps its end, " + describeUntil(after.Until) +
			"; then it ends by itself."
	case add:
		return "Time limit: " + describeUntil(until) + "; then it ends by itself, and the run's ledger says so (live-block-expired)."
	case word == "was not blocked":
		return "Nothing to unblock, so the time limit sets nothing."
	case after.Kind == "":
		return "The block ends before that limit would, so it is removed for the rest of the run."
	}
	return "Unblocked for a while, " + describeUntil(after.From) + "; then the block refuses again, and the run's ledger " +
		"says so (live-unblock-expired)."
}

// blockRun resolves ref to a run directory and the run id it is under (resolveRunDir: a whole run id, an
// abbreviation of one, or a run directory). A malformed, unknown or ambiguous run is a usage error.
func blockRun(name, ref string, stderr io.Writer) (dir, run string, code int) {
	mc := &machineOnce{stderr: stderr}
	dir, err := resolveRunDir(name, ref, true, mc)
	if err != nil {
		return "", "", runRefFailed(stderr, name, err)
	}
	return dir, filepath.Base(dir), identity.ExitOK
}

// blockEntryJSON is one block in `tego block --list --json`.
type blockEntryJSON struct {
	Kind  string    `json:"kind"`
	Value string    `json:"value"`
	Rule  string    `json:"rule"`
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	// State and Sentence are what the block does to the run now (internal/check/livestatus: in_force, waiting,
	// partial, recorded_only, ended; and, for a block with a time limit, dormant and expired). Added within version 1.
	State    string `json:"state"`
	Sentence string `json:"sentence"`
	// Until is when the block ends by itself; DormantUntil is when a block unblocked for a while refuses again
	// (ADR 0125 decision 4). Each is absent when not set. Added within version 1.
	Until        time.Time `json:"until,omitzero"`
	DormantUntil time.Time `json:"dormant_until,omitzero"`
}

func runBlockList(ref string, asJSON bool, stdout, stderr io.Writer) int {
	dir, run, code := blockRun("block", ref, stderr)
	if code != identity.ExitOK {
		return code
	}
	var blocks []liveblock.Entry
	o, err := liveblock.Read(dir, run)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		message(stderr, "", 0, 0, "tego block: "+err.Error(), codeIO)
		return identity.ExitError
	default:
		blocks = o.Blocks
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego block: "+err.Error(), codeIO)
		return identity.ExitError
	}
	// Each block's state now (internal/check/livestatus): the run's facts and the serials its launcher confirmed, read
	// from its ledger, against the serial of the block's own add.
	var facts livestatus.Facts
	var confirmed uint64
	if len(blocks) > 0 {
		facts, confirmed = liveFacts(dir, true)
		facts.Ended = !held
	}
	now := time.Now()
	stateOf := func(b liveblock.Entry) livestatus.Result {
		s := o.Serial
		for _, c := range o.Changes {
			if c.Op == liveblock.OpAdd && c.Kind == b.Kind && c.Value == b.Value {
				s = c.Serial
			}
		}
		return livestatus.StatusAt(string(b.Kind), facts, s, confirmed, now, b.From, b.Until)
	}
	if asJSON {
		out := struct {
			V       int              `json:"v"`
			Run     string           `json:"run"`
			Running bool             `json:"running"`
			Blocks  []blockEntryJSON `json:"blocks"`
		}{blockJSONVersion, run, held, []blockEntryJSON{}}
		for _, b := range blocks {
			st := stateOf(b)
			out.Blocks = append(out.Blocks, blockEntryJSON{string(b.Kind), b.Value, b.Rule(), b.By, b.At, string(st.State), st.Sentence, b.Until, b.From})
		}
		if err := json.NewEncoder(stdout).Encode(out); err != nil {
			return identity.ExitError
		}
		return identity.ExitOK
	}
	if len(blocks) == 0 {
		fmt.Fprintf(stdout, "%s: no live blocks\n", run)
		return identity.ExitOK
	}
	fmt.Fprintf(stdout, "%s: %d live block(s)", run, len(blocks))
	if !held {
		fmt.Fprint(stdout, " (the run has ended; they are no longer enforced)")
	}
	fmt.Fprintln(stdout)
	timed := false
	for _, b := range blocks {
		fmt.Fprintf(stdout, "  %-5s %s  (%s, %s)", b.Kind, record.Printable(b.Value), record.Printable(b.By), b.At.Local().Format(time.DateTime))
		if !b.Until.IsZero() {
			fmt.Fprintf(stdout, "  ends %s", livetime.At(b.Until, now, time.Local))
			timed = true
		}
		if !b.From.IsZero() && now.Before(b.From) {
			fmt.Fprintf(stdout, "  unblocked %s", livetime.Describe(b.From, now, time.Local))
		}
		timed = timed || !b.From.IsZero()
		if held {
			fmt.Fprintf(stdout, "  %s", stateOf(b).Sentence)
		}
		fmt.Fprintln(stdout)
	}
	if timed && held {
		fmt.Fprintln(stdout, timeCaveat)
	}
	return identity.ExitOK
}

// timeCaveat follows a list holding a time limit: the states above are this machine's wall clock, while the launcher
// ends a block only once its wall clock and CLOCK_BOOTTIME have both passed the limit, and an unblock once either has
// (ADR 0125 decision 4). So after a clock change the run may refuse longer than the list says, never less.
const timeCaveat = "  (Times are this computer's clock. After a clock change the run may refuse a little longer than this says, never less.)"

// startFacts is liveFacts without the confirmed serial: run_start's facts only.
func startFacts(dir string) livestatus.Facts {
	f, _ := liveFacts(dir, false)
	return f
}

// liveFacts reads the run's ledger in dir for what livestatus needs: run_start's facts (watched or not, reads seen or
// not) and, with confirmed, the highest overlay serial a launcher's gap line live-block-added or live-block-removed
// carries. Only lines naming a live block are decoded past the first. A ledger that cannot be read gives no facts and
// nothing confirmed, which every view reads as "waiting"; the facts say StartUnreadable unless that is only because
// no first line is there yet (no events file, an empty one, or a first line still being written), which is a run
// still starting (livestatus.Facts.StartUnreadable, the review's S1).
func liveFacts(dir string, confirmed bool) (livestatus.Facts, uint64) {
	rd, err := ledger.OpenReader(dir)
	if errors.Is(err, os.ErrNotExist) {
		return livestatus.Facts{}, 0
	}
	if err != nil {
		return livestatus.Facts{StartUnreadable: true}, 0
	}
	defer func() { _ = rd.Close() }() // read-only
	var f livestatus.Facts
	var top uint64
	first := true
	for line, err := range rd.Lines() {
		if err != nil {
			f.StartUnreadable = first || f.StartUnreadable
			break
		}
		if first {
			first = false
			e, err := record.Decode(line)
			if err != nil || e.Kind != record.KindRunStart {
				f.StartUnreadable = true
				break
			}
			f = livestatus.FromStartJSON(e.Payload)
			if !confirmed {
				break
			}
			continue
		}
		if !bytes.Contains(line, []byte(record.GapLiveBlockAdded)) && !bytes.Contains(line, []byte(record.GapLiveBlockRemoved)) {
			continue
		}
		e, err := record.Decode(line)
		if err != nil || e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if e.DecodePayload(&p) != nil || p.What != record.GapEnforce || p.LiveBlock == nil ||
			(p.Why != record.GapLiveBlockAdded && p.Why != record.GapLiveBlockRemoved) {
			continue
		}
		top = max(top, p.LiveBlock.Serial)
	}
	return f, top
}
