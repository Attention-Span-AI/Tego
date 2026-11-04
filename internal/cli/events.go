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
	"slices"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdEvents) }

// cmdEvents is `tego events <run> [--json] [--kind K] ... ` (R29): the run's record, as a table or as the
// stored lines byte for byte. It is the escape hatch for when a derived view looks wrong, so it never
// re-encodes what it prints. `--verify` instead checks the record itself (record-ledger.md I3, I4, E29):
// every line against its id, the seq and prev links, and the head against chain.log. `--follow` prints the
// same rows as the run's Writer appends them, checking the chain as each line arrives, and exits at run_end.
func cmdEvents() Command {
	var (
		asJSON   bool
		limit    int
		last     bool
		verify   bool
		follow   bool
		kinds    repeatable
		sources  repeatable
		verdicts repeatable
		rules    repeatable
		steps    repeatable
	)
	return Command{
		Name:    "events",
		Summary: "the run's record",
		Usage:   "<run> [--json] [--kind K] [--source S] [--verdict V] [--rule R] [--step N] [--limit N] [--last | --follow] | <run> --verify [--json]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "print the stored lines byte for byte, one per line (with --verify: one JSON object)")
			fs.IntVar(&limit, "limit", 0, "stop after this many events")
			fs.BoolVar(&last, "last", false, "only the last refusal, gap or limit (what went wrong); read from the end, so damage before it is left to --verify")
			fs.BoolVar(&verify, "verify", false, "check the hash chain and the chain.log anchor instead of printing events")
			fs.BoolVar(&follow, "follow", false, "keep printing as the run appends, checking the chain line by line; exit 0 at run_end")
			fs.Var(&kinds, "kind", "event kind to keep; repeatable")
			fs.Var(&sources, "source", "producer to keep; repeatable")
			fs.Var(&verdicts, "verdict", "allow, ask, refused or observed; repeatable")
			fs.Var(&rules, "rule", "declared entry to keep, or \"unmatched\"; repeatable")
			fs.Var(&steps, "step", "model step to keep; repeatable")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego events: give one run id or run directory; tego status --all lists the ids, then tego events <run> shows its record", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if verify {
				// --verify reads every line whatever a filter would keep: a filter could only hide
				// the line that breaks the chain.
				if last || follow || limit != 0 || len(kinds)+len(sources)+len(verdicts)+len(rules)+len(steps) > 0 {
					message(stderr, "", 0, 0, "tego events: --verify takes no filter, --limit, --last or --follow", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				return runVerify(ctx, fs.Arg(0), asJSON, stdout, stderr)
			}
			if last && follow {
				// --last reads back from the end for one answer; --follow reads forward and waits for more.
				message(stderr, "", 0, 0, "tego events: --last and --follow cannot be combined", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if limit < 0 {
				// A negative count was taken and meant nothing (R29); 0, or no --limit, is none.
				message(stderr, "", 0, 0, fmt.Sprintf("tego events: --limit %d is not a count of events; omit it for every event", limit), codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if last && len(kinds) == 0 {
				// --last is "what went wrong": with no --kind of its own it looks at the three
				// kinds that carry a failure. Given explicit kinds it only narrows them to the
				// last one — appending here made `--last --kind exec` widen to the union of
				// {exec, refused, gap, limit}, which is the opposite of what a filter flag means.
				kinds = append(kinds, "refused", "gap", "limit")
			}
			f, err := events.ParseFilter(kinds, sources, verdicts, rules, steps, limit)
			if err != nil {
				message(stderr, "", 0, 0, "tego events: "+err.Error(), codeUsage)
				return identity.ExitUsage // R25: usage error — a filter value that names no kind
			}
			if follow {
				return runFollow(ctx, fs.Arg(0), f, asJSON, stdout, stderr)
			}
			return runEvents(ctx, fs.Arg(0), f, last, asJSON, stdout, stderr)
		},
	}
}

// repeatable collects a flag given more than once.
type repeatable []string

func (r *repeatable) String() string     { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error { *r = append(*r, v); return nil }

// runEvents resolves the run, opens it read-only (never taking the lock, so a live run can be watched)
// and renders it.
func runEvents(ctx context.Context, ref string, f events.Filter, last, asJSON bool, stdout, stderr io.Writer) int {
	dir, err := resolveRunDir("events", ref, true, &machineOnce{stderr: stderr})
	if err != nil {
		return runRefFailed(stderr, "events", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego events: no run record at %s", dir), codeIO)
			return identity.ExitError
		}
		message(stderr, "", 0, 0, "tego events: "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	defer func() { warnNewer(stderr, "events", dir, r.SkippedNewer()) }()
	if err := needRunRecord(r, dir); err != nil {
		message(stderr, "", 0, 0, "tego events: "+err.Error(), readCode(err))
		return identity.ExitError
	}

	entries := r.Entries()
	if last {
		// §3: --last answers with the last refusal, gap or limit, not with all of them. The
		// answer is read from the ledger rather than from last-refusal.json: that file is
		// advisory, holds no gap or limit, and carries none of the event identity a row (or I8's
		// byte-exact --json line) is made of. See docs/p0/limits-check-doctor-cli.md §3.
		en, found, err := lastMatch(ctx, r, f)
		if err != nil {
			return readFailed(stderr, "events", err)
		}
		entries = func(yield func(ledger.Entry, error) bool) {
			if found {
				yield(en, nil)
			}
		}
	}

	render := events.TableOf
	if asJSON {
		render = events.JSONOf
	}
	n, err := render(ctx, stdout, r, entries, f)
	if err != nil {
		return readFailed(stderr, "events", err)
	}
	if n == 0 {
		// A note, never a non-zero code: R29 gives events exit 0 alone, and RUN-IDENTITY.md's
		// exit-1 set is drift/status/doctor/compile — a finding is about the run's conformance,
		// never about how many rows a query returned. `events <run> --kind refused` on a run that
		// refused nothing is the healthy answer and must not fail a CI gate under `set -e`.
		message(stderr, "", 0, 0, "tego events: no events matched", codeNotFound)
		return identity.ExitOK
	}
	return identity.ExitOK
}

// runFollow is `events --follow`: the rows events prints, for the lines the run holds and then for each line its
// Writer appends, read by one ledger.Follower that checks the chain as each line arrives (record-ledger.md §4
// Follow). It exits 0 at run_end once the launcher has released the lock; a break in the chain is 125
// [ledger-corrupt] after the rows before it, and a run whose launcher is gone without run_end is 125 [run-lost].
func runFollow(ctx context.Context, ref string, f events.Filter, asJSON bool, stdout, stderr io.Writer) int {
	dir, err := resolveRunDir("events", ref, true, &machineOnce{stderr: stderr})
	if err != nil {
		return runRefFailed(stderr, "events", err)
	}
	fl, err := ledger.Follow(dir, ledger.Cursor{})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego events: no run record at %s", dir), codeIO)
			return identity.ExitError
		}
		message(stderr, "", 0, 0, "tego events: "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = fl.Close() }()
	fl.SkipNewerVersions()
	defer func() { warnNewer(stderr, "events", dir, fl.SkippedNewer()) }()
	if mode, why := fl.Wake(); mode == ledger.WakePoll {
		// Said, never silent: the follow still sees every line, up to a second late.
		message(stderr, "", 0, 0, fmt.Sprintf("warning: tego events: inotify is unavailable (%v); polling every second", why),
			codeIO)
	}
	render := events.FollowTable
	if asJSON {
		render = events.FollowJSON
	}
	n, err := render(ctx, stdout, fl, f)
	switch {
	case errors.Is(err, ledger.ErrRunLost):
		message(stderr, "", 0, 0, "tego events: "+err.Error()+"; the next tego run, tego stop or tego gc ends it as orphaned",
			codeRunLost)
		return identity.ExitError
	case err != nil:
		return readFailed(stderr, "events", err)
	case n == 0:
		message(stderr, "", 0, 0, "tego events: no events matched", codeNotFound)
	}
	return identity.ExitOK
}

// lastMatch is the newest event f matches, read from the end of the ledger (ledger.Reader.Backward): the lines
// after it are all --last reads, so its cost is the distance from the end to the answer, not the ledger's length
// (the custom-agent POC, item 8). It answers with that one event, which is what --last promises (§3), even when an
// older event is stamped at the same nanosecond. found is false when nothing matches; the renderer then prints no row and
// the note below says so. A line it does not reach is not decoded, so damage before the answer is left to a full
// read or --verify, as ledger.Reader.State leaves it.
func lastMatch(ctx context.Context, r *ledger.Reader, f events.Filter) (ledger.Entry, bool, error) {
	read := 0
	for en, err := range r.Backward() {
		if err != nil {
			return ledger.Entry{}, false, err
		}
		if read++; read%1024 == 0 && ctx.Err() != nil {
			return ledger.Entry{}, false, ctx.Err()
		}
		if f.Match(en.Event) {
			return en, true, nil
		}
	}
	return ledger.Entry{}, false, nil
}

// resolveRunDir accepts a run directory, or a run id, whole or abbreviated, under the machine's ledger
// root. A directory is returned as ledger.RunDirPath names it: absolute and cleaned, ending in the run id
// the path gives it, or, for a path that reaches no run id (a copy under another name), the directory's
// resolved path.
// Shell completion hands over "<root>/<run>/", and filepath.Dir of that is the run directory itself,
// which made `drift --aggregate` aggregate the one run it was given and report it as the agent's total;
// "." and a link such as ~/latest end in no run id, and `events --verify` binds the ledger to that id
// (R29: the run directory's own, never the id the ledger claims while the path names one). A last component that is a run id is
// kept as given, never resolved: <root>/<A> replaced by a link to <root>/<B> is A's record gone, and
// resolving it verified B's anchored ledger as A's. Normalizing here serves every consumer of a
// caller-supplied path alike.
//
// An argument that is neither a directory nor shaped like a run id is errBadRunID, and, when mustExist,
// a run id naming no directory under the root is errRunNotFound: both are the caller's typo, a usage
// error exiting 2, as status and stop already exit for them (runRefFailed). events, drift and measure
// used to report them as tego's own error, 125 [io], so one mistyped id exited 2 or 125 depending on
// the command (R25). `events --verify` passes mustExist false: a run whose directory is gone
// while its anchor line stays is a ledger that does not verify, a finding it has to reach.
//
// A bare run id is always the run under the ledger root, never a directory of that name in the current
// directory: the agent knows its run id (TEGO_RUN_ID) and can write the project, so a planted ./<id>/ won
// over the real record in every command run from the project. ./<id> names the local directory.
//
// An argument shaped like the start or the end of a run id (runAbbrevShaped) abbreviates one (H08): "28t5cy" or
// "t5cy" for r-00000000-0dmktimu5hrut-28t5cy, the id the end summary and the ask line print. It names the one run
// under the ledger root whose id starts or ends with it and is then resolved as that whole id (expandRunAbbrev), so
// no command needs the whole id typed. Too short to name a run by either end (abbrevEnds), no run, or two runs
// (errAmbiguousRun, naming them) is a usage error. Matched or not, it never names a directory in the current
// directory, for the reason a whole id does not: the agent knows every start and end of its id, and a ./28t5cy/ it
// planted would answer for its run, or, once the run is collected, for a run that is gone. ./28t5cy names the local
// directory, and when there is one, the error says so, and so does a note on stderr when the abbreviation names a
// run: before abbreviations, a bare 28t5cy read that directory, and whoever keeps a copy of a run under such a name
// is told which run they get instead. cmd is the command, which the note names.
func resolveRunDir(cmd, ref string, mustExist bool, mc *machineOnce) (string, error) {
	if ledger.IsRunID(ref) {
		return runDirUnderRoot(cmd, ref, mustExist, mc)
	}
	if runAbbrevShaped(ref) {
		if start, end := abbrevEnds(ref); !start && !end {
			return "", fmt.Errorf("%q %w or a run directory: %s%s", ref, errBadRunID, runAbbrevHint, localDirNote(ref))
		}
		return runDirUnderRoot(cmd, ref, mustExist, mc)
	}
	info, err := os.Stat(ref)
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENAMETOOLONG) {
		// A path the caller cannot stat (EACCES on a parent, ELOOP, EIO) is not a typo: the errno is
		// the answer, 125 [io], never "is not a run id" (E26). A name too long to be a file is one.
		return "", err
	}
	if err == nil && info.IsDir() {
		dir := ledger.RunDirPath(ref)
		// A directory that holds no run record (the project, /tmp, a ledger root) is the caller's
		// mistake like a run id that names no run, a usage error: it was 125 [io] (R25).
		if _, err := os.Lstat(filepath.Join(dir, ledger.EventsFile)); mustExist && errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%s: %w: the directory holds no %s", ref, errRunNotFound, ledger.EventsFile)
		}
		return dir, nil
	}
	return "", fmt.Errorf("%q %w or a run directory", ref, errBadRunID)
}

// runDirUnderRoot is the directory under the machine's ledger root of run id ref, or of the run ref abbreviates.
// For an abbreviation that is also the name of a directory in the current directory, it says what each names
// (resolveRunDir): in the error when ref names no run or several, in a note on stderr for command cmd when it names
// one.
//
// The config comes from the invocation's one load, whose diagnostics it has already printed: a layer
// skipped for its trust is what explains a root that is not the one the operator set.
func runDirUnderRoot(cmd, ref string, mustExist bool, mc *machineOnce) (string, error) {
	m, err := mc.load()
	if err != nil {
		return "", fmt.Errorf("machine config: %w", err)
	}
	// The root is resolved the way status, stop and run resolve it, "~/" included.
	root, err := ledgerRootOf(m)
	if err != nil {
		return "", err
	}
	id := ref
	if !ledger.IsRunID(ref) {
		if mustExist {
			id, err = expandRunAbbrev(ref, root)
		} else {
			anchor, aerr := anchorPath(m)
			if aerr != nil {
				return "", aerr
			}
			ids, aerr := ledger.AnchoredRuns(anchor)
			if aerr != nil {
				return "", aerr
			}
			id, err = expandRunAbbrevWith(ref, root, ids)
		}
		note := localDirNote(ref)
		switch {
		case err != nil && note != "" && (errors.Is(err, errRunNotFound) || errors.Is(err, errAmbiguousRun)):
			return "", fmt.Errorf("%w%s", err, note)
		case err != nil:
			return "", err
		case note != "":
			message(mc.stderr, "", 0, 0, fmt.Sprintf("tego %s: note: %s names run %s under %s%s", cmd, ref, id, root, note), "")
		}
	}
	dir := filepath.Join(root, id)
	if !mustExist {
		return dir, nil
	}
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		// A run id that names no run gets the next step, the command that lists the runs.
		return "", fmt.Errorf("%s: %w under %s; %s", id, errRunNotFound, root, listRunsHint)
	}
	return dir, nil
}

// runIDArg is nil when ref may name a run by its id: a whole run id, or text long enough to abbreviate one by its
// start or its end (abbrevEnds). Anything else is errBadRunID, which says how much of an id is enough when ref could
// start or end one. It reads nothing, so a command can check its argument before it loads the machine config.
func runIDArg(ref string) error {
	switch {
	case ledger.IsRunID(ref):
		return nil
	case !runAbbrevShaped(ref):
		return fmt.Errorf("%q %w", ref, errBadRunID)
	}
	if start, end := abbrevEnds(ref); !start && !end {
		return fmt.Errorf("%q %w: %s", ref, errBadRunID, runAbbrevHint)
	}
	return nil
}

// runIDUnder is the whole id of the run ref names under the ledger root root, for the commands that take a run by
// its id alone (status, stop, ask, approve, deny and alternate): ref when it is one, else the one run whose id ends
// or starts with it (expandRunAbbrev), held to the floors resolveRunDir holds an abbreviation to, with its errors.
// These commands never took a directory, so nothing in the current directory is read for ref, and no note names one.
func runIDUnder(ref, root string) (string, error) {
	if err := runIDArg(ref); err != nil {
		return "", err
	}
	if ledger.IsRunID(ref) {
		return ref, nil
	}
	return expandRunAbbrev(ref, root)
}

// runRefUsage reports whether err is the caller's mistake in naming a run, a usage error (R25): an argument that is
// not a run id nor long enough to abbreviate one, one that names no run, or one that two or more runs have.
func runRefUsage(err error) bool {
	return errors.Is(err, errBadRunID) || errors.Is(err, errRunNotFound) || errors.Is(err, errAmbiguousRun)
}

// minRunAbbrev is the fewest characters past what the runs of one host share that abbreviate a run id, git's floor
// for an abbreviated object name. An end counts all of its characters: a run id's last six are rand6, 30 random
// bits, so its last four are 20, which two runs share by chance about once in a million. A start counts only those
// past r-<host8>- (runHostLen), which every run minted on the host begins with, or `r-00` would name whichever one
// run the root holds. The time36 digits that follow are not random: the first four change every 150 years, 4 years,
// 6 weeks and 28 hours, so a start's four name the runs minted in the same day or so. Neither floor is what keeps
// block, stop and the other live controls off another run: an abbreviation names a run only when exactly one run
// under the ledger root has it (expandRunAbbrev); two or more are a usage error that names them.
const minRunAbbrev = 4

// runHostLen is the length of r-<host8>-, the start every run id minted on one host shares (identity-config.md R2).
const runHostLen = len("r-00000000-")

// maxRunMatches is how many of the runs an ambiguous abbreviation matches its error names.
const maxRunMatches = 5

// runIDTemplate is a run id each of whose characters is one every run id may have at that place (identity-config.md
// R2): the shape runIDEnds lays text over.
const runIDTemplate = "r-00000000-0000000000000-000000"

// runAbbrevHint is what a run argument too short to abbreviate a run id by either end (abbrevEnds) is told to give.
var runAbbrevHint = fmt.Sprintf("give the run's id, or at least its last %d characters or its first %d (%d past r-<host8>-)",
	minRunAbbrev, runHostLen+minRunAbbrev, minRunAbbrev)

// runIDEnds reports whether s, shorter than a run id, could begin one and whether it could end one: every character
// is one a run id has at that place, a dash only where a run id has one.
func runIDEnds(s string) (begins, ends bool) {
	n := len(s)
	if n == 0 || n >= len(runIDTemplate) {
		return false, false
	}
	return ledger.IsRunID(s + runIDTemplate[n:]), ledger.IsRunID(runIDTemplate[:len(runIDTemplate)-n] + s)
}

// runAbbrevShaped reports whether s, shorter than a run id, could be the start or the end of one, however short.
// "28t5cy" and "r-00000000-0dm" are; "my_copy", "." and "runs/x" are not, and stay paths.
func runAbbrevShaped(s string) bool {
	begins, ends := runIDEnds(s)
	return begins || ends
}

// abbrevEnds reports by which end s abbreviates a run id: start when it could begin one and runs minRunAbbrev
// characters past r-<host8>-, end when it could end one and is minRunAbbrev characters long. Each end is held to
// its own floor, so "r-abcdef", which could begin an id of host abcdef.. as well as end one, names a run only by
// its end. Neither, for text too short for both, or that no run id begins or ends with.
func abbrevEnds(s string) (start, end bool) {
	begins, ends := runIDEnds(s)
	return begins && len(s) >= runHostLen+minRunAbbrev, ends && len(s) >= minRunAbbrev
}

// expandRunAbbrev is the id of the one run under root whose id starts or ends with abbrev, by whichever ends
// abbrevEnds allows it. It reads the root's names, never what they hold: every name shaped like a run id counts,
// whatever the entry is (a run directory, or a link put in its place), as a whole id names it. A root that is not
// there holds no run; one that cannot be read is its errno, 125 [io], since the run may be there.
func expandRunAbbrev(abbrev, root string) (string, error) {
	return expandRunAbbrevWith(abbrev, root, nil)
}

func expandRunAbbrevWith(abbrev, root string, anchored []string) (string, error) {
	start, end := abbrevEnds(abbrev)
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("read ledger root: %w", err)
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range anchored {
		if (start && strings.HasPrefix(id, abbrev) || end && strings.HasSuffix(id, abbrev)) && !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	for _, e := range entries {
		if n := e.Name(); ledger.IsRunID(n) && !seen[n] && (start && strings.HasPrefix(n, abbrev) || end && strings.HasSuffix(n, abbrev)) {
			ids = append(ids, n)
		}
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		how := "ends"
		switch {
		case start && end:
			how = "starts or ends"
		case start:
			how = "starts"
		}
		return "", fmt.Errorf("%s: %w under %s: no run id there %s with it; %s", abbrev, errRunNotFound, root, how,
			listRunsHint)
	}
	slices.SortFunc(ids, func(a, b string) int { return ledger.CompareRunIDs(b, a) }) // newest first
	named, more := ids, ""
	if len(named) > maxRunMatches {
		named, more = named[:maxRunMatches], fmt.Sprintf(" and %d more", len(ids)-maxRunMatches)
	}
	return "", fmt.Errorf("%s %w under %s: %s%s; give more of its id", abbrev, errAmbiguousRun, root,
		strings.Join(named, ", "), more)
}

// localDirNote is "; ./<ref> names the local directory" when the current directory holds a directory named ref, or a
// link to one, else "": a bare run argument never reads it, and this says how to. It only looks at the name.
func localDirNote(ref string) string {
	if info, err := os.Stat(ref); err == nil && info.IsDir() {
		return "; ./" + ref + " names the local directory"
	}
	return ""
}

// errNoRunRecord is a run directory whose events.jsonl holds no run_start: empty, only a torn line, or a
// first line of another kind. There is no run to report, so events, drift and measure say so, 125 [io]
// (R25), as `events --verify` does, where they printed an empty table and exited 0 as if for a complete run
// that did nothing.
var errNoRunRecord = errors.New("no run record")

// errNeverStarted is the errNoRunRecord of a ledger with no complete line: a run younger than its
// run_start, or a launcher that died before writing it. Nothing was recorded there to be missing, so
// drift --aggregate does not count it (§6 case 8); a first line of another kind still does.
var errNeverStarted = errors.New("ledger holds no complete line")

// needRunRecord returns errNoRunRecord unless the ledger's first line is run_start, and the reader's error
// when that line does not read.
func needRunRecord(r *ledger.Reader, dir string) error {
	for e, err := range r.Iter() {
		if err != nil {
			return err
		}
		if e.Kind != record.KindRunStart {
			return fmt.Errorf("%w at %s: its first line is %s, not run_start", errNoRunRecord, dir, e.Kind)
		}
		return nil
	}
	return fmt.Errorf("%w at %s: %s holds no run_start (%w)", errNoRunRecord, dir, ledger.EventsFile, errNeverStarted)
}

// readCode is the diagnostic code of a failure to read a run's ledger: [ledger-corrupt] for a line that
// does not decode, the code limits-check-doctor-cli §7 documents for it, and [io] for anything else. Every
// read failure was [io], so a corrupt ledger read as a disk error.
func readCode(err error) string {
	if errors.Is(err, ledger.ErrCorruptLedger) {
		return codeUnverified
	}
	return codeIO
}

// readFailed reports a failed pass over the ledger for command cmd and returns its exit code, 125 either
// way: a SIGINT or SIGTERM that cancelled ctx (R29) says "interrupted", anything else is the read's own error.
func readFailed(stderr io.Writer, cmd string, err error) int {
	if errors.Is(err, context.Canceled) {
		message(stderr, "", 0, 0, "tego "+cmd+": interrupted", codeIO)
		return identity.ExitError
	}
	message(stderr, "", 0, 0, "tego "+cmd+": "+err.Error(), readCode(err))
	return identity.ExitError
}

// runRefFailed reports a resolveRunDir or runIDUnder failure for command cmd and returns its exit code: a
// malformed or unknown run id, or an abbreviation that names no run or several, is a usage error (R25,
// runRefUsage), anything else — an unreadable machine config, no ledger root, a root that cannot be listed — is
// tego's own (125).
func runRefFailed(stderr io.Writer, cmd string, err error) int {
	if runRefUsage(err) {
		message(stderr, "", 0, 0, "tego "+cmd+": "+err.Error(), codeUsage)
		return identity.ExitUsage
	}
	message(stderr, "", 0, 0, "tego "+cmd+": "+err.Error(), codeIO)
	return identity.ExitError
}
