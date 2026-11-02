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
				message(stderr, "", 0, 0, "tego events: exactly one run id or run directory", codeUsage)
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
	dir, err := resolveRunDir(ref, true, &machineOnce{stderr: stderr})
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
	dir, err := resolveRunDir(ref, true, &machineOnce{stderr: stderr})
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

// resolveRunDir accepts a run directory or a run id under the machine's ledger root. A directory is
// returned as ledger.RunDirPath names it: absolute and cleaned, ending in the run id the path gives it,
// or, for a path that reaches no run id (a copy under another name), the directory's resolved path.
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
func resolveRunDir(ref string, mustExist bool, mc *machineOnce) (string, error) {
	if ledger.IsRunID(ref) {
		return runDirUnderRoot(ref, mustExist, mc)
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

// runDirUnderRoot is run id ref's directory under the machine's ledger root.
//
// The config comes from the invocation's one load, whose diagnostics it has already printed: a layer
// skipped for its trust is what explains a root that is not the one the operator set.
func runDirUnderRoot(ref string, mustExist bool, mc *machineOnce) (string, error) {
	m, err := mc.load()
	if err != nil {
		return "", fmt.Errorf("machine config: %w", err)
	}
	// The root is resolved the way status, stop and run resolve it, "~/" included.
	root, err := ledgerRootOf(m)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, ref)
	if !mustExist {
		return dir, nil
	}
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		// A run id that names no run gets the next step, the command that lists the runs.
		return "", fmt.Errorf("%s: %w under %s; %s", ref, errRunNotFound, root, listRunsHint)
	}
	return dir, nil
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

// runRefFailed reports a resolveRunDir failure for command cmd and returns its exit code: a malformed
// or unknown run id is a usage error (R25), anything else — an unreadable machine config, no ledger
// root — is tego's own (125).
func runRefFailed(stderr io.Writer, cmd string, err error) int {
	if errors.Is(err, errBadRunID) || errors.Is(err, errRunNotFound) {
		message(stderr, "", 0, 0, "tego "+cmd+": "+err.Error(), codeUsage)
		return identity.ExitUsage
	}
	message(stderr, "", 0, 0, "tego "+cmd+": "+err.Error(), codeIO)
	return identity.ExitError
}
