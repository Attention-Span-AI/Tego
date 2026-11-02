// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// KeepChanges is how many of a contract's newest changes that stand (not undone) Prune keeps however old, with every
// line after the oldest of them, while the contract's file is there: Undo can always go that many changes back.
const KeepChanges = 20

// pruneLock is the file in locks/ a write holds shared from its first blob to its journal line (share) and Prune holds
// exclusively. It is never removed.
const pruneLock = "prune.lock"

// ErrOtherOwner is a Prune of a journal another user owns, which a root pass over the invoking user's ledger root
// meets when it does not prune as that user: root may not write there, since what it wrote would be refused as not
// the user's.
var ErrOtherOwner = errors.New("rulefile: the rule-change journal is another user's")

// lookWait bounds how long a Prune waits for the contracts' files to be looked at (there): a file on a stale mount,
// whose lstat never returns, counts as there once it is spent, so its lines stay and the pass goes on. A variable so
// a test can spend it.
var lookWait = 3 * time.Second

// lstat is os.Lstat; a test replaces it to play a file that never answers.
var lstat = os.Lstat

// PruneOptions are a Prune's.
type PruneOptions struct {
	// Before is the retention's edge: a line written before it may go, and so may a file in blobs/ no line left names
	// whose modification time is before it.
	Before time.Time
	// Gone are runs the caller's pass removes from the ledger root, or with DryRun would remove: they count as gone
	// although their directories may still be there. A dry run of `tego gc` names the runs its sweep would remove, so
	// that it counts what the pass would prune once they are.
	Gone []string
	// DryRun counts what would go and changes nothing: no file is made, locked, written or removed.
	DryRun bool
}

// Pruned is what a Prune removed, or with DryRun would remove.
type Pruned struct {
	// Lines are journal lines: aged out, or torn by a crash mid-append.
	Lines int
	// Blobs are files in blobs/ no line left names: the texts of the lines that went, and what a failed write left.
	Blobs int
	// Locks are the lock files of contracts with no line left.
	Locks int
}

// Prune applies retention to root's journal. A line goes only when no reader of the journal can need it: the
// History and Undo of what is left, an Undo's lift (internal/control/rules heldByOther), a run's pending changes
// and Apply now (internal/control/rulesview) and the feed answer as before it for every line left and every run still
// in the ledger root. So of each contract it keeps every line from the first one on, in the journal's order, that
//
//   - was written at or after o.Before, or after the oldest run still in the ledger root started (o.Gone count as
//     gone): that run's page lists the changes made since its start, and Apply now places them;
//   - names a run still there, on the line or in a live line of it, however old its date (a clock set back): a live
//     block a change that stands placed on a running run is one an Undo of another change must not lift;
//   - is, while the contract's file is there, the KeepChanges-th newest change that stands: how far Undo goes back;
//   - was undone by a revert left, and so on back: the revert's words say what it undid, and a run's pending changes
//     leave out a revert of a change made since its start; or undid a line left;
//
// and, while the file is there, its newest creation, which the Rules page offers a contract made here by. Every line
// after a line kept stays, so whether a line left reads as undone is as before. A live line stays or goes with the
// line it belongs to, a line of an op this tego does not know stays, and a torn line goes.
//
// It holds prune.lock exclusively, so no write is between its first blob and its line meanwhile, and rewrites the
// journal under journal.lock through a new file renamed over it; only then do the files in blobs/ that no line left
// names go, once their modification time is before o.Before, and the lock files of contracts with no line left, each
// removed while Prune holds its flock, so one a write holds stays (flock). The runs are listed and the contracts' files
// looked at before any lock is taken, the looks waited for at most lookWait. A journal holding a line this tego does
// not read, or two lines of one id, is left whole, and so is one another user owns (ErrOtherOwner). No journal is
// nothing to do.
func Prune(ctx context.Context, root string, o PruneOptions) (Pruned, error) {
	var p Pruned
	if err := ctx.Err(); err != nil {
		return p, err
	}
	j, err := openJournalRead(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return p, nil
	case errors.Is(err, ErrGuard) && otherOwner(root):
		return p, fmt.Errorf("%w: %v", ErrOtherOwner, err)
	case err != nil:
		return p, err
	}
	defer j.close()
	runs, oldest, err := j.runsIn(ctx, o.Gone)
	if err != nil {
		return p, err
	}
	r := keepRule{before: o.Before, edge: o.Before, runs: runs, there: func(string) bool { return false }}
	if !oldest.IsZero() && oldest.Before(r.edge) {
		r.edge = oldest
	}
	// Which contracts' files decide anything is read from the journal as it stands, with no lock: a contract first
	// written after this read is not looked at and counts as there.
	pre, err := j.lines()
	if err != nil {
		return p, err
	}
	seen := lookThere(ctx, losing(pre, r))
	r.there = func(c string) bool { t, ok := seen[c]; return !ok || t }
	if err := ctx.Err(); err != nil {
		return p, err // the pass's budget went on looking: the next pass prunes
	}
	if !o.DryRun {
		unlock, err := j.flock(ctx, pruneLock, unix.LOCK_EX,
			"a contract change is being written, or another pass is pruning; the next pass prunes")
		if err != nil {
			return p, err
		}
		defer unlock()
	}
	named, kept, err := j.pruneLines(ctx, o, r, &p)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = j.pruneBlobs(o, named, &p)
	}
	if err == nil {
		err = j.pruneLocks(o, kept, &p)
	}
	return p, err
}

// pruneLines rewrites the journal without the lines that go, under journal.lock, and returns the blobs the lines left
// name and the lock files of the contracts they write. A Prune that crashed mid-rewrite left its new file behind; it
// goes here, since prune.lock keeps any other Prune from writing one meanwhile.
func (j *journal) pruneLines(ctx context.Context, o PruneOptions, r keepRule, p *Pruned) (named, kept map[string]bool, err error) {
	if !o.DryRun {
		unlock, err := j.flock(ctx, "journal.lock", unix.LOCK_EX, "a line is being appended; the next pass prunes")
		if err != nil {
			return nil, nil, err
		}
		defer unlock()
	}
	ls, err := j.lines()
	if err != nil {
		return nil, nil, err
	}
	keep := retain(ls, r)
	named, kept = map[string]bool{}, map[string]bool{}
	var out bytes.Buffer
	dropped := 0
	for i, l := range ls {
		if !keep[i] {
			dropped++
			continue
		}
		out.Write(l.raw)
		out.WriteByte('\n')
		named[l.e.OldSHA256], named[l.e.NewSHA256] = true, true
		if isWrite(l.e.Op) {
			kept[Sum([]byte(l.e.Contract))+".lock"] = true
		}
	}
	delete(named, "")
	if !o.DryRun {
		if err := j.removeTemps(); err != nil {
			return nil, nil, err
		}
		if dropped > 0 {
			if err := writeFile(j.dir, journalTemp, JournalFile, out.Bytes()); err != nil {
				return nil, nil, fmt.Errorf("rewrite %s: %w", JournalFile, err)
			}
		}
	}
	p.Lines += dropped
	return named, kept, nil
}

// journalTemp is the prefix of the new journal file a Prune writes before it renames it over journal.jsonl.
const journalTemp = "." + JournalFile + "."

// removeTemps removes the new journal files a Prune that crashed between its write and its rename left.
func (j *journal) removeTemps() error {
	ns, err := dirNames(j.dir, JournalDirName)
	if err != nil {
		return err
	}
	for _, n := range ns {
		if rest, ok := strings.CutPrefix(n, journalTemp); ok && len(rest) == 16 && strings.Trim(rest, "0123456789abcdef") == "" {
			if err := j.dir.Borrow(func(d int) error { return unix.Unlinkat(d, n, 0) }); err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("remove %s: %w", n, err)
			}
		}
	}
	return nil
}

// jline is one journal line as Prune reads it: its bytes, written back as they are, and what it says.
type jline struct {
	raw  []byte
	e    Entry
	torn bool // not JSON: a line a crash cut short, which every reader skips
}

// lines reads the journal for a Prune. A line that is JSON but not a line of this version with an id refuses the
// Prune: a newer tego's line may name blobs or lines in ways this one cannot see. So do two write lines of one id,
// which no write of this tego makes: a revert names one of them, and the readers fold such a journal in ways a Prune
// could not keep as they were.
func (j *journal) lines() ([]jline, error) {
	f, err := j.openFile(JournalFile, unix.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	var ls []jline
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for n := 1; sc.Scan(); n++ {
		l := jline{raw: bytes.Clone(sc.Bytes())}
		switch {
		case !json.Valid(l.raw):
			l.torn = true
		case json.Unmarshal(l.raw, &l.e) != nil || l.e.V != JournalVersion || l.e.ID == "":
			return nil, fmt.Errorf("%s line %d is not a line this tego reads (a newer tego's?), so the journal is left whole",
				JournalFile, n)
		}
		ls = append(ls, l)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", JournalFile, err)
	}
	return ls, wellFormed(ls)
}

// wellFormed refuses a journal with two write lines of one id (lines).
func wellFormed(ls []jline) error {
	seen := map[string]bool{}
	for _, l := range ls {
		if l.torn || !isWrite(l.e.Op) {
			continue
		}
		if seen[l.e.ID] {
			return fmt.Errorf("%s holds two lines of id %s, so the journal is left whole", JournalFile, l.e.ID)
		}
		seen[l.e.ID] = true
	}
	return nil
}

// keepRule is what decides which lines a Prune keeps (Prune).
type keepRule struct {
	// before is PruneOptions.Before; edge is before, or the start of the oldest run still in the ledger root when that
	// is earlier.
	before, edge time.Time
	// runs are the runs still in the ledger root.
	runs map[string]bool
	// there is whether a contract's file is there.
	there func(contract string) bool
}

// namesRun is whether e names a run still in the ledger root: the run it was made from, or one of its live outcomes'.
func (r keepRule) namesRun(e Entry) bool {
	return r.runs[e.Run] || slices.ContainsFunc(e.Live, func(l Live) bool { return r.runs[l.Run] })
}

// retain says which of a journal's lines (oldest first, wellFormed) stay, as Prune says.
func retain(ls []jline, r keepRule) []bool {
	keep := make([]bool, len(ls))
	byContract := map[string][]int{}
	byID := map[string]int{}
	pos := map[int]int{} // a write line's place in its contract's lines
	for i, l := range ls {
		switch {
		case l.torn:
		case isWrite(l.e.Op):
			pos[i] = len(byContract[l.e.Contract])
			byContract[l.e.Contract] = append(byContract[l.e.Contract], i)
			byID[l.e.ID] = i
		case l.e.Op != OpLive:
			keep[i] = true // an op this tego does not know
		}
	}
	// The write lines that name a run still here, on the line or in a live line of it.
	named := map[int]bool{}
	for i, l := range ls {
		if l.torn || !r.namesRun(l.e) {
			continue
		}
		if isWrite(l.e.Op) {
			named[i] = true
		} else if k, ok := byID[l.e.Of]; ok && l.e.Op == OpLive {
			named[k] = true
		}
	}
	undone := undoneLines(ls, byID)
	from := map[string]int{} // a contract's first line that stays: every one of its lines after it does too
	alone := map[int]bool{}  // a contract's newest creation, which stays while its file is there however old
	for c, is := range byContract {
		f := len(is)
		for k, i := range is {
			if !ls[i].e.At.Before(r.edge) || named[i] {
				f = k
				break
			}
		}
		if r.there(c) {
			for k, n := len(is)-1, 0; k >= 0 && n < KeepChanges; k-- {
				if ls[is[k]].e.Op == OpChange && !undone[is[k]] {
					n++
					f = min(f, k)
				}
			}
			// The Rules page offers a contract made here that no run ran yet by its creation line (rules.createdHere).
			for k := len(is) - 1; k >= 0; k-- {
				if ls[is[k]].e.Op == OpCreate {
					alone[is[k]] = true
					break
				}
			}
		}
		from[c] = f
	}
	// A revert that stays keeps the line it undid, and a line that stays every revert that undid it, each with every
	// line of its contract after it, and so on: whether a line left reads as undone, and what a revert left says it
	// undid, read as before. A revert names a line of its own contract but when the contract's folder was moved behind
	// a symlink between the two (a revert resolves the folder again), so this follows lines across contracts.
	reverters := map[int][]int{}
	for i, l := range ls {
		if t, ok := byID[l.e.Reverts]; ok && !l.torn && l.e.Op == OpRevert {
			reverters[t] = append(reverters[t], i)
		}
	}
	grow := func(i int) bool {
		c := ls[i].e.Contract
		if pos[i] >= from[c] {
			return false
		}
		from[c] = pos[i]
		return true
	}
	for grown := true; grown; {
		grown = false
		for c, is := range byContract {
			for k := len(is) - 1; k >= from[c]; k-- { // the bound follows from[c] as it moves
				i := is[k]
				if t, ok := byID[ls[i].e.Reverts]; ok && ls[i].e.Op == OpRevert && grow(t) {
					grown = true
				}
				for _, rv := range reverters[i] {
					grown = grow(rv) || grown
				}
			}
		}
		for i := range alone {
			for _, rv := range reverters[i] {
				grown = grow(rv) || grown
			}
		}
	}
	for c, is := range byContract {
		for _, i := range is[from[c]:] {
			keep[i] = true
		}
	}
	for i := range alone {
		keep[i] = true
	}
	for i, l := range ls {
		if l.torn || l.e.Op != OpLive {
			continue
		}
		if k, ok := byID[l.e.Of]; ok {
			keep[i] = keep[k]
		} else {
			keep[i] = !l.e.At.Before(r.before) // of no line: no reader reads it
		}
	}
	return keep
}

// undoneLines is which write lines a revert that stands undid, as Fold reads the journal: walking newest first, a
// revert not undone itself undoes the earlier line it names.
func undoneLines(ls []jline, byID map[string]int) map[int]bool {
	u := map[int]bool{}
	for i := len(ls) - 1; i >= 0; i-- {
		if l := ls[i]; !l.torn && l.e.Op == OpRevert && !u[i] {
			if k, ok := byID[l.e.Reverts]; ok && k < i && !u[k] {
				u[k] = true
			}
		}
	}
	return u
}

// losing is the contracts of which some line would go were their file not there: only those are looked at.
func losing(ls []jline, r keepRule) []string {
	r.there = func(string) bool { return false }
	keep := retain(ls, r)
	var cs []string
	for i, l := range ls {
		if !keep[i] && !l.torn && isWrite(l.e.Op) && !slices.Contains(cs, l.e.Contract) {
			cs = append(cs, l.e.Contract)
		}
	}
	return cs
}

// lookThere is, for each of cs, whether the contract's file is there (there). The files are looked at off the
// caller's goroutine, waited for at most lookWait or until ctx ends: a stale hard NFS or FUSE mount never answers an
// lstat, and a run's start must not wait on one. A contract the wait did not reach is not in the map, which counts as
// there. The goroutine stops at the next file once the wait is over; one stuck in an lstat ends when it returns.
func lookThere(ctx context.Context, cs []string) map[string]bool {
	out := make(map[string]bool, len(cs))
	if len(cs) == 0 {
		return out
	}
	type look struct {
		contract string
		there    bool
	}
	looks := make(chan look, len(cs)) // never full: the goroutine sends once per contract
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(looks)
		for _, c := range cs {
			select {
			case <-stop:
				return
			default:
			}
			looks <- look{c, there(c)}
		}
	}()
	wait := time.NewTimer(lookWait)
	defer wait.Stop()
	for {
		select {
		case l, ok := <-looks:
			if !ok {
				return out
			}
			out[l.contract] = l.there
		case <-wait.C:
			return out
		case <-ctx.Done():
			return out
		}
	}
}

// isWrite is whether op is a line that wrote a contract: a change, a revert or a creation.
func isWrite(op string) bool { return op == OpChange || op == OpRevert || op == OpCreate }

// there is whether a contract's file is at path; one that cannot be looked at counts as there, so its lines stay.
func there(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	_, err := lstat(path)
	return err == nil || !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, unix.ENOTDIR)
}

// runsIn is the runs whose directory is in the ledger root, but for gone, and when the oldest of them started (zero
// when none says): what the journal's readers may still answer about. A run is a directory the dashboard reads as
// one (runName). It started at the time of its run_start line, which the readers compare a line's time with, or at
// its id's mint time (identity R1) when that is earlier (a clock set back while it started) or the line does not read
// yet. A run whose start nothing says (a name that is no minted id, with no run_start that reads) is one no reader
// reads: it moves no edge, but a line that names it still stays.
func (j *journal) runsIn(ctx context.Context, gone []string) (map[string]bool, time.Time, error) {
	ns, err := dirNames(j.root, "the ledger root")
	if err != nil {
		return nil, time.Time{}, err
	}
	runs := map[string]bool{}
	var oldest time.Time
	for _, n := range ns {
		if err := ctx.Err(); err != nil {
			return nil, time.Time{}, err
		}
		var st unix.Stat_t
		if !runName(n) || slices.Contains(gone, n) || j.root.Fstatat(n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		runs[n] = true
		at, ok := mintTime(n)
		if ts, read := j.runStart(n); read && (!ok || ts.Before(at)) {
			at, ok = ts, true
		}
		if ok && (oldest.IsZero() || at.Before(oldest)) {
			oldest = at
		}
	}
	return runs, oldest, nil
}

// runName is a name the dashboard reads as a run's directory (internal/control/rules runID): "r-", then lower-case
// letters, digits and dashes, at most 128 bytes.
func runName(n string) bool {
	return strings.HasPrefix(n, "r-") && len(n) <= 128 && strings.Trim(n, "-0123456789abcdefghijklmnopqrstuvwxyz") == ""
}

// mintTime is the time36 of a minted run id r-<host8>-<time36>-<rand6> (identity R1): when it was minted.
func mintTime(id string) (time.Time, bool) {
	if !identity.RunID(id).Valid() {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(id[len("r-01234567-"):len("r-01234567-0123456789abc")], 36, 64)
	if err != nil || ns <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

// runStart is the time of run_start, the first line of the run directory name's events file, as the dashboard reads a
// run's start (readStart).
func (j *journal) runStart(name string) (time.Time, bool) {
	d, err := j.root.Openat2(name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH})
	if err != nil {
		return time.Time{}, false
	}
	defer func() { _ = d.Close() }() // read-only
	f, err := ledger.OpenRegularAt(d, ledger.EventsFile, name+"/"+ledger.EventsFile)
	if err != nil {
		return time.Time{}, false
	}
	defer func() { _ = f.Close() }() // read-only
	first, ok := lineAt(f, 0)
	if !ok {
		return time.Time{}, false
	}
	e, err := record.Decode(first)
	if err != nil || e.Kind != record.KindRunStart || e.TS.IsZero() {
		return time.Time{}, false
	}
	return e.TS, true
}

// pruneBlobs removes the files in blobs/ that no line left names, once their modification time is before o.Before:
// the texts of the lines that went, and what a write that failed after its blobs, or a crash, left. A write of this
// tego holds prune.lock from its first blob to its line, so none is in between now; the time only spares a write of a
// tego from before Prune, which takes no prune.lock, the blob it has just made (one it found there already, older,
// is not spared: such a tego is to be restarted once the new one is installed).
func (j *journal) pruneBlobs(o PruneOptions, named map[string]bool, p *Pruned) error {
	ns, err := dirNames(j.blobs, BlobsDir)
	if err != nil {
		return err
	}
	for _, n := range ns {
		if sum, ok := strings.CutSuffix(n, ".yaml"); ok && named[sum] {
			continue
		}
		var st unix.Stat_t
		if j.blobs.Fstatat(n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT == unix.S_IFDIR ||
			!time.Unix(st.Mtim.Unix()).Before(o.Before) {
			continue
		}
		if o.DryRun || j.blobs.Borrow(func(d int) error { return unix.Unlinkat(d, n, 0) }) == nil {
			p.Blobs++
		}
	}
	return nil
}

// pruneLocks removes the lock files of contracts with no line left (kept names the others); journal.lock and
// prune.lock are no contract's and stay.
func (j *journal) pruneLocks(o PruneOptions, kept map[string]bool, p *Pruned) error {
	ns, err := dirNames(j.locks, LocksDir)
	if err != nil {
		return err
	}
	for _, n := range ns {
		if sum, ok := strings.CutSuffix(n, ".lock"); !ok || !hexSum(sum) || kept[n] {
			continue
		}
		if o.DryRun || j.removeLock(n) {
			p.Locks++
		}
	}
	return nil
}

// removeLock removes locks/name while it holds the file's flock: false, and the file stays, when a write holds it.
func (j *journal) removeLock(name string) bool {
	l, err := sys.Strict(j.locks.Openat(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
	if err != nil {
		return false
	}
	defer func() { _ = l.Close() }() // after the unlink: the flock is held until the name is gone
	if l.Flock(unix.LOCK_EX|unix.LOCK_NB) != nil || !j.holds(l, name) {
		return false
	}
	return j.locks.Borrow(func(d int) error { return unix.Unlinkat(d, name, 0) }) == nil
}

// dirNames lists the directory open at d through a descriptor of its own, so d's offset stays as it was.
func dirNames(d *sys.FD, what string) ([]string, error) {
	fd, err := d.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", what, err)
	}
	f, err := fd.Release(what)
	if err != nil {
		_ = fd.Close() // Release failed, so the owner still holds the number; its error is the one to report
		return nil, fmt.Errorf("list %s: %w", what, err)
	}
	defer func() { _ = f.Close() }() // read-only
	return f.Readdirnames(-1)
}

// otherOwner is whether root's journal directory is another user's.
func otherOwner(root string) bool {
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	var st unix.Stat_t
	return unix.Lstat(filepath.Join(r, JournalDirName), &st) == nil && st.Uid != uint32(geteuid())
}
