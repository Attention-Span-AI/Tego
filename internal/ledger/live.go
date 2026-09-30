// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The live index (record-ledger.md §3) is <ledger_root>/.live: one empty entry, named by its run id, for each
// run whose launcher has taken the run's lock and has not yet seen it end. `tego run` and `tego stop` sweep
// only the runs it names (SweepLive), so what they pay before acting is the runs alive or lost, not every run
// retention has kept: GC's pass over the whole root cost `tego run` about 73 µs per stored run, some 2 s at
// 30,000 runs. `tego gc` still walks every run directory.
//
// The order the launcher keeps is what makes the index complete. It lists its run once it holds the run's
// lock and before run_start (MarkLive), and clears the entry only once run_end is in the ledger (ClearLive).
// A lost run — run_start written, no run_end, lock free — is therefore listed whatever instant its launcher
// died at. A launcher that died before listing its run left no run_start, which no sweep ends and gc's
// retention removes; one that died between run_end and clearing left the entry of an ended run, which the
// next sweep clears.
//
// A sweep reads an entry's name and nothing else. The name must be a run id, so it names no path outside the
// ledger root, and the run it names is swept only when it is a directory directly in the root, not a link:
// what GC's List would find there. An entry is never opened, so a FIFO or a link planted as one blocks and
// redirects nothing, and an entry that is no run id is passed over. Anyone who can plant entries can write
// the ledger root already; each entry costs the sweep one probe of a run's state, never a directory outside
// the root.

// LiveDir is the live index's directory in a ledger root. It is no run id, so a pass over the root's run
// directories (RunRepository.List) never takes it for a run.
const LiveDir = ".live"

// keepAll is GC's keep for a pass that ends orphans and removes nothing.
const keepAll = time.Duration(math.MaxInt64)

// MarkLive lists run id in the live index of the ledger root at root, creating the index directory 0700 when
// it is missing. The launcher calls it holding the run's lock, before run_start.
//
// It follows the hand-over rule as MakeRunDir does (§3): the index is reached by the walk that, as root,
// refuses a link in a directory that is not root's alone; an index directory root creates in a ledger root
// another uid owns is handed to that uid; and so is an entry root creates in an index another uid owns. The
// entry is made O_CREAT|O_EXCL|O_NOFOLLOW, so whatever already sits under the name is neither followed nor
// handed over; such a name lists the run as well, so it is not an error.
func MarkLive(root, id string) error {
	if !IsRunID(id) {
		return fmt.Errorf("%w: %q", ErrBadRunRef, id)
	}
	dir := filepath.Join(root, LiveDir)
	path := filepath.Join(dir, id)
	d, err := openDir(dir, true)
	if err != nil {
		return fmt.Errorf("ledger: live index: %w", err)
	}
	defer func() { _ = d.Close() }()
	fd, err := d.Openat(id, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ledger: live index: %w", openError(d, id, path, err))
	}
	defer func() { _ = fd.Close() }()
	if err := giveCreated(d, dir, fd, path); err != nil {
		return fmt.Errorf("ledger: live index: %w", err)
	}
	return nil
}

// ClearLive removes run id's entry from the live index of the ledger root at root once the run is over: its
// ledger ends in run_end, or its directory is gone (a run that never started, which the launcher removes). A
// run whose Close could not append run_end reads as lost, and keeps its entry for the next sweep to end. A
// missing index or entry is not an error.
func ClearLive(root, id string) error {
	if !IsRunID(id) {
		return fmt.Errorf("%w: %q", ErrBadRunRef, id)
	}
	over, err := runOver(root, id)
	if err != nil || !over {
		return err
	}
	d, err := openDir(filepath.Join(root, LiveDir), false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("ledger: live index: %w", err)
	}
	defer func() { _ = d.Close() }()
	return unlist(d, root, id)
}

// runOver reports whether run id under root has ended or is gone.
func runOver(root, id string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(root, id)); errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	state, err := NewRunRepository(root).State(context.Background(), id)
	if err != nil {
		return false, err
	}
	return state == StateEnded, nil
}

// unlist removes the entry id from the index directory open at d, by name: unlinkat removes the name
// whatever it is and follows nothing, and an empty directory planted under the name goes the same way. An
// entry already gone is not an error.
func unlist(d *sys.FD, root, id string) error {
	err := d.Borrow(func(n int) error {
		err := unix.Unlinkat(n, id, 0)
		if errors.Is(err, unix.EISDIR) {
			err = unix.Unlinkat(n, id, unix.AT_REMOVEDIR)
		}
		return err
	})
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("ledger: live index: %w", &os.PathError{Op: "unlink", Path: filepath.Join(root, LiveDir, id), Err: err})
	}
	return nil
}

// SweepLive is the sweep `tego run` and `tego stop` make before they act: GC's orphan pass over the runs the
// live index names, and nothing else (§4 gc). For each entry that is a run id, a run still running keeps its
// entry; a lost one is swept — the hook, then run_end{orphaned} under its lock, as GC does — and its entry is
// cleared once the run reads as ended; one that ended, holds no ledger line, or whose directory is gone has its
// entry cleared. A run that could not be read or swept keeps its entry and is reported, so the next sweep meets
// it again. Nothing but index entries is ever removed, and one run's failure never stops the others.
//
// A ledger root with no index gets GC's pass over every run instead, with nothing removed: a root written only
// by a tego that kept no index, or whose index was deleted, may hold lost runs no entry names. The first run
// started there creates the index. An index that is there but cannot be read is reported and gets the same
// full pass, since the runs it would have named are unknown.
func SweepLive(ctx context.Context, root string, opts ...GCOption) (Report, error) {
	o := gcOptions{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	// The walk keeps the writer's path-trust checks before the root is held, as GC's does.
	rd, err := openDir(root, false)
	if err != nil {
		return Report{Errors: map[string]error{}}, fmt.Errorf("ledger: open ledger root: %w", err)
	}
	defer func() { _ = rd.Close() }()
	repo := o.repository(root, rd)
	if o.opened != nil {
		o.opened()
	}
	return sweepLive(ctx, root, rd, repo, &o)
}

// sweepLive is SweepLive's pass once the root is held.
func sweepLive(ctx context.Context, root string, rd *sys.FD, repo *fsRunRepository, o *gcOptions) (Report, error) {
	dfd, names, err := readLive(rd, root)
	if err != nil {
		// GC's pass over the directory already held and its repository, including when its named path or an
		// ancestor has moved, with the anchor derived from the configured root.
		rep, gerr := gcPass(ctx, repo, keepAll, false, o)
		if !errors.Is(err, os.ErrNotExist) {
			rep.Errors[LiveDir] = err
		}
		return rep, gerr
	}
	defer func() { _ = dfd.Close() }()
	rep := Report{Errors: map[string]error{}}
	for _, id := range names {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if !IsRunID(id) {
			continue
		}
		var (
			keep bool
			err  error
		)
		if o.isForeign(id) {
			// Another host's run: its entry is that host's to clear (L3), until retention has removed the run.
			// gc ages a foreign run out whatever it reads but running, and an entry
			// whose run is gone would otherwise stay forever.
			keep = !gone(rd, id)
		} else {
			keep, err = sweepListed(ctx, repo, rd, id, o, &rep)
		}
		if err != nil {
			rep.Errors[id] = err
		}
		if keep {
			continue
		}
		if err := unlist(dfd, root, id); err != nil {
			rep.Errors[id] = errors.Join(rep.Errors[id], err)
		}
	}
	return rep, nil
}

// LiveEntries returns the run ids the live index of the ledger root at root lists, reading nothing but the
// index's names; a root with no index lists none. `tego doctor` uses it to name the runs no sweep has been able
// to finish (limits-check-doctor-cli.md R27).
func LiveEntries(root string) ([]string, error) {
	rd, err := openDir(root, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("ledger: open ledger root: %w", err)
	}
	defer func() { _ = rd.Close() }()
	dfd, names, err := readLive(rd, root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	_ = dfd.Close()
	ids := names[:0]
	for _, n := range names {
		if IsRunID(n) {
			ids = append(ids, n)
		}
	}
	return ids, nil
}

// gone reports whether nothing is left under id in the ledger root open at rd: retention removed the run. A
// probe that fails for any other reason is not gone.
func gone(rd *sys.FD, id string) bool {
	var st unix.Stat_t
	return errors.Is(rd.Fstatat(id, &st, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT)
}

// readLive opens the live index of the ledger root open at rd and returns it with the names it holds. The
// index is opened O_NOFOLLOW whoever runs the sweep: tego never makes it a link.
func readLive(rd *sys.FD, root string) (*sys.FD, []string, error) {
	path := filepath.Join(root, LiveDir)
	d, err := rd.Openat(LiveDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// O_DIRECTORY|O_NOFOLLOW refuses a link as ENOTDIR, not ELOOP.
		if errors.Is(err, unix.ENOTDIR) && isLink(rd, LiveDir) {
			return nil, nil, fmt.Errorf("ledger: live index: %w: %s", ErrLinkRefused, path)
		}
		return nil, nil, fmt.Errorf("ledger: live index: %w", openError(rd, LiveDir, path, err))
	}
	names, err := readDirNames(d, path)
	if err != nil {
		_ = d.Close()
		return nil, nil, fmt.Errorf("ledger: live index: %w", err)
	}
	return d, names, nil
}

// sweepListed handles the run one index entry names and reports whether the entry stays: while the run may
// still be live or lost, or its state is unknown.
func sweepListed(ctx context.Context, repo *fsRunRepository, rd *sys.FD, id string, o *gcOptions, rep *Report) (keep bool, err error) {
	var st unix.Stat_t
	if err := rd.Fstatat(id, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil // removed by gc, or by a launcher that never started it
		}
		return true, &os.PathError{Op: "lstat", Path: repo.dir(id), Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, nil // a link or a file under a run id is no run directory: List passes it over too
	}
	state, err := repo.State(ctx, id)
	if err != nil {
		return true, err
	}
	if state == StateRunning {
		state = reclaimed(ctx, repo, record.RunRef{ID: id}, o)
	}
	switch state {
	case StateRunning:
		rep.Kept = append(rep.Kept, id)
		return true, nil
	case StateLost:
	case StateEmpty:
		// Died before run_start: nothing to end, but its cgroup may be left (sweepEmpty). The entry stays when
		// the hook failed, so the next sweep tries again.
		busy, err := sweepEmpty(ctx, repo, record.RunRef{ID: id}, o)
		if err != nil {
			return true, err
		}
		return busy, nil // a lock still held was not swept: the entry stays for the next sweep
	case StateEnded:
		return endListed(ctx, repo, id, o)
	default:
		return false, nil
	}
	// An agent the first line cannot give is taken from the contract copy (sweep).
	agent, aerr := repo.agentOf(id)
	swept, err := sweep(ctx, repo, record.RunRef{ID: id, Agent: agent}, o)
	if err != nil {
		if aerr != nil {
			err = errors.Join(err, fmt.Errorf("ledger: run %s: %w", id, aerr))
		}
		// A line after run_end can never be ended or repaired by another sweep: reported, and the entry goes.
		return !errors.Is(err, ErrRunEnded), err
	}
	if swept {
		rep.Swept = append(rep.Swept, id)
		return false, nil
	}
	// Another sweeper holds the lock mid-sweep, or the run became live or ended: the entry goes only once the
	// ledger says the run is over, or the next sweep could not find a run the other sweeper then failed to
	// end. The run is that sweeper's to count, not this one's (case 10).
	if state, err = repo.State(ctx, id); err != nil {
		return true, err
	}
	return state != StateEnded, nil
}

// endListed handles an ended run the live index still lists, and reports whether the entry stays. Its launcher
// died after run_end, somewhere between the append and ClearLive, or is still between them. Two things it left
// may be undone:
//
//   - A launcher that died inside Close between run_end and the chain.log append left an ended run with no
//     anchor line, which `events --verify` reads as ErrAnchorMissing ([ledger-corrupt]) forever. Under the
//     run's lock, a run with no anchor line whose chain verifies — every line chained and valid, run_start
//     first and run_end last, all of this run — is anchored at the ledger's own last id, in the anchor the
//     Writer's options name (the one its launcher would have used, WithSweepAnchor in internal/runtime), and
//     that is logged. A chain that does not verify is reported and not anchored: nothing vouches for it, and
//     verify says so. That includes a ledger with no run_start (an old launcher's unwind wrote run_end as line
//     0): Verify refuses it, so it is reported and left unanchored.
//   - Its scope, empty but not removed, and at tier 2 its handle never detached: the ended hook
//     (WithEndedHook) runs with the run's agent. What it cannot recover is the runtime's to say.
//
// A lock held here is a launcher still inside Close, or a process of the run holding the lock of a launcher
// that died: the entry stays, and the hook still runs, since it is what ends the latter. A lock file that is
// missing is no lock anyone holds, and nothing then keeps two sweeps from both finding the run unanchored and
// both appending a line, which Head refuses as two heads: the repair is skipped, as under a held lock, and the
// run is left for `events --verify` to report. The entry itself goes as it would with
// the lock free, since the next sweep would find the lock missing again. A repair that failed for a reason that
// may pass — the anchor could not be read, or its line could not be written, or the ledger's read failed or was
// cut short (*amended 2026-09-24:* a cancelled context or EIO in Verify had cleared the entry
// as a chain that does not verify) — keeps the entry, so the next sweep
// tries again; only a chain that does not verify, or is not one whole run of its own, is left unanchored and its
// entry cleared, since no later sweep would find it otherwise. GC's pass over every
// run directory has no index and leaves an ended run alone.
//
// The repair is a sweeper's word on a ledger it can read: it stands against a launcher killed in Close, not
// against someone who can write the ledger root, who can write a whole chain that verifies and have a sweep
// anchor it. The anchor file is outside the ledger root so that deleting or editing a run already anchored is
// seen; a run never anchored has only its ledger to vouch for it.
//
// The run's directory is opened once, under the held root: the lock, the repair, the agent and the hook's lent
// directory all come from it, so a directory renamed over the run's name meanwhile is not what the hook checks.
func endListed(ctx context.Context, repo *fsRunRepository, id string, o *gcOptions) (keep bool, err error) {
	d, err := repo.openRun(id)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // removed since sweepListed looked: by gc, as there
	}
	if err != nil {
		return true, fmt.Errorf("ledger: run %s: %w", id, err)
	}
	defer func() { _ = d.Close() }()
	dir := repo.dir(id)
	held, unlock, err := tryLockAt(d, dir)
	if err != nil {
		return true, fmt.Errorf("ledger: run %s: %w", id, err)
	}
	var errs []error
	if !held && unlock != nil {
		o.lockedRun(id)
		if rerr := repairAnchor(ctx, d, dir, id, o); rerr != nil {
			errs = append(errs, rerr)
			keep = !errors.Is(rerr, errUnanchorable)
		}
		unlock()
	}
	if o.ended != nil {
		agent, aerr := firstAgent(OpenReaderAt(d, dir))
		if agent == "" {
			agent = contractAgent(openRegularAt(d, ContractFile, filepath.Join(dir, ContractFile)))
		}
		if agent == "" {
			errs = append(errs, errors.Join(fmt.Errorf("ledger: run %s: no agent to find its scope by", id), aerr))
		} else {
			var done bool
			herr := lendDir(d, dir, func(lent sys.Lender) error {
				var err error
				done, err = o.ended(ctx, lent, record.RunRef{ID: id, Agent: agent})
				return err
			})
			if herr != nil {
				return true, errors.Join(append(errs, fmt.Errorf("%w: %w", errSweepHook, herr))...)
			}
			keep = keep || !done
		}
	}
	return keep || held, errors.Join(errs...)
}

// tryLockAt takes the lock file of the run directory open at d (dir names it in errors) LOCK_EX|LOCK_NB on a
// descriptor of its own, opened as a reader opens it (openRegularAt). held reports another holder; otherwise
// unlock releases it. A missing lock file is not held and is not taken either: unlock is nil, and the caller
// does nothing it would need the lock for.
func tryLockAt(d *sys.FD, dir string) (held bool, unlock func(), err error) {
	f, err := openRegularAt(d, LockFile, filepath.Join(dir, LockFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("open lock: %w", err)
	}
	if err := sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return true, nil, nil
		}
		return false, nil, fmt.Errorf("flock: %w", err)
	}
	return false, func() { _ = f.Close() }, nil
}

// errUnanchorable is a repair refused on the ledger itself: its chain does not verify, or it is not one whole
// run of its own. No later sweep would find it otherwise, so its entry goes (endListed).
var errUnanchorable = errors.New("left unanchored")

// repairAnchor anchors the ended run id, the run directory open at d (dir names it), at its ledger's last id when
// its anchor has no line for it and its chain verifies (endListed). The caller holds the run's lock, taken under d.
func repairAnchor(ctx context.Context, d *sys.FD, dir, id string, o *gcOptions) error {
	wo := options{log: slog.New(slog.DiscardHandler)}
	for _, opt := range o.writer {
		opt(&wo)
	}
	if wo.anchor == nil {
		wo.anchor = NewFileChainAnchor(DefaultAnchorPath(dir))
	}
	if _, ok, err := wo.anchor.Head(id); err != nil || ok {
		if err != nil {
			return fmt.Errorf("ledger: run %s: read its anchor: %w", id, err)
		}
		return nil
	}
	rd, err := OpenReaderAt(d, dir)
	if err != nil {
		return fmt.Errorf("ledger: run %s: %w", id, err)
	}
	rep, err := rd.Verify(ctx, nil)
	_ = rd.Close()
	switch {
	case err != nil && !errors.Is(err, ErrUnverified) && !errors.Is(err, ErrCorruptLedger):
		// A read that failed or was cut short (a cancelled context, EIO) says nothing about the chain: the entry
		// stays and the next sweep tries again.
		return fmt.Errorf("ledger: run %s: verify its chain: %w", id, err)
	case err != nil:
		return fmt.Errorf("ledger: run %s ended with no anchor line, and its chain does not verify; %w: %w", id, errUnanchorable, err)
	case !rep.Ended || rep.Run != id || rep.TornBytes > 0:
		return fmt.Errorf("ledger: run %s ended with no anchor line, and its ledger is not one whole run of its own; %w", id, errUnanchorable)
	}
	if err := wo.anchor.Append(id, rep.Head); err != nil {
		return fmt.Errorf("ledger: run %s: %w: %w", id, ErrAnchorWrite, err)
	}
	wo.log.Warn("ledger: sweep anchored an ended run whose launcher died before its anchor line",
		"run", id, "head", rep.Head, "lines", rep.Lines)
	return nil
}
