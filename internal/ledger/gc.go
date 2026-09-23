// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Report is what GC did, or would do with dryRun: run ids per outcome and one error per failed run.
type Report struct {
	Deleted []string
	Kept    []string
	Swept   []string
	Errors  map[string]error
}

// GCOption configures GC.
type GCOption func(*gcOptions)

type gcOptions struct {
	// held is the pass's pinned repository: the run directories the sweep, reclaim and ended hooks receive are
	// opened under its root (lendRun).
	held        *fsRunRepository
	now         func() time.Time
	sweep       func(ctx context.Context, dir sys.Lender, run record.RunRef) error
	writer      []Option
	boundWriter func(root sys.Lender) []Option // options whose lookups must use the held root
	// opened runs once GC or SweepLive holds the root, before it lists: tests swap its path there.
	opened func()
	// locked runs once the pass holds run id's lock, before its hook: tests swap the run's name there.
	locked func(id string)
	// reclaim is WithReclaimHook.
	reclaim func(ctx context.Context, dir sys.Lender, run record.RunRef) bool
	// ended is WithEndedHook.
	ended func(ctx context.Context, dir sys.Lender, run record.RunRef) (done bool, err error)
	// foreign is WithForeignRun.
	foreign func(id string) bool
}

// WithForeignRun names the runs another host minted (a ledger root shared between machines): internal/runtime
// passes the check of a run id's host8 against this host's. GC and SweepLive leave such a run alone entirely —
// no reclaim, no hook, no run_end{orphaned}, no anchor repair, and its live-index entry stays — since its lock
// is only a lock on this machine, its launcher may be alive on its own, and its anchor is its own host's.
// GC still ages out one that reads ended or empty; one that reads running is kept.
// *Amended 2026-09-24:* one that reads lost is not swept but ages out past retention too,
// with no run_end written, and SweepLive clears its entry once its directory is gone: a machine id that changed
// made every run of this host foreign, and kept for its own host to end, they were never removed.
func WithForeignRun(fn func(id string) bool) GCOption {
	return func(o *gcOptions) { o.foreign = fn }
}

// isForeign reports whether WithForeignRun names run id.
func (o *gcOptions) isForeign(id string) bool { return o.foreign != nil && o.foreign(id) }

// WithEndedHook runs, in SweepLive alone, for an ended run the live index still lists: its launcher died after
// run_end and before it cleared the entry, or is still between the two. internal/runtime uses it to remove the
// scope such a launcher may have left. dir lends the run's directory, which hooks make their lookups under
// (WithSweepHook). done=false keeps the entry for the next sweep without an error (a launcher still alive and
// finishing); an error keeps it and is reported.
func WithEndedHook(fn func(ctx context.Context, dir sys.Lender, run record.RunRef) (done bool, err error)) GCOption {
	return func(o *gcOptions) { o.ended = fn }
}

// WithReclaimHook runs for a run whose lock is held, before the run is kept as running. It reports whether it
// freed the lock, and the run's state is then read again: internal/runtime uses it for a lock whose launcher
// is gone, which only a process of the run itself can hold (it opened the lock file and flocked it), and which
// kept its dead launcher's run from ever being swept (runtime-launch.md R20). It kills the run's cgroup and
// waits for the lock to come free; a lock held by a live launcher it leaves alone.
// dir lends the run's directory, which hooks make their lookups under (WithSweepHook); a directory that cannot
// be opened frees nothing.
func WithReclaimHook(fn func(ctx context.Context, dir sys.Lender, run record.RunRef) bool) GCOption {
	return func(o *gcOptions) { o.reclaim = fn }
}

// reclaimed runs the reclaim hook for a run whose lock is held and reports the run's state after it:
// StateRunning when there is no hook, it freed nothing, or the state cannot be read again.
func reclaimed(ctx context.Context, repo RunRepository, ref record.RunRef, o *gcOptions) RunState {
	fs, ok := repo.(*fsRunRepository)
	if !ok || o.reclaim == nil {
		return StateRunning
	}
	if ref.Agent == "" {
		if agent, err := fs.agentOf(ref.ID); err == nil && agent != "" {
			ref.Agent = agent
		} else {
			ref.Agent = fs.agentOfContract(ref.ID)
		}
	}
	freed := false
	if err := o.lendRun(ref.ID, func(dir sys.Lender) error {
		freed = o.reclaim(ctx, dir, ref)
		return nil
	}); err != nil || !freed {
		return StateRunning
	}
	state, err := repo.State(ctx, ref.ID)
	if err != nil {
		return StateRunning
	}
	return state
}

// WithNow replaces time.Now for retention math; tests and replays use it.
func WithNow(now func() time.Time) GCOption { return func(o *gcOptions) { o.now = now } }

// WithSweepHook runs before a lost run is ended: internal/runtime uses it to kill a still-populated cgroup.
// An error from the hook skips the sweep for that run and is reported. dir lends the run's directory, opened
// under the ledger root the pass holds with a link refused, for the hook's call alone: every hook gets it and
// makes its run lookups under it (*at() calls, ADR 0023). Where the pass holds the run's lock (a lost run's
// Writer, an empty run's or an ended run's lock), it is the directory that lock was taken in (lendDir), so the
// run the hook checks is the run the pass ends, whatever is renamed over the configured path, an ancestor or the
// run's name meanwhile. Where it holds none (a reclaim hook, a ledger that cannot be ended) it is the run's name
// opened under the held root when the hook runs (lendRun): renaming entries inside a writable root stays the
// separate boundary GC names. A directory that cannot be opened is the hook's error, and the run stays lost.
func WithSweepHook(fn func(ctx context.Context, dir sys.Lender, run record.RunRef) error) GCOption {
	return func(o *gcOptions) { o.sweep = fn }
}

// WithBoundWriterOptions builds writer options after the ledger root is held open. root lends that
// directory for this pass only; ownership-dependent anchors must look up runs through it.
// These options follow the sweep's other writer options (gcOptions.writer) and can override them, while their factory may retain the
// declared root separately for an anchor's configured fallback location.
func WithBoundWriterOptions(fn func(root sys.Lender) []Option) GCOption {
	return func(o *gcOptions) { o.boundWriter = fn }
}

// repository binds decisions and writer-option lookups to rd, the ledger root the pass holds.
func (o *gcOptions) repository(label string, rd *sys.FD) *fsRunRepository {
	repo := pinnedRepository(label, rd, o.writer...)
	o.held = repo
	if o.boundWriter != nil {
		repo.opts = append(repo.opts, o.boundWriter(rd)...)
	}
	// WithAnchor(nil) means the default, including repairAnchor, whose read path is descriptor-bound.
	// Keep this fallback tied to the configured label; a missing-index GC fallback retains the closure.
	fallback := NewFileChainAnchor(DefaultAnchorPath(filepath.Join(label, "run")))
	repo.opts = append(repo.opts, func(w *options) {
		if w.anchor == nil {
			w.anchor = fallback
		}
	})
	o.writer = repo.opts
	return repo
}

// GC applies retention over every run under root (§4 gc). A running run is always kept. A lost run is swept
// first: the hook runs, then run_end{reason: orphaned} is appended and the run closed under its lock. Any
// ended or empty run older than keep is removed whole; age comes from the run id's time36 (R16), then the
// last event's ts, then the directory's mtime. A run whose state cannot be read at all is reported and still
// aged out, unless its lock says a Writer may be live. With dryRun nothing is written or removed. One run's
// failure never stops the others; only an unreadable root is a returned error. Re-running GC at once is a
// no-op.
//
// Listing, state/age reads, lock probes, sweep writes and removal are all *at() calls under the root opened
// before the pass. Hooks receive the run's directory opened under it (WithSweepHook), the one the pass locked
// where it holds the run's lock, so runtime orphan checks cannot consult a decoy after a root or ancestor
// rename, nor after a rename of the run's name once the run is locked. The final named-root check still
// refuses deletion if the configured path no longer names that directory. Replacing entries inside a writable
// root is otherwise a separate boundary; deletion also takes the actual run's lock so a live Writer keeps its
// directory.
func GC(ctx context.Context, root string, keep time.Duration, dryRun bool, opts ...GCOption) (Report, error) {
	o := gcOptions{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	// The walk keeps the privileged writer's path-trust checks (openDir: as root, a link in a directory that
	// is not root's alone is refused) before the root is held: OpenAt below must not turn a previously
	// refused symlink under an untrusted ancestor into an accepted write because the target directory is now
	// held by descriptor.
	rd, err := openDir(root, false)
	if err != nil {
		return Report{Errors: map[string]error{}}, fmt.Errorf("ledger: open ledger root: %w", err)
	}
	defer func() { _ = rd.Close() }()
	repo := o.repository(root, rd)
	if o.opened != nil {
		o.opened()
	}
	return gcPass(ctx, repo, keep, dryRun, &o)
}

// lendRun runs fn with run id's directory, opened under the root the pass holds (o.held) with a link refused, and
// lent for fn's call alone (ADR 0023 A11): what a hook the pass holds no lock for makes every lookup of its under
// (a reclaim hook, a ledger that cannot be ended); a hook under the pass's lock is lent that directory (lendDir).
// A directory that cannot be opened, or a pass that holds no root, is fn's error, fn unrun.
func (o *gcOptions) lendRun(id string, fn func(dir sys.Lender) error) error {
	if o.held == nil {
		return fmt.Errorf("ledger: run %s: the pass holds no ledger root to lend the run's directory from", id)
	}
	d, err := o.held.openRun(id)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return fn(d)
}

// lendDir runs fn with the run directory open at d (dir names it in errors), opened again for fn's call alone
// (ADR 0023 A11): the directory whose lock the pass took, so a hook checks the run the pass ends, whatever is
// renamed over the run's name after the lock.
func lendDir(d *sys.FD, dir string, fn func(lent sys.Lender) error) error {
	l, err := reopenDir(d)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer func() { _ = l.Close() }()
	return fn(l)
}

// lockedRun runs the locked test seam, if any, for run id.
func (o *gcOptions) lockedRun(id string) {
	if o.locked != nil {
		o.locked(id)
	}
}

// gcPass is GC's pass over every run of repo, a pinned repository: GC's own, or SweepLive's when its root has
// no index.
func gcPass(ctx context.Context, repo *fsRunRepository, keep time.Duration, dryRun bool, o *gcOptions) (Report, error) {
	rep := Report{Errors: map[string]error{}}
	refs, err := repo.List(ctx)
	if err != nil && refs == nil {
		return rep, err
	}
	if err != nil {
		rep.Errors["."] = err
	}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if err := gcRun(ctx, repo, repo, ref, keep, dryRun, o, &rep); err != nil {
			rep.note(ref.ID, err)
		}
	}
	return rep, nil
}

// gcRun handles one run in the held root and records its outcome. held is the pass's pinned repository, and
// repo the one state reads and sweep writes go through (held itself, but for tests that wrap it). held.root,
// the configured name, is used only for the final identity check and in errors; every decision is made under
// the held root.
func gcRun(ctx context.Context, repo RunRepository, held *fsRunRepository, ref record.RunRef, keep time.Duration,
	dryRun bool, o *gcOptions, rep *Report) error {
	state, err := repo.State(ctx, ref.ID)
	if err != nil {
		// A state that cannot be read must not exempt the directory from retention: aborting here leaves it
		// untouched and erroring on every later pass, with no command an operator can use to clear it, and
		// retention is the product's only bound on ledger_root's growth (§4 gc, E22). The error is still
		// reported. State is left "", which is neither running nor lost, so no sweep is attempted on a ledger
		// nothing could read; the age below still comes from runTime, whose run-id time36 needs no ledger and
		// whose mtime fallback covers a run id that does not parse.
		rep.note(ref.ID, err)
		// Liveness is the one thing retention may not guess at, and it does not depend on the ledger: a held
		// lock means a live Writer whose directory must never be removed (§7, I7). Anything but a free lock,
		// including a lock that cannot be probed, keeps the run.
		if free, lerr := held.lockFree(ref.ID); lerr != nil || !free {
			rep.Kept = append(rep.Kept, ref.ID)
			return nil
		}
	}
	foreign := o.isForeign(ref.ID)
	if state == StateRunning && !dryRun && !foreign {
		state = reclaimed(ctx, repo, ref, o)
	}
	if state == StateRunning {
		rep.Kept = append(rep.Kept, ref.ID)
		return nil
	}
	if state == StateEmpty && !dryRun && !foreign {
		if _, err := sweepEmpty(ctx, held, ref, o); err != nil {
			return err // the orphan's tree may be alive: keep the run, as for a lost run's hook
		}
	}
	// Another host's lost run is not swept, but it ages out like any other: kept whatever its age, it was never
	// removed, and a machine id that changed (a reinstall keeping /home, a cloned image) makes every run of this
	// host foreign for good. Its removal below writes nothing to it.
	if state == StateLost && !foreign {
		swept := true
		if !dryRun {
			var err error
			swept, err = sweep(ctx, repo, ref, o)
			if err == nil && !swept {
				// Not this pass's to end: a probe's or another sweeper's lock, or the run became live, ended or
				// went. A vanished run (State reads a missing directory as empty, never as not-exist, so the
				// directory itself is asked) has its retention outcome already; only an ended run may age out
				// below, and a run still lost had no hook run, so its orphan tree may be alive and the run is
				// kept for the next pass.
				if gone(held.rootDir, ref.ID) {
					rep.Deleted = append(rep.Deleted, ref.ID)
					return nil
				}
				if st, _ := repo.State(ctx, ref.ID); st != StateEnded {
					rep.Kept = append(rep.Kept, ref.ID)
					return nil
				}
			}
			if err != nil {
				// A hook that failed may have left the orphan's tree alive: keep the run. A sweep that failed on
				// the ledger itself (a damaged line before an intact last one, which resume refuses) is
				// reported, and the run still ages out below like one whose state cannot be read: returning
				// here kept it forever and failed the same way on every pass (E22).
				if errors.Is(err, errSweepHook) {
					return err
				}
				rep.note(ref.ID, err)
				swept = false
			}
		}
		if swept {
			rep.Swept = append(rep.Swept, ref.ID)
		}
	}
	age := o.now().Sub(runTime(held, ref.ID))
	if age <= keep {
		rep.Kept = append(rep.Kept, ref.ID)
		return nil
	}
	if err := sameRoot(held.rootDir, held.root); err != nil {
		return err
	}
	if !dryRun {
		// Every Writer holds the run's flock before it writes a byte, so the decision above holds only
		// while gc holds that lock itself: a launcher that took it since State read the directory (a
		// run between MakeRunDir and its first line reads empty) keeps its directory, and one that
		// comes after fails its own flock or finds the directory gone, before run_start.
		lk, err := held.lockForRemoval(ref.ID)
		if errors.Is(err, os.ErrNotExist) {
			// A concurrent gc removed the run between List and here: retention got its outcome.
			rep.Deleted = append(rep.Deleted, ref.ID)
			return nil
		}
		if err != nil {
			return fmt.Errorf("ledger: lock run for removal: %w", err)
		}
		defer func() { _ = lk.Close() }()
		if err := sys.Flock(lk, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			if errors.Is(err, unix.EWOULDBLOCK) {
				rep.Kept = append(rep.Kept, ref.ID)
				return nil
			}
			return fmt.Errorf("ledger: lock run for removal: %w", err)
		}
		if err := removeAllAt(held.rootDir, ref.ID, held.dir(ref.ID)); err != nil {
			return fmt.Errorf("ledger: remove run: %w", err)
		}
	}
	rep.Deleted = append(rep.Deleted, ref.ID)
	return nil
}

// lockForRemoval opens run id's lock file for gc's removal, creating it when it is missing, with a link
// refused at both steps; os.ErrNotExist when the run directory is gone.
func (r *fsRunRepository) lockForRemoval(id string) (*os.File, error) {
	d, err := r.openRun(id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	path := filepath.Join(r.dir(id), LockFile)
	fd, err := d.Openat(LockFile, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f, err := fd.Release(path)
	if err != nil {
		_ = fd.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return f, nil
}

// removeAllAt removes name and everything under it from the directory open at at, as os.RemoveAll does, with
// every step an *at() call that follows no link: a link is removed, never what it names, and a directory is
// entered only through a descriptor of its own, so a rename above it during the removal moves nothing it
// deletes outside the run. A name already gone is no error. path is what an error names.
func removeAllAt(at *sys.FD, name, path string) error {
	err := unlinkAt(at, name)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.EISDIR) {
		return &os.PathError{Op: "unlinkat", Path: path, Err: err}
	}
	removeAllAtOpenHook(path)
	d, err := at.Openat(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	names, err := readDirNames(d, path)
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, n := range names {
		if err := removeAllAt(d, n, filepath.Join(path, n)); err != nil {
			errs = append(errs, err)
		}
	}
	_ = d.Close()
	if err := rmdirAt(at, name); err != nil && !errors.Is(err, unix.ENOENT) {
		errs = append(errs, &os.PathError{Op: "unlinkat", Path: path, Err: err})
	}
	return errors.Join(errs...)
}

// removeAllAtOpenHook runs between removeAllAt's unlinkat that answered EISDIR and its open of the directory: a
// test swaps the directory for a link there.
var removeAllAtOpenHook = func(string) {}

// rmdirAt is unlinkat(2) of the directory name in the directory open at at.
func rmdirAt(at *sys.FD, name string) error {
	return at.Borrow(func(n int) error { return unix.Unlinkat(n, name, unix.AT_REMOVEDIR) })
}

// sameRoot refuses deletion when the configured path no longer names the held root. Decisions already
// use the held root; this check additionally avoids deleting from a directory the operator moved away.
func sameRoot(held *sys.FD, root string) error {
	var hst, nst unix.Stat_t
	if err := held.Fstat(&hst); err != nil {
		return fmt.Errorf("ledger: stat the ledger root gc holds: %w", err)
	}
	if err := unix.Stat(root, &nst); err != nil {
		return fmt.Errorf("ledger: ledger root %s: %w; nothing removed", root, &os.PathError{Op: "stat", Path: root, Err: err})
	}
	if hst.Dev != nst.Dev || hst.Ino != nst.Ino {
		return fmt.Errorf("ledger: ledger root %s no longer names the directory gc opened; nothing removed", root)
	}
	return nil
}

// sweep ends a lost run: lock, hook, run_end{orphaned}, Close. Open resumes the chain and discards a torn
// tail; a run whose ledger lost its run_start cannot be ended and is left for retention. It reports whether
// this pass ended the run.
//
// The lock comes before the hook, so of sweepers racing for one orphan exactly one kills its tree and ends it:
// the others fail the lock, read the run as not theirs to end, and move on without killing or counting it
// (runtime-launch.md §6 case 10, R12). With the hook first, every racer killed the tree, and every racer that
// lost the lock afterwards still reported the run as swept.
//
// A run whose agent its first line does not give (a line that does not decode) takes the agent its contract
// copy names, as a run that died before run_start does (sweepEmpty); with neither, the sweep is an error. It
// returned nil there, so GC counted the run as swept while nothing had killed its tree or ended it.
func sweep(ctx context.Context, repo RunRepository, ref record.RunRef, o *gcOptions) (bool, error) {
	if ref.Agent == "" {
		if fs, ok := repo.(*fsRunRepository); ok {
			ref.Agent = fs.agentOfContract(ref.ID)
		}
	}
	if ref.Agent == "" {
		return false, fmt.Errorf("ledger: run %s: lost, and neither its ledger nor its contract copy names its agent; not swept", ref.ID)
	}
	w, err := repo.Lock(ctx, ref.ID, ref)
	// A probe (status, stop, a reaper) holds the lock for an instant; a real sweeper holds it far longer.
	for deadline := time.Now().Add(freshLockWait); errors.Is(err, ErrRunLocked) && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
		w, err = repo.Lock(ctx, ref.ID, ref)
	}
	if err != nil {
		if errors.Is(err, ErrRunEnded) {
			// Ended between State and Lock, unless the ledger still reads lost: then a line follows run_end
			// (resume refuses it), the run can never be ended, and it is reported so that it ages out.
			if st, serr := repo.State(ctx, ref.ID); serr != nil || st == StateEnded || st == StateRunning {
				return false, nil
			}
		} else if errors.Is(err, ErrRunLocked) || errors.Is(err, os.ErrNotExist) {
			return false, nil // became live, removed, or another sweeper holds it, between State and Lock
		}
		// The ledger cannot be ended (a damaged line before an intact last one, which resume refuses), but the
		// lock was free, so the dead launcher's tree may still be alive: it is killed all the same. No Writer
		// holds the directory here, so the hook is lent the run's name opened again (lendRun).
		if o.sweep != nil {
			if herr := o.lendRun(ref.ID, func(dir sys.Lender) error { return o.sweep(ctx, dir, ref) }); herr != nil {
				return false, fmt.Errorf("%w: %w", errSweepHook, errors.Join(herr, err))
			}
		}
		return false, err
	}
	o.lockedRun(ref.ID)
	if o.sweep != nil {
		// The hook is lent the directory the Writer locked and will end, not the run's name opened again: a
		// directory renamed over the name since the lock would feed every orphan check of the hook while
		// run_end went into the locked run.
		if err := lendDir(w.dirFD, w.dir, func(dir sys.Lender) error { return o.sweep(ctx, dir, ref) }); err != nil {
			// Nothing is written: the run stays lost for the next pass, which kills again.
			if aerr := w.Abandon(); aerr != nil {
				err = errors.Join(err, aerr)
			}
			return false, fmt.Errorf("%w: %w", errSweepHook, err)
		}
	}
	// The launcher died without a terminal result. This is its logical failure
	// code, not a recovered wait status for the agent or the sweeping process.
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned, ExitCode: identity.ExitLauncher}); err != nil {
		return false, err
	}
	return true, nil
}

// sweepEmpty runs the sweep hook for a run whose launcher died before run_start, the lock free and no line
// written: its cgroup may already exist and hold nothing, which nothing else ever removed (3 of
// 40 random launcher kills left an empty ledger and a scope behind). The agent, and so the cgroup's path, comes
// from the contract copy Open wrote; with none there was no cgroup yet. The ledger is left for retention: a run
// that never started has nothing to end. busy reports a lock still held after freshLockWait, so the run was not
// looked at: a caller with an index entry for it keeps the entry rather than drop the scope unswept.
func sweepEmpty(ctx context.Context, fs *fsRunRepository, ref record.RunRef, o *gcOptions) (busy bool, err error) {
	if o.sweep == nil {
		return false, nil
	}
	// The lock comes before the hook, as in sweep: a launcher between MakeRunDir and its first line reads empty
	// too, and killing its scope would kill a live run. A held lock, or a missing lock file (the launcher has not
	// opened yet, so no contract copy and no cgroup), leaves nothing to sweep.
	// A probe (status, stop, a reaper) holds it for an instant, so a held lock is retried as sweep does.
	// The run's directory is opened once: the lock, the emptiness check, the contract copy and the hook's lent
	// directory all come from it (sweep).
	d, err := fs.openRun(ref.ID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // removed since List: no lock, no contract copy, nothing to sweep
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = d.Close() }()
	dir := fs.dir(ref.ID)
	held, unlock, err := tryLockAt(d, dir)
	for deadline := time.Now().Add(freshLockWait); err == nil && held && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
		held, unlock, err = tryLockAt(d, dir)
	}
	if err != nil {
		return false, err
	}
	if held {
		return true, nil
	}
	if unlock == nil {
		return false, nil
	}
	defer unlock()
	o.lockedRun(ref.ID)
	// Under the lock, the run must still be empty: nobody has written a line since State read it.
	// (State itself would read our own lock as a live Writer's.)
	if rd, err := OpenReaderAt(d, dir); err == nil {
		st, serr := rd.f.Stat()
		present := false
		if serr == nil {
			_, present, serr = lastLine(rd.f, st.Size())
		}
		_ = rd.Close()
		if serr != nil || present {
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if ref.Agent == "" {
		ref.Agent = contractAgent(openRegularAt(d, ContractFile, filepath.Join(dir, ContractFile)))
	}
	if ref.Agent == "" {
		return false, nil
	}
	if err := lendDir(d, dir, func(lent sys.Lender) error { return o.sweep(ctx, lent, ref) }); err != nil {
		return false, fmt.Errorf("%w: %w", errSweepHook, err)
	}
	return false, nil
}

// errSweepHook is a sweep whose hook failed: the orphan's tree may still be alive (its cgroup could not be
// killed), so the run is kept whatever its age, unlike a run whose own ledger cannot be swept.
var errSweepHook = errors.New("ledger: sweep hook")

// runTime is when run id of repo started for retention purposes: the run id's time36 (R16), else the last
// event's ts (R7 caveat), else the directory's mtime.
func runTime(repo *fsRunRepository, id string) time.Time {
	if t, ok := timeFromRunID(id); ok {
		return t
	}
	if rd, err := repo.reader(id); err == nil {
		defer func() { _ = rd.Close() }()
		// Only the last complete line's ts is wanted: a tail read, as State does, not a decode of the whole
		// ledger on every pass.
		if st, err := rd.f.Stat(); err == nil {
			if line, present, err := lastLine(rd.f, st.Size()); err == nil && present {
				if e, err := record.Decode(line); err == nil && !e.TS.IsZero() {
					return e.TS
				}
			}
		}
	}
	var st unix.Stat_t
	var err error
	if repo.rootDir != nil {
		err = repo.rootDir.Fstatat(id, &st, unix.AT_SYMLINK_NOFOLLOW)
	} else {
		err = unix.Stat(repo.dir(id), &st)
	}
	if err == nil {
		return time.Unix(st.Mtim.Unix())
	}
	return time.Time{}
}

// timeFromRunID parses the 13-character base36 UnixNano field of r-<host8>-<time36>-<rand6>.
func timeFromRunID(id string) (time.Time, bool) {
	parts := strings.Split(id, "-")
	if len(parts) != 4 {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(parts[2], 36, 64)
	if err != nil || ns <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, ns).UTC(), true
}

// note records err for the run, joined with any error the pass already recorded for it, so a run that could not
// be read and then could not be removed reports both.
func (r *Report) note(id string, err error) {
	if prev := r.Errors[id]; prev != nil {
		err = errors.Join(prev, err)
	}
	r.Errors[id] = err
}
