// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// KeepForever is the retention of a Sweep that ends orphans but never deletes a run directory, which
// is `gc`'s job alone (docs/p0/runtime-launch.md §5 R20). `run` and `stop` call SweepLive, which never
// deletes one either.
const KeepForever = time.Duration(math.MaxInt64)

// sweepKillTimeout bounds the wait for a killed orphan's cgroup to empty before the pass gives up
// and leaves the removal to the next one (case 9): a task in uninterruptible sleep must never make
// `tego run` hang on startup.
const sweepKillTimeout = 5 * time.Second

// SweepResult is what one pass over a ledger root did.
type SweepResult struct {
	// Scanned is the number of run directories the pass looked at.
	Scanned int
	// Orphaned is the number of runs that were lost (lock free, no run_end) and have now been
	// ended with run_end reason=orphaned.
	Orphaned int
	// Deleted is the number of run directories removed by retention; always 0 for KeepForever.
	Deleted int
	// Removed are the ids of those run directories, or, with WithSweepDryRun, of the ones the pass would remove: a
	// dry run of gc counts what the rule-change journal's prune would leave once they are gone.
	Removed []string
	// Errs holds one error per run the pass could not finish, plus any per-run cgroup failure. A
	// non-empty Errs never means the pass stopped: one run's failure never blocks the others.
	Errs []error
}

// sweepOptions configure Sweep.
type sweepOptions struct {
	manager cgroup.Manager
	log     *slog.Logger
	now     func() time.Time
	dryRun  bool
	anchor  string  // WithSweepAnchor: the sweeper's own anchor; "" leaves the ledger's default
	marks   markDir // WithSweepRootMarks: the root launch records consulted; rootMarkDir by default
}

// SweepOption configures Sweep.
type SweepOption func(*sweepOptions)

// WithSweepLogger routes the pass's operational detail to the product's own log.
func WithSweepLogger(l *slog.Logger) SweepOption { return func(o *sweepOptions) { o.log = l } }

// WithSweepDryRun reports what the pass would do without writing or removing anything.
func WithSweepDryRun(dry bool) SweepOption { return func(o *sweepOptions) { o.dryRun = dry } }

// Sweep ends every orphaned run under root and applies retention keep (P0-DESIGN §4.6,
// docs/p0/runtime-launch.md §5 R12, R20). It is `gc`'s pass over every run directory, and the one
// recovery path for a launcher that died without writing run_end that does not depend on the live
// index: `run` and `stop` call SweepLive, and all three run with no coordination between them — the
// per-run flock(LOCK_EX|LOCK_NB) probe inside ledger.GC is the entire serialization mechanism, and it
// refuses the sweeper's own live run too because flock(2) is per open file description (R1, R12,
// cases 10-11).
//
// A lost run is killed first (its cgroup may still hold a process tree the dead launcher left
// behind, P0-DESIGN §4.6) and then closed with run_end reason=orphaned by the ledger's sweep hook.
// Pass KeepForever as keep to sweep without deleting anything.
func Sweep(ctx context.Context, root string, keep time.Duration, opts ...SweepOption) (SweepResult, error) {
	return sweepWith(ctx, root, opts, func(o sweepOptions, gc []ledger.GCOption) (ledger.Report, error) {
		return ledger.GC(ctx, root, keep, o.dryRun, gc...)
	})
}

// SweepLive is the sweep `run` and `stop` make before they act (R20): it ends the orphans among the
// runs the ledger root's live index names, killing what each left behind first as Sweep does, and
// deletes nothing (ledger.SweepLive). Its cost is the runs alive or lost, not every run the root has
// kept: a pass over the whole root was about 73 µs per stored run on every `tego run`. A root with no
// index yet gets Sweep's full pass with KeepForever. WithSweepDryRun does not apply: a dry run is gc's.
func SweepLive(ctx context.Context, root string, opts ...SweepOption) (SweepResult, error) {
	return sweepWith(ctx, root, append(opts[:len(opts):len(opts)], WithSweepDryRun(false)),
		func(_ sweepOptions, gc []ledger.GCOption) (ledger.Report, error) {
			return ledger.SweepLive(ctx, root, gc...)
		})
}

// sweepWith is Sweep and SweepLive around the ledger pass each makes: the cgroup manager that kills an
// orphan's tree, the hook that does it, and the writer options that end the run.
func sweepWith(ctx context.Context, root string, opts []SweepOption,
	pass func(sweepOptions, []ledger.GCOption) (ledger.Report, error)) (SweepResult, error) {
	o := sweepOptions{now: time.Now, log: slog.New(slog.DiscardHandler), marks: rootMarkDir}
	for _, opt := range opts {
		opt(&o)
	}
	var res SweepResult
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return res, nil // no run has ever been recorded here: nothing to sweep
	}
	if o.manager == nil && !o.dryRun {
		uid, _ := config.InvokingUID()
		m, err := detectCgroups(uid)
		if err != nil {
			res.Errs = append(res.Errs, fmt.Errorf("sweep: no cgroup manager, orphan trees are left running: %w", err))
		} else {
			o.manager = m
		}
	}
	// Each hook is lent the run's directory, opened under the ledger root the pass holds; every check below looks
	// the run up under it (runDir), and root names it in messages.
	lent := func(dir sys.Lender, ref record.RunRef) runDir {
		return runDir{path: filepath.Join(root, ref.ID), at: dir}
	}
	rep, err := pass(o, []ledger.GCOption{
		ledger.WithNow(o.now),
		// Another host's run is left alone entirely: not only its kill and reclaim, below, but its run_end
		// and its anchor repair, and its live-index entry stays (case 28).
		ledger.WithForeignRun(func(id string) bool { return foreignRun(id) }),
		ledger.WithSweepHook(func(ctx context.Context, dir sys.Lender, ref record.RunRef) error {
			if foreignRun(ref.ID) {
				// A run another host minted (a ledger root shared between machines): its scope, if any, is in
				// that host's cgroup tree, and a same-named scope here is not its (case 28).
				return nil
			}
			if o.manager == nil && !o.dryRun {
				// No way to kill the tree, so nothing here knows it is gone: the run stays lost until a
				// sweeper that can place cgroups meets it (R20), as reclaimHeld and endedListed also leave it.
				return fmt.Errorf("orphan %s: %w: no cgroup manager", ref.ID, errOrphanAlive)
			}
			if err := killOrphan(ctx, o, lent(dir, ref), ref); err != nil {
				o.log.Warn("sweep: kill orphan cgroup", "run", ref.ID, "err", err)
				// A tree still running keeps the run lost, so the next pass meets it again: run_end
				// over a live tree ended the one record that something ran unsupervised, and nothing
				// revisited it (R20). Any other failure, a scope that
				// cannot even be read, still ends the run, as before.
				if errors.Is(err, errOrphanAlive) {
					return err
				}
			}
			return nil
		}),
		ledger.WithReclaimHook(func(ctx context.Context, dir sys.Lender, ref record.RunRef) bool {
			return reclaimHeld(ctx, o, lent(dir, ref), ref)
		}),
		ledger.WithEndedHook(func(ctx context.Context, dir sys.Lender, ref record.RunRef) (bool, error) {
			return endedListed(ctx, o, lent(dir, ref), ref)
		}),
		ledger.WithBoundWriterOptions(func(held sys.Lender) []ledger.Option {
			return sweepWriterOptions(o, root, held)
		}),
	})
	res.Scanned = countRuns(rep)
	res.Orphaned = len(rep.Swept)
	res.Deleted, res.Removed = len(rep.Deleted), rep.Deleted
	for id, e := range rep.Errors {
		res.Errs = append(res.Errs, fmt.Errorf("sweep: run %s: %w", id, e))
	}
	if err != nil {
		return res, fmt.Errorf("sweep %s: %w", root, err)
	}
	return res, nil
}

// sweepWriterOptions are the options of the writer that ends an orphan under root: the pass's logger,
// and, when the caller named its own anchor, the anchor each orphan's own launcher would have used
// (sweepAnchor), so a swept run's head lands in the chain.log its owner's `events --verify` reads.
// Ownership comes from bound, the held root the pass lends; root remains the configured no-home fallback
// location.
func sweepWriterOptions(o sweepOptions, root string, bound sys.Lender) []ledger.Option {
	opts := []ledger.Option{ledger.WithLogger(o.log)}
	if o.anchor != "" {
		opts = append(opts, ledger.WithAnchor(newSweepAnchor(root, o.anchor).boundTo(bound)))
	}
	return opts
}

// countRuns counts the distinct run ids a GC report mentions: a swept run is also either kept or
// deleted, so the three lists overlap.
func countRuns(rep ledger.Report) int {
	seen := make(map[string]struct{}, len(rep.Kept)+len(rep.Deleted)+len(rep.Swept))
	for _, list := range [][]string{rep.Kept, rep.Deleted, rep.Swept} {
		for _, id := range list {
			seen[id] = struct{}{}
		}
	}
	return len(seen)
}

// reclaimHeld frees the lock of a run whose launcher is gone (R20). The lock is the
// liveness signal, and it was the only one: a process of the run that opened the lock file (a read is enough
// to flock) and locked it after its launcher died kept the run from ever being swept, and `tego stop` called
// it not running. The launcher that holds a run's lock records its pid and start time in the lock file
// (WriteLockInfo); when that process no longer exists, whatever holds the lock is not a launcher. The run's
// tree is killed as an orphan's is, which ends the holder with it, and the lock is then free for the sweep to
// take. A lock with no launcher recorded (a run in the instant between its lock and its lock line), a launcher
// that is alive, a sweep with no cgroup manager, and a kill that fails all leave the run running. A holder
// outside the run's cgroup survives the kill and keeps the run; clone3 is refused so no process of the run can
// start one there.
//
// The lock line's pid is a pid of the host that minted the run: a run of another host (a ledger root shared
// between machines) is never reclaimed, since whatever process has that pid here is not its launcher, and its
// scope is not in this host's cgroup tree (case 28).
func reclaimHeld(ctx context.Context, o sweepOptions, dir runDir, ref record.RunRef) bool {
	if foreignRun(ref.ID) {
		return false
	}
	held, info, err := probeLock(dir)
	switch {
	case err != nil:
		return false
	case !held:
		return true // freed since State read it: read the state again
	case info.PID == 0 || o.manager == nil:
		return false
	}
	target, err := openStopTarget(dir, info)
	if err == nil {
		_ = target.Close()
		return false // the launcher is alive: the run is running
	}
	if !errors.Is(err, ErrStale) {
		return false
	}
	o.log.Warn("sweep: a run's lock is held with its launcher gone; killing the run's tree", "run", ref.ID,
		"launcher", info.PID)
	if err := killOrphan(ctx, o, dir, ref); err != nil {
		o.log.Warn("sweep: kill the holder of a dead launcher's lock", "run", ref.ID, "err", err)
		return false
	}
	wait, cancel := context.WithTimeout(ctx, sweepKillTimeout)
	defer cancel()
	for {
		if held, _, err := probeLock(dir); err == nil && !held {
			return true
		}
		select {
		case <-wait.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// endedListed is the ended hook of SweepLive (ledger.WithEndedHook): a run that ended while the live index still
// lists it. Its launcher is still between Close and clearing the entry, or died there. A launcher that is
// alive — the lock line's pid, with its start time — is left to finish: the entry stays,
// and it clears the entry itself. One that is gone may have left its scope, since the launcher removes it after
// Close (releaseKernelState): the scope is found as an orphan's is (orphanScope), killed if anything is left in
// it and removed, and that is logged. A tree that stays keeps the entry, as for a lost run.
//
// At tier 2 the dead launcher's Detach never ran either. Its cgroup links are pinned under the build's
// links/run-<id> (ADR 0020 (1)), and once the scope is removed killOrphan purges them with the run-set rows of
// vanished cgroups and the verdict rows of dead launchers' slots (purgeOrphan), which is what the run's reaper does
// when it outlives its launcher. If it was the last launcher of its build, the shared pins stay until the build's
// timer, a reaper or gc removes them (ADR 0022). A run of another host is left alone (L5).
func endedListed(ctx context.Context, o sweepOptions, dir runDir, ref record.RunRef) (bool, error) {
	if foreignRun(ref.ID) || o.manager == nil {
		return true, nil
	}
	if _, info, err := probeLock(dir); err == nil && info.PID != 0 {
		target, err := openStopTarget(dir, info)
		if err == nil {
			_ = target.Close()
			return false, nil // the launcher is alive: it clears the entry once it is done
		}
		if !errors.Is(err, ErrStale) {
			return false, nil // its liveness cannot be read: the next sweep asks again
		}
	}
	agentID, err := identity.ParseAgentID(ref.Agent)
	if err != nil {
		return false, fmt.Errorf("ended run %s: %w", ref.ID, err)
	}
	if _, ok := orphanScope(o.manager, o.marks, dir, ref, agentID); !ok {
		return true, nil
	}
	o.log.Warn("sweep: removing the scope of an ended run whose launcher died before it cleaned up; "+
		"at tier 2 its handle was never detached", "run", ref.ID)
	if err := killOrphan(ctx, o, dir, ref); err != nil {
		if errors.Is(err, errOrphanAlive) {
			return false, err
		}
		o.log.Warn("sweep: remove an ended run's scope", "run", ref.ID, "err", err)
	}
	return true, nil
}

// localHost8 is this host's host8, the one its runs are minted with (hostID with no machine id override).
var localHost8 = sync.OnceValue(func() string {
	h := hostID(nil)
	return hex.EncodeToString(h[:4])
})

// foreignRun reports whether run id was minted on another host: its host8 is not this host's. A variable so
// the unit tests' runs, minted with host8 00000000, read as this host's.
var foreignRun = func(id string) bool {
	h := identity.RunID(id).Host8()
	return h != "" && h != localHost8()
}

// detectCgroups is cgroup.Detect; a test replaces it to make the sweeping process one that has no cgroup manager.
var detectCgroups = cgroup.Detect

// errOrphanAlive is a sweep that could not end an orphan's process tree: the kill was refused, or the tree
// did not empty within sweepKillTimeout. The ledger's sweep then keeps the run lost (its hook failed), so the
// next pass meets it again.
var errOrphanAlive = errors.New("the orphan's process tree is still running")

// killOrphan ends the process tree a dead launcher left in a run's cgroup: cgroup.kill, wait for
// cgroup.events to report populated 0, then remove the scope bottom-up. A cgroup that is already
// gone or already empty is not an error; a scope that stays busy past sweepKillTimeout, or whose kill
// is refused, is errOrphanAlive and left for the next pass (case 9). Nothing here writes the ledger —
// ledger.GC's sweep does that after.
func killOrphan(ctx context.Context, o sweepOptions, dir runDir, ref record.RunRef) error {
	m, marks := o.manager, o.marks
	if m == nil {
		return nil
	}
	if adoption, err := sweepAdoption(ctx, o, dir, ref); adoption {
		// An adoption's agent is never killed: released from its record, or the run stays lost (sweep_adopt.go).
		return err
	}
	agentID, err := identity.ParseAgentID(ref.Agent)
	if err != nil {
		return fmt.Errorf("orphan %s: %w", ref.ID, err)
	}
	c, ok := orphanScope(m, marks, dir, ref, agentID)
	if !ok {
		purgeOrphan(o, dir, ref, marks.launched(dir)) // no scope of the run's is left
		return nil
	}
	populated, err := cgroup.Populated(c)
	if err != nil {
		return fmt.Errorf("orphan %s: read cgroup.events: %w", ref.ID, err)
	}
	if populated {
		if err := m.Kill(c); err != nil {
			return fmt.Errorf("orphan %s: %w: %w", ref.ID, errOrphanAlive, err)
		}
		wait, cancel := context.WithTimeout(ctx, sweepKillTimeout)
		defer cancel()
		if err := m.WaitEmpty(wait, c); err != nil {
			return fmt.Errorf("orphan %s: %w: wait empty: %w", ref.ID, errOrphanAlive, err)
		}
	}
	if err := m.Remove(ctx, c); err != nil {
		if errors.Is(err, cgroup.ErrBusy) {
			// The tree is gone but the scope will not go: left for the next pass, with the run still lost
			// (runtime-launch.md case 9), not ended with its scope leaked and nothing listing it again.
			return fmt.Errorf("orphan %s: %w: remove cgroup: %w", ref.ID, errOrphanAlive, err)
		}
		return fmt.Errorf("orphan %s: remove cgroup: %w", ref.ID, err)
	}
	// The root launcher's record of this run goes with its scope, and only when it names this very directory:
	// a planted directory of the same id must not remove another run's record (rootmark.go). The purge below
	// is decided on that record, read before it goes.
	rootLaunched := marks.launched(dir)
	if rootLaunched {
		marks.remove(ref.ID)
	}
	purgeOrphan(o, dir, ref, rootLaunched)
	return nil
}

// purgeOrphan removes what a run whose scope is gone left of its tier-2 kernel state, as its reaper would have
// (ADR 0020 (3), cgroupenforce.PurgeRun): a reaper killed with its launcher, or one that could not start, leaves
// it to the sweep. The build is run_start's bpf_hash, never this binary's own (ADR 0020 (6)), and PurgeRun keeps
// everything while a cgroup of the id run_start recorded exists. It needs root, and a run of a tier with no
// programs has no hash; either way there is nothing to do. A failure is logged, never the sweep's: the kernel
// state it leaves is the next Prepare's and gc's to reclaim, and none of it loosens anything.
//
// Only for a run root's own record says root launched (rootLaunched, markDir.launched): the run id, hash and
// cgroup id are ledger data its owner writes, and a planted directory named after another user's live run,
// its run_start naming a cgroup id of 0 or one no cgroup has, would otherwise unpin that run's links with the
// alive check skipped or passed. A tier-2 run is launched by root, which records it.
func purgeOrphan(o sweepOptions, dir runDir, ref record.RunRef, rootLaunched bool) {
	if o.dryRun || sweeperUID() != 0 || !rootLaunched {
		return
	}
	start := runStartOf(dir)
	if start.hash == "" {
		return
	}
	if !cgroupenforce.IsBuildHash(start.hash) {
		// run_start is in a ledger its owner writes: a bpf_hash that is no build's name never becomes a path.
		o.log.Warn("sweep: the orphan's run_start names no build", "run", ref.ID, "bpf_hash", start.hash)
		return
	}
	res, err := purgeRun(cgroupenforce.PurgeOptions{Hash: start.hash, RunID: ref.ID, CgroupID: start.cgroup})
	if err != nil {
		o.log.Warn("sweep: purge the orphan's kernel state", "run", ref.ID, "err", err)
	}
	if res.Links || len(res.Slots) > 0 || res.Rings > 0 {
		o.log.Info("sweep: purged the orphan's kernel state", "run", ref.ID, "links", res.Links, "slots", res.Slots,
			"rings", res.Rings)
	}
}

// purgeRun is cgroupenforce.PurgeRun; a variable so the unit tests see what a sweep would purge.
var purgeRun = cgroupenforce.PurgeRun

// orphanScope finds the scope a lost run's launcher made: tego.slice/tego-<agent>.slice/run-<id>.scope
// under the root of the manager that made it, which need not be the sweeper's. A root launcher makes it
// under the cgroup2 mount root and an unprivileged one under its uid's user@<uid>.service, and a sweep by the
// other kind looked under its own root alone, found nothing, killed nothing and ended the run (R20). Every
// root the scope can be under is tried (orphanRoots). When run_start
// recorded the scope's cgroup id, a candidate is the run's only if its id is that one, so a scope of the same
// name made since is never touched; a ledger with no id (one that predates it, or a launcher that died
// before run_start) takes the first candidate that exists — *amended 2026-09-24:* but a candidate under the
// cgroup mount root only when root's record says root launched this very directory (markDir.launched).
func orphanScope(m cgroup.Manager, marks markDir, dir runDir, ref record.RunRef, agentID identity.AgentID) (cgroup.Cgroup, bool) {
	rel := filepath.Join(identity.TopSlice, identity.AgentSlice(agentID), identity.RunScope(identity.RunID(ref.ID)))
	want := runCgroupID(dir)
	for _, base := range orphanRoots(m, marks, dir) {
		c := cgroup.Cgroup{Path: filepath.Join(base, rel)}
		if _, err := os.Lstat(c.Path); err != nil {
			continue
		}
		if want != 0 {
			if id, err := m.ID(c); err != nil || id != want {
				continue
			}
		} else if base == cgroup.Mount && !marks.launched(dir) {
			// With no cgroup id to check, a scope of that name under the mount root is as likely another run's
			// as this one's: it is taken only on root's record that root launched this very directory.
			continue
		}
		return c, true
	}
	return cgroup.Cgroup{}, false
}

// RunScope finds the scope of run id, of agent, in the ledger root root the way a sweep finds an orphan's
// (orphanScope): under every root the scope can be under, the manager's own first, and, when run_start
// recorded the scope's cgroup id, only a candidate with that id. ok is false when no scope of the run's is
// left. `tego stop`'s backstop kill uses it: built under the stopper's own cgroup root with no id check, it
// wrote cgroup.kill into whatever scope of that name was there — none of the run's when a root launcher made it
// and the user stops it, and another run's when one of that name was made since (limits-check-doctor-cli.md R29).
//
// Of the sweep options only WithSweepRootMarks applies: the root launch records the search consults.
func RunScope(m cgroup.Manager, root, id, agent string, opts ...SweepOption) (cgroup.Cgroup, bool, error) {
	agentID, err := identity.ParseAgentID(agent)
	if err != nil {
		return cgroup.Cgroup{}, false, fmt.Errorf("run %s: %w", id, err)
	}
	o := sweepOptions{marks: rootMarkDir}
	for _, opt := range opts {
		opt(&o)
	}
	c, ok := orphanScope(m, o.marks, pathDir(filepath.Join(root, id)), record.RunRef{ID: id, Agent: agent}, agentID)
	return c, ok, nil
}

// orphanRoots are the roots a run's scope can be under, the sweeper's own first: the cgroup2 mount root, where
// a root launcher makes it, and the delegated subtree of the run directory's owner, which is the invoking
// user whichever launcher made the run (a root launcher hands the directory over). A variable so a test can
// root them in a temporary tree.
//
// Only for a run directory the sweeper owns, though. The run's id, agent and cgroup id are ledger data its
// owner can write, so a run directory the sweeper does not own names a scope under the mount root only when a
// record root alone writes says root launched that directory (markDir.launched); otherwise its scope is looked for
// in its owner's subtree alone. `sudo tego run` over a planted run directory named after another user's
// root-launched run, its run_start naming that run's scope, wrote cgroup.kill into it (R20).
//
// *Amended 2026-09-24:* nor, for a root sweeper, a run directory it owns. A root launcher killed between
// MakeRunDir and run_start leaves a root-owned directory in a ledger root its user owns; the user
// can rename it (a write on the ledger root, not on the directory) to another user's live root-launched run id,
// and with no run_start there is no cgroup id to check, so a root sweep took the first scope of that name under
// the mount root and killed the other run. A root sweeper (the uid records are owned by) searches the mount
// root only on a record naming that very directory, whoever owns it; every root launcher
// records its run, root's own included. On that record the manager's own root is searched too, as for any
// run the sweeper launched: a root launcher made the scope there, which is the mount root unless root runs
// inside a nested cgroup namespace (cgroup.Detect), and leaving it out lost a root stop's own run's scope.
var orphanRoots = func(m cgroup.Manager, marks markDir, dir runDir) []string {
	if uid, ok := dir.ownerUID(); !ok || uid != sweeperUID() || sweeperUID() == rootMarkOwner {
		var roots []string
		if ok && uid != 0 {
			roots = append(roots, cgroup.UserSubtree(uid))
		}
		if marks.launched(dir) {
			if sweeperUID() == rootMarkOwner && !slices.Contains(roots, m.Root()) {
				roots = append(roots, m.Root())
			}
			if !slices.Contains(roots, cgroup.Mount) {
				roots = append(roots, cgroup.Mount)
			}
		}
		return roots
	}
	roots := []string{m.Root()}
	add := func(r string) {
		if !slices.Contains(roots, r) {
			roots = append(roots, r)
		}
	}
	add(cgroup.Mount)
	if uid, ok := dir.ownerUID(); ok && uid != 0 {
		add(cgroup.UserSubtree(uid))
	}
	return roots
}

// runCgroupID is the cgroup id run_start recorded for the run in dir, 0 when it recorded none or cannot be
// read.
func runCgroupID(dir runDir) uint64 { return runStartOf(dir).cgroup }

// runStart is what a sweep reads of a run's run_start: its cgroup id and the build its programs live in.
type runStart struct {
	cgroup uint64
	hash   string
}

// runStartOf reads run_start of the run in dir; the zero value when it has none or cannot be read.
func runStartOf(dir runDir) runStart {
	rd, err := dir.reader()
	if err != nil {
		return runStart{}
	}
	defer func() { _ = rd.Close() }()
	for e, err := range rd.Iter() {
		if err != nil || e.Kind != record.KindRunStart {
			return runStart{}
		}
		out := runStart{cgroup: e.Cgroup}
		var p record.RunStartPayload
		if err := e.DecodePayload(&p); err == nil {
			out.hash = p.BPFHash
		}
		return out
	}
	return runStart{}
}
