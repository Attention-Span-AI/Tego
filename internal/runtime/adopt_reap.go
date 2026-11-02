// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An adoption's reaper (ADR 0055, as ADR 0020's reaper is a launched run's): `tego __adopt-reap
// <state dir> <run id>`, started before the move with the adopter's pidfd at descriptor 3 and the run directory at 4.
// It waits for the adopter to end. One that ended its adoption removed the adoption's record first, and the reaper
// exits. One that died left it, and the reaper does what the adopter would have: the agent's tree goes back where it
// came from (frozen while it moves, never signalled), run_end is written (reason orphaned), the scope is removed and
// the run's kernel state purged (cgroupenforce.PurgeRun, then the build's duties): killing the adopter leaves nothing
// attached, and never kills the agent. It acts only on the record root alone can write (adopt_state.go), never on the
// ledger's contents.

// AdoptReapCommand is the hidden first argument cmd/tego dispatches to AdoptReapMain.
const AdoptReapCommand = "__adopt-reap"

// The reaper's inherited descriptors.
const (
	adoptReapPidFD = 3
	adoptReapDirFD = 4
)

// startReaper starts the adoption's reaper, before the move, so no process is ever adopted without one. It runs
// before any Arm (the adopter places no fanotify mark: a record-only table has no rule a listener decides, and a
// boundary needs a plane mode, which marks nothing), so the start is never refused for an armed process.
func (a *adoption) startReaper() error {
	exe := a.deps.ReaperExe
	switch exe {
	case NoAdoptReaper:
		return nil
	case "":
		// Re-executed with AdoptReapCommand, a test binary would run its whole suite, detached: one adopts with no
		// reaper, as a test binary's run does (runner.reaperExe).
		if self, err := os.Executable(); err == nil && strings.HasSuffix(self, ".test") {
			return nil
		}
		exe = "/proc/self/exe"
	}
	if err := startAdoptReaperProcess(exe, a.store.dir, string(a.r.id), a.r.writer); err != nil {
		return fmt.Errorf("runtime: start the adoption's reaper, without which the adopter's death would leave the "+
			"agent in the run's cgroup with its programs attached: %w", err)
	}
	return nil
}

// startAdoptReaperProcess starts exe as run's adoption reaper, in tego's helper cgroup when this process can put it
// there (cgroup.StartHelper), in a session of its own, with this process's pidfd and the run directory, from w, as
// its only descriptors beyond /dev/null.
func startAdoptReaperProcess(exe, stateDir, run string, w *ledger.Writer) error {
	pfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open(self): %w", err)
	}
	pidfd := os.NewFile(uintptr(pfd), "adopter-pidfd")
	defer func() { _ = pidfd.Close() }()
	if w == nil {
		return errors.New("the run has no ledger writer")
	}
	dir, err := w.OpenDirPath()
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	_, err = cgroup.StartHelper(func(extra []string) *proc.Cmd {
		cmd := proc.Command(exe, AdoptReapCommand, stateDir, run)
		cmd.Dir = "/"
		cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, extra...)
		cmd.ExtraFiles = []*os.File{pidfd, dir}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		return cmd
	})
	return err
}

// AdoptReapMain is `tego __adopt-reap <state dir> <run id>`, the reaper of one adoption. It returns the process's
// exit code.
func AdoptReapMain(args []string) int {
	closeStrayFDs(adoptReapDirFD + 1)
	if len(args) != 2 || !ledger.IsRunID(args[1]) || !filepath.IsAbs(args[0]) {
		fmt.Fprintf(os.Stderr, "tego %s: want <state dir> <run id>\n", AdoptReapCommand)
		return identity.ExitUsage
	}
	_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("run", args[1])
	if err := waitPidfd(adoptReapPidFD); err != nil {
		log.Error("adopt-reap: wait for the adopter", "err", err)
		return identity.ExitError
	}
	_ = unix.Close(adoptReapPidFD)
	defer func() { _ = unix.Close(adoptReapDirFD) }()
	store := &adoptStore{dir: args[0]}
	rec, err := store.read(args[1])
	if errors.Is(err, os.ErrNotExist) {
		return identity.ExitOK // the adopter ended its adoption itself
	}
	if err != nil {
		log.Error("adopt-reap: the adoption's record", "err", err)
		return identity.ExitError
	}
	if _, _, err := releaseHeld(context.Background(), store, rec, adoptReapDirFD, "the adopter died", log); err != nil {
		log.Error("adopt-reap", "err", err)
		return identity.ExitError
	}
	return identity.ExitOK
}

// releaseHeld is releaseOrphan under the adopted process's lock, so a reaper and `tego adopt --release` never
// release one adoption at once: the lock is taken (waiting for the other while it works), the record read again, and
// the adoption released only when the record is still there. ended false says it was gone: someone else released it.
func releaseHeld(ctx context.Context, store *adoptStore, rec adoptRecord, dirfd int, why string, log *slog.Logger) (OrphanRelease, bool, error) {
	lock, err := store.claimWait(ctx, rec.Root, releaseWait)
	if err != nil {
		return OrphanRelease{}, false, fmt.Errorf("take the adoption's lock: %w", err)
	}
	rec, err = store.read(rec.Run)
	if errors.Is(err, os.ErrNotExist) {
		store.unclaim(lock, rec.Root)
		return OrphanRelease{}, false, nil
	}
	if err != nil {
		_ = lock.Close()
		return OrphanRelease{}, false, err
	}
	out, err := releaseOrphan(store, rec, adoptReleaseEnv(), dirfd, why, log)
	_ = lock.Close() // releaseOrphan removed its file with the record, or kept both for the next release
	return out, true, err
}

// OrphanRelease is what releaseOrphan did.
type OrphanRelease struct {
	Released adopt.ReleaseResult
	// Ended says run_end was written here; Removed the scope removed; Purged the run's kernel state purged.
	Ended, Removed, Purged bool
}

// adoptReleaseEnv is the /proc and cgroup filesystem a release acts on: the system's. A variable so a test can release
// over a fake.
var adoptReleaseEnv = func() adopt.Env {
	return adopt.Env{Proc: adopt.NewFS(""), FS: adopt.Cgroups{}, Live: adopt.Pidfds{}}
}

// releaseOrphan ends an adoption whose adopter is gone, from its record: the tree released, run_end (orphaned, why)
// written through dirfd (by the record's path when dirfd is negative) when the run has started and not ended, the
// scope removed once empty, the kernel state purged, the record and the process's lock file removed, the live index
// entry cleared. It makes nothing where the run's ledger is: a run directory, or a file of it, that is missing is a
// run being removed, with no run_end to write.
func releaseOrphan(store *adoptStore, rec adoptRecord, env adopt.Env, dirfd int, why string, log *slog.Logger) (OrphanRelease, error) {
	var out OrphanRelease
	env.Mount = rec.Mount
	out.Released = adopt.Release(env, rec.Scope, adopt.ReleaseTargets(rec.Mount, rec.From))
	var errs []error
	ref := record.RunRef{ID: rec.Run, Agent: rec.Agent}
	// The adopter's Writer made every file before the record was written, so a release makes none. The reaper wakes as
	// its adopter exits, and a run that ended with a process left in its scope keeps its record, which a release can
	// meet long after retention removed the run: a file made there leaves `tego gc`'s or a test's RemoveAll with a
	// directory that is not empty, and its empty ledger reads as a run never started. By path, the run directory and
	// the ledger root are not made either.
	opts := []ledger.Option{ledger.WithLogger(log), ledger.WithExistingFiles()}
	if rec.Anchor != "" {
		opts = append(opts, ledger.WithAnchor(ledger.NewFileChainAnchor(rec.Anchor)))
	}
	var w *ledger.Writer
	var err error
	switch {
	case rec.Unstarted:
		err = ledger.ErrRunEnded // the adoption failed before run_start and its run directory went: no run to end
	case dirfd >= 0:
		w, err = openLedgerAt(dirfd, rec.Dir, ref, opts...)
	default:
		w, err = ledger.Open(rec.Dir, ref, append(opts, ledger.WithExistingRunDir())...)
	}
	switch {
	case err == nil && w.Seq() == 0:
		_ = w.Abandon() // the adopter died before run_start: a run that never started, for the sweep to remove
	case err == nil:
		detail := why + "; released, never killed: " + describeRelease(out.Released, rec)
		if cerr := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned, Detail: record.CutDetail(detail)}); cerr != nil {
			errs = append(errs, fmt.Errorf("run_end: %w", cerr))
		} else {
			out.Ended = true
		}
	case errors.Is(err, ledger.ErrRunEnded), errors.Is(err, os.ErrNotExist):
		// Ended, or being removed: no run to end.
	default:
		errs = append(errs, fmt.Errorf("the run's ledger: %w", err))
	}
	errs = append(errs, finishOrphan(store, rec, &out)...)
	if out.Removed && out.Ended {
		_ = ledger.ClearLive(filepath.Dir(rec.Dir), rec.Run)
	}
	return out, errors.Join(errs...)
}

// finishOrphan is what follows a released orphan's run_end: the scope removed once nothing is left in it, the run's
// kernel state purged and the build's duties done, the record and the process's lock file removed. A scope a process
// stays in keeps the record, so a later release (or sweep) can try again.
func finishOrphan(store *adoptStore, rec adoptRecord, out *OrphanRelease) []error {
	var errs []error
	if len(out.Released.Left) == 0 {
		fs, err := cgroup.NewAt(rec.Mount)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), killTimeout)
			err = fs.Remove(ctx, cgroup.Cgroup{Path: rec.Scope})
			cancel()
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", rec.Scope, err))
		} else {
			out.Removed = true
		}
	}
	if out.Removed && rec.Target != nil && rec.Target.Hash != "" {
		_, perr := cgroupenforce.PurgeRun(cgroupenforce.PurgeOptions{BPFFS: rec.Target.BPFFS, StateDir: rec.Target.StateDir,
			CgroupMount: rec.Mount, Hash: rec.Target.Hash, RunID: rec.Run, CgroupID: rec.ScopeID})
		if perr != nil {
			errs = append(errs, fmt.Errorf("purge the run's kernel state: %w", perr))
		} else {
			out.Purged = true
			if berr := reapBuild(*rec.Target, rec.Mount, nil); berr != nil {
				errs = append(errs, fmt.Errorf("the build's duties: %w", berr))
			}
		}
	}
	if out.Removed {
		store.remove(rec.Run)
		if dfd, err := store.open(); err == nil {
			_ = unix.Unlinkat(dfd, targetName(rec.Root), 0)
			_ = unix.Close(dfd)
		}
	}
	return errs
}

// describeRelease is a release's one sentence for run_end.
func describeRelease(res adopt.ReleaseResult, rec adoptRecord) string {
	var parts []string
	for to, pids := range res.To {
		parts = append(parts, fmt.Sprintf("%d process(es) to %s", len(pids), strings.TrimPrefix(to, rec.Mount)))
	}
	if len(res.Left) > 0 {
		parts = append(parts, fmt.Sprintf("%d left in %s", len(res.Left), rec.Scope))
	}
	if len(parts) == 0 {
		return "no process was left in the run's cgroup"
	}
	return strings.Join(parts, "; ")
}

// ReleaseReport is what ReleaseAdoption did.
type ReleaseReport struct {
	Run string
	// Adopter is the live adopter that released its agent at the request (0 when none was alive); Reaper says the
	// adopter was gone and its reaper (or another release) ended the adoption meanwhile; Orphan is what was done here
	// in the adopter's place.
	Adopter int
	Reaper  bool
	Orphan  *OrphanRelease
	// Again says the run had ended already, with processes left in its scope that this release moved out (Orphan);
	// Unstarted that the adoption had failed before run_start, leaving them there.
	Again, Unstarted bool
	// Left is how many processes the live adopter's release left in the scope (Adopter set, and an error saying they
	// stay): the adoption has ended, its record kept for a later release.
	Left int
}

// ErrNotAdopted is a process no adoption holds.
var ErrNotAdopted = errors.New("runtime: the process is in no adoption")

// AdoptionOf is the run whose adoption holds pid: the process's cgroup (its live threads', adopt.CgroupOf, for one
// whose leader exited too) is exactly an adoption's scope, /tego.slice/tego-<agent>.slice/adopt-<run id>.scope at the
// cgroup2 root (runscope.AdoptionScopeRun), and that run's record in stateDir ("" is the host's) names that scope. A
// cgroup a user made with an adoption's name in their own subtree, or a launched run's scope (that run is `tego
// stop`'s), is ErrNotAdopted: a release by pid never ends an adoption the process is not in.
func AdoptionOf(p adopt.Proc, stateDir string, pid int) (string, error) {
	cg, err := adopt.CgroupOf(p, pid)
	if err != nil {
		return "", err
	}
	id := runscope.AdoptionScopeRun(cg)
	if id == "" {
		return "", fmt.Errorf("%w: pid %d is in %s", ErrNotAdopted, pid, cg)
	}
	store, err := openAdoptStore(stateDir)
	if err != nil {
		return "", err
	}
	rec, err := store.read(id)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: pid %d is in %s, and run %s has no adoption record", ErrNotAdopted, pid, cg, id)
	}
	if err != nil {
		return "", err
	}
	if scope := strings.TrimPrefix(filepath.Clean(rec.Scope), filepath.Clean(rec.Mount)); scope != filepath.Clean("/"+cg) {
		return "", fmt.Errorf("%w: pid %d is in %s, not in run %s's scope %s", ErrNotAdopted, pid, cg, id, scope)
	}
	return id, nil
}

// releaseWait bounds how long ReleaseAdoption waits for a live adopter to release its agent, and a release of an
// orphan for another one in progress.
var releaseWait = 30 * time.Second

// ReleaseAdoption ends the adoption of run as root asks it to (`tego adopt --release`, `tego stop <run>`), by says
// who asked, for run_end. A live adopter is asked through a release request beside the adoption's record, which
// releases this adoption alone (the guard holds many, and a signal would end them all), and is waited for until the
// record is gone. A run whose adopter is gone is its reaper's, waited for; when the reaper is gone too it is released
// here, from its record, as the reaper would. stateDir "" is the host's records.
func ReleaseAdoption(ctx context.Context, stateDir, run, by string, log *slog.Logger) (ReleaseReport, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	out := ReleaseReport{Run: run}
	store, err := openAdoptStore(stateDir)
	if err != nil {
		return out, err
	}
	rec, err := store.read(run)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, fmt.Errorf("%w: run %s has no adoption record (it ended, or was never an adoption)", ErrNotAdopted, run)
		}
		return out, err
	}
	if rec.Released {
		// The run ended and released its tree, leaving processes no cgroup took back in the scope: nothing is asked of
		// the adopter (whose adoption is over), they are moved out here, from the record, and the ended run's ledger
		// is left as it is.
		out.Again, out.Unstarted = true, rec.Unstarted
		o, _, err := releaseHeld(ctx, store, rec, -1, "released by "+sanitizeReleaseBy(by), log)
		out.Orphan = &o
		if err == nil && len(o.Released.Left) > 0 {
			err = fmt.Errorf("%d process(es) still stay in %s: neither the cgroup they came from nor any above it takes "+
				"them", len(o.Released.Left), rec.Scope)
		}
		return out, err
	}
	if pfd, err := unix.PidfdOpen(rec.Adopter.PID, 0); err == nil {
		defer func() { _ = unix.Close(pfd) }()
		if adopterAlive(rec.Adopter) { // checked after the pidfd is open: the pidfd is this process, not a reuse
			if err := store.requestRelease(run, by); err != nil {
				return out, err
			}
			released, left, err := awaitRelease(ctx, store, run, pfd)
			if released && left > 0 {
				// The adopter answered and its run ended, but its release left processes in the scope: the record stays
				// (marked released) for the next release, and the request goes.
				out.Adopter, out.Left = rec.Adopter.PID, left
				store.clearRequest(run)
				return out, fmt.Errorf("adopter %d released the agent and its run ended, but %d process(es) stay in %s: "+
					"neither the cgroup they came from nor any above it takes them; a later release moves them out once "+
					"one does", rec.Adopter.PID, left, rec.Scope)
			}
			if released {
				out.Adopter = rec.Adopter.PID
				store.remove(run) // a request that met an adoption ending by itself is not left behind
				return out, nil
			}
			if err != nil {
				return out, fmt.Errorf("adopter %d: %w; the request stays, and it releases the agent when it next looks", rec.Adopter.PID, err)
			}
			// The adopter died before it released: its reaper's, or this release's below.
		}
	}
	o, ended, err := releaseHeld(ctx, store, rec, -1, "released by "+sanitizeReleaseBy(by)+": its adopter was gone", log)
	if !ended && err == nil {
		out.Reaper = true
		return out, nil
	}
	out.Orphan = &o
	return out, err
}

// awaitRelease waits, after a release request, until the adoption answered it (released true): its record is gone,
// or kept and marked released, with left the processes its release left in the scope. Its adopter dying first, the
// record neither gone nor released, is (false, 0, nil); releaseWait or ctx running out (false, 0, why).
func awaitRelease(ctx context.Context, store *adoptStore, run string, pfd int) (released bool, left int, err error) {
	wait, cancel := context.WithTimeout(ctx, releaseWait)
	defer cancel()
	answered := func() (bool, int) {
		rec, err := store.read(run)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return true, 0
		case err == nil && rec.Released:
			return true, rec.Left
		}
		return false, 0
	}
	for {
		if ok, n := answered(); ok {
			return true, n, nil
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(pfd), Events: unix.POLLIN}}, 100)
		if err == nil && n > 0 {
			ok, left := answered()
			return ok, left, nil
		}
		if wait.Err() != nil {
			if ctx.Err() != nil {
				return false, 0, ctx.Err()
			}
			return false, 0, fmt.Errorf("it did not release within %s", releaseWait)
		}
	}
}

// adopterAlive reports whether id still names a live process.
func adopterAlive(id adopt.Identity) bool {
	st, err := proc.New().Stat(id.PID)
	return err == nil && st.StartTicks == id.Start && !st.Gone()
}
