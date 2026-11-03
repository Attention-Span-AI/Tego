// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/rulefile"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// retentionStamp is the file in the ledger root whose modification time says when the last retention pass began: a
// `tego run` start's (retainBeforeRun) or `tego gc`'s with no --keep. Its flock is held for the pass, so two starts
// never run one together. It is not a run id, so no listing of the root reads it as a run.
const retentionStamp = ".gc-stamp"

// retentionBudget bounds a start's retention pass: the pass stops between two runs once it is spent, and the next
// pass, one gc_interval later or the next `tego gc`, goes on from the oldest run left. A run's own work is bounded
// on its own (a lost run's kill waits at most five seconds, tegoruntime.Sweep). A variable so a test can spend it.
var retentionBudget = 2 * time.Second

// retainBeforeRun is the automatic retention: when the machine's gc_interval is set and the last pass began at
// least that long ago, a `tego run` start applies `tego gc`'s pass with the machine's retention, within
// retentionBudget. It is gc's pass, so what may be removed is gc's rule: an ended or empty run older than retention;
// never a run whose lock is held (a live run however old), and a lost run is ended orphaned first. chain.log is
// never rewritten: a removed run's line stays, so the runs left verify as before and `events <removed> --verify`
// reports the anchored ledger missing. The rule-change journal is pruned with the same retention in what is left of
// the budget (pruneRuleChanges, which ds, the machine config's diagnostics, may stop), by a root start (`sudo tego
// run`, which tiers 2 and 3 need) as the invoking user whose journal it is; a journal it leaves unpruned, or pruned
// but for the rules files it could not look at, is in tego's own log. It never fails the run that is starting. Its
// lines name cmd, the command starting the run.
func retainBeforeRun(ctx context.Context, m *config.Machine, cmd string, ds []config.Diagnostic, stderr io.Writer) {
	if m.GCInterval.Value <= 0 {
		return
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		return
	}
	release, ok := claimRetention(root, m.GCInterval.Value, time.Now())
	if !ok {
		return
	}
	defer release()
	pass, cancel := context.WithTimeout(ctx, retentionBudget)
	defer cancel()
	res, err := tegoruntime.Sweep(pass, root, m.Retention.Value, sweepOptions(m, tegoruntime.WithSweepLogger(ownLogger(m)))...)
	for _, e := range res.Errs {
		logOwn("retention: " + e.Error())
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		logOwn(fmt.Sprintf("retention: the pass stopped at its %s budget after %d run(s); the next pass goes on",
			retentionBudget, res.Scanned))
	case err != nil:
		logOwn("retention: " + err.Error())
	}
	if res.Deleted > 0 || res.Orphaned > 0 {
		message(stderr, "", 0, 0, fmt.Sprintf("%s: retention removed %d ended run(s) older than %s, ended %d orphaned",
			cmd, res.Deleted, config.FormatDuration(m.Retention.Value), res.Orphaned), codeSweep)
	}
	// Every journal the pass leaves unpruned, or prunes in part, is logged: a cause that recurs (a rules file on a stale
	// mount, a budget the runs spend) otherwise stops the prune on every pass with no word of it.
	pruned, perr := pruneRuleChanges(pass, root, m.Retention.Value, false, false, nil, ds)
	switch {
	case perr == nil:
	case errors.Is(perr, context.DeadlineExceeded):
		logOwn(fmt.Sprintf("retention: rule-change journal: not pruned, the pass's %s budget ran out; the next pass "+
			"prunes it", retentionBudget))
	default:
		logOwn("retention: rule-change journal: " + perr.Error())
	}
	if pruned.Lines > 0 {
		message(stderr, "", 0, 0, fmt.Sprintf("%s: retention pruned %d rule-change journal line(s) older than %s", cmd,
			pruned.Lines, config.FormatDuration(m.Retention.Value)), codeSweep)
	}
}

// errRetentionUnknown is a rule-change journal left unpruned because a machine config layer was skipped.
var errRetentionUnknown = errors.New("not pruned")

// pruneRuleChanges is a retention pass's prune of the ledger root's rule-change journal (rulefile.Prune) with the
// pass's keep: a line older than keep goes once no reader of the journal needs it (a run still in the root, its
// pending changes and an Undo's lift read the lines since it started and those that name it; each contract keeps its
// newest rulefile.KeepChanges changes that stand while its file is there), then the blobs no line left names and the
// lock files of contracts with no line left. gone are the runs the pass removes, or as a dry run would remove, which
// count as gone already. When keep is the machine's own (explicit false) and the machine config load skipped a layer
// (ds), nothing is pruned (errRetentionUnknown): the retention that layer may set is not known, and history removed on
// a guess does not come back; a --keep given on the command line is known. A root pass (`sudo tego run`, `sudo tego
// gc`) prunes the invoking user's journal as that user (journalOwner).
func pruneRuleChanges(ctx context.Context, root string, keep time.Duration, explicit, dryRun bool, gone []string,
	ds []config.Diagnostic) (rulefile.Pruned, error) {
	if d, ok := skippedLayer(ds); ok && !explicit {
		what := "a machine config layer"
		if d.File != "" {
			what = "the machine config layer " + d.File
		}
		return rulefile.Pruned{}, fmt.Errorf("%w: %s was skipped, so the retention it may set is not known",
			errRetentionUnknown, what)
	}
	o := rulefile.PruneOptions{Before: time.Now().Add(-keep), Gone: gone, DryRun: dryRun}
	as, ok, err := journalOwner(root)
	switch {
	case err != nil:
		return rulefile.Pruned{}, err
	case !ok:
		return rulefile.Prune(ctx, root, o)
	}
	var p rulefile.Pruned
	perr := errors.New("the prune did not run")
	if err := runAs(as, func() { p, perr = rulefile.Prune(ctx, root, o) }); err != nil {
		return rulefile.Pruned{}, fmt.Errorf("prune as uid %d, whose journal it is: %w", as.EUID, err)
	}
	return p, perr
}

// Test seams, the real calls in a product build: procEUID is this process's effective uid, invokingUID the SUDO_UID
// rule (config.InvokingUID), invokingGID the group a root tego gives the invoking user's files (sudoGID), and runAs
// sys.RunAs.
var (
	procEUID    = os.Geteuid
	invokingUID = config.InvokingUID
	invokingGID = sudoGID
	runAs       = sys.RunAs
)

// errGroupUnknown is a root pass that leaves the invoking user's journal unpruned because it cannot tell that user's
// group, which the prune would run with.
var errGroupUnknown = errors.New("the group of the user whose journal it is is not known")

// journalOwner says as whom root's rule-change journal is pruned: as this process (ok false), or, when this process is
// root and the journal is the invoking user's (`sudo tego run` and `sudo tego gc` work in that user's ledger root), as
// that user (ok; sys.RunAs). Root may not write there: a journal file root made would be refused by the user's own
// writes, and acting as the user, the prune can do there only what the user could. A root process that meets the
// journal of a user who did not invoke it leaves it to that user (rulefile.ErrOtherOwner). The owner is read before
// the prune and checked again by it (rulefile.Prune opens only a journal of the user it runs as), so a directory
// swapped meanwhile is refused, never written as another user.
//
// The prune runs with the user's uid and the user's group alone, SUDO_GID or else the passwd database's (sudoGID),
// which a root `tego run` drops its agent to as well, and no capability. It took the journal folder's group, which
// says only what group the folder carries: one a setgid ledger root or a chgrp gave it, which the user may not even
// be in, held by the prune as its own. A user whose group neither names leaves the journal unpruned
// (errGroupUnknown), as a root run of theirs is refused for the same lack.
func journalOwner(root string) (sys.TaskCreds, bool, error) {
	if procEUID() != 0 {
		return sys.TaskCreds{}, false, nil
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(root, rulefile.JournalDirName), &st); err != nil || st.Uid == 0 {
		return sys.TaskCreds{}, false, nil // no journal, which Prune finds too, or root's own
	}
	uid, viaSudo := invokingUID()
	if !viaSudo || st.Uid != uint32(uid) {
		return sys.TaskCreds{}, false, fmt.Errorf("%w: uid %d's, which did not invoke this tego; it is left to its owner",
			rulefile.ErrOtherOwner, st.Uid)
	}
	gid, ok := invokingGID(uid)
	if !ok {
		return sys.TaskCreds{}, false, fmt.Errorf("%w: uid %d's, and neither SUDO_GID nor the passwd database names "+
			"its group; it is left to its owner", errGroupUnknown, uid)
	}
	g := uint32(gid)
	return sys.TaskCreds{EUID: st.Uid, EGID: g, FSUID: st.Uid, FSGID: g, Groups: []uint32{g}}, true, nil
}

// skippedLayer is the first of ds that says the load left a machine config layer out: one TrustWarn skipped as
// untrusted, invalid or missing, whose fix ends "The layer was skipped." (pkg/spec/config skipOrAbort and demote, as
// serve's envSkipped reads it), or the per-user layer of a uid the passwd database does not name (E9).
func skippedLayer(ds []config.Diagnostic) (config.Diagnostic, bool) {
	for _, d := range ds {
		if strings.Contains(d.Fix, "The layer was skipped") ||
			d.Code == config.CodeIgnored && strings.HasSuffix(d.Message, "config layer skipped") {
			return d, true
		}
	}
	return config.Diagnostic{}, false
}

// claimRetention takes the ledger root's retention stamp for one pass: ok when no other pass holds it and the last
// began every or longer ago (every 0: whenever), and then the stamp says now and release ends the claim. A root that
// does not exist, a stamp that is a link or not a regular file, or one another pass holds is no claim.
func claimRetention(root string, every time.Duration, now time.Time) (release func(), ok bool) {
	f, err := openRetentionStamp(root, every, now)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errStampFresh) {
			logOwn("retention: " + err.Error())
		}
		return nil, false
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	if err := sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, false // another pass holds it
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	if stampFresh(st, every, now) {
		return nil, false
	}
	if err := f.Truncate(0); err != nil {
		logOwn("retention: stamp: " + err.Error())
		return nil, false
	}
	if _, err := f.WriteAt([]byte(now.UTC().Format(time.RFC3339)+"\n"), 0); err != nil {
		logOwn("retention: stamp: " + err.Error())
		return nil, false
	}
	// A root launcher's stamp in the invoking user's ledger root is handed to the root's owner, as a run directory
	// is. A hand-over that fails costs that user nothing: openRetentionStamp replaces a stamp it cannot open.
	if os.Geteuid() == 0 {
		if rs, err := os.Stat(root); err == nil {
			if o, ok := rs.Sys().(*syscall.Stat_t); ok && o.Uid != 0 {
				if err := f.Chown(int(o.Uid), int(o.Gid)); err != nil {
					logOwn("retention: stamp: " + err.Error())
				}
			}
		}
	}
	keep = true
	return func() { _ = f.Close() }, true
}

// errStampFresh is a stamp this process may not open, written inside the interval: a pass ran, so none is due.
var errStampFresh = errors.New("retention stamp is inside gc_interval")

// stampFresh says the stamp was written less than every ago. A stamp with nothing in it never counts: the pass that
// made it died before writing it.
func stampFresh(st fs.FileInfo, every time.Duration, now time.Time) bool {
	age := now.Sub(st.ModTime())
	return every > 0 && st.Size() > 0 && age >= 0 && age < every
}

// openRetentionStamp opens the ledger root's stamp, making it if it is not there. A stamp this process may not open
// is another uid's: a root pass that died before its hand-over, or whose chown failed. The stamp only spaces the
// passes, and the owner of the ledger root may unlink it, so a due one is replaced rather than leaving that user's
// starts without a pass from then on. One inside the interval is left alone, which also leaves alone a root pass
// that has just made it. A `tego gc` (every 0) replaces it whatever its age, and may then run beside that pass; each
// run's own lock keeps two passes off the same run.
func openRetentionStamp(root string, every time.Duration, now time.Time) (*os.File, error) {
	path := filepath.Join(root, retentionStamp)
	open := func() (*os.File, error) {
		return os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	}
	f, err := open()
	if !errors.Is(err, fs.ErrPermission) {
		return f, err
	}
	st, serr := os.Lstat(path)
	if serr != nil || !st.Mode().IsRegular() {
		return nil, err // the root itself is closed to this user, or the name is no stamp
	}
	if stampFresh(st, every, now) {
		return nil, errStampFresh
	}
	if rerr := os.Remove(path); rerr != nil {
		return nil, errors.Join(err, rerr)
	}
	return open()
}
