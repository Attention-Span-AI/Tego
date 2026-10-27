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
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
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
// reports the anchored ledger missing. It never fails the run that is starting.
func retainBeforeRun(ctx context.Context, m *config.Machine, stderr io.Writer) {
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
		message(stderr, "", 0, 0, fmt.Sprintf("tego run: retention removed %d ended run(s) older than %s, ended %d orphaned",
			res.Deleted, config.FormatDuration(m.Retention.Value), res.Orphaned), codeSweep)
	}
}

// claimRetention takes the ledger root's retention stamp for one pass: ok when no other pass holds it and the last
// began every or longer ago (every 0: whenever), and then the stamp says now and release ends the claim. A root that
// does not exist, a stamp that is a link or not a regular file, or one another pass holds is no claim.
func claimRetention(root string, every time.Duration, now time.Time) (release func(), ok bool) {
	f, err := os.OpenFile(filepath.Join(root, retentionStamp),
		os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
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
	if age := now.Sub(st.ModTime()); every > 0 && st.Size() > 0 && age >= 0 && age < every {
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
	// is, or that user's next start could not open it and would never run a pass again.
	if os.Geteuid() == 0 {
		if rs, err := os.Stat(root); err == nil {
			if o, ok := rs.Sys().(*syscall.Stat_t); ok && o.Uid != 0 {
				_ = f.Chown(int(o.Uid), int(o.Gid))
			}
		}
	}
	keep = true
	return func() { _ = f.Close() }, true
}
