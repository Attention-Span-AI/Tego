// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// runDir is a run's directory as the lock probe, the launcher check and the orphan checks look it up. A sweep
// hook is lent the directory itself (ledger.WithSweepHook), opened under the ledger root the pass holds, and
// then every lookup is an *at() call under at (ADR 0023): the directory the pass decided on, whatever is renamed
// over the configured root or an ancestor meanwhile, and over the run's name too once the pass holds the run's
// lock (a reclaim hook, which runs with no lock of the pass's, is lent the name as it stands). With no at (tego stop's and ask's probes,
// RunScope, a run's own shutdown) the lookups resolve path. path names the directory in errors and messages, and
// its last element is the run's id.
type runDir struct {
	path string
	at   sys.Lender
}

// pathDir is the run directory at path, looked up by path.
func pathDir(path string) runDir { return runDir{path: path} }

// lock is d as the lock probe and the lock-holder proof look it up (internal/runlock).
func (d runDir) lock() runlock.Dir { return runlock.Dir{Path: d.path, At: d.at} }

// id is the run id the directory is named after.
func (d runDir) id() string { return filepath.Base(d.path) }

// reader opens the run's ledger for reading.
func (d runDir) reader() (*ledger.Reader, error) {
	if d.at == nil {
		return ledger.OpenReader(d.path)
	}
	return ledger.OpenReaderAt(d.at, d.path)
}

// lstat is the directory's own status, never what a link at path names: fstat of the lent directory, or lstat
// of path.
func (d runDir) lstat() (unix.Stat_t, error) {
	var st unix.Stat_t
	if d.at == nil {
		return st, unix.Lstat(d.path, &st)
	}
	return st, d.at.Borrow(func(n int) error { return unix.Fstat(n, &st) })
}
