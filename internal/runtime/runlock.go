// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// The lock probe, the lock line and the verified stop target live in internal/runlock, which the engine's clients
// link without the engine (ADR 0100 (7)); these names delegate to it. What stays here is the
// launcher's side: writing the line, and the stop marker.

// LockInfo is the advisory content of a run's lock file (runlock.LockInfo).
type LockInfo = runlock.LockInfo

// StopTarget is a launcher held by a verified pidfd (runlock.StopTarget).
type StopTarget = runlock.StopTarget

// Lock and stop-marker errors, one per failure class (docs/p0/runtime-launch.md §9 "Naming").
var (
	// ErrStale is runlock.ErrStale: the pid the lock names is now another process (R22, case 15).
	ErrStale = runlock.ErrStale
	// ErrLockInfo is runlock.ErrLockInfo: a torn or malformed lock line.
	ErrLockInfo = runlock.ErrLockInfo
	// ErrNotLockHolder is runlock.ErrNotLockHolder: the pid the line names does not hold the run's lock (R22).
	ErrNotLockHolder = runlock.ErrNotLockHolder
	// ErrStopRequested is returned by RequestStopGraceThen with no after step when a stop marker already exists for the run.
	ErrStopRequested = errors.New("runtime: stop already requested")
)

// StopRequestFile is the marker `tego stop` drops in a run directory before signalling the
// launcher, so the launcher's signal handler can tell a requested stop (run_end reason=stopped)
// from an arbitrary SIGTERM (reason=signal) — docs/p0/runtime-launch.md §3, R9.
const StopRequestFile = ledger.StopRequestFile

// ParseLockInfo is runlock.ParseLockInfo.
func ParseLockInfo(b []byte) (LockInfo, error) { return runlock.ParseLockInfo(b) }

// probeLock is runlock.ProbeLock for d, under the directory a sweep hook was lent when d holds one.
func probeLock(d runDir) (held bool, info LockInfo, err error) { return runlock.ProbeLockIn(d.lock()) }

// OpenStopTargetFor is runlock.OpenStopTargetFor, whose doc is the contract (R22).
func OpenStopTargetFor(runDir string, info LockInfo) (*StopTarget, error) {
	return runlock.OpenStopTargetFor(runDir, info)
}

// openStopTarget is OpenStopTargetFor for d, whose lock is proved under the directory a sweep hook was lent when d
// holds one.
func openStopTarget(d runDir, info LockInfo) (*StopTarget, error) {
	return runlock.OpenStopTargetIn(d.lock(), info)
}

// StartBootNS is runlock.StartBootNS: a process's start time in CLOCK_BOOTTIME nanoseconds.
func StartBootNS(pid int) (uint64, error) { return runlock.StartBootNS(pid) }

// ownPIDNS is the inode of this process's pid namespace, 0 when /proc does not say.
func ownPIDNS() uint64 { return runlock.OwnPIDNS() }

// lockPath is the run's lock file, the one ledger.Open flocks (R1).
func lockPath(runDir string) string { return filepath.Join(runDir, ledger.LockFile) }

// openLockFile opens a run's lock file as the ledger's readers do (ledger.OpenRegular).
func openLockFile(path string) (*os.File, error) { return ledger.OpenRegular(path) }

// writeLockInfo records who holds the run's lock, through the descriptor ledger.Writer holds the flock
// on (R1): writing there never disturbs the lock, and the file is never reopened by name. A root
// launcher reopening <run>/lock by path — O_TRUNC included — would follow whatever a user who owns the
// ledger root had renamed into place since the run directory was made (record-ledger.md §3).
func writeLockInfo(w *ledger.Writer, info LockInfo) error {
	if err := w.WriteLockInfo([]byte(info.String())); err != nil {
		return fmt.Errorf("runtime: write lock file: %w", err)
	}
	return nil
}

// StopRequested reports whether a stop marker exists for the run. It is the launcher's
// SignalPolicy.StopRequested hook: a stop signal arriving while it is true ends the run with
// reason=stopped instead of reason=signal (R9).
func StopRequested(runDir string) bool {
	_, err := os.Lstat(filepath.Join(runDir, StopRequestFile))
	return err == nil
}
