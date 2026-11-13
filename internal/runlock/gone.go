// SPDX-License-Identifier: Apache-2.0

package runlock

import "errors"

// Launcher is what a run's lock says of its launcher: alive, gone, or unknown.
type Launcher int

const (
	// Alive is a launcher proved to hold the run's lock: the lock line's process, by its pid and start time,
	// still running and holding the flock; or a held lock whose holder has not written its line yet (a launcher
	// starting).
	Alive Launcher = iota
	// Gone is a launcher confirmed gone: the lock is free, or the process the lock line names has exited
	// (reaped or not) or is another process by its start time (ErrStale).
	Gone
	// Unknown is a held lock whose holder cannot be judged: its identity cannot be read (ErrUnverified), a
	// line names a live process that does not hold the lock, or a launcher in another pid namespace
	// (ErrNotLockHolder). Callers never kill, reclaim or call lost on it.
	Unknown
)

// LauncherOf says whether the launcher of the run in runDir is alive, gone or unknown, and never by a bare pid:
// a lock line's pid is proved by its start time and its pidfd, through OpenStopTargetFor, the check `tego stop` and
// the sweep make (R22). It is the one judgement of "an orphaned run" for a paused run (ADR 0124, second amendment of
// 2026-11-11): `tego status`, `tego pause`, `tego resume`, `tego stop` and the dashboard read a paused run as lost on
// Gone only. err is set only when the lock itself cannot be probed.
func LauncherOf(runDir string) (Launcher, error) {
	l, _, err := LauncherCheck(runDir)
	return l, err
}

// LauncherCheck is LauncherOf with the cause of an Unknown: the identity check that failed, in words a person can act
// on (UnknownRecovery says what to do). cause is nil for Alive and Gone.
func LauncherCheck(runDir string) (l Launcher, cause, err error) {
	held, info, err := ProbeLock(runDir)
	if err != nil {
		return Unknown, nil, err
	}
	if !held {
		return Gone, nil, nil
	}
	if info.PID <= 0 {
		return Alive, nil, nil // between the flock and the lock line: a launcher still starting
	}
	t, err := OpenStopTargetFor(runDir, info)
	switch {
	case err == nil:
		_ = t.Close() // only probed
		return Alive, nil, nil
	case errors.Is(err, ErrStale):
		return Gone, nil, nil
	}
	return Unknown, err, nil
}

// UnknownRecovery is what a person can do about a launcher LauncherCheck could not judge.
const UnknownRecovery = "make /proc/<pid>/stat of the pid in the run's lock file readable (a procfs mounted hidepid or " +
	"with restricted access hides it), or run the command in the launcher's pid namespace; until then Tego treats the run " +
	"as running and never ends or reclaims it on that"

// LauncherGone reports whether LauncherOf confirms the launcher gone; unknown and alive are both false.
func LauncherGone(runDir string) (bool, error) {
	l, err := LauncherOf(runDir)
	return l == Gone, err
}
