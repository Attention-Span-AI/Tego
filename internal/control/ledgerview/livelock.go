// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"os"
	"path/filepath"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// A run is running while its launcher holds the run's lock (<root>/<run>/lock), which the kernel releases when the
// launcher dies. The live index (<root>/.live, liveSet) alone cannot say that: a launcher lists its run once it holds
// the lock and takes the entry out only after run_end, so one that died without writing run_end (killed, out of
// memory, a crash) leaves its run listed with nothing holding the lock, and the dashboard showed that run as running
// until a sweep (`tego run`, `tego stop`, `tego gc`) ended it: under Running now, with Stop, Pause and Block now, its
// open asks waiting. So a listed run is running only while a process holds its lock, as `tego status`
// (internal/check/status) and the rule service (rules.Service.isLive) read it, and lost otherwise.
//
// The probe is the one the ledger's readers share (ledger.LockHeld): the lock file opened read-only, O_NOFOLLOW and
// O_NONBLOCK, then flock(LOCK_SH|LOCK_NB) on that descriptor of its own, released at once. It never waits, and it never
// takes or delays a launcher's lock: while the launcher holds it, the request fails at once (EWOULDBLOCK) and takes
// nothing; and only a run the index lists is probed, which its launcher lists after it took the lock, so a launcher
// still taking its lock is never met. A free lock, a dead launcher's, is held for the instant of the probe; the
// processes that take a lost run's lock to end it (a sweep, the reaper) wait out such a hold, as they do the other
// readers' (ledger takeLock and sweep, runtime's reap).
//
// Each answer is kept for lockProbeAge, so pages and the live state, which ask several times a second, probe each
// listed run at most once in that time, and a run whose launcher died reads as lost at most that long after.
//
// The lock is probed before any events file is looked at: a launcher appends run_end and only then releases its lock,
// so a lock seen free means the look after it finds run_end when the run ended, and a run that just ended never reads
// as lost on the way (ledger.State keeps the same order). A kept answer was taken before the look too.

// lockProbeAge is how long a run's lock probe is kept. A variable so tests can change it.
var lockProbeAge = 2 * time.Second

// lockHeld is the probe, a variable so a test can see which locks are probed.
var lockHeld = ledger.LockHeld

// lockProbe is one listed run's last probe: whether a process held its lock, and when it was asked.
type lockProbe struct {
	held bool
	at   time.Time
}

// liveRuns is the runs of the root that are running: listed in its live index and their lock held.
func (s *Store) liveRuns() map[string]bool {
	listed := liveSet(s.root)
	out := make(map[string]bool, len(listed))
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	now := time.Now()
	for id := range listed {
		p, ok := s.probes[id]
		if !ok || now.Sub(p.at) >= lockProbeAge {
			p = lockProbe{held: s.probeLock(id), at: now}
			s.probes[id] = p
		}
		if p.held {
			out[id] = true
		}
	}
	for id := range s.probes {
		if !listed[id] {
			delete(s.probes, id)
		}
	}
	return out
}

// probeLock reports whether a process holds run id's lock. Only a run directory in the root is probed, never one
// reached through a link nor a name that is no run id (as the ledger's sweep of the index takes them,
// ledger.SweepLive): such an entry lists nothing that runs. A probe that cannot answer (an unreadable lock file, no
// descriptor to spare) keeps the index's word; a missing lock file is a free one (ledger.LockHeld).
func (s *Store) probeLock(id string) bool {
	if !validRunID(id) {
		return false
	}
	dir := filepath.Join(s.root, id)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return false
	}
	held, err := lockHeld(dir)
	if err != nil {
		return true
	}
	// A lock held by a process that is not the run's launcher (the launcher exited, or its pid is another process now,
	// by start time) is a lost run's, as tego status reads it (runlock.LauncherOf, ADR 0124's second amendment of
	// 2026-11-11). Only a launcher confirmed gone turns it lost; one whose identity cannot be read stays running.
	return held && !launcherGone(dir)
}

// launcherGone is runlock.LauncherGone, a variable so a test can stand in for the process table; an error is not gone.
var launcherGone = func(dir string) bool {
	gone, err := runlock.LauncherGone(dir)
	return err == nil && gone
}
