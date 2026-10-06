// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Coordination bounds only a concurrent cache miss, never the probe's answer.
// A lock file is unlinked only by a caller that holds its lock, and a caller
// that takes a lock checks that the name still leads to it, opening the name
// again when it does not (errFlightMoved), so waiters never split across two
// inodes. A short admission lock bounds their number without serializing the
// expensive probes of independent full keys.
const (
	runProbeFlightWait = 30 * time.Second
	runProbeFlightPoll = 10 * time.Millisecond
	maxRunProbeFlights = 128
	probeFlightDir     = "doctor-probe-flights"
	probeFlightIndex   = ".index.lock"
)

// errCacheDir marks a flight not taken because the run-probe cache directory itself could not be opened: the
// cache's own note (runCache.refused) names that, so ForRun notes no coordination failure for it.
var errCacheDir = errors.New("run-probe cache directory unusable")

// errFlightMoved is a lock file whose name no longer leads to it: it was reclaimed (createFlight), and the
// caller opens the name again.
var errFlightMoved = errors.New("probe lock name changed")

type probeFlight struct {
	dir, fd int
	// waited is whether another caller held the lock when this one first asked: the holder's probe has
	// ended by the time this one has it, and what it kept, if anything, is in the cache (ForRun).
	waited bool
}

func (f *probeFlight) close() {
	if f.fd >= 0 {
		_ = unix.Close(f.fd) // closing the owned descriptor releases flock
		f.fd = -1
	}
	if f.dir >= 0 {
		_ = unix.Close(f.dir)
		f.dir = -1
	}
}

func probeFlightName(k runCacheKey) string {
	b, _ := json.Marshal(k)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) + ".lock"
}

// flightFile opens only a private empty regular file, and proves the name still
// names that descriptor. Neither an external hardlink nor a removed lock inode
// can coordinate callers using the current name.
func (c *runCache) flightFile(dir int, name string, create bool) (int, error) {
	flags := unix.O_RDWR | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Openat(dir, name, flags, 0o600)
	if err != nil {
		return -1, err
	}
	if err := c.flightNamed(dir, fd, name); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (c *runCache) flightNamed(dir, fd int, name string) error {
	var held, named unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return err
	}
	if held.Mode&unix.S_IFMT == unix.S_IFREG && held.Nlink == 0 {
		return errFlightMoved // unlinked since it was opened
	}
	if held.Mode&unix.S_IFMT != unix.S_IFREG || int(held.Uid) != c.owner || held.Mode&0o7777 != 0o600 ||
		held.Nlink != 1 || held.Size != 0 {
		return errors.New("probe lock is not an owner's private empty single-link regular file")
	}
	if err := unix.Fstatat(dir, name, &named, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return errFlightMoved
	} else if err != nil {
		return err
	}
	if named.Dev != held.Dev || named.Ino != held.Ino {
		return errFlightMoved
	}
	return nil
}

// lockFlight takes fd's lock, trying every runProbeFlightPoll until ctx ends; waited is whether another
// caller held it at some try.
func (c *runCache) lockFlight(ctx context.Context, dir, fd int, name string) (waited bool, err error) {
	tick := time.NewTicker(runProbeFlightPoll)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return waited, err
		}
		if err := c.flightNamed(dir, fd, name); err != nil {
			return waited, err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return waited, c.flightNamed(dir, fd, name)
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return waited, err
		}
		if !waited && errors.Is(err, unix.EWOULDBLOCK) {
			waited = true
			if c.waiting != nil {
				c.waiting(name)
			}
		}
		select {
		case <-ctx.Done():
			return waited, ctx.Err()
		case <-tick.C:
		}
	}
}

func (c *runCache) flightDirectory() (int, error) {
	parent, err := c.openDir(true)
	if err != nil {
		return -1, fmt.Errorf("%w: %w", errCacheDir, err)
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Mkdirat(parent, probeFlightDir, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	dir, err := unix.Openat(parent, probeFlightDir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(dir, &st); err != nil {
		_ = unix.Close(dir)
		return -1, err
	}
	if int(st.Uid) != c.owner || st.Mode&0o7777 != 0o700 {
		_ = unix.Close(dir)
		return -1, errors.New("probe lock directory is not owner's mode0700")
	}
	return dir, nil
}

// createFlight holds admission only while adding a new inode. The bounded
// private directory census prevents unbounded lock-file growth: at the limit it
// reclaims lock files nobody holds (reclaimFlights), and only when every one is
// held does a new key probe without coordination; existing keys still work.
func (c *runCache) createFlight(ctx context.Context, dir int, name string) (int, error) {
	index, err := c.flightFile(dir, probeFlightIndex, true)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(index) }()
	if _, err := c.lockFlight(ctx, dir, index, probeFlightIndex); err != nil {
		return -1, err
	}
	if fd, err := c.flightFile(dir, name, false); !errors.Is(err, unix.ENOENT) {
		return fd, err
	}
	copyFD, err := unix.FcntlInt(uintptr(dir), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	f := os.NewFile(uintptr(copyFD), probeFlightDir)
	entries, readErr := f.ReadDir(maxRunProbeFlights + 2)
	_ = f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return -1, readErr
	}
	count := 0
	for _, e := range entries {
		if e.Name() == probeFlightIndex {
			continue
		}
		digest, err := hex.DecodeString(strings.TrimSuffix(e.Name(), ".lock"))
		if err != nil || len(digest) != sha256.Size || !strings.HasSuffix(e.Name(), ".lock") {
			return -1, errors.New("unexpected entry in probe lock directory")
		}
		count++
	}
	if count >= maxRunProbeFlights {
		count -= c.reclaimFlights(dir, entries, count-maxRunProbeFlights+1)
	}
	if count >= maxRunProbeFlights {
		return -1, fmt.Errorf("all %d lock files are held by runs of other keys", maxRunProbeFlights)
	}
	if err := c.flightNamed(dir, index, probeFlightIndex); err != nil {
		return -1, err
	}
	return c.flightFile(dir, name, true)
}

// reclaimFlights unlinks up to want lock files that no caller holds, and returns how many it unlinked. It runs
// under the admission lock. Each is unlinked while this caller holds its lock and its name still leads to it,
// so a caller waiting on it takes the lock only after the unlink, finds the name gone, and opens it again
// (acquireFlight); a held one is never touched. Amended 2026-10-05 (v73 review races-4): lock files were
// never unlinked, and the key holds the run's cgroup and binary, so after 128 session scopes, units or builds
// in one boot no new key coordinated at all.
func (c *runCache) reclaimFlights(dir int, entries []os.DirEntry, want int) int {
	n := 0
	for _, e := range entries {
		if n >= want {
			break
		}
		name := e.Name()
		if name == probeFlightIndex {
			continue
		}
		fd, err := c.flightFile(dir, name, false)
		if err != nil {
			continue // gone, or not a lock this cache made: left as it is
		}
		if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) == nil && c.flightNamed(dir, fd, name) == nil &&
			unix.Unlinkat(dir, name, 0) == nil {
			n++
		}
		_ = unix.Close(fd)
	}
	return n
}

// acquireFlight coordinates ForRun misses of one full key. Failure is a
// fresh probe, not a tier downgrade or a fabricated answer. The caller must
// re-read its full key and validated cache after acquisition before reusing it,
// and lets the flight go when it waited and finds no answer: the holder's was
// not one the cache keeps, and waiting again would gain the next caller nothing.
//
// Its error is the reason as a run's coordination note gives it (Report.CoordinationNote), with no prefix of
// its own; a wait that ran out is said as one, and still matches context.DeadlineExceeded.
func (c *runCache) acquireFlight(parent context.Context, key runCacheKey, wait time.Duration) (*probeFlight, error) {
	ctx, cancel := context.WithTimeout(parent, wait)
	defer cancel()
	dir, err := c.flightDirectory()
	if err != nil {
		return nil, err
	}
	f := &probeFlight{dir: dir, fd: -1}
	name := probeFlightName(key)
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		f.fd, err = c.flightFile(dir, name, false)
		if errors.Is(err, unix.ENOENT) {
			f.fd, err = c.createFlight(ctx, dir, name)
		}
		if err == nil {
			var waited bool
			waited, err = c.lockFlight(ctx, dir, f.fd, name)
			f.waited = f.waited || waited
		}
		if !errors.Is(err, errFlightMoved) {
			break
		}
		if f.fd >= 0 { // a reclaimed inode: open the name again
			_ = unix.Close(f.fd)
			f.fd = -1
		}
	}
	if err != nil {
		f.close()
		if errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil {
			return nil, fmt.Errorf("another run's probe of the same key held its lock for %s (%w)", wait, err)
		}
		return nil, err
	}
	return f, nil
}
