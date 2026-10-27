// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"
)

// MaxLiveFollowed is the most runs a LiveWatch follows at once. Each followed run costs its consumer a Follower
// (a descriptor, an inotify instance and a buffer of 32 KiB at rest); the runs listed past it are counted and
// reported (LiveExcess), never dropped without a word, and are taken up as followed runs leave.
const MaxLiveFollowed = 512

// LiveChangeKind is what a LiveChange reports.
type LiveChangeKind string

// The changes a LiveWatch reports.
const (
	LiveEntered LiveChangeKind = "entered" // Run is listed in the live index and now followed
	LiveLeft    LiveChangeKind = "left"    // Run, followed until now, is no longer listed
	LiveExcess  LiveChangeKind = "excess"  // Excess runs are listed and not followed; reported whenever it changes
)

// LiveChange is one change in what a LiveWatch follows.
type LiveChange struct {
	Kind   LiveChangeKind
	Run    string // LiveEntered, LiveLeft
	Excess int    // LiveExcess
}

// LiveWatch reports the runs entering and leaving the live index (<ledger_root>/.live, §3 Live index) of a
// ledger root. It reads the index's names and nothing else, as SweepLive does: an entry that is no run id is
// passed over, and no entry is opened. Its memory is bounded by MaxLiveFollowed whatever the index holds: the
// names are read in batches, and only the followed runs and at most MaxLiveFollowed candidates are kept.
type LiveWatch struct {
	root    string
	wake    *waker
	max     int
	tracked map[string]struct{}
	excess  int
	used    bool
}

// WatchLive watches the live index of the ledger root at root. A root or an index not made yet lists no run
// until it is.
func WatchLive(root string) *LiveWatch {
	return &LiveWatch{root: root, wake: newWaker(), max: MaxLiveFollowed, tracked: map[string]struct{}{}}
}

// Wake reports how the LiveWatch learns of changes to the index: WakeInotify, or WakePoll and why.
func (lw *LiveWatch) Wake() (string, error) { return lw.wake.mode, lw.wake.why }

// Close releases the inotify instance.
func (lw *LiveWatch) Close() error { return lw.wake.close() }

// Changes yields the changes in what the index lists, scan by scan, until ctx ends (ctx's error) or the index
// cannot be read (that error, and the sequence ends); a LiveWatch is read once. The first scan reports every
// run listed as entered, up to MaxLiveFollowed. Each scan reports the runs that left first, then those that
// entered (sorted), then the excess when it changed. A run that leaves and comes back between two scans is not
// reported; a consumer that follows a run learns from its Follower when it ends.
func (lw *LiveWatch) Changes(ctx context.Context) iter.Seq2[LiveChange, error] {
	return func(yield func(LiveChange, error) bool) {
		if lw.used {
			yield(LiveChange{}, errors.New("ledger: a LiveWatch's changes are read once"))
			return
		}
		lw.used = true
		for {
			left, entered, excess, err := lw.scan()
			if err != nil {
				yield(LiveChange{}, err)
				return
			}
			for _, id := range left {
				if !yield(LiveChange{Kind: LiveLeft, Run: id}, nil) {
					return
				}
			}
			for _, id := range entered {
				if !yield(LiveChange{Kind: LiveEntered, Run: id}, nil) {
					return
				}
			}
			if excess != lw.excess {
				lw.excess = excess
				if !yield(LiveChange{Kind: LiveExcess, Excess: excess}, nil) {
					return
				}
			}
			if err := lw.wake.wait(ctx); err != nil {
				yield(LiveChange{}, err)
				return
			}
		}
	}
}

// liveBatch is how many names a scan reads from the index at a time.
const liveBatch = 256

// scan reads the index once and updates the followed set: the runs that left, those admitted (sorted), and how
// many listed runs are left over.
func (lw *LiveWatch) scan() (left, entered []string, excess int, err error) {
	seen := make(map[string]struct{}, len(lw.tracked))
	var cand []string
	over := 0
	err = lw.names(func(name string) {
		if !IsRunID(name) {
			return
		}
		if _, ok := lw.tracked[name]; ok {
			seen[name] = struct{}{}
			return
		}
		if len(cand) < lw.max {
			cand = append(cand, name)
			return
		}
		over++
	})
	if err != nil {
		return nil, nil, 0, err
	}
	for id := range lw.tracked {
		if _, ok := seen[id]; !ok {
			left = append(left, id)
			delete(lw.tracked, id)
		}
	}
	slices.Sort(left)
	slices.Sort(cand)
	room := lw.max - len(lw.tracked)
	entered = cand[:min(room, len(cand))]
	for _, id := range entered {
		lw.tracked[id] = struct{}{}
	}
	return left, entered, over + len(cand) - len(entered), nil
}

// names calls fn with each name the index holds, read in batches, and arms the waker on the index (or, while
// there is none, on the root, to learn when it is made). A root or index that is not there holds no names.
func (lw *LiveWatch) names(fn func(string)) error {
	const dirEvents = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
		unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR
	rd, err := openDir(lw.root, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("ledger: open ledger root: %w", err)
	}
	defer func() { _ = rd.Close() }()
	path := filepath.Join(lw.root, LiveDir)
	d, err := rd.Openat(LiveDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			_ = lw.wake.watch(lw.root, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_ONLYDIR)
			return nil
		}
		// O_DIRECTORY|O_NOFOLLOW refuses a link as ENOTDIR, not ELOOP.
		if errors.Is(err, unix.ENOTDIR) && isLink(rd, LiveDir) {
			return fmt.Errorf("ledger: live index: %w: %s", ErrLinkRefused, path)
		}
		return fmt.Errorf("ledger: live index: %w", openError(rd, LiveDir, path, err))
	}
	f, err := d.Release(path)
	if err != nil {
		_ = d.Close()
		return fmt.Errorf("ledger: live index: %w", err)
	}
	defer func() { _ = f.Close() }()
	_ = lw.wake.watch(path, dirEvents)
	for {
		batch, err := f.Readdirnames(liveBatch)
		for _, name := range batch {
			fn(name)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ledger: live index: %w", err)
		}
	}
}
