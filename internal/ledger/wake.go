// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Wake modes a Follower and a LiveWatch report (Wake): how they learn that the file or directory they read
// changed.
const (
	WakeInotify = "inotify" // inotify(7), with the poll interval as a backstop
	WakePoll    = "poll"    // the poll interval alone: inotify could not be had (EMFILE, ENOSPC, or refused)
)

// pollInterval is how long a waker sleeps when nothing woke it: the whole wait in poll mode, and the backstop
// with inotify, so a change inotify never reports (a file replaced under its name, a filesystem that raises no
// events for another mount's writes) costs at most this much delay, never a hang. Tests shorten it.
var pollInterval = time.Second

// newInotify makes the inotify instance a waker reads; tests replace it to stand for an exhausted
// fs.inotify.max_user_instances (EMFILE).
var newInotify = func() (*sys.FD, error) {
	return sys.Own(unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC))
}

// watchRefused, set by tests, is the error every watch fails with, standing for an exhausted
// fs.inotify.max_user_watches (ENOSPC).
var watchRefused error

// waker is the one wait of a Follower or a LiveWatch: until inotify reports a change on a watched path, the poll
// interval passes, or ctx ends. The pattern is internal/runtime/cgroup's watcher's, which this layer may not
// import. Any inotify failure degrades it to polling, which only delays a reader, and the mode says so; whatever
// the mode, the reader re-reads its file after every wait, so a wake carries no information beyond "look again".
type waker struct {
	f    *os.File // the inotify instance; nil in poll mode
	mode string
	why  error // what put the waker in poll mode, for a caller that reports it
}

// newWaker returns a waker in inotify mode, or in poll mode when no inotify instance can be made.
func newWaker() *waker {
	fd, err := newInotify()
	if err != nil {
		return &waker{mode: WakePoll, why: fmt.Errorf("inotify_init1: %w", err)}
	}
	f, err := fd.Release("inotify")
	if err != nil {
		_ = fd.Close()
		return &waker{mode: WakePoll, why: fmt.Errorf("inotify: %w", err)}
	}
	return &waker{f: f, mode: WakeInotify}
}

// watch adds path to the instance with mask (IN_DONT_FOLLOW always: a link planted under the name is not
// watched through). A path that is not there is reported (os.ErrNotExist) and leaves the mode alone, since the
// poll backstop covers it; any other failure, ENOSPC (fs.inotify.max_user_watches) among them, drops the
// instance and leaves the waker polling.
func (w *waker) watch(path string, mask uint32) error {
	if w.f == nil {
		return nil
	}
	werr := watchRefused
	if werr == nil {
		werr = sys.FileDo(w.f, func(n int) error {
			_, err := unix.InotifyAddWatch(n, path, mask|unix.IN_DONT_FOLLOW)
			return err
		})
	}
	switch {
	case werr == nil:
		return nil
	case errors.Is(werr, unix.ENOENT):
		return &os.PathError{Op: "inotify_add_watch", Path: path, Err: werr}
	}
	w.degrade(&os.PathError{Op: "inotify_add_watch", Path: path, Err: werr})
	return nil
}

// degrade drops the inotify instance: the waker polls from now on, and why is what it reports.
func (w *waker) degrade(why error) {
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	w.mode, w.why = WakePoll, why
}

// wait blocks until a change notification, the poll interval, or ctx; only ctx's end is an error. ctx's end
// cuts the read short from a callback on a goroutine of its own, and wait does not return while that callback
// runs, so it never sets a deadline on a file close has released.
func (w *waker) wait(ctx context.Context) error {
	if w.f == nil {
		t := time.NewTimer(pollInterval)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.f.SetReadDeadline(time.Now().Add(pollInterval)); err != nil {
		w.degrade(fmt.Errorf("inotify deadline: %w", err))
		return nil
	}
	f := w.f
	cut := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(cut)
		_ = f.SetReadDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-cut
		}
	}()
	// The events are drained and dropped: the reader looks again whatever changed. A full queue
	// (IN_Q_OVERFLOW) is a wake like any other.
	var buf [4096]byte
	if _, err := f.Read(buf[:]); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		w.degrade(fmt.Errorf("read inotify: %w", err))
	}
	return nil
}

// close releases the inotify instance.
func (w *waker) close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
