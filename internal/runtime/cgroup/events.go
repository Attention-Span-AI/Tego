// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// Control-file names read by this package.
const (
	fileEvents       = "cgroup.events"
	fileKill         = "cgroup.kill"
	fileProcs        = "cgroup.procs"
	fileControllers  = "cgroup.controllers"
	fileSubtreeCtl   = "cgroup.subtree_control"
	fileMemoryEvents = "memory.events"
	filePidsEvents   = "pids.events"
)

// pollFallback bounds how long WaitEmpty and Events trust inotify before re-reading the file.
const pollFallback = 200 * time.Millisecond

// parseCounter finds "<key> <n>" in a cgroup key-value file and returns n. Missing key, a
// malformed number or a value that does not fit uint64 report ok=false. Never panics (fuzzed).
func parseCounter(data []byte, key string) (uint64, bool) {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		k, v, found := bytes.Cut(bytes.TrimSpace(line), []byte{' '})
		if !found || string(k) != key {
			continue
		}
		n, err := strconv.ParseUint(string(bytes.TrimSpace(v)), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// readCounter reads one key from a control file of c. A missing file reports (0, false, nil):
// the controller is not delegated, so its counter cannot have moved.
func readCounter(c Cgroup, name, key string) (uint64, bool, error) {
	data, err := readControl(c, name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return 0, false, nil
		}
		return 0, false, err
	}
	n, ok := parseCounter(data, key)
	if !ok {
		return 0, false, fmt.Errorf("cgroup: %s: no %q counter", filepath.Join(c.Path, name), key)
	}
	return n, true, nil
}

// ReadLimitEvents returns the raw memory.events oom_kill and pids.events max counters of c so the
// caller can diff them against its own baseline (R10, R11). A counter whose controller is not
// delegated reads as 0.
func ReadLimitEvents(c Cgroup) (oomKill, pidsMax uint64, err error) {
	oomKill, _, err = readCounter(c, fileMemoryEvents, "oom_kill")
	if err != nil {
		return 0, 0, err
	}
	pidsMax, _, err = readCounter(c, filePidsEvents, "max")
	if err != nil {
		return 0, 0, err
	}
	return oomKill, pidsMax, nil
}

// Populated reads the populated flag of cgroup.events: whether any live task remains in c or a
// descendant. A cgroup that no longer exists reads as empty.
func Populated(c Cgroup) (bool, error) {
	data, err := readControl(c, fileEvents)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	n, ok := parseCounter(data, "populated")
	if !ok {
		return false, fmt.Errorf("cgroup: %s: no populated line", filepath.Join(c.Path, fileEvents))
	}
	return n != 0, nil
}

// watcher wakes when cgroup.events changes. It uses inotify(IN_MODIFY) on the file (kernfs
// raises fsnotify on every cgroup.events update) and falls back to plain polling when inotify
// is unavailable; either way wait returns after at most pollFallback so a lost notification
// only delays, never hangs.
type watcher struct {
	f *os.File // nil = polling only
}

// newWatcher arms inotify on path; an inotify failure degrades to polling rather than erroring.
func newWatcher(path string) *watcher {
	fd, err := sys.Own(unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC))
	if err != nil {
		return &watcher{}
	}
	if err := fd.Borrow(func(n int) error {
		_, err := unix.InotifyAddWatch(n, path, unix.IN_MODIFY|unix.IN_DELETE_SELF)
		return err
	}); err != nil {
		_ = fd.Close()
		return &watcher{}
	}
	f, err := fd.Release("inotify:" + path)
	if err != nil {
		_ = fd.Close()
		return &watcher{}
	}
	return &watcher{f: f}
}

// wait blocks until a change notification, pollFallback, or ctx; only ctx's end is an error.
//
// ctx's end cuts the read short from a callback on a goroutine of its own, and wait does not return
// while that callback runs. stop() alone does not give that: once ctx has ended the callback has
// started, and stop reports false and returns at once, so the callback could still be setting its
// deadline after wait had returned, while close (which WaitEmpty and Events run as soon as wait
// reports ctx's end) releases the file, or on the next wait's read. A started callback is waited for.
func (w *watcher) wait(ctx context.Context) error {
	if w.f == nil {
		t := time.NewTimer(pollFallback)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	if err := w.f.SetReadDeadline(time.Now().Add(pollFallback)); err != nil {
		return fmt.Errorf("inotify deadline: %w", err)
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
	var buf [4096]byte
	if _, err := f.Read(buf[:]); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		return fmt.Errorf("read inotify: %w", err)
	}
	return nil
}

// close releases the inotify fd.
func (w *watcher) close() {
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
}
